#include "pe_resource.h"
#include <fstream>
#include <cstring>
#include <filesystem>

/*! \file
 *  \brief See pe_resource.h.
 *
 *  THE STRUCTURE WALKED
 *
 *    MZ header            "MZ"; the offset of the PE header is at 0x3C
 *    PE header            "PE\0\0", then the file header (20 bytes) and the
 *                         optional header, whose magic distinguishes 32-bit from
 *                         64-bit — which shifts the directory table
 *    directories          the 3rd (index 2) is the resource one: RVA+size
 *    section table        translates the RVAs into file positions
 *    resource tree        THREE nested levels: type, name, language. Each level
 *                         is a directory whose named entries precede the
 *                         numbered ones; an entry points either to a
 *                         subdirectory (bit 31 of the offset), or to a data
 *                         description (RVA + size).
 */

namespace {

inline uint16_t rd16(const std::vector<uint8_t>& d, size_t o) {
	if (o + 2 > d.size()) return 0;
	return (uint16_t)(d[o] | (d[o + 1] << 8));
}
inline uint32_t rd32(const std::vector<uint8_t>& d, size_t o) {
	if (o + 4 > d.size()) return 0;
	return (uint32_t)d[o] | ((uint32_t)d[o + 1] << 8)
	     | ((uint32_t)d[o + 2] << 16) | ((uint32_t)d[o + 3] << 24);
}

//! Compares without regard to case (ASCII), type names being Latin.
bool sameName(const std::wstring& a, const std::wstring& b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); ++i) {
		wchar_t x = a[i], y = b[i];
		if (x >= L'a' && x <= L'z') x = (wchar_t)(x - L'a' + L'A');
		if (y >= L'a' && y <= L'z') y = (wchar_t)(y - L'a' + L'A');
		if (x != y) return false;
	}
	return true;
}

const size_t MAX_ENTRIES    = 8192;   // guard on a directory

} // namespace

size_t PeResource::offsetDeRva(uint32_t rva) const {
	for (const Section& s : sections_) {
		// The VIRTUAL size bounds the membership, the RAW size bounds the reading: a
		// section can be larger in memory than on the disk.
		if (rva >= s.rva && rva < s.rva + (s.virtualSize ? s.virtualSize : s.rawSize)) {
			const uint32_t delta = rva - s.rva;
			if (delta >= s.rawSize) return 0;      // area not present on the disk
			const size_t pos = (size_t)s.fileOffset + delta;
			return (pos < file_.size()) ? pos : 0;
		}
	}
	return 0;
}

bool PeResource::open(const std::wstring& path) {
	open_ = false;
	error_.clear();
	sections_.clear();
	file_.clear();

	std::ifstream f(std::filesystem::path(path), std::ios::binary);
	if (!f) { error_ = L"cannot be opened"; return false; }
	file_.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
	if (file_.size() < 0x40) { error_ = L"file too short"; return false; }

	if (file_[0] != 'M' || file_[1] != 'Z') { error_ = L"MZ signature absent"; return false; }
	const uint32_t offsetPe = rd32(file_, 0x3C);
	if (offsetPe + 24 > file_.size()) { error_ = L"PE header outside the file"; return false; }
	if (std::memcmp(file_.data() + offsetPe, "PE\0\0", 4) != 0) {
		error_ = L"PE signature absent"; return false;
	}

	const uint16_t nbSections    = rd16(file_, offsetPe + 6);
	const uint16_t optionalHeaderSize = rd16(file_, offsetPe + 20);
	const size_t   offsetOptions = offsetPe + 24;
	if (offsetOptions + optionalHeaderSize > file_.size()) {
		error_ = L"optional header outside the file"; return false;
	}

	/*  The magic of the optional header decides the position of the directory
	    table: 0x10b for 32-bit (96 bytes before the table), 0x20b for 64-bit
	    (112). Getting it wrong has the wrong directory read. */
	const uint16_t magic = rd16(file_, offsetOptions);
	size_t directoriesOffset;
	if      (magic == 0x010B) directoriesOffset = offsetOptions + 96;
	else if (magic == 0x020B) directoriesOffset = offsetOptions + 112;
	else { error_ = L"optional header of unknown type"; return false; }

	// Resource directory: the third one (index 2), 8 bytes per entry.
	resourcesRva_    = rd32(file_, directoriesOffset + 2 * 8);
	resourcesSize_ = rd32(file_, directoriesOffset + 2 * 8 + 4);
	if (resourcesRva_ == 0 || resourcesSize_ == 0) {
		error_ = L"no resource"; return false;
	}

	// Section table, just after the optional header.
	const size_t offsetSections = offsetOptions + optionalHeaderSize;
	for (uint16_t i = 0; i < nbSections; ++i) {
		const size_t s = offsetSections + (size_t)i * 40;
		if (s + 40 > file_.size()) break;
		Section sec;
		sec.virtualSize = rd32(file_, s + 8);
		sec.rva             = rd32(file_, s + 12);
		sec.rawSize     = rd32(file_, s + 16);
		sec.fileOffset   = rd32(file_, s + 20);
		sections_.push_back(sec);
	}
	if (sections_.empty()) { error_ = L"no section"; return false; }

	resourcesOffset_ = offsetDeRva(resourcesRva_);
	if (resourcesOffset_ == 0) { error_ = L"resource directory not located"; return false; }

	open_ = true;
	return true;
}

/*! Walks the resource tree and returns the bytes of the first resource whose
 *  TYPE matches, then the wanted language.
 *
 *  The level-2 name is not filtered: providers use only one name per type, and
 *  keeping the first one avoids forcing the caller to know a naming convention
 *  that is not documented.
 */
std::vector<uint8_t> PeResource::find(uint32_t type, const std::wstring& typeName,
                                         uint32_t language) const {
	std::vector<uint8_t> empty;
	if (!open_) return empty;

	//! Reads an entry's name (a UTF-16 string preceded by its length).
	auto entryName = [&](uint32_t nameOffset) -> std::wstring {
		const size_t p = resourcesOffset_ + (nameOffset & 0x7FFFFFFF);
		if (p + 2 > file_.size()) return std::wstring();
		const uint16_t n = rd16(file_, p);
		if (n == 0 || n > 512 || p + 2 + 2ULL * n > file_.size()) return std::wstring();
		std::wstring s;
		s.reserve(n);
		for (uint16_t i = 0; i < n; ++i) s.push_back((wchar_t)rd16(file_, p + 2 + 2ULL * i));
		return s;
	};

	// Level 1: the types.
	const size_t r1 = resourcesOffset_;
	const uint16_t nNamed1  = rd16(file_, r1 + 12);
	const uint16_t nNumbers1 = rd16(file_, r1 + 14);
	const size_t total1 = (size_t)nNamed1 + nNumbers1;
	if (total1 == 0 || total1 > MAX_ENTRIES) return empty;

	for (size_t i = 0; i < total1; ++i) {
		const size_t e = r1 + 16 + i * 8;
		if (e + 8 > file_.size()) break;
		const uint32_t id  = rd32(file_, e);
		const uint32_t sub = rd32(file_, e + 4);

		bool correspond;
		if (i < nNamed1) correspond = !typeName.empty() && sameName(entryName(id), typeName);
		else               correspond = typeName.empty() && (id == type);
		if (!correspond) continue;
		if (!(sub & 0x80000000u)) break;      // a type must lead to a subdirectory

		// Level 2: the names. The first one is taken.
		const size_t r2 = resourcesOffset_ + (sub & 0x7FFFFFFF);
		if (r2 + 16 > file_.size()) break;
		const size_t total2 = (size_t)rd16(file_, r2 + 12) + rd16(file_, r2 + 14);
		if (total2 == 0 || total2 > MAX_ENTRIES) break;

		for (size_t j = 0; j < total2; ++j) {
			const size_t e2 = r2 + 16 + j * 8;
			if (e2 + 8 > file_.size()) break;
			const uint32_t sub2 = rd32(file_, e2 + 4);
			if (!(sub2 & 0x80000000u)) continue;

			// Level 3: the languages.
			const size_t r3 = resourcesOffset_ + (sub2 & 0x7FFFFFFF);
			if (r3 + 16 > file_.size()) break;
			const size_t total3 = (size_t)rd16(file_, r3 + 12) + rd16(file_, r3 + 14);
			if (total3 == 0 || total3 > MAX_ENTRIES) break;

			for (size_t k = 0; k < total3; ++k) {
				const size_t e3 = r3 + 16 + k * 8;
				if (e3 + 8 > file_.size()) break;
				const uint32_t languageId = rd32(file_, e3);
				const uint32_t data     = rd32(file_, e3 + 4);
				if (data & 0x80000000u) continue;              // not a piece of data
				if (language != 0 && languageId != language) continue;

				// Description of the data: RVA then size.
				const size_t d = resourcesOffset_ + data;
				if (d + 8 > file_.size()) continue;
				const uint32_t rva    = rd32(file_, d);
				const uint32_t size = rd32(file_, d + 4);
				const size_t pos = offsetDeRva(rva);
				if (pos == 0 || size == 0 || pos + size > file_.size()) continue;
				return std::vector<uint8_t>(file_.begin() + pos,
				                            file_.begin() + pos + size);
			}
		}
		break;                                 // type found, no point in going on
	}
	return empty;
}

std::vector<uint8_t> PeResource::resource(uint32_t type, uint32_t language) const {
	return find(type, std::wstring(), language);
}

std::vector<uint8_t> PeResource::namedResource(const std::wstring& typeName,
                                                 uint32_t language) const {
	return find(0, typeName, language);
}

std::vector<std::wstring> PeResource::typesPresent() const {
	std::vector<std::wstring> types;
	if (!open_) return types;
	const size_t r1 = resourcesOffset_;
	const uint16_t nNamed  = rd16(file_, r1 + 12);
	const uint16_t nNumbers = rd16(file_, r1 + 14);
	const size_t total = (size_t)nNamed + nNumbers;
	if (total > MAX_ENTRIES) return types;
	for (size_t i = 0; i < total; ++i) {
		const size_t e = r1 + 16 + i * 8;
		if (e + 8 > file_.size()) break;
		const uint32_t id = rd32(file_, e);
		if (i < nNamed) {
			const size_t p = resourcesOffset_ + (id & 0x7FFFFFFF);
			if (p + 2 > file_.size()) continue;
			const uint16_t n = rd16(file_, p);
			if (n == 0 || n > 512) continue;
			std::wstring s;
			for (uint16_t c = 0; c < n; ++c) s.push_back((wchar_t)rd16(file_, p + 2 + 2ULL * c));
			types.push_back(s);
		}
		else types.push_back(std::to_wstring(id));
	}
	return types;
}
