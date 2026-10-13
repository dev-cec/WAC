/*! \file
 *  \brief Explorer's thumbnail and icon caches (see thumbcache.h).
 */
#include "thumbcache.h"
#include "conversions.h"
#include "consigne.h"
#include "sha.h"
#include <array>
#include <filesystem>
#include <fstream>

const wchar_t THUMBCACHE_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Windows\\Explorer";

namespace {

const size_t FILE_HEADER = 24;           //!< signature, version, type, unknown, first entry, first free place
const size_t ENTRY_HEADER = 56;          //!< the entry's fixed part, Windows 8 to 11
const size_t HEADER_CHECKED = 48;        //!< what the header checksum covers: the entry up to it
const size_t DATA_FIRST = 1024;          //!< the image's bytes covered whole by its checksum
const size_t DATA_STRIDE = 400;          //!< beyond them, four bytes every this many
const uint64_t POLYNOMIAL = 0x92C64265D32139A4ULL;   //!< reflected, as thumbcache.dll's table holds it
const uintmax_t FILE_MAX = 1024ull * 1024 * 1024;   //!< a cache is up to hundreds of MiB

//! The CRC table, built once from the polynomial.
const std::array<uint64_t, 256>& crcTable() {
	static const std::array<uint64_t, 256> table = [] {
		std::array<uint64_t, 256> t{};
		for (uint64_t i = 0; i < 256; ++i) {
			uint64_t c = i;
			for (int k = 0; k < 8; ++k) c = (c & 1) ? (c >> 1) ^ POLYNOMIAL : c >> 1;
			t[(size_t)i] = c;
		}
		return t;
	}();
	return table;
}

//! The file's kind of image, from its first bytes; "bin" when none is known.
std::wstring imageExtension(const uint8_t* data, size_t size) {
	if (size >= 2 && data[0] == 'B' && data[1] == 'M') return L"bmp";
	if (size >= 4 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') return L"png";
	if (size >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return L"jpg";
	return L"bin";
}

//! The image of an entry written next to the JSON. @return its path, empty if not written
std::wstring exportImage(const std::wstring& folder, const ThumbcacheEntry& e, const uint8_t* data) {
	const std::wstring image = folder + L"\\" + to_hex(e.hash, 16) + L"." + imageExtension(data, e.dataSize);
	std::ofstream out(std::filesystem::path(conf._outputDir) / image, std::ios::binary);
	out.write(reinterpret_cast<const char*>(data), (std::streamsize)e.dataSize);
	if (out) return image;
	log(2, L"🔥Thumbnail not written: " + image);
	return L"";
}

} // namespace

uint64_t thumbcacheCrc64(const uint8_t* bytes, size_t size, uint64_t initial) {
	const std::array<uint64_t, 256>& table = crcTable();
	uint64_t crc = initial;
	for (size_t i = 0; i < size; ++i) crc = table[(size_t)((crc ^ bytes[i]) & 0xFF)] ^ (crc >> 8);
	return crc;
}

uint64_t thumbcacheDataChecksum(const uint8_t* data, size_t size) {
	if (size <= DATA_FIRST) return thumbcacheCrc64(data, size, 0);
	uint64_t sampled = 0;
	for (size_t at = DATA_FIRST; at < size; at += DATA_STRIDE)
		sampled = thumbcacheCrc64(data + at, std::min<size_t>(4, size - at), sampled);
	return thumbcacheCrc64(data, DATA_FIRST, 0) ^ sampled;
}

std::wstring thumbcacheSize(uint32_t type) {
	static const wchar_t* const SIZES[] = { L"16", L"32", L"48", L"96", L"256", L"768", L"1280", L"1920", L"2560",
	                                        L"sr", L"wide", L"exif", L"wide_alternate", L"custom_stream" };
	return type < sizeof(SIZES) / sizeof(SIZES[0]) ? SIZES[type] : L"";
}

bool decodeThumbcache(const std::vector<uint8_t>& bytes, ThumbcacheFile& file) {
	file = ThumbcacheFile{};
	if (bytes.size() < FILE_HEADER || memcmp(bytes.data(), "CMMM", 4) != 0) return false;
	file.version = readLittleEndian<uint32_t>(bytes.data() + 4);
	file.type = readLittleEndian<uint32_t>(bytes.data() + 8);
	/* The version decides, and the table holds which ones are decoded
	   (pieceFormat): Vista and 7 have another entry layout, and a version
	   nobody has seen yet may have another one still. Such a cache used to be
	   skipped without a word; it is now declared "unsupported format". */
	if (!pieceFormat("thumbcache", file.version).decoded) {
		file.unsupportedFormat = true;
		return true;
	}
	size_t offset = readLittleEndian<uint32_t>(bytes.data() + 16);
	// The first free place ends the entries; never beyond the file itself.
	const size_t end = std::min<size_t>(readLittleEndian<uint32_t>(bytes.data() + 20), bytes.size());
	while (fits(end, offset, ENTRY_HEADER) && memcmp(bytes.data() + offset, "CMMM", 4) == 0) {
		const uint8_t* p = bytes.data() + offset;
		const size_t size = readLittleEndian<uint32_t>(p + 4);
		const size_t identifierSize = readLittleEndian<uint32_t>(p + 16);
		const size_t padding = readLittleEndian<uint32_t>(p + 20);
		const size_t dataSize = readLittleEndian<uint32_t>(p + 24);
		// Each length is the file's word: the entry must hold them all, and lie in the file.
		if (size < ENTRY_HEADER || !fits(end, offset, size) || identifierSize % 2 != 0
		    || identifierSize > size - ENTRY_HEADER || padding > size - ENTRY_HEADER - identifierSize
		    || dataSize > size - ENTRY_HEADER - identifierSize - padding) {
			log(2, L"🔥Thumbnail cache: entry at " + std::to_wstring(offset) + L" outside its bounds, reading stopped");
			break;
		}
		ThumbcacheEntry e;
		e.offset = offset;
		e.hash = readLittleEndian<uint64_t>(p + 8);
		for (size_t i = 0; i < identifierSize; i += 2)
			e.identifier += (wchar_t)readLittleEndian<uint16_t>(p + ENTRY_HEADER + i);
		e.width = readLittleEndian<uint32_t>(p + 28);
		e.height = readLittleEndian<uint32_t>(p + 32);
		e.dataOffset = offset + ENTRY_HEADER + identifierSize + padding;
		e.dataSize = dataSize;
		e.headerChecksumValid = thumbcacheCrc64(p, HEADER_CHECKED, ~0ULL) == readLittleEndian<uint64_t>(p + 48);
		e.dataChecksumValid = thumbcacheDataChecksum(bytes.data() + e.dataOffset, dataSize) == readLittleEndian<uint64_t>(p + 40);
		file.entries.push_back(std::move(e));
		offset += size;
	}
	return true;
}

HRESULT Thumbcaches::getData() {
	log(0, L"ℹ️Thumbnail and icon caches :");
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring sid = std::get<0>(profileEntry), profile = std::get<1>(profileEntry);
		for (const std::filesystem::path& path : listFilesByExtension(extractedPath(profile + THUMBCACHE_FOLDER), { L".db" })) {
			std::vector<uint8_t> bytes;
			ThumbcacheFile cache;
			if (!readWholeFile(path, FILE_MAX, bytes) || !decodeThumbcache(bytes, cache)) continue;   // the index (IMMM)
			const std::wstring source = originalPath(path.wstring());
			if (cache.unsupportedFormat) {
				Json o = Json::obj();
				addUser(o, sid);
				o.add(L"Cache", Json::str(source));
				o.add(L"FormatVersion", Json::num((unsigned long long)cache.version));
				addUnsupportedFormat(o, "thumbcache", cache.version);
				entries_.push(std::move(o));
				log(2, L"❇️" + source + L" : unsupported version " + std::to_wstring(cache.version));
				continue;
			}
			const std::wstring folder = L"thumbcache\\" + sid + L"\\" + path.filename().wstring();
			std::error_code ec;
			std::filesystem::create_directories(std::filesystem::path(conf._outputDir) / folder, ec);
			for (const ThumbcacheEntry& e : cache.entries) {
				Json o = Json::obj();
				addUser(o, sid);
				o.add(L"Cache", Json::str(source));
				if (!thumbcacheSize(cache.type).empty()) o.add(L"CacheSize", Json::str(thumbcacheSize(cache.type)));
				o.add(L"Offset", Json::num((unsigned long long)e.offset));
				o.add(L"Hash", Json::str(to_hex(e.hash, 16)));
				if (!e.identifier.empty()) o.add(L"Identifier", Json::str(e.identifier));
				o.add(L"HeaderChecksumValid", Json::boolean(e.headerChecksumValid));
				// An entry without image (a placeholder Explorer keeps): no size, no data.
				if (e.dataSize) {
					const uint8_t* data = bytes.data() + e.dataOffset;
					o.add(L"Width", Json::num((unsigned long long)e.width));
					o.add(L"Height", Json::num((unsigned long long)e.height));
					o.add(L"DataSize", Json::num((unsigned long long)e.dataSize));
					o.add(L"Format", Json::str(imageExtension(data, e.dataSize)));
					o.add(L"DataChecksumValid", Json::boolean(e.dataChecksumValid));
					Sha256Stream digest;
					digest.update(data, e.dataSize);
					o.add(L"Sha256", Json::str(digest.hexDigest()));
					const std::wstring image = exportImage(folder, e, data);
					if (!image.empty()) o.add(L"Image", Json::str(image));
				}
				entries_.push(std::move(o));
			}
			log(2, L"❇️" + source + L" : " + std::to_wstring(cache.entries.size()) + L" entry(ies)");
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Thumbcaches::toJson() {
	return writeJsonFile("thumbcache.json", entries_);
}

void Thumbcaches::clear() {
	entries_ = Json::arr();
}
