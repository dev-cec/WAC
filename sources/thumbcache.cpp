/*! \file
 *  \brief Explorer's thumbnail and icon caches (see thumbcache.h).
 */
#include "thumbcache.h"
#include "conversions.h"
#include "consigne.h"
#include "sha.h"
#include "oleparser.h"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>

const wchar_t THUMBCACHE_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Windows\\Explorer";

namespace {

const size_t FILE_HEADER = 24;           //!< signature, version, type, then three offsets and counts of the version
const uint32_t VISTA = 0x14;             //!< the version of Vista's caches
const uint32_t WINDOWS_7 = 0x15;         //!< the version of Windows 7's caches
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

/*! Where a version keeps what the decoder reads. Windows 7 has neither the
 *  header's unknown field nor the entry's width and height: its offsets come
 *  four bytes earlier in the header, and its entry is 48 bytes, not 56.
 *  Vista has Windows 7's file header, and after the entry's hash the source
 *  file's extension (four UTF-16 characters): every later field comes eight
 *  bytes further, its entry is 56 bytes (measured on Vista SP2, 28 entries,
 *  every checksum as Windows wrote it; read the same way by
 *  dissect.thumbcache). The header checksum covers the entry up to itself in
 *  all three. */
struct Layout {
	size_t firstEntryAt;   //!< in the file header, the offset of the first entry
	size_t firstFreeAt;    //!< in the file header, the offset of the first free place
	size_t extensionAt;    //!< in the entry, the source's extension; 0 when the version has none
	size_t sizesAt;        //!< in the entry, the identifier's size, then the padding's and the data's
	size_t entryHeader;    //!< the entry's fixed part
	size_t dataChecksumAt; //!< in the entry, the data checksum; the header checksum follows it
	bool hasSize;          //!< the entry gives the image's width and height
};

//! The layout of a decoded version: Vista's, Windows 7's, or Windows 8 to 11's.
Layout layoutOf(uint32_t version) {
	if (version == VISTA) return { 12, 16, 16, 24, 56, 40, false };
	if (version == WINDOWS_7) return { 12, 16, 0, 16, 48, 32, false };
	return { 16, 20, 0, 16, 56, 40, true };
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

std::wstring thumbcacheSize(uint32_t version, uint32_t type) {
	static const std::vector<std::wstring> SEVEN = { L"32", L"96", L"256", L"1024", L"sr" };
	static const std::vector<std::wstring> LATER = { L"16", L"32", L"48", L"96", L"256", L"768", L"1280", L"1920", L"2560",
	                                                 L"sr", L"wide", L"exif", L"wide_alternate", L"custom_stream" };
	const std::vector<std::wstring>& sizes = version == VISTA || version == WINDOWS_7 ? SEVEN : LATER;
	return type < sizes.size() ? sizes[type] : L"";
}

bool decodeThumbcache(const std::vector<uint8_t>& bytes, ThumbcacheFile& file) {
	file = ThumbcacheFile{};
	if (bytes.size() < FILE_HEADER || memcmp(bytes.data(), "CMMM", 4) != 0) return false;
	file.version = readLittleEndian<uint32_t>(bytes.data() + 4);
	file.type = readLittleEndian<uint32_t>(bytes.data() + 8);
	/* The version decides, and the table holds which ones are decoded
	   (pieceFormat): Vista has another entry layout, and a version nobody has
	   seen yet may have another one still. Such a cache used to be skipped
	   without a word; it is now declared "unsupported format". */
	if (!pieceFormat("thumbcache", file.version).decoded) {
		file.unsupportedFormat = true;
		return true;
	}
	const Layout layout = layoutOf(file.version);
	const size_t entryHeader = layout.entryHeader;
	size_t offset = readLittleEndian<uint32_t>(bytes.data() + layout.firstEntryAt);
	// The first free place ends the entries; never beyond the file itself.
	const size_t end = std::min<size_t>(readLittleEndian<uint32_t>(bytes.data() + layout.firstFreeAt), bytes.size());
	while (fits(end, offset, entryHeader) && memcmp(bytes.data() + offset, "CMMM", 4) == 0) {
		const uint8_t* p = bytes.data() + offset;
		const size_t size = readLittleEndian<uint32_t>(p + 4);
		const size_t identifierSize = readLittleEndian<uint32_t>(p + layout.sizesAt);
		const size_t padding = readLittleEndian<uint32_t>(p + layout.sizesAt + 4);
		const size_t dataSize = readLittleEndian<uint32_t>(p + layout.sizesAt + 8);
		// Each length is the file's word: the entry must hold them all, and lie in the file.
		if (size < entryHeader || !fits(end, offset, size) || identifierSize % 2 != 0
		    || identifierSize > size - entryHeader || padding > size - entryHeader - identifierSize
		    || dataSize > size - entryHeader - identifierSize - padding) {
			log(2, L"🔥Thumbnail cache: entry at " + std::to_wstring(offset) + L" outside its bounds, reading stopped");
			break;
		}
		ThumbcacheEntry e;
		e.offset = offset;
		e.hash = readLittleEndian<uint64_t>(p + 8);
		// Vista's extension: up to four characters, null-padded.
		for (size_t i = 0; layout.extensionAt && i < 8; i += 2) {
			const wchar_t c = (wchar_t)readLittleEndian<uint16_t>(p + layout.extensionAt + i);
			if (c == 0) break;
			e.extension += c;
		}
		for (size_t i = 0; i < identifierSize; i += 2)
			e.identifier += (wchar_t)readLittleEndian<uint16_t>(p + entryHeader + i);
		if (layout.hasSize) {
			e.width = readLittleEndian<uint32_t>(p + 28);
			e.height = readLittleEndian<uint32_t>(p + 32);
		}
		e.dataOffset = offset + entryHeader + identifierSize + padding;
		e.dataSize = dataSize;
		const size_t headerChecked = layout.dataChecksumAt + 8;
		e.headerChecksumValid = thumbcacheCrc64(p, headerChecked, ~0ULL) == readLittleEndian<uint64_t>(p + headerChecked);
		e.dataChecksumValid = thumbcacheDataChecksum(bytes.data() + e.dataOffset, dataSize)
		                      == readLittleEndian<uint64_t>(p + layout.dataChecksumAt);
		file.entries.push_back(std::move(e));
		offset += size;
	}
	return true;
}

bool decodeThumbsDb(const std::vector<uint8_t>& bytes, std::vector<ThumbsDbEntry>& entries) {
	entries.clear();
	try {
		std::vector<uint8_t> copy = bytes;   // the OLE reader takes a writable buffer
		oleParser ole(copy.data(), copy.size());
		const Directory catalogue = ole.findDirectory(L"Catalog");
		if (catalogue.name.empty()) return false;
		const std::vector<BYTE> c = ole.Getdata(catalogue);
		if (c.size() < 16) return false;
		const size_t headerSize = readLittleEndian<uint16_t>(c.data());
		const uint32_t count = readLittleEndian<uint32_t>(c.data() + 4);
		size_t at = std::max<size_t>(headerSize, 16);
		for (uint32_t i = 0; i < count && fits(c.size(), at, 16); ++i) {
			const size_t size = readLittleEndian<uint32_t>(c.data() + at);
			if (size < 16 || !fits(c.size(), at, size)) break;   // a forged size ends the catalogue
			ThumbsDbEntry e;
			e.index = readLittleEndian<uint32_t>(c.data() + at + 4);
			std::memcpy(&e.sourceModifiedUtc, c.data() + at + 8, sizeof e.sourceModifiedUtc);
			e.name = readWideZ(c.data(), at + size, at + 16);
			at += size;
			std::wstring stream = std::to_wstring(e.index);
			std::reverse(stream.begin(), stream.end());
			const Directory d = ole.findDirectory(stream);
			if (!d.name.empty()) {
				const std::vector<BYTE> s = ole.Getdata(d);
				// The stream's header gives its own size; the image's then gives its length and size.
				const size_t header = s.size() >= 4 ? readLittleEndian<uint32_t>(s.data()) : 0;
				if (header >= 12 && fits(s.size(), header, 16)) {
					const size_t length = readLittleEndian<uint32_t>(s.data() + header + 4);
					e.width = readLittleEndian<uint32_t>(s.data() + header + 8);
					e.height = readLittleEndian<uint32_t>(s.data() + header + 12);
					if (fits(s.size(), header + 16, length)) e.image.assign(s.begin() + header + 16, s.begin() + header + 16 + length);
				}
			}
			entries.push_back(std::move(e));
		}
	} catch (const std::exception&) {
		return false;   // a chain outside the file: not read further
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
				const std::wstring cacheSize = thumbcacheSize(cache.version, cache.type);
				if (!cacheSize.empty()) o.add(L"CacheSize", Json::str(cacheSize));
				o.add(L"Offset", Json::num((unsigned long long)e.offset));
				o.add(L"Hash", Json::str(to_hex(e.hash, 16)));
				if (!e.identifier.empty()) o.add(L"Identifier", Json::str(e.identifier));
				if (!e.extension.empty()) o.add(L"SourceExtension", Json::str(e.extension));
				o.add(L"HeaderChecksumValid", Json::boolean(e.headerChecksumValid));
				// An entry without image (a placeholder Explorer keeps): no size, no data.
				if (e.dataSize) {
					const uint8_t* data = bytes.data() + e.dataOffset;
					// Windows 7's entry has no size: none given rather than zeros.
					if (e.width) o.add(L"Width", Json::num((unsigned long long)e.width));
					if (e.height) o.add(L"Height", Json::num((unsigned long long)e.height));
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
	readThumbsDb();
	return ERROR_SUCCESS;
}

void Thumbcaches::readThumbsDb() {
	// Windows XP: one Thumbs.db per folder shown as thumbnails, found by name in the exhibit store.
	size_t file = 0;
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		const std::filesystem::path source(exhibit.sourcePath);
		if (exhibit.workingFile.empty() || _wcsicmp(source.filename().c_str(), L"Thumbs.db") != 0) continue;
		std::vector<uint8_t> bytes;
		std::vector<ThumbsDbEntry> thumbnails;
		if (!readWholeFile(std::filesystem::path(exhibit.workingFile), FILE_MAX, bytes) || !decodeThumbsDb(bytes, thumbnails)) {
			log(2, L"🔥Thumbs.db unreadable or without its Catalog: " + exhibit.sourcePath);
			continue;
		}
		const std::wstring folder = L"thumbcache\\Thumbs.db\\" + std::to_wstring(++file);
		std::error_code ec;
		std::filesystem::create_directories(std::filesystem::path(conf._outputDir) / folder, ec);
		for (const ThumbsDbEntry& t : thumbnails) {
			Json o = Json::obj();
			o.add(L"Cache", Json::str(exhibit.sourcePath));
			o.add(L"Index", Json::num((unsigned long long)t.index));
			o.add(L"Name", Json::str(t.name));
			o.add(L"Path", Json::str(source.parent_path().wstring() + L"\\" + t.name));
			addDate(o, L"SourceModified", t.sourceModifiedUtc);
			if (!t.image.empty()) {
				o.add(L"Width", Json::num((unsigned long long)t.width));
				o.add(L"Height", Json::num((unsigned long long)t.height));
				o.add(L"DataSize", Json::num((unsigned long long)t.image.size()));
				// Not a JPEG a viewer renders (see decodeThumbsDb): named for what it is.
				o.add(L"Format", Json::str(L"JPEG with four components (R, G, B, A), without its tables"));
				Sha256Stream digest;
				digest.update(t.image.data(), t.image.size());
				o.add(L"Sha256", Json::str(digest.hexDigest()));
				const std::wstring image = folder + L"\\" + std::to_wstring(t.index) + L".bin";
				std::ofstream out(std::filesystem::path(conf._outputDir) / image, std::ios::binary);
				out.write(reinterpret_cast<const char*>(t.image.data()), (std::streamsize)t.image.size());
				if (out) o.add(L"Image", Json::str(image));
				else log(2, L"🔥Thumbnail not written: " + image);
			}
			entries_.push(std::move(o));
		}
		log(2, L"❇️" + exhibit.sourcePath + L" : " + std::to_wstring(thumbnails.size()) + L" thumbnail(s)");
	}
}

HRESULT Thumbcaches::toJson() {
	return writeJsonFile("thumbcache.json", entries_);
}

void Thumbcaches::clear() {
	entries_ = Json::arr();
}
