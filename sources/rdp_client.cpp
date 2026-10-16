/*! \file
 *  \brief Outgoing Remote Desktop connections: see rdp_client.h.
 */
#include "rdp_client.h"
#include "conversions.h"
#include "consigne.h"
#include "registry_common.h"
#include "sha.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

const wchar_t RDP_CACHE_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache";

namespace {

const wchar_t CLIENT_KEY[] = L"Software\\Microsoft\\Terminal Server Client";
const char CACHE_MAGIC[] = "RDP8bmp";              // then a NUL: 8 bytes
const size_t CACHE_HEADER = 12, TILE_HEADER = 12;
const uintmax_t FILE_MAX = 512ull * 1024 * 1024;   // a bitmap cache is tens of MiB at most
const size_t BMC_TILE_HEADER = 20;                  // keys, width, height, data length, flags
const unsigned BMC_TILE_SIDE = 64;                  // a slot holds a tile of 64 × 64 pixels at most
const uint32_t BMC_COMPRESSED = 0x08;               // flag of a tile compressed by the interleaved RLE

// The orders of the interleaved RLE codec (MS-RDPBCGR 2.2.9.1.1.3.1.2.4).
enum RleOrder : unsigned {
	REGULAR_BG_RUN = 0x0, REGULAR_FG_RUN = 0x1, REGULAR_FGBG_IMAGE = 0x2, REGULAR_COLOR_RUN = 0x3,
	REGULAR_COLOR_IMAGE = 0x4, LITE_SET_FG_FG_RUN = 0xC, LITE_SET_FG_FGBG_IMAGE = 0xD, LITE_DITHERED_RUN = 0xE,
	MEGA_MEGA_BG_RUN = 0xF0, MEGA_MEGA_FG_RUN = 0xF1, MEGA_MEGA_FGBG_IMAGE = 0xF2, MEGA_MEGA_COLOR_RUN = 0xF3,
	MEGA_MEGA_COLOR_IMAGE = 0xF4, MEGA_MEGA_SET_FG_RUN = 0xF6, MEGA_MEGA_SET_FGBG_IMAGE = 0xF7,
	MEGA_MEGA_DITHERED_RUN = 0xF8, SPECIAL_FGBG_1 = 0xF9, SPECIAL_FGBG_2 = 0xFA, WHITE = 0xFD, BLACK = 0xFE
};
const uint16_t WHITE_16 = 0xFFFF, BLACK_16 = 0;

//! The order of a header byte: regular (3 bits), lite (4 bits) or a whole byte.
unsigned rleOrder(uint8_t header) {
	if ((header & 0xC0) != 0xC0) return header >> 5;
	if ((header & 0xF0) == 0xF0) return header;
	return header >> 4;
}

/*! The run length of an order and the bytes its header takes.
 *  @return false if the data ends inside the header */
bool rleRunLength(unsigned order, const uint8_t* at, const uint8_t* end, size_t& run, size_t& advance) {
	const uint8_t header = *at;
	advance = 1;
	run = 0;
	const bool lite = order == LITE_SET_FG_FG_RUN || order == LITE_DITHERED_RUN || order == LITE_SET_FG_FGBG_IMAGE;
	const bool mask = order == REGULAR_FGBG_IMAGE || order == LITE_SET_FG_FGBG_IMAGE;
	if (order <= REGULAR_COLOR_IMAGE || lite) {
		run = lite ? (header & 0x0F) : (header & 0x1F);
		if (run != 0) { if (mask) run *= 8; return true; }
		if (end - at < 2) return false;
		run = (size_t)at[1] + (mask ? 1 : lite ? 16 : 32);
		advance = 2;
		return true;
	}
	if (order >= MEGA_MEGA_BG_RUN && order <= MEGA_MEGA_DITHERED_RUN) {
		if (end - at < 3) return false;
		run = readLittleEndian<uint16_t>(at + 1);
		advance = 3;
	}
	return true;
}

/*! The bitmap being written by the RLE decoder: every pixel written or read
 *  is bounded by it, the row above by its start. */
struct RleCanvas {
	std::vector<uint16_t>& pixels;
	size_t row, at = 0;
	bool full() const { return at >= pixels.size(); }
	bool firstRow() const { return at < row; }
	uint16_t above() const { return pixels[at - row]; }
	bool put(uint16_t pixel) { if (full()) return false; pixels[at++] = pixel; return true; }
	/*! The pixels of a foreground/background mask, `count` bits of `mask`:
	 *  a set bit is the foreground (XOR the pixel above past the first row).
	 *  @param first whether the order began on the first row: the codec
	 *         decides it once per order, not per pixel */
	bool putMask(uint8_t mask, size_t count, uint16_t foreground, bool first) {
		for (size_t bit = 0; bit < count; ++bit) {
			const bool set = (mask >> bit) & 1;
			const uint16_t pixel = first ? (set ? foreground : BLACK_16) : (set ? (uint16_t)(above() ^ foreground) : above());
			if (!put(pixel)) return false;
		}
		return true;
	}
};

/*! The recent connections and the servers of one profile's NTUSER.DAT.
 *  @param root the hive's root
 *  @param sid the profile
 *  @param records receives a RecentConnection per MRU value, a Server per key */
void readClientKeys(ORHKEY root, const std::wstring& sid, std::vector<RdpClientRecord>& records) {
	const std::wstring defaultKey = std::wstring(CLIENT_KEY) + L"\\Default";
	ORHKEY key = NULL;
	if (OROpenKey(root, defaultKey.c_str(), &key) == ERROR_SUCCESS) {
		const FILETIME written = lastWrite(key);
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		for (DWORD i = 0; enumRegistryValue(key, i, name, type, data) == ERROR_SUCCESS; ++i) {
			// MRU0, MRU1…: the most recent first.
			if (name.size() < 4 || _wcsnicmp(name.c_str(), L"MRU", 3) != 0) continue;
			const std::wstring digits = name.substr(3);
			if (digits.find_first_not_of(L"0123456789") != std::wstring::npos) continue;
			RdpClientRecord r;
			r.type = L"RecentConnection";
			r.sid = sid;
			r.source = L"NTUSER.DAT\\" + defaultKey;
			r.fields.add(L"Target", Json::str(valueText(type, data)));
			r.fields.add(L"MruPosition", Json::num((long long)_wtoi(digits.c_str())));
			addDate(r.fields, L"KeyLastWrite", written);
			records.push_back(std::move(r));
		}
		ORCloseKey(key);
	}
	const std::wstring serversKey = std::wstring(CLIENT_KEY) + L"\\Servers";
	for (const std::wstring& host : subkeys(root, serversKey)) {
		ORHKEY server = NULL;
		if (OROpenKey(root, (serversKey + L"\\" + host).c_str(), &server) != ERROR_SUCCESS) continue;
		RdpClientRecord r;
		r.type = L"Server";
		r.sid = sid;
		r.source = L"NTUSER.DAT\\" + serversKey + L"\\" + host;
		r.fields.add(L"Host", Json::str(host));
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		for (DWORD i = 0; enumRegistryValue(server, i, name, type, data) == ERROR_SUCCESS; ++i)
			r.fields.add(registryNameToJsonKey(name), registryValueToJson(type, data));
		addDate(r.fields, L"KeyLastWrite", lastWrite(server));
		ORCloseKey(server);
		records.push_back(std::move(r));
	}
}

/*! The tiles of a decoded cache, each exported as a BMP image under
 *  `rdp_cache\\<SID>\\<file>`, listed with its size, keys and the SHA-256 of
 *  its pixels.
 *  @return the list of the tiles */
Json exportTiles(const std::vector<RdpCacheTile>& tiles, const std::wstring& sid, const std::wstring& fileName) {
	const std::wstring folder = L"rdp_cache\\" + sid + L"\\" + fileName;
	std::error_code ec;
	std::filesystem::create_directories(std::filesystem::path(conf._outputDir) / folder, ec);
	Json list = Json::arr();
	for (size_t i = 0; i < tiles.size(); ++i) {
		wchar_t name[32];
		swprintf(name, 32, L"tile_%04zu.bmp", i);
		const std::wstring image = folder + L"\\" + name;
		const std::vector<uint8_t> bmp = rdpTileBmp(tiles[i]);
		std::ofstream out(std::filesystem::path(conf._outputDir) / image, std::ios::binary);
		out.write(reinterpret_cast<const char*>(bmp.data()), (std::streamsize)bmp.size());
		Sha256Stream digest;
		digest.update(tiles[i].pixels.data(), tiles[i].pixels.size());
		Json t = Json::obj();
		t.add(L"Index", Json::num((unsigned long long)i));
		t.add(L"Width", Json::num((unsigned long long)tiles[i].width));
		t.add(L"Height", Json::num((unsigned long long)tiles[i].height));
		t.add(L"Key1", Json::str(to_hex(tiles[i].key1, 8, HexLetters::Upper, true)));
		t.add(L"Key2", Json::str(to_hex(tiles[i].key2, 8, HexLetters::Upper, true)));
		t.add(L"PixelsSha256", Json::str(digest.hexDigest()));
		if (out) t.add(L"Image", Json::str(image));
		else log(2, L"🔥RDP tile image not written: " + image);
		list.push(std::move(t));
	}
	return list;
}

/*! One bitmap cache, `Cache<NNNN>.bin` or `bcache2?.bmc`, as a BitmapCache
 *  record. A .bmc of a depth WAC has no sample of is recorded as collected,
 *  its tiles not decoded.
 *  @param file the cache, in the working copy
 *  @param sid the profile
 *  @param r receives the record
 *  @return false if the file is unreadable or not of its format (logged) */
bool readBitmapCache(const std::filesystem::path& file, const std::wstring& sid, RdpClientRecord& r) {
	std::vector<uint8_t> bytes;
	if (!readWholeFile(file, FILE_MAX, bytes)) {
		log(2, L"🔥RDP bitmap cache unreadable or too large: " + file.wstring());
		return false;
	}
	r.type = L"BitmapCache";
	r.sid = sid;
	r.source = originalPath(file.wstring());
	std::vector<RdpCacheTile> tiles;
	const bool bmc = _wcsicmp(file.extension().wstring().c_str(), L".bmc") == 0;
	if (!bmc) {
		uint32_t version = 0;
		if (!decodeRdpBitmapCache(bytes, version, tiles)) {
			log(2, L"🔥RDP bitmap cache without its header: " + file.wstring());
			return false;
		}
		r.fields.add(L"Version", Json::num((unsigned long long)version));
	} else if (bmcBytesPerPixel(file.filename().wstring()) == 0) {
		r.fields.add(L"DecodingStatus", Json::str(L"UnsupportedFormat"));
	} else {
		size_t unread = 0;
		if (!decodeRdpBmcCache(bytes, tiles, unread)) {
			log(2, L"🔥RDP bitmap cache whose first tile is not one: " + file.wstring());
			return false;
		}
		r.fields.add(L"BitsPerPixel", Json::num(16ull));
		if (unread) r.fields.add(L"UnreadTiles", Json::num((unsigned long long)unread));
	}
	r.fields.add(L"TileCount", Json::num((unsigned long long)tiles.size()));
	FILETIME created{}, modified{}, accessed{};
	if (ExhibitSourceTimes(file.wstring(), created, modified, accessed)) addDate(r.fields, L"SourceModified", modified);
	if (!tiles.empty()) r.fields.add(L"Tiles", exportTiles(tiles, sid, file.filename().wstring()));
	log(2, L"❇️" + r.source + L" : " + std::to_wstring(tiles.size()) + L" tile(s)");
	return true;
}

} // namespace

bool decodeRdpBitmapCache(const std::vector<uint8_t>& bytes, uint32_t& version, std::vector<RdpCacheTile>& tiles) {
	if (bytes.size() < CACHE_HEADER || std::memcmp(bytes.data(), CACHE_MAGIC, sizeof CACHE_MAGIC) != 0) return false;
	version = readLittleEndian<uint32_t>(bytes.data() + 8);
	size_t at = CACHE_HEADER;
	while (at + TILE_HEADER <= bytes.size()) {
		RdpCacheTile t;
		t.key1 = readLittleEndian<uint32_t>(bytes.data() + at);
		t.key2 = readLittleEndian<uint32_t>(bytes.data() + at + 4);
		t.width = readLittleEndian<uint16_t>(bytes.data() + at + 8);
		t.height = readLittleEndian<uint16_t>(bytes.data() + at + 10);
		const size_t size = (size_t)4 * t.width * t.height;
		// A tile its header announces beyond the file is cut: the reading stops there.
		if (size > bytes.size() - at - TILE_HEADER) break;
		t.pixels.assign(bytes.begin() + (std::ptrdiff_t)(at + TILE_HEADER), bytes.begin() + (std::ptrdiff_t)(at + TILE_HEADER + size));
		at += TILE_HEADER + size;
		if (t.width && t.height) tiles.push_back(std::move(t));
	}
	return true;
}

bool rdpRleDecompress16(const uint8_t* data, size_t size, unsigned width, unsigned height, std::vector<uint16_t>& pixels) {
	pixels.assign((size_t)width * height, 0);
	if (pixels.empty()) return false;
	RleCanvas canvas{ pixels, width };
	const uint8_t* at = data;
	const uint8_t* const end = data + size;
	uint16_t foreground = WHITE_16;
	/* `first`: whether the order starts on the first row, decided once per
	   order as the codec does — an order that runs into the second row keeps
	   the first row's rule to its end. */
	bool insertForeground = false, first = true;
	auto readPixel = [&](uint16_t& pixel) {
		if (end - at < 2) return false;
		pixel = readLittleEndian<uint16_t>(at);
		at += 2;
		return true;
	};
	while (at < end) {
		// Leaving the first row: a background run there no longer calls for an inserted pixel.
		if (first && !canvas.firstRow()) { first = false; insertForeground = false; }
		const unsigned order = rleOrder(*at);
		size_t run = 0, advance = 0;
		if (!rleRunLength(order, at, end, run, advance)) return false;
		at += advance;
		if (order == REGULAR_BG_RUN || order == MEGA_MEGA_BG_RUN) {
			/* Two background runs in a row: the second starts with a
			   foreground pixel, which no other order could have written. */
			if (insertForeground && run > 0) {
				if (!canvas.put(first ? foreground : (uint16_t)(canvas.above() ^ foreground))) return false;
				--run;
			}
			for (; run > 0; --run) if (!canvas.put(first ? BLACK_16 : canvas.above())) return false;
			insertForeground = true;
			continue;
		}
		insertForeground = false;
		switch (order) {
		case LITE_SET_FG_FG_RUN: case MEGA_MEGA_SET_FG_RUN:
			if (!readPixel(foreground)) return false;
			[[fallthrough]];
		case REGULAR_FG_RUN: case MEGA_MEGA_FG_RUN:
			for (; run > 0; --run) if (!canvas.put(first ? foreground : (uint16_t)(canvas.above() ^ foreground))) return false;
			break;
		case LITE_DITHERED_RUN: case MEGA_MEGA_DITHERED_RUN: {
			uint16_t a = 0, b = 0;
			if (!readPixel(a) || !readPixel(b)) return false;
			for (; run > 0; --run) if (!canvas.put(a) || !canvas.put(b)) return false;
			break;
		}
		case REGULAR_COLOR_RUN: case MEGA_MEGA_COLOR_RUN: {
			uint16_t pixel = 0;
			if (!readPixel(pixel)) return false;
			for (; run > 0; --run) if (!canvas.put(pixel)) return false;
			break;
		}
		case LITE_SET_FG_FGBG_IMAGE: case MEGA_MEGA_SET_FGBG_IMAGE:
			if (!readPixel(foreground)) return false;
			[[fallthrough]];
		case REGULAR_FGBG_IMAGE: case MEGA_MEGA_FGBG_IMAGE:
			for (; run > 0; run -= std::min<size_t>(run, 8)) {
				if (at >= end) return false;
				if (!canvas.putMask(*at++, std::min<size_t>(run, 8), foreground, first)) return false;
			}
			break;
		case REGULAR_COLOR_IMAGE: case MEGA_MEGA_COLOR_IMAGE:
			for (; run > 0; --run) {
				uint16_t pixel = 0;
				if (!readPixel(pixel) || !canvas.put(pixel)) return false;
			}
			break;
		case SPECIAL_FGBG_1: if (!canvas.putMask(0x03, 8, foreground, first)) return false; break;
		case SPECIAL_FGBG_2: if (!canvas.putMask(0x05, 8, foreground, first)) return false; break;
		case WHITE: if (!canvas.put(WHITE_16)) return false; break;
		case BLACK: if (!canvas.put(BLACK_16)) return false; break;
		default: return false;   // an order the codec does not have
		}
	}
	return canvas.full();
}

unsigned bmcBytesPerPixel(const std::wstring& fileName) {
	return _wcsicmp(fileName.c_str(), L"bcache22.bmc") == 0 ? 2 : 0;
}

bool decodeRdpBmcCache(const std::vector<uint8_t>& bytes, std::vector<RdpCacheTile>& tiles, size_t& unread) {
	const size_t slot = BMC_TILE_HEADER + (size_t)BMC_TILE_SIDE * BMC_TILE_SIDE * 2;
	unread = 0;
	for (size_t at = 0; at + BMC_TILE_HEADER <= bytes.size(); at += slot) {
		const uint8_t* header = bytes.data() + at;
		RdpCacheTile t;
		t.key1 = readLittleEndian<uint32_t>(header);
		t.key2 = readLittleEndian<uint32_t>(header + 4);
		t.width = readLittleEndian<uint16_t>(header + 8);
		t.height = readLittleEndian<uint16_t>(header + 10);
		const size_t length = readLittleEndian<uint32_t>(header + 12);
		const uint32_t flags = readLittleEndian<uint32_t>(header + 16);
		// Not a slot: the first one says the file is not of this layout, a later one ends it.
		if (t.width == 0 || t.height == 0 || t.width > BMC_TILE_SIDE || t.height > BMC_TILE_SIDE
		    || length > slot - BMC_TILE_HEADER || length > bytes.size() - at - BMC_TILE_HEADER) {
			if (at == 0) return false;
			break;
		}
		std::vector<uint16_t> pixels;
		if (!(flags & BMC_COMPRESSED) || !rdpRleDecompress16(header + BMC_TILE_HEADER, length, t.width, t.height, pixels)) {
			++unread;
			continue;
		}
		// RGB 5-6-5, rows from the bottom, to BGRA rows from the top: each component widened by its high bits.
		t.pixels.resize((size_t)4 * t.width * t.height);
		for (size_t y = 0; y < t.height; ++y)
			for (size_t x = 0; x < t.width; ++x) {
				const uint16_t p = pixels[(t.height - 1 - y) * t.width + x];
				const uint8_t r = (uint8_t)((p >> 11) & 0x1F), g = (uint8_t)((p >> 5) & 0x3F), b = (uint8_t)(p & 0x1F);
				uint8_t* out = &t.pixels[4 * (y * t.width + x)];
				out[0] = (uint8_t)((b << 3) | (b >> 2));
				out[1] = (uint8_t)((g << 2) | (g >> 4));
				out[2] = (uint8_t)((r << 3) | (r >> 2));
				out[3] = 0xFF;
			}
		tiles.push_back(std::move(t));
	}
	return true;
}

std::vector<uint8_t> rdpTileBmp(const RdpCacheTile& tile) {
	const uint32_t rowBytes = 4u * tile.width, imageBytes = rowBytes * tile.height;
	const uint32_t FILE_HEADER = 14, INFO_HEADER = 40;
	std::vector<uint8_t> bmp(FILE_HEADER + INFO_HEADER, 0);
	auto put16 = [&](size_t at, uint16_t v) { bmp[at] = (uint8_t)v; bmp[at + 1] = (uint8_t)(v >> 8); };
	auto put32 = [&](size_t at, uint32_t v) { for (int i = 0; i < 4; ++i) bmp[at + i] = (uint8_t)(v >> (8 * i)); };
	bmp[0] = 'B'; bmp[1] = 'M';
	put32(2, FILE_HEADER + INFO_HEADER + imageBytes);
	put32(10, FILE_HEADER + INFO_HEADER);
	put32(14, INFO_HEADER);
	put32(18, tile.width);
	put32(22, tile.height);          // positive: rows from the bottom
	put16(26, 1);                    // planes
	put16(28, 32);                   // bits per pixel, BI_RGB
	put32(34, imageBytes);
	for (uint32_t row = tile.height; row-- > 0;)
		bmp.insert(bmp.end(), tile.pixels.begin() + (std::ptrdiff_t)(row * rowBytes),
		           tile.pixels.begin() + (std::ptrdiff_t)((row + 1) * rowBytes));
	return bmp;
}

void parseRdpFile(const std::wstring& text, Json& settings) {
	size_t start = 0;
	while (start < text.size()) {
		size_t end = text.find(L'\n', start);
		if (end == std::wstring::npos) end = text.size();
		std::wstring line = text.substr(start, end - start);
		start = end + 1;
		while (!line.empty() && (line.back() == L'\r' || line.back() == L' ')) line.pop_back();
		// name:type:value — the value may itself hold colons ("full address:s:host:3389").
		const size_t first = line.find(L':');
		const size_t second = first == std::wstring::npos ? std::wstring::npos : line.find(L':', first + 1);
		if (second == std::wstring::npos || first == 0) continue;
		settings.add(registryNameToJsonKey(line.substr(0, first)), Json::str(line.substr(second + 1)));
	}
}

Json RdpClientRecord::toJson() const {
	Json o = Json::obj();
	o.add(L"Type", Json::str(type));
	addUser(o, sid);
	o.add(L"Source", Json::str(source));
	o.merge(fields);
	return o;
}

HRESULT RdpClient::getData() {
	log(0, L"ℹ️Outgoing RDP connections :");
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) { readClientKeys(root, sid, records_); });
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring sid = std::get<0>(profileEntry), profile = std::get<1>(profileEntry);
		// The connection files of the profile's Documents, Default.rdp among them.
		for (const std::filesystem::path& file : listFilesByExtension(extractedPath(profile + L"\\Documents"), { L".rdp" })) {
			std::vector<uint8_t> bytes;
			if (!readWholeFile(file, FILE_MAX, bytes) || bytes.empty()) continue;
			// mstsc writes them in UTF-16 with a byte-order mark; a hand-made one may be in ANSI.
			const bool utf16 = bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE;
			std::wstring text;
			if (utf16) for (size_t i = 2; i + 1 < bytes.size(); i += 2) text += (wchar_t)readLittleEndian<uint16_t>(bytes.data() + i);
			else text = decodeText(std::string(bytes.begin(), bytes.end()), 0);
			RdpClientRecord r;
			r.type = L"ConnectionFile";
			r.sid = sid;
			r.source = originalPath(file.wstring());
			Json settings = Json::obj();
			parseRdpFile(text, settings);
			r.fields.add(L"Settings", std::move(settings));
			FILETIME created{}, modified{}, accessed{};
			if (ExhibitSourceTimes(file.wstring(), created, modified, accessed)) addDate(r.fields, L"SourceModified", modified);
			records_.push_back(std::move(r));
		}
		// The bitmap caches, each tile exported as an image next to the JSON.
		for (const std::filesystem::path& file : listFilesByExtension(extractedPath(profile + RDP_CACHE_FOLDER), { L".bin", L".bmc" })) {
			RdpClientRecord r;
			if (readBitmapCache(file, sid, r)) records_.push_back(std::move(r));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT RdpClient::toJson() {
	Json list = Json::arr();
	for (const RdpClientRecord& r : records_) list.push(r.toJson());
	return writeJsonFile("rdp_client.json", list);
}

void RdpClient::clear() {
	records_.clear();
}
