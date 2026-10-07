/*! \file
 *  \brief Outgoing Remote Desktop connections: see rdp_client.h.
 */
#include "rdp_client.h"
#include "conversions.h"
#include "consigne.h"
#include "registry_common.h"
#include "sha.h"
#include <cstring>
#include <filesystem>
#include <fstream>

const wchar_t RDP_CACHE_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache";

namespace {

const wchar_t CLIENT_KEY[] = L"Software\\Microsoft\\Terminal Server Client";
const char CACHE_MAGIC[] = "RDP8bmp";              // then a NUL: 8 bytes
const size_t CACHE_HEADER = 12, TILE_HEADER = 12;
const uintmax_t FILE_MAX = 512ull * 1024 * 1024;   // a bitmap cache is tens of MiB at most

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
			const std::vector<uint8_t> bytes = readWorkingFile(file, FILE_MAX);
			if (bytes.empty()) continue;
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
		for (const std::filesystem::path& file : listFilesByExtension(extractedPath(profile + RDP_CACHE_FOLDER), { L".bin" })) {
			const std::vector<uint8_t> bytes = readWorkingFile(file, FILE_MAX);
			uint32_t version = 0;
			std::vector<RdpCacheTile> tiles;
			if (!decodeRdpBitmapCache(bytes, version, tiles)) {
				log(2, L"🔥RDP bitmap cache without its header: " + file.wstring());
				continue;
			}
			RdpClientRecord r;
			r.type = L"BitmapCache";
			r.sid = sid;
			r.source = originalPath(file.wstring());
			r.fields.add(L"Version", Json::num((unsigned long long)version));
			r.fields.add(L"TileCount", Json::num((unsigned long long)tiles.size()));
			FILETIME created{}, modified{}, accessed{};
			if (ExhibitSourceTimes(file.wstring(), created, modified, accessed)) addDate(r.fields, L"SourceModified", modified);
			const std::wstring folder = L"rdp_cache\\" + sid + L"\\" + file.filename().wstring();
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
			r.fields.add(L"Tiles", std::move(list));
			log(2, L"❇️" + r.source + L" : " + std::to_wstring(tiles.size()) + L" tile(s)");
			records_.push_back(std::move(r));
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
