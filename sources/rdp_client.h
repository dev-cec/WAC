/*! \file
 *  \brief Outgoing Remote Desktop connections: the servers each profile
 *         reached, its connection files, and its bitmap cache.
 *
 *  WHAT THE ARTEFACT PROVES. An intruder who moves from this machine to
 *  another by RDP leaves, in the profile that ran mstsc.exe:
 *    - in NTUSER.DAT, `Software\\Microsoft\\Terminal Server Client`: the
 *      recent connections (`Default\\MRU0`…, the most recent first) and one
 *      key per server reached (`Servers\\<host>`), with the user name offered
 *      (UsernameHint), the hash of the certificate accepted (CertHash) and
 *      the key's last write — about the last connection to that server;
 *    - the connection files (*.rdp) in the profile's Documents, Default.rdp
 *      among them: the settings of the last connection, its address and user;
 *    - the persistent bitmap cache, in
 *      `AppData\\Local\\Microsoft\\Terminal Server Client\\Cache`: pieces of
 *      the remote screen as the client drew it — what the intruder saw there.
 *
 *  THE CACHE FILES. `Cache<NNNN>.bin` (RDP 8 and later, the graphics pipeline
 *  of Windows 10 and 11) is read: the header "RDP8bmp\\0" and a version on
 *  four bytes, then tiles, each a header — two keys, width and height on two
 *  bytes each — and its pixels, 4 × width × height bytes, BGRA, rows from the
 *  top. Each tile is exported as a BMP image next to the JSON
 *  (`rdp_cache\\<SID>\\<file>\\tile_<NNNN>.bmp`); the JSON gives its size, keys
 *  and the SHA-256 of its pixels. The format was established on a session of
 *  the test VM and confronted with bmc-tools (ANSSI) tile by tile.
 *  The older `bcache2*.bmc` (compressed tiles of the RDP 6/7 drawing orders)
 *  are collected but not decoded: the test VM writes them empty, and nothing
 *  is decoded without a sample to check it on.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One tile of a bitmap cache. */
struct RdpCacheTile {
	uint32_t key1 = 0, key2 = 0;   //!< the client's keys of the tile
	uint16_t width = 0, height = 0;
	std::vector<uint8_t> pixels;   //!< BGRA, rows from the top, 4 × width × height bytes
};

/*! Decodes a `Cache<NNNN>.bin` bitmap cache.
 *  @param bytes the file
 *  @param version receives the version of its header
 *  @param tiles receives its tiles, in the file's order
 *  @return true if the file has the format; a tile cut by the end of the file
 *          ends the reading, the tiles before it kept */
bool decodeRdpBitmapCache(const std::vector<uint8_t>& bytes, uint32_t& version, std::vector<RdpCacheTile>& tiles);

/*! A tile as a BMP file: 32 bits per pixel, rows from the bottom as BMP
 *  stores them.
 *  @param tile the tile
 *  @return the file's bytes */
std::vector<uint8_t> rdpTileBmp(const RdpCacheTile& tile);

/*! The settings of a connection file (*.rdp): one "name:type:value" per line.
 *  @param text the file, decoded
 *  @param settings receives each setting under its name as a key ("full
 *         address" -> FullAddress), its value as written */
void parseRdpFile(const std::wstring& text, Json& settings);

/*! One trace of an outgoing connection. */
struct RdpClientRecord {
	std::wstring type;          //!< "RecentConnection", "Server", "ConnectionFile" or "BitmapCache"
	std::wstring sid;           //!< the profile
	std::wstring source;        //!< the registry key or the file
	Json fields = Json::obj();  //!< what the trace holds
	//! @return the trace as a JSON object
	Json toJson() const;
};

/*! The outgoing RDP connections of every profile (rdp_client.json). */
class RdpClient {
public:
	/*! Reads the user hives and the files extracted from every profile.
	 *  @return ERROR_SUCCESS, even without any trace: none is an answer */
	HRESULT getData();
	/*! Writes rdp_client.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the traces read.
	void clear();
private:
	std::vector<RdpClientRecord> records_;
};

//! The bitmap cache's folder, relative to a profile.
extern const wchar_t RDP_CACHE_FOLDER[];
