/*! \file
 *  \brief The thumbnail and icon caches of Explorer: what each user had on
 *         screen, even after the file itself was deleted.
 *
 *  WHAT THE ARTEFACT PROVES. Explorer keeps, per profile, in
 *  `AppData\\Local\\Microsoft\\Windows\\Explorer`, the thumbnails it drew
 *  (`thumbcache_<size>.db`: pictures, videos, documents seen as large icons
 *  or in the preview pane) and the icons of the programs it showed
 *  (`iconcache_<size>.db`). A thumbnail stays after the file is deleted: it
 *  shows what the user had under his eyes.
 *
 *  THE FORMAT, "CMMM" (Windows 8 to 11, versions 0x1E to 0x20). A file header
 *  of 24 bytes — signature, version, cache type (its size: 16, 32, 48, 96,
 *  256… pixels), the offset of the first entry and of the first free place —
 *  then entries of 56 bytes: signature, size, 64-bit hash, length of the
 *  identifier, padding, size of the data, width, height, data checksum,
 *  header checksum; then the identifier (the hash in hexadecimal, or a shell
 *  name), the padding, and the image itself: BMP, PNG or JPEG. The hash is
 *  the file's System.ThumbnailCacheId, which Windows gives for a file through
 *  its property system: it ties a thumbnail to its file.
 *
 *  WINDOWS 7 (version 0x15) has neither the header's unknown field — its
 *  offsets of the first entry and of the first free place come at 12 and 16,
 *  the number of entries at 20 — nor the entry's width and height: its entry
 *  is 48 bytes, the checksums at 32 and 40, and its cache types name other
 *  sizes (32, 96, 256, 1024, sr). Measured on the test VM's caches, every
 *  checksum recomputed valid. Vista's (0x14) adds an extension of 8 bytes
 *  after the hash; no sample was at hand: it stays declared unsupported.
 *
 *  THE CHECKSUMS are the format's own control, recomputed for every entry:
 *  a CRC-64 (reflected polynomial 0x92C64265D32139A4, the table of
 *  thumbcache.dll) over the first 48 bytes of the entry for the header; for
 *  the data, over at most its first 1,024 bytes, XOR, beyond them, a second
 *  CRC of four bytes every 400. Both were checked on every entry of the test
 *  VM's caches; an entry whose checksum fails is still given, and says so.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One entry of a cache file. */
struct ThumbcacheEntry {
	size_t offset = 0;              //!< position of the entry in the file
	uint64_t hash = 0;              //!< the file's System.ThumbnailCacheId
	std::wstring identifier;        //!< the hash in hexadecimal, or the shell name of what is shown
	uint32_t width = 0, height = 0; //!< size of the image, in pixels; 0 on Windows 7, whose entry has none
	size_t dataOffset = 0;          //!< position of the image in the file
	size_t dataSize = 0;            //!< its size, 0 for an entry without image
	bool headerChecksumValid = false; //!< the entry's header is as Windows wrote it
	bool dataChecksumValid = false;   //!< the image is as Windows wrote it
};

/*! A decoded cache file. */
struct ThumbcacheFile {
	uint32_t version = 0;                  //!< 0x14 Vista, 0x15 Windows 7, 0x1E Windows 8, 0x1F 8.1, 0x20 10 and 11
	bool unsupportedFormat = false;        //!< a version WAC has no decoder for (pieceFormat): no entry was read
	uint32_t type = 0;                     //!< index of the cache's size (see thumbcacheSize)
	std::vector<ThumbcacheEntry> entries;  //!< in the file's order
};

/*! CRC-64 of the format, byte by byte.
 *  @param bytes the bytes
 *  @param size their number
 *  @param initial the starting value: all ones for a header, zero for data
 *  @return the CRC */
uint64_t thumbcacheCrc64(const uint8_t* bytes, size_t size, uint64_t initial);

/*! The checksum of an entry's image, as Windows computes it (see the file's
 *  header).
 *  @param data the image
 *  @param size its size
 *  @return the checksum */
uint64_t thumbcacheDataChecksum(const uint8_t* data, size_t size);

/*! The size a cache type names ("256", "sr", "wide"…): Windows 7 numbers
 *  its sizes otherwise than Windows 8 and later.
 *  @param version the file's version
 *  @param type the header's type
 *  @return its name, empty if unknown */
std::wstring thumbcacheSize(uint32_t version, uint32_t type);

/*! Decodes a cache file. Every length comes from the file and is bounded by
 *  its real size; a cut or forged entry ends the reading, those before kept.
 *  @param bytes the file
 *  @param file receives its header and entries
 *  @return true if the file is a CMMM cache of a version decoded */
bool decodeThumbcache(const std::vector<uint8_t>& bytes, ThumbcacheFile& file);

/*! The thumbnail and icon caches of every profile (thumbcache.json). */
class Thumbcaches {
public:
	/*! Reads the cache files extracted from every profile and exports their
	 *  images next to the JSON.
	 *  @return ERROR_SUCCESS, even without any cache: none is an answer */
	HRESULT getData();
	/*! Writes thumbcache.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the entries read.
	void clear();
private:
	Json entries_ = Json::arr();
};

//! The caches' folder, relative to a profile.
extern const wchar_t THUMBCACHE_FOLDER[];
