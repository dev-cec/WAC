/*! \file
 *  \brief Internet Explorer 5 to 9's cache files (index.dat): history, cache, cookies, downloads of Windows 7 and earlier.
 *
 *  WHAT THE ARTEFACT PROVES. Before the WebCache (IE 10, Windows 8), WinINet
 *  kept one "MSIE Cache File" per kind of record and per user: the history
 *  (global, and the daily and weekly `MSHist01…` folders), the cache of
 *  Temporary Internet Files (the URL of each cached file, its server headers,
 *  its file in one of the cache directories), the cookies, the downloads.
 *  Internet Explorer is still there on the machines it ran on, and its engine
 *  served mshta.exe and the scripts of an attack.
 *
 *  THE FORMAT (version 5.2), as libmsiecf (J. Metz) documents it: a header
 *  of 72 bytes and the cache directories' names; a chain of HASH tables whose
 *  entries point at the records; records in 128-byte blocks from 0x4000 —
 *  URL (an entry), REDR (a redirection), LEAK (an entry dropped from the cache
 *  but not erased). A URL or REDR record that no hash table names any longer
 *  is RECOVERED from the blocks: an entry deleted but still there. Every
 *  offset read from the file is checked against its size and its record.
 *
 *  TIMES. Two FILETIMEs whose meaning depends on the file (libmsiecf, "Use of
 *  the FILETIME values"): in a weekly history the secondary one is a LOCAL
 *  time, converted with the offset in force at its date; everywhere else
 *  UTC. The expiry and last check are FAT date-times, a clock time without a
 *  time zone: given as written, never as an instant.
 *
 *  Checked against pymsiecf (libmsiecf's own reader) on public test files of
 *  the plaso project (ie_index_dat_test, ie_index_fixtures.sh).
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

/*! One record of an index.dat. */
struct IeIndexRecord {
	std::wstring kind;            //!< URL, REDR or LEAK
	uint32_t offset = 0;          //!< its place in the file
	bool recovered = false;       //!< a URL or REDR no hash table names: deleted, still in the blocks
	std::wstring location;        //!< the URL, as written (ASCII, URL-encoded)
	std::wstring filename;        //!< the cached file's name, in its cache directory
	int cacheDirectory = -1;      //!< index in the header's cache directories; -1 for none
	uint64_t primaryTime = 0;     //!< FILETIME, see the file's header comment
	uint64_t secondaryTime = 0;   //!< FILETIME, see the file's header comment
	uint32_t expiry = 0;          //!< FAT date-time, as written
	uint32_t lastChecked = 0;     //!< FAT date-time, as written
	uint32_t hits = 0;            //!< number of hits
	uint32_t flags = 0;           //!< cache entry flags (NORMAL 0x1, STICKY 0x4, COOKIE 0x100000, URLHISTORY 0x200000…)
	uint64_t fileSize = 0;        //!< the cached file's size
	std::vector<uint8_t> data;    //!< the record's data: a cache entry's HTTP response headers…
};

/*! An index.dat, decoded. */
struct IeIndexFile {
	std::wstring version;                      //!< "5.2"
	std::vector<std::wstring> cacheDirectories; //!< the 8-character names of the cache directories
	std::vector<IeIndexRecord> records;        //!< the hash tables' records and the LEAKs, then the recovered ones
};

/*! Decodes an index.dat. Every read is bounded by `size`.
 *  @param data the file's bytes
 *  @param size their number
 *  @param file receives the header and the records
 *  @return false if the file is not a version 5.2 MSIE Cache File */
bool parseIeIndexDat(const uint8_t* data, size_t size, IeIndexFile& file);
