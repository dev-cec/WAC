/*! \file
 *  \brief Recycle bin: the `$I` index files of `\\$Recycle.Bin\\<SID>\\` on every fixed NTFS volume.
 *
 *  WHAT THE ARTEFACT PROVES. A file sent to the recycle bin is renamed
 *  `$R<random><extension>` and Windows writes beside it `$I<same>` — the
 *  original path, the size and the instant of the deletion. Until the bin is
 *  emptied, it names who deleted (the SID folder), what and when; emptied, the
 *  names of both files remain as deleted records of mft.json.
 *
 *  ONLY THE `$I` ARE COLLECTED: the `$R` are the deleted files themselves, of
 *  any size; their presence and size are in mft.json, and --binary collects
 *  the executables among them.
 *
 *  WINDOWS XP AND SERVER 2003 keep one index per user folder instead,
 *  `\\RECYCLER\\<SID>\\INFO2` (measured on the XP VM): a header of 20 bytes
 *  — version 5, two DWORDs, the record size 800, a DWORD — then a record per
 *  deleted file: its path in the ANSI code page (260 bytes), its number n —
 *  the copy is `Dc<n><extension>` in the same folder —, its drive (0 for
 *  A:), the deletion (FILETIME UTC), the size the file occupied, its path in
 *  UTF-16 (520 bytes). Each record is one entry, its `RecycledName` the
 *  `Dc<n>` name.
 *
 *  THE FORMAT (little-endian):
 *      0   8   version: 1 (Vista to 8.1) or 2 (Windows 10 and later)
 *      8   8   size of the deleted file, bytes
 *      16  8   deletion, FILETIME UTC
 *      v1: 24  520  original path, UTF-16, 260 characters, zero-padded
 *      v2: 24  4    length of the path in characters, terminating zero included
 *          28  …    original path, UTF-16
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One `$I` file: one deleted file. */
struct RecycledFile {
	std::wstring indexFile;          //!< the `$I` file on the examined machine
	std::wstring sid;                //!< SID of the folder: the user who deleted
	uint64_t version = 0;            //!< the format of the `$I`, as the file states it
	bool unsupportedFormat = false;  //!< a version WAC has no decoder for (pieceFormat): nothing but the version was read
	uint64_t size = 0;               //!< size of the deleted file, bytes
	FILETIME deletedUtc = { 0 };     //!< instant of the deletion, UTC
	std::wstring originalPath;       //!< where the file was before being deleted
	std::wstring recycledName;       //!< INFO2 (Windows XP): the copy's name in the bin, Dc<n><extension>
	//! @return the deleted file as a JSON object
	Json toJson() const;
};

/*! Reads a `$I` file.
 *  @param bytes its content
 *  @param recycled receives version, size, deletion and original path; for a
 *         version the artefact table holds no decoder for, the version alone
 *         and `unsupportedFormat`
 *  @return false if the content is truncated: every read is bounded by the
 *          size given */
bool parseRecycleBinIndex(const std::vector<uint8_t>& bytes, RecycledFile& recycled);

/*! Reads an INFO2 file of Windows XP and Server 2003 (version 5).
 *  @param bytes its content
 *  @param indexFile its path on the examined machine
 *  @param sid the user folder it is in
 *  @param files receives one entry per record; one entry declared
 *         "unsupported format" for another version
 *  @return false if the header is missing: every record is bounded by the size */
bool parseInfo2(const std::vector<uint8_t>& bytes, const std::wstring& indexFile, const std::wstring& sid,
                std::vector<RecycledFile>& files);

/*! The recycle bins of every volume (recycle_bin.json). */
class RecycleBin {
public:
	/*! Reads the `$I` collected, from the exhibit store.
	 *  @return ERROR_SUCCESS, even without any */
	HRESULT getData();
	/*! Writes recycle_bin.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the files read.
	void clear();
private:
	std::vector<RecycledFile> files_;   //!< one per `$I`
};
