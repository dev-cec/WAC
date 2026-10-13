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
