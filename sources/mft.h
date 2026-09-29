/*! \file
 *  \brief THE $MFT of the system volume: every file, present or deleted, with
 *         its dates — the base of the file system's timeline.
 *
 *  WHY. Each file and directory of an NTFS volume has a record in the $MFT,
 *  which keeps it after deletion until NTFS reuses it. A record carries two
 *  sets of four dates:
 *    - $STANDARD_INFORMATION (creation, modification, record change, access):
 *      what Explorer shows, and what SetFileTime rewrites — a tool that
 *      antedates its own files ("timestomping") changes these;
 *    - $FILE_NAME: written by NTFS itself when the file is created, moved or
 *      renamed, out of reach of SetFileTime. A $STANDARD_INFORMATION earlier
 *      than its $FILE_NAME betrays a forged date.
 *  Together with the change journal (usn_journal.h), they give the timeline
 *  of the machine's files: what was dropped, when, and what was removed.
 *
 *  READ FROM THE EXHIBIT. The $MFT is copied raw by the collection
 *  (ExtractNtfsMetadataRaw, raw_collect.h) and read here from the exhibit
 *  store, in place: a conversion on an analysis workstation reads the same
 *  bytes. Up to gigabytes: it is read by blocks, and mft.json is written as
 *  it goes (JsonArrayWriter), never held in memory. Only what the paths need
 *  is kept — each record's name and parent.
 *
 *  THE PATH of a record is rebuilt from its parent references up to the root.
 *  A parent reference carries the SEQUENCE number of the parent record: if
 *  the record was reused since, the parent named now is another directory,
 *  and the path is marked incomplete rather than made up. A deleted record
 *  keeps its content, its sequence number raised by one: that is accepted.
 *
 *  THE DATES are written in UTC only: the timeline tools work in UTC, and the
 *  pairs local/UTC of the other artefacts would double a file that already
 *  counts one object per file of the volume.
 */
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include "tools.h"

/*! One record of the $MFT: a file or a directory, present or deleted. */
struct MftEntry {
	uint64_t entry = 0;              //!< record number (the file's identity on the volume)
	uint16_t sequence = 0;           //!< sequence number: raised each time the record is freed
	bool inUse = false;              //!< false: a deleted file whose record is not reused yet
	bool directory = false;          //!< the record is a directory
	uint64_t parentEntry = 0;        //!< record of the directory holding the file (its $FILE_NAME)
	uint16_t parentSequence = 0;     //!< sequence number of that directory when the name was written
	std::wstring name;               //!< the file's long name (Win32), the 8.3 name as a last resort
	/*! Preference of `name`'s namespace (namePreference): 0 long name, 1
	 *  POSIX, 2 the 8.3 alias, 3 none. A record with many names has its long
	 *  one in an extension record and only its alias here: the better name
	 *  wins, wherever it lies. */
	int nameRank = 3;
	/*! One name of the file in a directory: a file with hard links has
	 *  several — System32\\crypt32.dll and its original under WinSxS are one
	 *  record. 8.3 aliases are not names of their own. */
	struct Link {
		uint64_t parentEntry = 0;
		uint16_t parentSequence = 0;
		std::wstring name;
	};
	std::vector<Link> links;         //!< every long name of the record, `name` included
	bool sizeKnown = false;          //!< true if `size` was read
	uint64_t size = 0;               //!< size of the content (unnamed $DATA)
	std::vector<std::wstring> streams; //!< named $DATA streams: Zone.Identifier (downloaded), hidden data…
	uint32_t attributes = 0;         //!< file attributes of $STANDARD_INFORMATION (a field of bits)
	FILETIME created = { 0 }, modified = { 0 }, mftModified = { 0 }, accessed = { 0 };  //!< $STANDARD_INFORMATION, UTC
	FILETIME fileNameCreated = { 0 }, fileNameModified = { 0 },
	         fileNameMftModified = { 0 }, fileNameAccessed = { 0 };                    //!< $FILE_NAME of `name`, UTC
	uint64_t baseEntry = 0;          //!< for an extension record: the record it extends; 0 otherwise

	/*! Decodes a record whose fixups are applied. Every read is bounded by
	 *  `size` and by the record's own used size.
	 *  @param record the record's bytes
	 *  @param recordSize their number
	 *  @param number the record's number, from its place in the $MFT
	 *  @return false if it is not a usable record (never used, torn, malformed) */
	bool parse(const uint8_t* record, size_t recordSize, uint64_t number);

	/*! Converts the record to JSON.
	 *  @param path its path, rebuilt by Mft::pathOf
	 *  @param pathComplete false if a parent could not be named
	 *  @param hardLinkPaths the paths of its other names (hard links)
	 *  @return its JSON object */
	Json toJson(const std::wstring& path, bool pathComplete,
	            const std::vector<std::wstring>& hardLinkPaths) const;

	//! True if the link is the name shown as `name` (same directory, same name).
	bool isShownName(const Link& link) const { return link.parentEntry == parentEntry && link.name == name; }
};

/*! The $MFT of the system volume, read from its exhibit. */
struct Mft {
	/*! Loads the $MFT exhibit and keeps each record's name and parent, for
	 *  the paths (of mft.json and of the change journal).
	 *  @return ERROR_SUCCESS, ERROR_FILE_NOT_FOUND if the collection holds no
	 *          $MFT, or ERROR_INVALID_DATA if it is not one */
	HRESULT getData();

	/*! Writes `mft.json` as it goes: one object per record, present or deleted.
	 *  @return the result of the write */
	HRESULT toJson();

	/*! The path of a file on the examined machine, from a reference.
	 *  @param entry record number of the file
	 *  @param sequence its sequence number in the reference; 0 to accept any
	 *  @param complete receives false if a record of the chain was reused
	 *         (or never read): the path then starts with what is known
	 *  @return "C:\…", or empty if the record itself cannot be named */
	std::wstring pathOf(uint64_t entry, uint16_t sequence, bool& complete) const;

	//! Releases the memory held by the index.
	void clear();

private:
	//! What the paths need of a record.
	struct Node {
		uint64_t parentEntry = 0;
		uint32_t nameOffset = 0;    //!< in names_
		uint16_t nameLength = 0;
		uint8_t nameRank = 3;       //!< MftEntry::nameRank of the name kept
		uint16_t sequence = 0;
		uint16_t parentSequence = 0;
		bool named = false;
		bool inUse = false;
	};
	std::wstring file_;             //!< the exhibit read
	size_t recordSize_ = 0;         //!< bytes per record, from record 0
	std::vector<Node> nodes_;       //!< by record number
	std::wstring names_;            //!< every name, end to end
	/*! What extension records carry for their base record, when the base
	 *  lacks it: a file with many names has its $FILE_NAME moved there. */
	std::map<uint64_t, MftEntry> extensions_;

	/*! Reads the exhibit record by record.
	 *  @param visit called with each decoded record
	 *  @return ERROR_SUCCESS, or why the exhibit could not be read */
	template <typename Visit> HRESULT forEachRecord(Visit visit) const;
	//! Completes a base record with what its extension records carry.
	void complete(MftEntry& entry) const;
};
