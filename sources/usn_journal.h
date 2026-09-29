/*! \file
 *  \brief THE CHANGE JOURNAL of the system volume ($UsnJrnl:$J): what happened
 *         to which file, and when.
 *
 *  WHY. NTFS records every change to a file — creation, write, rename,
 *  deletion, attribute or security change — as a record of its change journal,
 *  for the indexer and the backup tools. The journal keeps weeks of activity
 *  where the $MFT only shows the last state: a tool dropped, run, then deleted
 *  leaves here its creation, its renames and its deletion, dated to the
 *  100 ns. With the $MFT (mft.h), it is the timeline of the machine's files.
 *
 *  A record names the file and the directory holding it by their $MFT
 *  references: the full path is rebuilt from the $MFT of the same collection
 *  (Mft::pathOf). A directory deleted and reused since cannot be named: the
 *  path then keeps what is known, and says it is incomplete.
 *
 *  READ FROM THE EXHIBIT. The stream is copied from its first allocated byte
 *  (ExtractStreamRaw): the record numbers (USN) are offsets in the whole
 *  stream, restored with the offset the manifest records
 *  (LeadingSparseBytes). Records of version 2 and 3 are decoded; version 4
 *  (ranges of a file written, when range tracking is on) carries no name and
 *  is counted, not converted.
 *
 *  THE DATES are written in UTC only, as mft.json and for the same reason.
 */
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include "tools.h"

struct Mft;

/*! One record of the change journal. */
struct UsnRecord {
	uint64_t usn = 0;                //!< its number: offset in the journal's stream
	FILETIME timestamp = { 0 };      //!< when the change was recorded, UTC
	uint64_t fileEntry = 0;          //!< $MFT record of the file
	uint16_t fileSequence = 0;       //!< its sequence number
	uint64_t parentEntry = 0;        //!< $MFT record of the directory holding it
	uint16_t parentSequence = 0;     //!< its sequence number
	uint32_t reason = 0;             //!< USN_REASON_*: a field of bits, the changes gathered in the record
	uint32_t sourceInfo = 0;         //!< USN_SOURCE_*: a change made by the system, not the user
	uint32_t securityId = 0;         //!< index of the file's security descriptor in $Secure
	uint32_t attributes = 0;         //!< the file's attributes (a field of bits)
	std::wstring name;               //!< the file's name at the time of the change

	/*! Decodes a record of version 2 or 3.
	 *  @param record its bytes
	 *  @param size their number, the record's length included: no read goes beyond
	 *  @param usnBase offset of `record` in the journal's stream
	 *  @return false if it is not a record of version 2 or 3 */
	bool parse(const uint8_t* record, size_t size, uint64_t usnBase);

	/*! Converts the record to JSON.
	 *  @param mft the $MFT of the collection, for the path
	 *  @return its JSON object */
	Json toJson(const Mft& mft) const;
};

/*! The change journal of one NTFS volume, read from its exhibit. */
struct UsnJournal {
	std::vector<UsnRecord> records;  //!< the records, in the journal's order
	uint64_t rangeRecords = 0;       //!< records of version 4, counted only

	/*! Reads the journal's exhibit of a volume and decodes its records.
	 *  @param volume the volume, "C:", "G:"…
	 *  @return ERROR_SUCCESS, or ERROR_FILE_NOT_FOUND if the collection holds
	 *          no journal (disabled on the machine, or not asked for) */
	HRESULT getData(const std::wstring& volume);

	/*! Writes the volume's records into usn_journal.json as it goes, each
	 *  file named by its full path. Every volume goes into the same file.
	 *  @param out the writer of usn_journal.json
	 *  @param mft the $MFT of the same volume, loaded (Mft::getData)
	 *  @return ERROR_SUCCESS */
	HRESULT toJson(JsonArrayWriter& out, const Mft& mft) const;

	//! Releases the memory held by the records.
	void clear();
};
