/*! \file
 *  \brief NTFS volumes: boot sector ($Boot) and change journal header ($UsnJrnl:$Max).
 *
 *  WHAT THE ARTEFACT PROVES.
 *    - $Boot holds the volume's SERIAL NUMBER, the one shortcuts, jump lists
 *      and Prefetch files record of the volume their target was on
 *      (`VolumeSerial`, its low 32 bits): it ties those traces to this disk.
 *      Its geometry (sector, cluster and record sizes, place of the $MFT and
 *      of its mirror) is what any later reading of the volume needs.
 *    - $Max is the change journal's header. `UsnJournalId` is the instant the
 *      journal was CREATED: a journal deleted and recreated — `fsutil usn
 *      deletejournal`, an intruder wiping the history of their files — shows
 *      a creation far later than the installation. `LowestValidUsn` says how
 *      much of the journal was already overwritten.
 *
 *  Both are read raw, from the copies in the exhibit store; $Boot's first
 *  sector is checked by its own signatures ("NTFS    ", 0x55AA) before any
 *  field is trusted.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "ntfs_boot_sector.h"

/*! The header of the change journal ($UsnJrnl:$Max). */
struct UsnJournalHeader {
	uint64_t maximumSize = 0;        //!< size the journal is kept under, in bytes
	uint64_t allocationDelta = 0;    //!< what is freed at once when it is full
	uint64_t journalId = 0;          //!< FILETIME of the journal's creation
	uint64_t lowestValidUsn = 0;     //!< first record still in the journal
};

/*! Decodes $UsnJrnl:$Max.
 *  @param data the stream's bytes
 *  @param size their number (32 at least)
 *  @param header receives the fields
 *  @return false if the stream is too short */
bool parseUsnJournalHeader(const uint8_t* data, size_t size, UsnJournalHeader& header);

/*! One NTFS volume. */
struct NtfsVolumeInfo {
	std::wstring volume;                      //!< "C:"
	std::optional<NtfsBootSector> boot;       //!< empty if $Boot is missing or not a valid NTFS boot sector
	std::optional<UsnJournalHeader> journal;  //!< empty if the volume has no change journal
	//! @return the volume as a JSON object
	Json toJson() const;
};

/*! The NTFS volumes collected (ntfs_volumes.json). */
class NtfsVolumes {
public:
	/*! Reads the $Boot and $Max copies of each fixed NTFS volume.
	 *  @return ERROR_SUCCESS if at least one volume gave one of them */
	HRESULT getData();
	/*! Writes ntfs_volumes.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases what was read.
	void clear();
private:
	std::vector<NtfsVolumeInfo> volumes_;   //!< one per volume
};
