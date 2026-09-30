/*! \file
 *  \brief The FAT and exFAT volumes of the machine — a suspect's USB keys and
 *         memory cards included —, read raw (fat_volumes.json).
 *
 *  WHAT IT PROVES. What a key holds and what was deleted from it, with the
 *  dates the file system kept: a document copied to a key, a tool run from
 *  it, a folder removed before the seizure. Deleted entries are listed with
 *  what survives of them (fat_volume.h).
 *
 *  HOW. The collection reads each volume raw — never through its file
 *  system, which would update access dates — and copies only its metadata
 *  (boot sector, FAT, directories) into the exhibit store, as
 *  `X:\$FatMetadata`; the conversion reads that copy, not the volume. Files'
 *  contents are not copied. The volume holding the collection is left out.
 *
 *  DATES. FAT keeps local time: each date is given as stored, with its
 *  offset (Created…), and in UTC (CreatedUtc…) by the examined machine's time
 *  zone, with the offset in force AT THAT DATE, as every local date of WAC.
 *  Windows converts a FAT time with the offset of the moment instead: in
 *  summer, it shows a winter date one hour off — measured in the test VM; a
 *  date written by SetFileTime in the other season is the one case where
 *  Windows' conversion is right and this one is not. exFAT keeps, when it
 *  can, the offset in force: the UTC date is then exact, and the offset is
 *  given (CreatedOffset…).
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "fat_volume.h"
#include "tools.h"

/*! Copies the metadata of every FAT and exFAT volume into the exhibit store
 *  (collection phase).
 *  @return S_OK, S_FALSE if one could not be read, ERROR_EMPTY if there is none */
HRESULT ExtractFatVolumesRaw();

/*! An entry with its volume, ready to be written. */
struct FatVolumeEntry {
	std::wstring volume, fileSystem, label;
	FatEntry entry;
	Json toJson() const;   //!< @return the entry as a JSON object
};

//! FAT and exFAT volumes (fat_volumes.json).
class FatVolumes {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any volume
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<FatVolumeEntry> entries_;
};
