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
 *  DATES. One instant must read the same in every artefact: each date is
 *  given in UTC (CreatedUtc…) and in the examined machine's local time
 *  derived from it (Created…), with the offset in force at that instant —
 *  the rule of every local date of WAC.
 *  FAT keeps local time, computed by Windows with the offset of the moment
 *  it WROTE the date. For a creation, or a modification made on the volume,
 *  that moment is the date itself. A modification earlier than the creation
 *  is a date kept by a copy (Explorer, robocopy, Copy-Item): written at the
 *  copy, which the creation dates, it is converted with the offset in force
 *  at the creation, and said so (ModifiedWrittenAt "Copy",
 *  ModifiedOffsetApplied, ModifiedAsStored). A winter file copied onto a key
 *  in summer is otherwise an hour off — measured in the test VM.
 *  exFAT keeps the offset it wrote (CreatedOffset…): the UTC date is exact.
 */
#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <windows.h>
#include "fat_volume.h"
#include "raw_hive.h"
#include "tools.h"

/*! The FAT and exFAT volumes WAC reads: fixed and removable, the volume
 *  holding the collection left out.
 *  @return their mount points, "E:"… */
std::vector<std::wstring> fatVolumesToRead();

/*! True if a path lies on one of those volumes.
 *  @param path "X:\\…" */
bool onFatVolume(const std::wstring& path);

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

/*! The files a collection reads on the examined machine — cited binaries,
 *  catalogs —, on NTFS volumes by RawReader, on FAT and exFAT volumes by
 *  FatVolume: a program run from a suspect's key is fingerprinted and
 *  collected like any other. */
class FatAwareReader : public FileSource {
public:
	HRESULT read(const std::wstring& absolutePath, const std::wstring& output,
	             RawHiveExtraction& line, std::streambuf* observer = nullptr) override;
	HRESULT list(const std::wstring& absoluteFolder, std::vector<RawDirEntry>& entries) override;
private:
	//! A FAT or exFAT volume open for reading, its present entries by lower-case path.
	struct Volume {
		std::unique_ptr<FileVolumeSource> source;
		FatVolume volume;
		std::map<std::wstring, FatEntry> byPath;
		std::map<std::wstring, uint64_t> ids;   //!< an identifier per entry, as $MFT numbers are for NTFS
	};
	Volume* fatVolume(const std::wstring& path);
	RawReader ntfs_;
	std::map<wchar_t, std::unique_ptr<Volume>> volumes_;   //!< nullptr: not FAT, or unreadable
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
