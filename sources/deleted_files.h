/*! \file
 *  \brief DELETED FILES: the content a deleted file still has on the disk,
 *         recovered by raw reading (deleted_files.json, backlog B-036).
 *
 *  WHY. mft.json lists the deleted files whose record NTFS has not reused,
 *  and usn_journal.json the deletions — not their content. Yet the tool, the
 *  script or the archive an intruder removed is often still on the disk: its
 *  clusters stay as they were until NTFS gives them to another file. Read
 *  raw (`\\.\X:`), they leave no trace on the examined machine: no file
 *  opened by the system, no recovery tool installed or run there, nothing
 *  written to the volume.
 *
 *  LEVEL 1 — THE $MFT'S DELETED RECORDS. A deleted record keeps its unnamed
 *  $DATA attribute: resident (the content in the record itself, a few hundred
 *  bytes), or the list of its clusters. Each cluster is checked FREE in
 *  $Bitmap before it is read and again after: one NTFS gave to another file
 *  in between holds that file's data, which would pass for the deleted one's
 *  — false and valid in appearance. Such a cluster is a hole, zeros in the
 *  copy, and its range is listed: the content is published as PARTIAL, never
 *  as recovered. Clusters read back all zero — what a solid-state drive
 *  returns once Windows sent it TRIM — are declared ZEROED, not copied.
 *
 *  WHERE WINDOWS 10 PUTS THEM. A file deleted while a handle is still open
 *  on it — an antivirus, the indexer — is renamed into $Extend\$Deleted,
 *  then freed at the last close: its record names it there. Measured on
 *  Windows 11: every witness the harness deleted. The conversion gives the
 *  path it had (FormerPath) and the deletion's time (DeletedUtc), from the
 *  change journal of the collection.
 *
 *  WHICH FILES. Every deleted file of every fixed NTFS volume but those of
 *  the folders `excluded_folders` names (wac.yml: WinSxS, Windows Update…,
 *  deleted by the thousand and of no intruder), the collection's own output
 *  folder, and files without content. The most recent first — the latest
 *  date their record carries, the deletion's being nowhere in it —, until
 *  `max_total_mib` is copied — the files the bound leaves out listed as
 *  NotRead, not omitted —; a file beyond `max_file_mib` is read for its
 *  fingerprints, not copied.
 *
 *  WHAT IS COPIED. An executable recovered is judged as the volume's are
 *  (binaires.h, `binary:` of wac.yml): an authentic one is fingerprinted, not
 *  copied; any other is copied. Documents, scripts, archives are copied. In
 *  the exhibit store, a content goes under `X:\$DeletedFiles\<record>-<sequence>_<name>`,
 *  never under its former path: a file of the same name may exist there now.
 *
 *  WHEN. The selection and the reading are the collection's: the $MFT read is
 *  the working copy of the collection's own (ExtractNtfsMetadataRaw), each
 *  record read again on the volume before its clusters — reused since, it is
 *  said so. What was found is a sealed snapshot (live_snapshot.h), which the
 *  conversion writes as deleted_files.json.
 */
#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "raw_hive.h"
#include "json.h"

/*! The unnamed $DATA attribute of a deleted base record, as the record holds it. */
struct DeletedData {
	bool found = false;               //!< the record has an unnamed $DATA
	bool resident = false;            //!< held in the record: `residentBytes`
	std::vector<uint8_t> residentBytes;
	std::vector<NtfsRun> runs;        //!< non-resident: the clusters, decoded and checked by checkRuns
	bool runsDecoded = false;         //!< the run list was well formed (decodeNtfsRuns)
	uint64_t lastVcn = 0;             //!< non-resident: last cluster of the attribute, as declared
	uint64_t allocatedSize = 0;       //!< non-resident: bytes of the clusters
	uint64_t size = 0;                //!< the content's size
	uint64_t initializedSize = 0;     //!< valid data length: beyond it, zeros by definition
	uint16_t flags = 0;               //!< 0x0001 compressed, 0x4000 encrypted, 0x8000 sparse
	bool attributeList = false;       //!< the record has an $ATTRIBUTE_LIST: part of its runs may lie elsewhere
};

/*! What a deleted record says, read as it is now. */
struct DeletedRecord {
	bool fileRecord = false;   //!< a FILE record, its fixups applied by the caller
	bool inUse = false;        //!< in use: reused since, by another file
	bool directory = false;
	bool baseRecord = true;    //!< not an extension record
	uint16_t sequence = 0;
	DeletedData data;
};

/*! Reads a $MFT record for a recovery. Every read is bounded by `size` and by
 *  the record's used size.
 *  @param record the record, its fixups applied
 *  @param size its size
 *  @return what it says; `fileRecord` false if it is not a FILE record */
DeletedRecord parseDeletedRecord(const uint8_t* record, size_t size);

/*! Whether the runs of a non-resident $DATA describe clusters of THIS volume,
 *  each once: a forged or damaged list — a run past the volume's end, two
 *  runs on the same clusters, a length that does not match the declared
 *  sizes — is refused, before any cluster is read.
 *  @param data the attribute
 *  @param clusterSize bytes per cluster
 *  @param clusters clusters of the volume
 *  @return an empty string if they hold, else why not */
std::string checkRuns(const DeletedData& data, uint32_t clusterSize, uint64_t clusters);

/*! The volume as the recovery reads it — the raw volume at collection, a
 *  volume in memory in the tests. */
struct ClusterSource {
	uint32_t clusterSize = 0;
	uint64_t clusters = 0;
	//! Whether each cluster of a range is in use now. @return false if unreadable
	std::function<bool(uint64_t lcn, uint64_t count, std::vector<bool>& inUse)> allocation;
	//! Reads clusters. @return false if unreadable
	std::function<bool(uint64_t lcn, uint64_t count, uint8_t* out)> read;
};

/*! What became of a deleted file's content. */
enum class RecoveryState {
	Recovered,       //!< every byte of content from clusters still free (or resident)
	Partial,         //!< some clusters given to another file: holes of zeros, listed
	Overwritten,     //!< every cluster given to another file: nothing recovered
	Zeroed,          //!< the free clusters read back all zero (TRIM): nothing to trust
	NotRecoverable   //!< compressed, encrypted, runs elsewhere or forged: not read
};

//! The state's name in deleted_files.json.
const wchar_t* recoveryStateName(RecoveryState state);

/*! A byte range of the content that could not be recovered. */
struct MissingRange {
	uint64_t offset = 0;
	uint64_t length = 0;
};

/*! The outcome of a recovery. */
struct Recovery {
	RecoveryState state = RecoveryState::NotRecoverable;
	std::string reason;                   //!< NotRecoverable: why
	uint64_t recoveredBytes = 0;          //!< bytes read from free clusters, or resident
	std::vector<MissingRange> missing;    //!< Partial, Overwritten: the holes
};

/*! Recovers a deleted file's content, handing it to `sink` from its first
 *  byte to its last, holes as zeros — `size` bytes in all, unless it is not
 *  recoverable (nothing handed then). Each cluster is checked free before
 *  and after it is read; one in use either time is a hole.
 *  @param data the record's $DATA (parseDeletedRecord)
 *  @param volume the clusters
 *  @param sink receives the content, in order
 *  @return what was recovered */
Recovery recoverContent(const DeletedData& data, const ClusterSource& volume,
                        const std::function<void(const uint8_t*, size_t)>& sink);

/*! A file name made safe for the exhibit store: the characters Windows
 *  refuses in a name replaced by "_", at most 120 characters. */
std::wstring safeFileName(const std::wstring& name);

/*! --collect: recovers the deleted files of every fixed NTFS volume into the
 *  exhibit store, and writes the snapshot the conversion reads. To be called
 *  after the $MFT's working copy exists, and after the executables' walk
 *  (its catalogs and its deduplication serve the recovered executables).
 *  @return ERROR_SUCCESS, S_FALSE if a volume could not be read */
HRESULT DeletedFilesCollect();

/*! The conversion: deleted_files.json from the collection's snapshot. */
class DeletedFiles {
public:
	/*! Reads the snapshot the collection wrote, each file completed from the
	 *  change journal: DeletedUtc, and FormerPath for a file of $Extend\$Deleted.
	 *  @return ERROR_SUCCESS, or why it could not be read */
	HRESULT getData();
	/*! Writes deleted_files.json, one object per file, most recent first.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the list.
	void clear();
private:
	Json files_ = Json::arr();   //!< the files, as the snapshot recorded them
};
