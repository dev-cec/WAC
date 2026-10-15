/*! \file
 *  \brief Background Intelligent Transfer Service jobs:
 *         `\ProgramData\Microsoft\Network\Downloader\qmgr.db` (bits_jobs.json).
 *
 *  WHAT IT PROVES. A BITS job downloads (or uploads) files in the
 *  background, surviving reboots, as SYSTEM or a user; its "notification
 *  command line" runs a program when the transfer ends or fails. Intruders
 *  use it to fetch a payload through a proxy-friendly Windows service, and
 *  as a persistence: a job that fails again and again runs its command each
 *  time. The source URL, the destination, the command and the owner are here.
 *
 *  THE FORMAT. Since Windows 10, qmgr.db is an ESE database (ese_database.h):
 *  table Jobs (Id, Blob), table Files (Id, Blob). The blobs are BITS's own
 *  serialisation, undocumented, described by FireEye (BitsParser,
 *  bits_parser) and checked on a witness job of the test VM against
 *  Get-BitsTransfer: after a 16-byte header, a job gives its type, priority,
 *  state, identifier, then UTF-16 strings each preceded by its length in
 *  characters — name, description, notification program and arguments, owner
 *  SID —, its notification flags; a delimited section lists its files'
 *  identifiers; then error counts, retry delay, timeout and dates. A file
 *  gives its destination, source, temporary file, sizes, drive and volume.
 *  The whole blob is also given in hexadecimal: beyond these fields, BITS 10
 *  keeps more (the path of the program that created the job) at places not
 *  described.
 *
 *  BEFORE WINDOWS 10, qmgr0.dat and qmgr1.dat, which BITS writes in turn: a
 *  header, the jobs each framed by a delimiter of its version of BITS, the
 *  same job layout without the blob's header, its files written in it after
 *  their count — each followed by a trailer not described —, then the same
 *  metadata (bits_parser, ANSSI; measured on the witness job of the Windows
 *  8.1 VM). Each job names the queue file it was read in: the older one may
 *  hold an earlier state of the same job.
 *
 *  A job is written to qmgr.db when created and when a file is added; BITS
 *  changes made since may be only in the service's logs (edb*.log),
 *  collected alongside.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! A file of a job (table Files). */
struct BitsFile {
	std::wstring id;                   //!< the row's GUID, which the job lists
	std::wstring destination, source, temporary, drive, volume;
	uint64_t downloadedBytes = 0, totalBytes = 0;   //!< totalBytes UINT64_MAX: unknown
	bool parsed = false;
	std::vector<uint8_t> blob;
	Json toJson() const;               //!< @return the file as a JSON object
};

/*! A job (table Jobs). */
struct BitsJob {
	std::wstring id, name, description, notifyProgram, notifyArguments, ownerSid;
	uint32_t type = 0, priority = 0, state = 0, notifyFlags = 0;
	uint32_t errorCount = 0, transientErrorCount = 0, retryDelay = 0, noProgressTimeout = 0;
	FILETIME createdUtc = { 0 }, modifiedUtc = { 0 };
	std::vector<std::wstring> fileIds;
	std::wstring queueFile;            //!< before Windows 10: the queue file it was read in (qmgr0.dat, qmgr1.dat)
	std::vector<BitsFile> inlineFiles; //!< before Windows 10: its files, written in the job itself
	bool parsed = false, metadataParsed = false;
	std::vector<uint8_t> blob;
	Json toJson(const std::vector<BitsFile>& files) const;   //!< @return the job, its files included
};

/*! Reads a job's blob. Every length is bounded by the blob.
 *  @return false if its first part (up to the notification flags) does not fit */
bool parseBitsJob(const std::vector<uint8_t>& blob, BitsJob& job);

/*! Reads the jobs of a queue file of Windows 8.1 and earlier (qmgr0.dat,
 *  qmgr1.dat): each between two delimiters of its version of BITS, its files
 *  written in it. Every length is bounded by the file.
 *  @param queue the queue file
 *  @param queueFile its path on the examined machine
 *  @param jobs receives the jobs read
 *  @return false if no known job delimiter is in it */
bool parseBitsQueue(const std::vector<uint8_t>& queue, const std::wstring& queueFile, std::vector<BitsJob>& jobs);

/*! Reads a file's blob.
 *  @return false if a length does not fit */
bool parseBitsFile(const std::vector<uint8_t>& blob, BitsFile& file);

//! BITS jobs (bits_jobs.json).
class BitsJobs {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why neither qmgr.db nor a queue file can be read
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the jobs
private:
	//! @return ERROR_SUCCESS if a queue file of Windows 8.1 and earlier was read
	HRESULT readQueueFiles();
	std::vector<BitsJob> jobs_;
	std::vector<BitsFile> files_;
};
