/*! \file
 *  \brief EXHIBIT STORE AND WORKING DIRECTORY.
 *
 *  THE PRINCIPLE, WHICH IS A PROCEDURE AND NOT A CONVENIENCE. A digital exhibit
 *  is never analysed on itself. A copy is taken and sealed, and all the work is
 *  done on a SECOND copy. If the analysis damages something — a tool that
 *  writes, a replayed hive, a mistaken command — the sealed exhibit remains
 *  available and the operation can be redone. Without that split, the first
 *  mistake destroys the evidence.
 *
 *  Hence two directories on the collection medium:
 *
 *      <output>\exhibits\   raw copies, as read from the volume.
 *                           NEVER reopened for writing after extraction.
 *                           Holds the manifest that identifies them.
 *      <output>\working\    working copies. That is where hives are replayed
 *                           and undo journals written, and what every
 *                           collector reads.
 *
 *  The split applies to EVERY extracted file, including those WAC does not
 *  modify — Prefetch, jump lists, .lnk, event logs. Duplicating only what one
 *  modifies would make the procedure depend on what the tool believes it does,
 *  which is precisely what must be checkable from outside.
 *
 *  THE MANIFEST. `exhibits\MANIFEST.json` identifies each exhibit and the
 *  collection. It is sealed by `exhibits\MANIFEST.sha256`, which carries its
 *  fingerprint: a manifest cannot hash itself, and without that second file, a
 *  retouched manifest would go undetected.
 *
 *  What it holds, and why each field is there:
 *
 *    for each exhibit
 *      - the SOURCE path with its volume letter, and the path in the exhibit
 *        store: what ties the copy to its origin;
 *      - MD5, SHA-1 and SHA-256: MD5 alone is no longer enough (collisions
 *        since 2008), nor is SHA-1 (2017); the three together settle it;
 *      - the extracted size AND the size declared by the $DATA attribute:
 *        their divergence reveals a truncated extraction, which a fingerprint
 *        alone would not;
 *      - the $MFT record number: it identifies the file on the volume
 *        independently of its name, so even if the name was changed to
 *        mislead;
 *      - the four NTFS timestamps of the SOURCE file: they are investigation
 *        data, and their presence attests that the raw reading did not change
 *        them, the copy carrying the current dates;
 *      - the extraction time, in UTC and in the SUSPECT's local time;
 *      - the collection method, and the outcome — a failure is recorded too,
 *        since an exhibit missing from the manifest would read as never
 *        looked for.
 *
 *    for the collection
 *      - the tool, its version, the command line;
 *      - the operator: name, SID, elevation;
 *      - the examined machine: name, system drive, OS version, time area, and
 *        the difference with the collecting machine's time area;
 *      - the volumes read: letter, serial number, file system;
 *      - the start and end of the extraction;
 *      - the counts, and the explicit statement that nothing was written to
 *        the examined system.
 */
#pragma once

#include <functional>
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include "raw_hive.h"

/*! Root of the exhibit store: `<output>\exhibits`. */
std::wstring exhibitStoreFolder();

/*! Writes into the exhibit store bytes WAC produced — a live snapshot, the
 *  metadata copied from a FAT volume —, fingerprints them and records them in
 *  the manifest, like an exhibit read from a volume.
 *  @param path the file to write, in the exhibit store
 *  @param bytes its content
 *  @param source what it stands for, as the manifest records it
 *  @param method how it was obtained, as the manifest records it
 *  @return ERROR_SUCCESS, or E_FAIL if the write failed */
HRESULT ExhibitStoreProduce(const std::wstring& path, const std::string& bytes, const std::wstring& source,
                            const std::wstring& method);

/*! Root of the working directory: `<output>\working`.
 *  It is the value of `conf.mountpoint`: the collectors read from here. */
std::wstring workingFolder();

/*! Checks that the collection location is usable, BEFORE any extraction.
*
*  Two refusals, both better than a collection that goes wrong midway:
*
*  - A WORKING DIRECTORY ALREADY POPULATED. `ExhibitStoreToWorking` does not
*    overwrite an existing working copy — it cannot, without undoing the
*    previous phase's replay. On a reused output folder, the analysis would
*    therefore bear on the files of an EARLIER collection, silently and with
*    nothing in the report saying so. That is the worst possible case:
*    conclusions drawn from another machine's data.
*
*  - NOT ENOUGH SPACE. Each exhibit is written twice, and a write truncated by a
*    full medium gives a copy that the fingerprint check will flag — but after
*    spending the extraction time. Better to say so beforehand.
*
*  @param estimatedNeed bytes expected for the exhibit store ALONE; the function
*         asks for twice that, the working copy coming on top
*  @return ERROR_SUCCESS, or an error code with the reason logged
*/
HRESULT ExhibitStoreCheckLocation(unsigned long long estimatedNeed);

/*! Checks, before a conversion rebuilds the working copy, that the medium
*  holds it: as many bytes as the exhibit store's contents.
*  WHY. A copy short of space fails file after file, and was reported as a
*  working copy "not matching" its store — invalid data —, the store being
*  sound (measured: a 7 GiB collection converted on a full disk).
*  @param freeBytes free bytes on the medium (ExhibitStoreFreeSpace); 0, unknown: not checked
*  @return ERROR_SUCCESS, or ERROR_DISK_FULL with the figures logged */
HRESULT ExhibitStoreCheckWorkingSpace(unsigned long long freeBytes);

/*! Free bytes on the volume holding the output folder.
*  @return 0 if the information could not be obtained */
unsigned long long ExhibitStoreFreeSpace();

/*! The verdict of the signature check of an executable, as the manifest
 *  records it ("SignatureVerified", "Signature", "SignatureReason"). */
struct SignatureVerdict {
	bool checked = false;     //!< a check was made
	bool valid = false;       //!< the signature holds (catalog, embedded, package)
	std::wstring label;       //!< what authenticated it, e.g. "Microsoft (catalog X.cat)"
	std::wstring reason;      //!< why not, when not valid
	/*! The embedded signature's signer, whoever it is ("CN, O"), and whether
	 *  it is intact (file as signed). Informative: the chain is not verified up
	 *  to a trusted root — anyone can sign with a certificate of their own. */
	std::wstring embeddedSigner;
	bool embeddedIntact = false;
	/*! That signature's chain, checked against the trust set of the key
	 *  (see ThirdPartyRoots): whether it was, whether it holds, to which
	 *  root, or why not. Not checked without a usable set. */
	bool chainChecked = false;
	bool chainTrusted = false;
	std::wstring chainRoot;
	std::wstring chainReason;
	std::wstring chainSignedUtc;          //!< the verified time stamp, ISO 8601 UTC; empty if none
	std::wstring chainTimeStampAuthority; //!< its authority
	std::wstring chainRevocationListsUtc; //!< issue of the oldest CRL the revocation was checked by, ISO 8601 UTC
};

/*! Records an extraction result in the exhibit store manifest.
 *
 *  To be called as extractions go, with the record returned by the `raw_hive`
 *  functions. Nothing is written to disk before `ExhibitStoreWriteManifest`.
 *
 *  @param reading extracted exhibits (or whose extraction failed)
 *  @param method collection method, as it will be recorded
 *         (e.g. L"Raw NTFS reading via \\\\.\\C: ($MFT, attribute $DATA)")
 */
void ExhibitStoreAdd(const std::vector<RawHiveExtraction>& reading,
                     const std::wstring& method, const SignatureVerdict& verdict = {});

/*! Records an exhibit whose CONTENT is already stored under another one.
 *
 *  `e.outputPath` points to the existing exhibit; the file is not copied
 *  again. The manifest declares it (`SharedExhibit`) and does not count its
 *  bytes twice. Used to deduplicate cited binaries (see binaires.h): three
 *  identical 332 MB copies of msedge.dll took 996 MB.
 */
void ExhibitStoreAddDuplicate(const RawHiveExtraction& e, const std::wstring& method,
                              const SignatureVerdict& verdict = {});

/*! Records a file FINGERPRINTED but not copied: an executable whose Microsoft
 *  authenticity was verified in memory (--collect --binary). Identical on
 *  every machine of the same build, its content does not serve the
 *  investigation; its fingerprints and the verdict go into the manifest
 *  ("ContentStored": false), so that the conversion knows every executable
 *  an artefact may cite, and a third party can check the verdict against the
 *  catalogs recorded.
 *  @param e the reading, fingerprints included (outputPath ignored)
 *  @param method collection method, as recorded
 *  @param verdict the signature check (valid, for an authentic binary) */
void ExhibitStoreAddFingerprint(const RawHiveExtraction& e, const std::wstring& method,
                                const SignatureVerdict& verdict);

/*! Copies the exhibit store to the working directory, verifying the copy.
 *  EVERYTHING is copied, the large files ($MFT, change journal, collected
 *  binaries) included: once copied, the exhibit store is touched no more,
 *  not even read — every reading of a collected file goes to its working
 *  copy (backlog B-040). Called after each extraction phase; a file already
 *  in the working directory is not copied again.
 *
 *  Each file is copied, then ITS COPY is hashed again and compared with the
 *  manifest's fingerprint. Without this check, a silently truncated copy — full
 *  medium, write error — would give a working directory that does not match
 *  the exhibit store, and the whole analysis would bear on something other than
 *  the exhibit.
 *
 *  @param copies (optional) receives the number of files copied
 *  @param bytes (optional) receives the volume copied
 *  @return ERROR_SUCCESS, S_FALSE if at least one file could not be copied or
 *          verified, or an error code if the exhibit store is missing
 */
HRESULT ExhibitStoreToWorking(size_t* copies = nullptr, unsigned long long* bytes = nullptr);

/*! Outcome of the check of an exhibit store before a conversion. */
struct ExhibitStoreCheck {
	std::wstring manifestSha256;     //!< actual fingerprint of the manifest (= its seal)
	size_t verified = 0;             //!< exhibits whose content matches the manifest
	size_t altered = 0;              //!< exhibits whose content no longer matches
	size_t failedAtCollection = 0;   //!< items the collection itself could not extract
	std::wstring firstAltered;       //!< the first altered exhibit, for the report
	std::wstring reason;             //!< why the store is refused, if it is
};

/*! True if an exhibit path of a manifest stays inside the exhibit store: it
 *  starts with "exhibits\\" and no component climbs out of it ("..", ".",
 *  or a drive / stream ":"). A forged manifest could otherwise have files
 *  elsewhere read.
 *  @param relative the ExhibitPath of an item, relative to the output folder
 *  @return true if contained */
bool exhibitPathContained(const std::wstring& relative);

/*! Reads back and checks the exhibit store of a collection, before converting
 *  it (--convert): the seal must carry the manifest's real fingerprint, and
 *  every exhibit's SHA-256 must be the one the manifest records. A store that
 *  fails either check is refused — converting it would bear on something other
 *  than the evidence. On success, the manifest's items are loaded, so that
 *  ExhibitStoreToWorking verifies the working copies against them.
 *  @param check receives the counts and, on refusal, the reason
 *  @return ERROR_SUCCESS, or ERROR_FILE_NOT_FOUND / ERROR_INVALID_DATA (as
 *          HRESULT) with check.reason */
HRESULT ExhibitStoreLoad(ExhibitStoreCheck& check);

/*! An exhibit of a loaded manifest (see ExhibitStoreIndex). */
struct StoredExhibit {
	std::wstring sourcePath;   //!< the file on the examined machine ("X:\…"), as recorded
	std::wstring workingFile;  //!< its WORKING copy, the only file to read; empty if its content was not stored
	bool contentStored = true; //!< false: fingerprinted and authenticated only
	std::wstring md5, sha1, sha256;   //!< its fingerprints, as recorded (absent for a fingerprint-only PE)
	std::wstring authenticodeSha256;  //!< Authenticode SHA-256 of a PE, if recorded
	std::wstring signature;    //!< Microsoft authenticity verdict, if recorded
	uint64_t leadingSparseBytes = 0;  //!< offset of the copy in its stream (the change journal)
	bool signatureChecked = false;    //!< the collection checked its signature (SignatureVerified), valid or not
};

/*! The exhibits of the manifest loaded by ExhibitStoreLoad, by source path in
 *  lower case (NTFS is case-insensitive); failed extractions left out.
 *
 *  WHY BY THE MANIFEST. A file of the examined machine is not always stored
 *  under its own path: a content already stored (deduplication), or another
 *  name of the same $MFT record (hard links: System32 and WinSxS), is
 *  declared as sharing an exhibit. Only the manifest ties every source path
 *  to its content. Built on first call; to be called after ExhibitStoreLoad.
 *  @return the index */
const std::map<std::wstring, StoredExhibit>& ExhibitStoreIndex();

/*! Timestamps of the SOURCE file of a working copy, as the raw reading
 *  recorded them ($STANDARD_INFORMATION, in the manifest).
 *
 *  WHY. The working copy is a new file: its own dates are those of the
 *  collection, or of the conversion that rebuilt it. Read on the copy, they
 *  gave the 335 Prefetch files of a collection one and the same "Modified",
 *  the minute of the collection — the last run of each program lost, in valid
 *  JSON. The dates of the file on the examined machine are in the manifest.
 *  @param workingCopy a file of the working directory
 *  @param created,modified,accessed receive them (left untouched if absent)
 *  @return false if the copy has no exhibit, or it recorded no date */
bool ExhibitSourceTimes(const std::wstring& workingCopy, FILETIME& created, FILETIME& modified, FILETIME& accessed);

/*! Whether a file of the exhibit store was written there by this run, from
 *  what WAC recorded — the store itself is not looked at: once copied, it is
 *  touched no more (backlog B-040).
 *  @param storedPath the file in the exhibit store
 *  @return true if an exhibit holds it */
bool ExhibitStoreHolds(const std::wstring& storedPath);

/*! The exhibit a file of the volume AS IT IS NOW was stored as: what the
 *  same file in a shadow copy is compared with, to store it only if it
 *  differs. Scanned at each call, the collection adding exhibits as it goes.
 *  @param sourcePath the file, "X:\\…"
 *  @param stored receives its record
 *  @return false if the collection stored no content for that file */
bool ExhibitStoreCurrent(const std::wstring& sourcePath, RawHiveExtraction& stored);

/*! The files of a shadow copy that were not copied again, identical to a
 *  newer version (SharedExhibit): their source path, and the working copy
 *  of the exhibit they share. A shadow copy's conversion puts them back in
 *  its tree, which then holds every file the copy kept.
 *  @param copyId the copy's identifier, "{…}"
 *  @param visit called with the source path ("X:\\…") and that working copy */
void ExhibitStoreSharedOfShadowCopy(const std::wstring& copyId,
                                    const std::function<void(const std::wstring& source, const std::wstring& workingCopy)>& visit);

/*! Writes `exhibits\MANIFEST.json` then its seal `exhibits\MANIFEST.sha256`.
 *
 *  To be called once every extraction is over. The seal is written AFTER the
 *  manifest and carries its SHA-256 fingerprint.
 *
 *  @param sealValue receives that fingerprint, for the console: written down
 *         by the investigator, it is the one copy of the seal a rewritten
 *         manifest and MANIFEST.sha256 cannot follow (optional)
 *  @return ERROR_SUCCESS, or E_FAIL if either file could not be written — in
 *          which case the exhibit store cannot be identified, and that must be
 *          known.
 */
HRESULT ExhibitStoreWriteManifest(std::wstring* sealValue = nullptr);

/*! Number of exhibits in the manifest, and total size.
 *  Used for the end-of-collection summary and the investigation log. */
void ExhibitStoreSummary(size_t* exhibits, size_t* failures, unsigned long long* bytes);
