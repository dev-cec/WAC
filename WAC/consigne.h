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

#include <windows.h>
#include <string>
#include <vector>
#include "raw_hive.h"

/*! Root of the exhibit store: `<output>\exhibits`. */
std::wstring exhibitStoreFolder();

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

/*! Free bytes on the volume holding the output folder.
*  @return 0 if the information could not be obtained */
unsigned long long ExhibitStoreFreeSpace();

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
                     const std::wstring& method);

/*! Records an exhibit whose CONTENT is already stored under another one.
 *
 *  `e.outputPath` points to the existing exhibit; the file is not copied
 *  again. The manifest declares it (`SharedExhibit`) and does not count its
 *  bytes twice. Used to deduplicate cited binaries (see binaires.h): three
 *  identical 332 MB copies of msedge.dll took 996 MB.
 */
void ExhibitStoreAddDuplicate(const RawHiveExtraction& e, const std::wstring& method);

/*! Copies the exhibit store to the working directory, verifying the copy.
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

/*! Writes `exhibits\MANIFEST.json` then its seal `exhibits\MANIFEST.sha256`.
 *
 *  To be called once every extraction is over. The seal is written AFTER the
 *  manifest and carries its SHA-256 fingerprint.
 *
 *  @return ERROR_SUCCESS, or E_FAIL if either file could not be written — in
 *          which case the exhibit store cannot be identified, and that must be
 *          known.
 */
HRESULT ExhibitStoreWriteManifest();

/*! Number of exhibits in the manifest, and total size.
 *  Used for the end-of-collection summary and the investigation log. */
void ExhibitStoreSummary(size_t* exhibits, size_t* failures, unsigned long long* bytes);
