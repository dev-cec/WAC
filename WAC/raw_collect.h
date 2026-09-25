/*! \file
 *  \brief Orchestration of the offline extraction of artefacts (WAC).
 *
 *  Replaces the VSS-based collection: extracts by raw NTFS reading (raw_hive)
 *  the hives and files needed into the output folder, on the USB stick — NO
 *  write to the host, no mount point, no snapshot.
 *
 *  conf.mountpoint is reused as a simple path prefix to the working directory
 *  (on the USB stick). Files are stored there under THEIR original path relative
 *  to the volume, so that the whole downstream pipeline (OROpenHive,
 *  listFilesByExtension) is unchanged.
 */
#pragma once
#include <windows.h>

/*  WHY HIVE EXTRACTION IS DONE IN TWO PASSES.
 *
 *  The per-user hives (`ntuser.dat`, `usrClass.dat`) live in the profile
 *  folder: the profiles' location must therefore be known before they can be
 *  extracted. That list used to be read in the LIVE registry, at
 *  `HKLM\SOFTWARE\...\ProfileList` — the last read WAC still made in the
 *  examined machine's registry.
 *
 *  It is now read in the extracted SOFTWARE hive, which imposes the following
 *  order, and explains why what was one function became two:
 *
 *    1. ExtractSystemHivesRaw()   — SYSTEM, SOFTWARE, SAM, Amcache
 *    2. OROpenHive(SOFTWARE)      — on the working copy
 *    3. loadProfileList()         — offline, in that copy
 *    4. ExtractUserHivesRaw()     — the hives of the profiles thus found
 *    5. ExtractFileArtefactsRaw() — Prefetch, jump lists, recent documents
 *
 *  The cost is a second pass over the volume's $MFT; the gain is that no key
 *  of the examined machine's registry is opened any more.
 */

/*! Extracts the MACHINE's hives (+ .LOG1/.LOG2 logs) into
 *  `_outputDir`\\exhibitStore, makes their working copy and makes it usable by
 *  the hive reader (offline_registry.h).
 *
 *  The transaction logs are extracted because they are artefacts in
 *  themselves, and document the pending changes the live copy does not hold.
 *
 *  A raw copy of a live system's hive is always "dirty" and refused by the hive
 *  reader:
 *  each hive therefore goes through a log replay, then MakeHiveLoadable() as a
 *  fallback (see hive_recover.h).
 *
 *  @return S_OK if everything succeeds, S_FALSE if some files are missing or a
 *          hive remains unusable, or an error code if the volume cannot be
 *          opened.
 */
HRESULT ExtractSystemHivesRaw();

/*! Extracts the hives of each user PROFILE listed in `conf.profiles`, under
 *  the same rules as `ExtractSystemHivesRaw`.
 *
 *  To be called AFTER `loadProfileList()`, which fills `conf.profiles` from the
 *  SOFTWARE hive extracted by the previous pass.
 *
 *  @return S_OK if everything succeeds, S_FALSE if no profile was found or some
 *          files are missing, or an error code if the volume cannot be opened.
 */
HRESULT ExtractUserHivesRaw();

/*! Extracts the file-based artefacts: Prefetch, jump lists and recent
 *  documents, into `_outputDir`\\exhibitStore under their original path.
 *
 *  Without this extraction, the matching collectors return NO data — and
 *  "0 entries" is, to the analyst, impossible to tell apart from "no trace on
 *  the machine". The count per directory is therefore logged, so that the
 *  report tells an empty folder from one not collected.
 *
 *  @return S_OK if everything succeeds, S_FALSE if at least one file failed, or
 *          an error code if the volume cannot be opened.
 */
HRESULT ExtractFileArtefactsRaw();

/*! Repairs the hives of a working copy rebuilt from an exhibit store
 *  (--convert): transaction log replay, patch as a fallback, as the collection
 *  does right after extracting them. The hives are found by name in the
 *  working directory.
 *  @return ERROR_SUCCESS, or S_FALSE if a hive stays unusable */
HRESULT RepairWorkingHives();
