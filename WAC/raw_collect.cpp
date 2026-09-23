/*  raw_collect.cpp — voir raw_collect.h. */
#include "raw_collect.h"
#include "consigne.h"
#include <string>
#include <vector>
#include <tuple>
#include <filesystem>
#include <map>
#include "tools.h"
#include "audit.h"
#include "raw_hive.h"
#include "hive_recover.h"
#include "quickdigest5.h"

namespace {

/*! Letter of the examined system volume, without the colon ("C").
 *
 *  Derived from conf.systemDrive: Windows is not always on C:.
 *
 *  To be used ONLY for what necessarily lives on the Windows volume —
 *  scheduled task definitions, for instance, live under
 *  `\Windows\System32\Tasks`. Anything that depends on a path found on the
 *  machine (user profiles first) must go through `volumeOfPath()`: assuming
 *  the system volume for those paths was precisely the defect that silently
 *  lost profiles located on another disk. */
std::wstring systemVolume() {
	return conf.systemDrive.substr(0, 1);
}

//! Extraction directory, on the USB stick (output folder). Never the host.
/*  Extraction writes into the EXHIBIT STORE, never into the working
 *  directory: the raw copy must exist before anything is done with it, and
 *  must not be touched afterwards (see exhibitStore.h). `conf.mountpoint` points to
 *  the working directory, so every collector reads the working copy without
 *  knowing anything about this split. */
std::wstring exhibitTarget(const std::wstring& path) {
	return pathUnder(exhibitStoreFolder(), path);
}

/*! Progress reporter for raw_hive: displays KiB, more readable than bytes for
 *  hives of several tens of MiB. */
void reportProgress(const wchar_t* item, unsigned long long done,
                          unsigned long long total) {
	printProgress(item ? item : L"", done / 1024, total / 1024, L"Kio");
}

/*! Raw extraction of a batch of hives, then repair of the working copies:
 *  transaction log replay, patch as a fallback.
 *
 *  SHARED BY BOTH PASSES. The user profile list is now read in the extracted
 *  SOFTWARE hive (see raw_collect.h and tools.h/loadProfileList): the per-user
 *  hives can therefore no longer be extracted in the same pass as the system
 *  hives, since their location is not yet known when that one starts.
 *
 *  @param hivePaths hive paths, absolute (with volume letter) or relative
 *                       to the system volume; the .LOG1 and .LOG2 logs are
 *                       added automatically.
 *  @param etiquette     what this pass extracts, for the audit log.
 */
HRESULT extractHiveSet(const std::vector<std::wstring>& hivePaths,
                            const std::wstring& etiquette) {
	conf.mountpoint = workingFolder();

	// The collection location is checked by main, before the very first
	// write — which can be collecting a process's binary.

	/* EXTRACTION GROUPED BY VOLUME.
	   A single volume used to be assumed, the Windows one: a profile on another
	   disk ("D:\Users\jean", a machine with a system SSD + a data disk) was
	   looked for in C:'s file table, so never extracted — and every artefact of
	   that user came out empty.
	   Files are now grouped by volume letter, and ExtractFilesRaw called once
	   per volume actually involved. */
	std::map<std::wstring, std::vector<std::pair<std::wstring, std::wstring>>> parVolume;
	std::vector<std::wstring> hives;   // local paths of the hives to repair

	// `path` is absolute (with letter) or relative to the system volume.
	auto add = [&](const std::wstring& path) {
		parVolume[volumeOfPath(path)].emplace_back(pathRelativeToVolume(path),
		                                               exhibitTarget(path));
	};
	// A hive + its two transaction logs.
	auto addHive = [&](const std::wstring& path) {
		add(path);
		add(path + L".LOG1");
		add(path + L".LOG2");
		// The replay and the patch apply to the WORKING copy, never to the
		// exhibit store: that is the whole point of the split.
		hives.push_back(extractedPath(path));
	};

	for (const std::wstring& hive : hivePaths) addHive(hive);

	// Create the destination tree under the exhibit store
	for (const auto& group : parVolume)
		for (const std::pair<std::wstring, std::wstring>& it : group.second) {
			std::error_code ec;
			std::filesystem::create_directories(std::filesystem::path(it.second).parent_path(), ec);
		}

	/* One pass per volume. An inaccessible volume must not take the others
	   down: its failure is recorded and we go on, as for a missing hive. The
	   first hard failure is nonetheless kept for the return value, so that the
	   caller knows the collection is incomplete. */
	std::map<std::wstring, std::wstring> md5ByFile;   // working path -> MD5
	unsigned missing = 0;
	HRESULT hr = ERROR_SUCCESS;
	HRESULT firstHardFailure = ERROR_SUCCESS;
	RawHiveSetProgress(&reportProgress);   // shows that extraction is progressing
	for (const auto& group : parVolume) {
		const std::wstring& volume = group.first;
		const auto& items = group.second;
		std::vector<HRESULT> res;
		std::vector<RawHiveExtraction> reading;      // fingerprints computed while writing
		const HRESULT hrVolume = ExtractFilesRaw(volume, items, &res, &reading);
		ExhibitStoreAdd(reading, L"Lecture brute NTFS (\\\\.\\" + volume
		                        + L": — $MFT, directory indexes, $DATA attribute); "
		                        L"no file opened by the system");
		// Recorded here, not by the caller: the extraction must come before the
		// patches it triggers in the log, otherwise the sequence reads
		// backwards.
		auditRecord(etiquette,
		            std::wstring(L"\\\\.\\") + volume + L": -> " + conf.mountpoint,
		            hrVolume, Footprint::VOLUME_BRUT);
		if (FAILED(hrVolume)) {                  // volume inaccessible
			log(2, L"🔥Volume " + volume + L": inaccessible pour la lecture brute", hrVolume);
			if (firstHardFailure == ERROR_SUCCESS) firstHardFailure = hrVolume;
			continue;
		}
		if (hrVolume == S_FALSE) hr = S_FALSE;

		// Log per-file failures without stopping (logs sometimes missing,
		// system profiles without UsrClass.dat, etc.)
		for (size_t i = 0; i < items.size() && i < res.size(); ++i)
			if (FAILED(res[i])) {
				++missing;
				log(2, L"🔥Raw extraction failed: " + volume + L":" + items[i].first, res[i]);
			}
		/* Fingerprints indexed by WORKING path: computed while the exhibit store
		   was being written, hence before any modification — exactly what must be
		   recorded. The key is the working path because that is the one the replay
		   and the patch will apply to. */
		for (const RawHiveExtraction& e : reading)
			if (!e.fingerprints.md5.empty()) {
				const std::filesystem::path relative = std::filesystem::relative(
					std::filesystem::path(e.outputPath), std::filesystem::path(exhibitStoreFolder()));
				md5ByFile.emplace((std::filesystem::path(workingFolder()) / relative).wstring(),
				                      e.fingerprints.md5);
			}
	}
	RawHiveSetProgress(nullptr);
	printProgressEnd();
	log(2, L"❇️Volumes read: " + std::to_wstring(parVolume.size()));
	/* No readable volume: nothing will follow, better say so at once. */
	if (md5ByFile.empty() && firstHardFailure != ERROR_SUCCESS) return firstHardFailure;

	/*  EXHIBIT STORE -> WORKING COPY. The raw copies are in place and
	 *  identified: their working copy is made, verified by fingerprint, and
	 *  everything that follows applies to it alone. */
	{
		size_t copies = 0;
		unsigned long long bytes = 0;
		const HRESULT hrCopy = ExhibitStoreToWorking(&copies, &bytes);
		auditRecord(L"Copy of the exhibit store into the working directory ("
		            + std::to_wstring(copies) + L" fichier(s), "
		            + std::to_wstring(bytes / 1024 / 1024) + L" Mio)",
		            exhibitStoreFolder() + L" -> " + workingFolder(),
		            hrCopy, Footprint::USB_WRITE);
		if (FAILED(hrCopy)) return hrCopy;     // without a working copy, nothing follows
		if (hrCopy == S_FALSE) hr = S_FALSE;
	}

	// Repair each hive (dirty -> loadable), with traceability.
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Hives recovery :");
	log(0, L"*******************************************************************************************************************");
	unsigned patchees = 0, failures = 0, replayed = 0;
	unsigned long long replayedPages = 0, replayedBytes = 0;
	/* This phase no longer re-reads the hives: the fingerprints come from the
	   computation made while writing (see QuickDigest5::Stream). Previously,
	   each hive was read back from the collection medium — about 150 MiB read a
	   second time from a USB stick, almost half the extraction time, without
	   any display. */
	size_t iHive = 0;
	for (const std::wstring& r : hives) {
		std::error_code ec;
		++iHive;
		if (!std::filesystem::exists(r, ec)) continue;   // not extracted: already logged

		printProgress(L"Repair of " + std::filesystem::path(r).filename().wstring(),
		              iHive, hives.size(), L"ruche");

		/* Fingerprint BEFORE any modification: the raw copy stays identifiable.
		   Taken from the computation made during extraction; the file is only
		   re-read if it is missing (theoretical case of an item without one). */
		std::wstring md5Before;
		const auto found = md5ByFile.find(r);
		if (found != md5ByFile.end()) md5Before = found->second;
		else md5Before = QuickDigest5::fileToHash(wstring_to_string(r));

		log(1, L"➕Hive");
		log(2, L"❇️MD5 of the raw copy (before any write): " + md5Before);

		/* REPLAY FIRST. The transaction logs hold the pages changed since the
		   hive's last full write: applying them gives the machine's real state,
		   and makes the hive clean by construction — hence no patch. The original
		   content of each replaced page goes into an undo log, so that the
		   raw copy stays rebuildable to the byte (verified on three real
		   hives). */
		const HiveReplayInfo rejeu = ReplayHiveLogs(r, md5Before);
		log(2, L"❇️" + HiveReplayInfoToString(rejeu));
		if (rejeu.applique) {
			++replayed;
			replayedPages  += rejeu.pages;
			replayedBytes  += rejeu.bytes;
			auditRecord(L"Replay of the transaction logs of a copied hive ("
			            + std::to_wstring(rejeu.keptEntries) + L" entree(s), "
			            + std::to_wstring(rejeu.pages) + L" page(s))",
			            r + L" | " + HiveReplayInfoToString(rejeu)
			            + L" | MD5 before the replay: " + md5Before
			            + L" | undo: " + rejeu.undoJournal,
			            ERROR_SUCCESS, Footprint::HIVE_REPLAY);
		}
		else if (!rejeu.ok) {
			// The replay wrote nothing: record it and fall back on the patch.
			log(2, L"🔥Rejeu impossible : " + r + L" (" + rejeu.error + L")");
			auditRecord(L"Replay of the transaction logs of a copied hive (non applique)",
			            r + L" | " + HiveReplayInfoToString(rejeu),
			            E_FAIL, Footprint::HIVE_COPY);
		}

		/* PATCH AS A FALLBACK. After a successful replay the hive is clean and
		   MakeHiveLoadable does nothing; it only remains useful for hives
		   without a usable log. */
		HiveFixInfo info = MakeHiveLoadable(r);
		log(2, L"❇️" + HiveFixInfoToString(info));

		// ONE entry per hive: every write WAC makes on evidence is recorded,
		// and the BEFORE fingerprint makes it verifiable to the byte. Hives that
		// are already clean are recorded too — "not modified" is information,
		// not a lack of information.
		// Note: the internal name returned by HiveFixInfoToString is truncated to
		// its last 31 characters, as the regf format stores it.
		auditRecord(info.patched ? L"Repair of d'une ruche copiee (patch applique)"
		                         : L"Check of a copied hive (already clean)",
		            r + L" | " + HiveFixInfoToString(info) + L" | MD5 before the patch: " + md5Before,
		            info.ok ? ERROR_SUCCESS : E_FAIL,
		            info.patched ? Footprint::HIVE_PATCH : Footprint::HIVE_COPY);
		if (!info.ok) { ++failures; log(2, L"🔥Hive not usable: " + r + L" (" + info.error + L")"); }
		else if (info.patched) ++patchees;
	}
	printProgressEnd();
	log(2, L"❇️Hives replayed: " + std::to_wstring(replayed)
	     + L" (" + std::to_wstring(replayedPages) + L" pages, "
	     + std::to_wstring(replayedBytes / 1024) + L" Kio appliqués)");
	log(2, L"❇️Hives repaired by patch: " + std::to_wstring(patchees)
	     + L", failures: " + std::to_wstring(failures)
	     + L", missing files: " + std::to_wstring(missing));

	// An unreadable hive blocks what follows (OROpenHive): report it.
	return (failures == 0) ? hr : S_FALSE;
}

} // namespace

HRESULT ExtractSystemHivesRaw() {
	/* The machine's hives. None depends on a path found on the system: that
	   is precisely what allows extracting them first, before knowing anything
	   of the registry's content. */
	std::vector<std::wstring> hives = {
		L"\\Windows\\system32\\config\\SYSTEM",
		L"\\Windows\\system32\\config\\SOFTWARE",
		/* SAM: database of LOCAL accounts. Extracted so that `users` is read
		   offline (last logon dates, logon failures, account flags) instead of
		   querying LSASS over RPC. See users.h. */
		L"\\Windows\\system32\\config\\SAM",
		L"\\Windows\\AppCompat\\Programs\\Amcache.hve",
	};
	return extractHiveSet(
		hives,
		L"Raw extraction of the system hives (+ .LOG1/.LOG2 logs)");
}

HRESULT ExtractUserHivesRaw() {
	/* `conf.profiles` is filled by loadProfileList(), which reads the SOFTWARE
	   hive extracted by the previous pass. An empty list is therefore not a
	   machine without users but a failed profile listing: saying so is better
	   than returning success on an empty extraction. */
	if (conf.profiles.empty()) {
		log(2, L"🔥No profile read: no per-user hive to extract");
		auditRecord(L"Raw extraction of the per-user hives (no profile read)",
		            conf.mountpoint, ERROR_EMPTY, Footprint::VOLUME_BRUT);
		return S_FALSE;
	}

	/* The path is passed ABSOLUTE, with its letter: that is what determines
	   which volume to read. A profile on a second disk ("D:\Users\jean") was
	   looked for in C:'s file table, so never extracted. */
	std::vector<std::wstring> hives;
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring profilePath = std::get<1>(profileEntry);   // ex. "D:\Users\jean"
		hives.push_back(profilePath + L"\\ntuser.dat");
		hives.push_back(profilePath + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
	}
	return extractHiveSet(
		hives,
		L"Raw extraction of the per-user hives (+ .LOG1/.LOG2 logs)");
}

HRESULT ExtractFileArtefactsRaw() {
	if (conf.mountpoint.empty()) conf.mountpoint = workingFolder();

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Raw file artefacts :");
	log(0, L"*******************************************************************************************************************");

	/* Directories to extract, with their collector's extension filter.
	   Each target carries ITS volume: the folders of a profile on a disk other
	   than Windows' were read on the system volume, so never found. */
	struct Target {
		std::wstring volume;       //!< volume letter, without the colon
		std::wstring path;       //!< path relative to that volume's root
		std::wstring output;       //!< destination on the collection medium
		std::vector<std::wstring> extensions;
	};
	std::vector<Target> targets;
	// `absolute` carries its letter, or is relative to the system volume.
	auto addTarget = [&](const std::wstring& absolute,
	                    const std::vector<std::wstring>& ext) {
		targets.push_back({ volumeOfPath(absolute), pathRelativeToVolume(absolute),
		                   exhibitTarget(absolute), ext });
	};

	addTarget(L"\\Windows\\Prefetch", { L".pf" });

	/* Event logs: extracted ONLY on request (--events). They are the system's
	   largest artefacts — over a hundred megabytes on an ordinary installation,
	   more on a server. Extracting them systematically would lengthen every
	   collection and fill the medium with data the operator did not ask for.
	   Reading them offline replaces the EventLog API (see events.h). */
	if (conf._events) addTarget(L"\\Windows\\System32\\winevt\\Logs", { L".evtx" });

	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring profile = std::get<1>(profileEntry);   // absolute, with its letter
		const std::wstring recent = profile + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
		addTarget(recent + L"\\AutomaticDestinations", { L".automaticDestinations-ms" });
		addTarget(recent + L"\\CustomDestinations",    { L".customDestinations-ms" });
		addTarget(recent,                              { L".lnk", L".url" });
		addTarget(profile + L"\\AppData\\Roaming\\Microsoft\\Office\\Recent",
		                                              { L".lnk", L".url" });
	}

	HRESULT global = S_OK;
	size_t total = 0;
	RawHiveSetProgress(&reportProgress);

	/* Scheduled task definitions: a tree, and the files have NO extension —
	   hence the recursive extraction without a filter. It replaces reading
	   through the Task Scheduler COM interface, which removes both the
	   execution trace and the dependency on COM. */
	{
		size_t extractedTasks = 0;
		const std::wstring tasksPath = L"\\Windows\\System32\\Tasks";
		std::vector<RawHiveExtraction> reading;
		const HRESULT hrTasks = ExtractDirectoryTreeRaw(
			systemVolume(), tasksPath, exhibitTarget(tasksPath),
			{}, &extractedTasks, 8, &reading);
		ExhibitStoreAdd(reading, L"Lecture brute NTFS recursive (\\\\.\\"
		                        + systemVolume() + L": — $MFT, index de repertoires) ; "
		                        L"no file opened by the system");
		auditRecord(L"Raw extraction of the scheduled task definitions ("
		            + std::to_wstring(extractedTasks) + L" fichier(s))",
		            std::wstring(L"\\\\.\\") + systemVolume() + L":" + tasksPath,
		            hrTasks, Footprint::VOLUME_BRUT);
		log(2, L"❇️" + tasksPath + L" : " + std::to_wstring(extractedTasks) + L" fichier(s)");
		if (hrTasks == S_FALSE) global = S_FALSE;
	}

	for (const Target& target : targets) {
		size_t extractedFiles = 0;
		std::wstring diagnostic;
		std::vector<RawHiveExtraction> reading;
		const HRESULT hr = ExtractDirectoryRaw(target.volume, target.path,
		                                       target.output,
		                                       target.extensions, &extractedFiles, &diagnostic,
		                                       &reading);
		ExhibitStoreAdd(reading, L"Lecture brute NTFS (\\\\.\\" + target.volume
		                        + L": — $MFT, directory indexes, $DATA attribute); "
		                        L"no file opened by the system");
		if (FAILED(hr)) {
			/* Inaccessible volume. We NO LONGER stop: with several volumes, an
			   unreadable disk took all the following targets down with it, the
			   system volume's included. */
			log(2, L"🔥Extraction brute impossible : " + target.volume + L":"
			     + target.path, hr);
			global = S_FALSE;
			continue;
		}
		if (hr == S_FALSE) global = S_FALSE;    // some files could not be read
		total += extractedFiles;
		// One entry per directory, with the count: that is what lets the
		// analysis tell "empty folder" from "folder not collected".
		// The diagnosis goes with the count: "0 files" does not say whether the
		// directory is missing, empty, or whether the filter discarded everything.
		auditRecord(L"Extraction brute d'un repertoire (" + std::to_wstring(extractedFiles)
		            + L" fichier(s) — " + diagnostic + L")",
		            std::wstring(L"\\\\.\\") + target.volume + L":" + target.path,
		            hr, Footprint::VOLUME_BRUT);
		log(1, L"➕Directory");
		log(2, L"❇️" + target.path + L" : " + std::to_wstring(extractedFiles)
		     + L" fichier(s) [" + diagnostic + L"]");
	}
	RawHiveSetProgress(nullptr);
	printProgressEnd();
	log(2, L"❇️Files extracted in total: " + std::to_wstring(total));

	/*  EXHIBIT STORE -> WORKING COPY, for the file-based artefacts. The hives
	 *  have already been copied and replayed: ExhibitStoreToWorking does not
	 *  overwrite them (see exhibitStore.cpp), it completes the working directory.
	 *  The split applies to these files too, which WAC does not modify:
	 *  duplicating only what one modifies would make the procedure depend on
	 *  what the tool believes it does, which is precisely what must be
	 *  checkable from outside. */
	{
		size_t copies = 0;
		unsigned long long bytes = 0;
		const HRESULT hrCopy = ExhibitStoreToWorking(&copies, &bytes);
		auditRecord(L"Copy of the exhibit store into the working directory ("
		            + std::to_wstring(copies) + L" fichier(s), "
		            + std::to_wstring(bytes / 1024 / 1024) + L" Mio)",
		            exhibitStoreFolder() + L" -> " + workingFolder(),
		            hrCopy, Footprint::USB_WRITE);
		if (FAILED(hrCopy)) return hrCopy;
		if (hrCopy == S_FALSE) global = S_FALSE;
	}
	return global;
}
