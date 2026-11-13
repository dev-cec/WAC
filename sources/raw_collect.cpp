/*! \file
 *  \brief Orchestration of the offline extraction of artefacts (see raw_collect.h).
 */
#include "raw_collect.h"
#include <set>
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
#include "powershell_history.h"
#include "powershell_profiles.h"
#include "activities_cache.h"
#include "search_index.h"
#include "rdp_client.h"
#include "thumbcache.h"
#include "emails.h"
#include "running_machine.h"
#include "startup_folders.h"
#include "shortcuts.h"
#include "dpapi_master_keys.h"
#include "web_client.h"
#include "live_snapshot.h"
#include "event_log_files.h"
#include "sysmon.h"
#include "firewall_log.h"
#include "web_server.h"
#include "application_traces.h"
#include "active_directory.h"
#include "dns_server.h"
#include "dhcp_server.h"
#include "hyperv.h"
#include "group_policies.h"
#include "web_installations.h"
#include "intune_logs.h"
#include "cloud_identity.h"
#include <algorithm>

//! Defender for Endpoint's local folder.
const wchar_t DEFENDER_ENDPOINT_FOLDER[] = L"\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection";
//! OneDrive's folder in a profile.
const wchar_t ONEDRIVE_FOLDER[] = L"\\AppData\\Local\\Microsoft\\OneDrive";

namespace {

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
	printProgress(item ? item : L"", done / 1024, total / 1024, text(Text::ProgressKibibytes));
}

/*! Repairs the working copies of hives: transaction log replay, patch as a
 *  fallback, each write recorded with the fingerprint of the copy before it.
 *  @param hives working paths of the hives (missing files are skipped)
 *  @param md5ByFile MD5 of each hive as extracted, by working path; a hive
 *         absent from it is hashed before any write
 *  @return ERROR_SUCCESS, or S_FALSE if a hive stays unusable */
HRESULT repairHives(const std::vector<std::wstring>& hives,
                    const std::map<std::wstring, std::wstring>& md5ByFile) {
	// Repair each hive (dirty -> loadable), with traceability.
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Hives recovery :");
	log(0, L"*******************************************************************************************************************");
	unsigned patchedHives = 0, failures = 0, replayed = 0;
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

		printProgress(text(Text::ProgressRepair, { std::filesystem::path(r).filename().wstring() }),
		              iHive, hives.size(), text(Text::ProgressHive));

		/* Fingerprint BEFORE any modification: the raw copy stays identifiable.
		   Taken from the computation made during extraction; the file is only
		   re-read if it is missing (theoretical case of an item without one). */
		std::wstring md5Before;
		const auto found = md5ByFile.find(r);
		if (found != md5ByFile.end()) md5Before = found->second;
		else md5Before = QuickDigest5::fileToHash(r);

		log(1, L"➕Hive");
		if (md5Before.empty()) log(2, L"🔥MD5 of the raw copy not computed, the copy unreadable: " + r);
		else log(2, L"❇️MD5 of the raw copy (before any write): " + md5Before);

		/* REPLAY FIRST. The transaction logs hold the pages changed since the
		   hive's last full write: applying them gives the machine's real state,
		   and makes the hive clean by construction — hence no patch. The original
		   content of each replaced page goes into an undo log, so that the
		   raw copy stays rebuildable to the byte (verified on three real
		   hives). */
		const HiveReplayInfo replay = ReplayHiveLogs(r, md5Before);
		log(2, L"❇️" + HiveReplayInfoToString(replay));
		if (replay.applied) {
			++replayed;
			replayedPages  += replay.pages;
			replayedBytes  += replay.bytes;
			auditRecord(L"Replay of the transaction logs of a copied hive ("
			            + std::to_wstring(replay.keptEntries) + L" entry(ies), "
			            + std::to_wstring(replay.pages) + L" page(s))",
			            r + L" | " + HiveReplayInfoToString(replay)
			            + L" | MD5 before the replay: " + md5Before
			            + L" | undo: " + replay.undoJournal,
			            ERROR_SUCCESS, Footprint::HIVE_REPLAY);
		}
		else if (!replay.ok) {
			// The replay wrote nothing: record it and fall back on the patch.
			log(2, L"🔥Replay impossible: " + r + L" (" + replay.error + L")");
			auditRecord(L"Replay of the transaction logs of a copied hive (not applied)",
			            r + L" | " + HiveReplayInfoToString(replay),
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
		auditRecord(info.patched ? L"Repair of a copied hive (patch applied)"
		                         : L"Check of a copied hive (already clean)",
		            r + L" | " + HiveFixInfoToString(info) + L" | MD5 before the patch: " + md5Before,
		            info.ok ? ERROR_SUCCESS : E_FAIL,
		            info.patched ? Footprint::HIVE_PATCH : Footprint::HIVE_COPY);
		if (!info.ok) { ++failures; log(2, L"🔥Hive not usable: " + r + L" (" + info.error + L")"); }
		else if (info.patched) ++patchedHives;
	}
	printProgressEnd();
	log(2, L"❇️Hives replayed: " + std::to_wstring(replayed)
	     + L" (" + std::to_wstring(replayedPages) + L" pages, "
	     + std::to_wstring(replayedBytes / 1024) + L" KiB applied)");
	log(2, L"❇️Hives repaired by patch: " + std::to_wstring(patchedHives)
	     + L", failures: " + std::to_wstring(failures));

	// An unreadable hive blocks what follows (OROpenHive): report it.
	return (failures == 0) ? ERROR_SUCCESS : S_FALSE;
}

/*! EXHIBIT STORE -> WORKING COPY after an extraction phase: what the
 *  phase added is copied into the working directory and verified
 *  (ExhibitStoreToWorking, which overwrites nothing already there), and the
 *  copy is recorded in the investigation log.
 *  @return the result of ExhibitStoreToWorking */
HRESULT storeToWorking() {
	size_t copies = 0;
	unsigned long long bytes = 0;
	const HRESULT hr = ExhibitStoreToWorking(&copies, &bytes);
	auditRecord(L"Copy of the exhibit store into the working directory ("
	            + std::to_wstring(copies) + L" file(s), "
	            + std::to_wstring(bytes / 1024 / 1024) + L" MiB)",
	            exhibitStoreFolder() + L" -> " + workingFolder(),
	            hr, Footprint::USB_WRITE);
	return hr;
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
 *  @param label     what this pass extracts, for the audit log.
 */
HRESULT extractHiveSet(const std::vector<std::wstring>& hivePaths,
                            const std::wstring& label) {
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
		for (const std::pair<std::wstring, std::wstring>& it : group.second)
			createFolders(parentFolder(it.second));

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
		ExhibitStoreAdd(reading, L"Raw NTFS reading (\\\\.\\" + volume
		                        + L": — $MFT, directory indexes, $DATA attribute); "
		                        L"no file opened by the system");
		// Recorded here, not by the caller: the extraction must come before the
		// patches it triggers in the log, otherwise the sequence reads
		// backwards.
		auditRecord(label,
		            std::wstring(L"\\\\.\\") + volume + L": -> " + conf.mountpoint,
		            hrVolume, Footprint::VOLUME_BRUT);
		if (FAILED(hrVolume)) {                  // volume inaccessible
			log(2, L"🔥Volume " + volume + L": not accessible for raw reading", hrVolume);
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
		const HRESULT hrCopy = storeToWorking();
		if (FAILED(hrCopy)) return hrCopy;     // without a working copy, nothing follows
		if (hrCopy == S_FALSE) hr = S_FALSE;
	}

	log(2, L"❇️Hive files missing from the extraction: " + std::to_wstring(missing));
	const HRESULT repaired = repairHives(hives, md5ByFile);
	return (repaired == ERROR_SUCCESS) ? hr : repaired;
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
		/* SECURITY: LSA secrets' names and dates, cached logons, audit policy
		   (security.json — never a secret's value). DEFAULT: the system
		   account's profile, its Run keys. */
		L"\\Windows\\system32\\config\\SECURITY",
		L"\\Windows\\system32\\config\\DEFAULT",
	};
	/* Amcache.hve is the `amcache` artefact's alone: copied for it only. */
	if (conf.artefacts.amcache) hives.push_back(L"\\Windows\\AppCompat\\Programs\\Amcache.hve");
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

namespace {

/*! The browsers' databases: for every Chromium user data folder of every
 *  profile, its Local State, and in each browser profile the files of
 *  CHROMIUM_PROFILE_FILES with their -journal and -wal. Found by listing the
 *  folders raw, through ONE RawReader: each volume is opened once, and the
 *  caches beside the databases are never walked.
 *  @return S_OK, or S_FALSE if a file could not be read */
HRESULT extractBrowserFiles() {
	RawReader reader;
	std::vector<RawHiveExtraction> reading;
	HRESULT result = S_OK;
	// A folder's entries by lower-case name, listed once.
	auto listing = [&](const std::wstring& folder, std::map<std::wstring, RawDirEntry>& out) {
		out.clear();
		std::vector<RawDirEntry> entries;
		if (FAILED(reader.list(folder, entries))) return false;
		for (const RawDirEntry& e : entries) out.emplace(toLower(e.name), e);
		return true;
	};
	// One file of the folder, as listed.
	auto takeOne = [&](const std::wstring& folder, const RawDirEntry& entry) {
		const std::wstring absolute = folder + L"\\" + entry.name;
		createFolders(parentFolder(exhibitTarget(absolute)));
		RawHiveExtraction line;
		if (FAILED(reader.read(absolute, exhibitTarget(absolute), line))) result = S_FALSE;
		reading.push_back(std::move(line));
	};
	// A database, with its journals beside it.
	auto take = [&](const std::wstring& folder, const std::map<std::wstring, RawDirEntry>& entries, const std::wstring& name) {
		for (const wchar_t* suffix : { L"", L"-journal", L"-wal", L"-shm" }) {
			const auto found = entries.find(toLower(name + suffix));
			if (found != entries.end() && !found->second.isDirectory) takeOne(folder, found->second);
		}
	};
	/* A file of a profile's list: a name, "<subfolder>\\<name>", or
	   "<subfolder>\\*" for every file of the subfolder. */
	auto takeListed = [&](const std::wstring& folder, const std::map<std::wstring, RawDirEntry>& entries,
	                      const std::wstring& file) {
		const size_t slash = file.find(L'\\');
		if (slash == std::wstring::npos) { take(folder, entries, file); return; }
		const std::wstring subfolder = file.substr(0, slash), name = file.substr(slash + 1);
		const auto found = entries.find(toLower(subfolder));
		std::map<std::wstring, RawDirEntry> inside;
		if (found == entries.end() || !found->second.isDirectory) return;
		const std::wstring path = folder + L"\\" + found->second.name;
		if (!listing(path, inside)) return;
		if (name != L"*") { take(path, inside, name); return; }
		for (const auto& e : inside) if (!e.second.isDirectory) takeOne(path, e.second);
	};
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
		for (size_t i = 0; i < CHROMIUM_ROOT_COUNT; ++i) {
			const std::wstring root = std::get<1>(profileEntry) + CHROMIUM_ROOTS[i].relative;
			std::map<std::wstring, RawDirEntry> rootEntries;
			if (!listing(root, rootEntries)) continue;   // no such browser for this user
			for (const std::wstring& name : CHROMIUM_ROOT_FILES) take(root, rootEntries, name);
			std::vector<std::wstring> folders = { root };   // Opera keeps a profile at its root
			for (const auto& e : rootEntries) if (e.second.isDirectory) folders.push_back(root + L"\\" + e.second.name);
			for (const std::wstring& folder : folders) {
				std::map<std::wstring, RawDirEntry> entries;
				if (folder == root) entries = rootEntries;
				else if (!listing(folder, entries)) continue;
				std::vector<std::wstring> names;
				for (const auto& e : entries) names.push_back(e.second.name);
				if (!isChromiumProfile(names)) continue;
				for (const std::wstring& file : CHROMIUM_PROFILE_FILES) takeListed(folder, entries, file);
			}
		}
	// Firefox: every subfolder of Profiles is a profile.
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring profiles = std::get<1>(profileEntry) + FIREFOX_PROFILES;
		std::map<std::wstring, RawDirEntry> folders;
		if (!listing(profiles, folders)) continue;
		for (const auto& f : folders) {
			if (!f.second.isDirectory) continue;
			const std::wstring folder = profiles + L"\\" + f.second.name;
			std::map<std::wstring, RawDirEntry> entries;
			if (!listing(folder, entries)) continue;
			for (const std::wstring& file : FIREFOX_PROFILE_FILES) takeListed(folder, entries, file);
		}
	}
	ExhibitStoreAdd(reading, L"Raw NTFS reading (RawReader — $MFT, directory indexes, $DATA attribute); "
	                         L"no file opened by the system");
	for (const RawHiveExtraction& line : reading)
		auditRecord(L"Raw extraction of a browser database", L"\\\\.\\" + line.volumePath, line.result, Footprint::VOLUME_BRUT);
	log(2, L"❇️Browser files: " + std::to_wstring(reading.size()));
	return result;
}

/*! Files taken one by one where the examined registry places them — the
 *  event logs kept outside winevt\\Logs (event_log_files.h), Sysmon's
 *  configuration file (sysmon.h): raw, one opening per volume, each exhibit
 *  under its volume's own folder ("_volume_D\\…").
 *  @param files absolute paths, with their letter
 *  @param what what they are, for the investigation log
 *  @param total incremented by the files taken
 *  @return S_OK, S_FALSE if one could not be read */
HRESULT extractFiles(const std::vector<std::wstring>& files, const std::wstring& what, size_t& total) {
	std::map<std::wstring, std::vector<std::pair<std::wstring, std::wstring>>> byVolume;
	for (const std::wstring& file : files)
		byVolume[volumeOfPath(file)].emplace_back(pathRelativeToVolume(file), exhibitTarget(file));
	HRESULT result = S_OK;
	for (const auto& volume : byVolume) {
		// ExtractFilesRaw writes into existing folders only, as for the hives.
		for (const auto& item : volume.second) createFolders(parentFolder(item.second));
		std::vector<RawHiveExtraction> reading;
		const HRESULT hr = ExtractFilesRaw(volume.first, volume.second, nullptr, &reading);
		ExhibitStoreAdd(reading, L"Raw NTFS reading (\\\\.\\" + volume.first
		                        + L": — $MFT, directory indexes, $DATA attribute); no file opened by the system");
		auditRecord(L"Raw extraction of " + what + L" (" + std::to_wstring(volume.second.size()) + L" file(s))",
		            L"\\\\.\\" + volume.first + L":", hr, Footprint::VOLUME_BRUT);
		if (hr != S_OK) result = S_FALSE;
		else total += volume.second.size();
	}
	return result;
}

/*! A folder the collection takes whole, or by extension, to a depth. */
struct Tree {
	std::wstring absolute;                 //!< the folder, with its letter or relative to the system volume
	std::vector<std::wstring> extensions;  //!< filter, empty for every file
	unsigned depth;                        //!< guard against an abnormal tree
	const wchar_t* what;                   //!< for the investigation log
	std::wstring skipped = L"";            //!< a subfolder another artefact extracts, same form as absolute; empty for none
	std::vector<std::wstring> taken = {};  //!< folders and files already taken, absolute: never taken twice
};

/*! Extracts a tree by raw reading of its directory indexes, into the
 *  exhibit store, recorded in the investigation log.
 *  @param written the tree, its paths as Vista and later lay them out
 *  @param total incremented by the files taken
 *  @return S_OK, also for an absent folder (the nominal case); otherwise
 *          its volume or its index failed — a part of the collection missing */
HRESULT extractTree(const Tree& written, size_t& total) {
	Tree tree = written;
	tree.absolute = examinedLayout(written.absolute);   // as for the targets
	tree.skipped = examinedLayout(written.skipped);
	const std::wstring volume = volumeOfPath(tree.absolute), path = pathRelativeToVolume(tree.absolute);
	size_t extractedFiles = 0;
	std::vector<RawHiveExtraction> reading;
	std::vector<std::wstring> skipped;
	if (!tree.skipped.empty()) skipped.push_back(pathRelativeToVolume(tree.skipped));
	for (const std::wstring& piece : tree.taken) skipped.push_back(pathRelativeToVolume(piece));
	const HRESULT hrTree = ExtractDirectoryTreeRaw(volume, path, exhibitTarget(tree.absolute),
	                                               tree.extensions, &extractedFiles, tree.depth, &reading,
	                                               skipped);
	ExhibitStoreAdd(reading, L"Recursive raw NTFS reading (\\\\.\\"
	                        + volume + L": — $MFT, directory indexes); "
	                        L"no file opened by the system");
	auditRecord(L"Raw extraction of the " + std::wstring(tree.what) + L" ("
	            + std::to_wstring(extractedFiles) + L" file(s))",
	            std::wstring(L"\\\\.\\") + volume + L":" + path,
	            hrTree, Footprint::VOLUME_BRUT);
	log(2, L"❇️" + path + L" : " + std::to_wstring(extractedFiles) + L" file(s)");
	total += extractedFiles;
	return hrTree;
}

/*! The pieces of a file: itself and what lies beside it under a name that
 *  starts the same (a database's -wal and -journal, a log's rotations), as its
 *  folder's index lists them.
 *  @param file the file, absolute
 *  @return the entries; none for a folder absent */
std::vector<RawDirEntry> piecesBeside(const std::wstring& file) {
	std::vector<RawDirEntry> pieces, entries;
	const std::wstring volume = volumeOfPath(file), path = pathRelativeToVolume(file);
	const size_t slash = path.rfind(L'\\');
	const std::wstring parent = path.substr(0, slash), name = toLower(path.substr(slash + 1));
	if (FAILED(ListDirectoryRaw(volume, parent.empty() ? L"\\" : parent, entries))) return pieces;
	for (const RawDirEntry& e : entries)
		if (!e.isDirectory && toLower(e.name).compare(0, name.size(), name) == 0) pieces.push_back(e);
	return pieces;
}

/*! The size of a folder, its index walked to a depth.
 *  @param volume its volume's letter
 *  @param path the folder on the volume
 *  @param depth levels left */
uint64_t rawTreeSize(const std::wstring& volume, const std::wstring& path, unsigned depth) {
	std::vector<RawDirEntry> entries;
	uint64_t size = 0;
	if (FAILED(ListDirectoryRaw(volume, path, entries))) return 0;
	for (const RawDirEntry& e : entries) {
		if (e.name == L"." || e.name == L"..") continue;
		if (!e.isDirectory) size += e.size;
		else if (depth > 0) size += rawTreeSize(volume, path + L"\\" + e.name, depth - 1);
	}
	return size;
}

//! The subfolders of a folder, by raw reading.
std::vector<std::wstring> rawSubfolders(const std::wstring& folder) {
	std::vector<std::wstring> names;
	std::vector<RawDirEntry> entries;
	const std::wstring path = pathRelativeToVolume(folder);
	if (FAILED(ListDirectoryRaw(volumeOfPath(folder), path.empty() ? L"\\" : path, entries))) return names;
	for (const RawDirEntry& e : entries)
		if (e.isDirectory && e.name != L"." && e.name != L"..") names.push_back(e.name);
	return names;
}

/*! Whether a folder is there, to spare the investigation log a line per product a
 *  machine does not have. An index that cannot be read counts as there: its tree
 *  then reports the failure, a part of the collection missing.
 *  @param folder the folder
 *  @return false only for a folder absent */
bool traceFolderPresent(const std::wstring& folder) {
	const std::wstring examined = examinedLayout(folder);
	std::vector<RawDirEntry> entries;
	const std::wstring path = pathRelativeToVolume(examined);
	return ListDirectoryRaw(volumeOfPath(examined), path.empty() ? L"\\" : path, entries) != HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
}

/*! What the products of application_traces.h left on this machine, those wac.yml keeps on.
 *  @param trees receives one tree per folder found */
void addApplicationTraces(std::vector<Tree>& trees) {
	const std::wstring mark = PROFILE_MARK;
	for (const TraceGroup& group : applicationTraces())
		for (const TraceProduct& product : group.products) {
			if (!traceProductWanted(conf.traceProducts, group.key, product.key, product.onByDefault)) continue;
			for (const TracePiece& piece : product.pieces) {
				std::vector<std::wstring> written;
				if (piece.folder.compare(0, mark.size(), mark) != 0) written.push_back(piece.folder);
				else for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
					written.push_back(std::get<1>(profileEntry) + piece.folder.substr(mark.size()));
				for (const std::wstring& each : written)
					for (const std::wstring& folder : expandFolderPattern(each, [](const std::wstring& parent) { return rawSubfolders(examinedLayout(parent)); }))
						if (traceFolderPresent(folder)) trees.push_back({ folder, piece.filter, piece.depth, product.name });
			}
		}
}

/*! What the collection of the web servers takes, each piece once. Two sites
 *  can share a folder, a nested application lies in its site's, a log in a
 *  document root, an option file in its data folder: taken a second time, an
 *  exhibit would be written again and declared twice in the manifest, and
 *  a store is never written again. */
class WebPieces {
public:
	explicit WebPieces(size_t& total) : total_(total) {}

	//! Takes a folder, whole or by extension, leaving out what is already taken.
	HRESULT tree(const std::wstring& folder, const std::vector<std::wstring>& extensions, unsigned depth, const wchar_t* what) {
		const std::wstring key = toLower(folder) + L"|" + std::to_wstring(extensions.size());
		if (holds(folder) || !filtered_.insert(key).second) return S_OK;
		Tree t{ folder, extensions, depth, what };
		for (const std::wstring& piece : taken_)
			if (folderHolds(folder, piece)) t.taken.push_back(piece);
		const HRESULT hr = extractTree(t, total_);
		if (extensions.empty()) taken_.push_back(folder);
		return hr;
	}

	//! Takes files, those not already taken.
	HRESULT files(const std::vector<std::wstring>& paths, const std::wstring& what) {
		std::vector<std::wstring> wanted;
		for (const std::wstring& path : paths)
			if (!holds(path)) { wanted.push_back(path); taken_.push_back(path); }
		return wanted.empty() ? S_OK : extractFiles(wanted, what, total_);
	}

	bool holds(const std::wstring& path) const {
		return std::any_of(taken_.begin(), taken_.end(), [&](const std::wstring& t) { return folderHolds(t, path); });
	}

private:
	size_t& total_;
	std::vector<std::wstring> taken_;     //!< folders taken whole, and files
	std::set<std::wstring> filtered_;     //!< the trees already asked for, by folder and filter
};

/*! The pieces of a database a site names outside the sites' folders: the
 *  file and its -wal and -journal, each up to max_database_mib — a larger one
 *  is said, with its size, and not copied: a very large base is taken on the
 *  operator's decision.
 *  @param file the database, absolute
 *  @return the pieces to take; none for a file absent */
std::vector<std::wstring> databasePieces(const std::wstring& file) {
	std::vector<std::wstring> pieces;
	const std::wstring parent = file.substr(0, file.rfind(L'\\')), name = toLower(file.substr(file.rfind(L'\\') + 1));
	const uint64_t ceiling = AppliConf::ceilingBytes(conf.webServerSettings.maxDatabaseMib);
	for (const RawDirEntry& e : piecesBeside(file)) {
		const std::wstring entry = toLower(e.name);
		if (entry != name && entry != name + L"-wal" && entry != name + L"-journal") continue;
		const std::wstring piece = parent + L"\\" + e.name;
		if (e.size > ceiling) {
			auditRecord(L"Database a site names, not copied: " + std::to_wstring(e.size >> 20)
			            + L" MiB, above max_database_mib (" + std::to_wstring(conf.webServerSettings.maxDatabaseMib) + L")",
			            piece, ERROR_SUCCESS, Footprint::VOLUME_BRUT);
			continue;
		}
		pieces.push_back(piece);
	}
	return pieces;
}

/*! IIS (web_server.h): its configuration first, raw — it names the sites'
 *  folders and the logs'; then the sites, whole; then the databases their
 *  web.config name elsewhere; then the logs and the configuration's
 *  history. Each step reads what the one before took in its working copy,
 *  made as soon as it is taken: the exhibit store is never read after its
 *  copy. Without IIS, the folder is absent: nothing taken, nothing failed.
 *  @param pieces what is taken
 *  @param total incremented by the files of its configuration
 *  @return S_OK, S_FALSE if a part could not be taken */
HRESULT extractIis(WebPieces& pieces, size_t& total) {
	HRESULT global = S_OK;
	const std::wstring configuration = iisConfigurationFile();
	const std::wstring folder = configuration.substr(0, configuration.rfind(L'\\'));
	size_t extracted = 0;
	std::wstring diagnostic;
	std::vector<RawHiveExtraction> reading;
	const HRESULT hr = ExtractDirectoryRaw(volumeOfPath(folder), pathRelativeToVolume(folder), exhibitTarget(folder),
	                                       { L"applicationHost.config", L"administration.config", L"redirection.config" },
	                                       &extracted, &diagnostic, &reading);
	ExhibitStoreAdd(reading, L"Raw NTFS reading (\\\\.\\" + volumeOfPath(folder)
	                        + L": — $MFT, directory indexes, $DATA attribute); no file opened by the system");
	auditRecord(L"Raw extraction of IIS's configuration (" + std::to_wstring(extracted) + L" file(s) — " + diagnostic + L")",
	            L"\\\\.\\" + volumeOfPath(folder) + L":" + pathRelativeToVolume(folder), hr, Footprint::VOLUME_BRUT);
	total += extracted;
	if (hr != S_OK) global = S_FALSE;
	if (storeToWorking() != S_OK) global = S_FALSE;
	const IisSources iis = iisSources(readIisConfiguration());
	//! Deepest folder walked in a site: far below any real site's tree.
	const unsigned SITE_DEPTH = 32;
	for (const std::wstring& site : iis.siteFolders)
		if (pieces.tree(site, {}, SITE_DEPTH, L"IIS site's content") != S_OK) global = S_FALSE;
	// The sites' web.config, read in their working copy, name the databases kept elsewhere.
	if (storeToWorking() != S_OK) global = S_FALSE;
	std::vector<std::wstring> databases;
	for (const std::wstring& file : externalDatabases(readConnectionStrings(iis.siteFolders), iis.siteFolders))
		for (const std::wstring& piece : databasePieces(file)) databases.push_back(piece);
	if (pieces.files(databases, L"databases named by the sites") != S_OK) global = S_FALSE;
	for (const std::wstring& logs : iis.logFolders)
		if (pieces.tree(logs, { L".log" }, 3, L"IIS logs") != S_OK) global = S_FALSE;
	if (pieces.tree(iis.historyFolder, { L".config" }, 2, L"IIS configuration history") != S_OK) global = S_FALSE;
	return global;
}

/*! Apache and nginx (web_installations.h): the folder of each one's
 *  configuration, which names the rest; then its document roots, whole, and
 *  its logs with their rotations. A folder of the right name without
 *  configuration holds no server: nothing more is taken.
 *  @param pieces what is taken
 *  @return S_OK, S_FALSE if a part could not be taken */
HRESULT extractWebInstallations(WebPieces& pieces) {
	HRESULT global = S_OK;
	const std::vector<WebCandidate> candidates = webCandidates(examinedServices(), rawSubfolders, conf.systemDrive.substr(0, 2));
	for (const WebCandidate& c : candidates) {
		const std::wstring folder = c.configFile.substr(0, c.configFile.rfind(L'\\'));
		if (pieces.tree(folder, {}, 8, L"web server's configuration") != S_OK) global = S_FALSE;
	}
	if (!candidates.empty() && storeToWorking() != S_OK) global = S_FALSE;
	const unsigned SITE_DEPTH = 32;
	for (const WebCandidate& c : candidates) {
		const WebInstallation installation = readWebInstallation(c);
		std::vector<std::wstring> logs;
		for (const WebHost& host : installation.hosts) {
			for (const std::wstring& root : host.documentRoots) {
				if (root.size() <= 3) {   // a volume's root is not a site: the whole volume would be copied
					log(2, L"🔈Web server: document root not copied, a volume's root: " + root);
					continue;
				}
				if (pieces.tree(root, {}, SITE_DEPTH, L"web site's content") != S_OK) global = S_FALSE;
			}
			for (const std::vector<std::wstring>* named : { &host.accessLogs, &host.errorLogs })
				for (const std::wstring& file : *named)
					for (const RawDirEntry& e : piecesBeside(file))
						logs.push_back(file.substr(0, file.rfind(L'\\')) + L"\\" + e.name);
		}
		if (pieces.files(logs, L"web server's logs") != S_OK) global = S_FALSE;
	}
	return global;
}

/*! The database engines, raw (web_installations.h): the option file first
 *  when the data folder depends on it; the data folder whole up to
 *  max_database_mib; above it, said, its configuration and logs alone.
 *  @param pieces what is taken
 *  @return S_OK, S_FALSE if a part could not be taken */
HRESULT extractDatabaseEngines(WebPieces& pieces) {
	HRESULT global = S_OK;
	const unsigned DATA_DEPTH = 16;
	for (const DatabaseEngine& named : databaseEngines(examinedServices())) {
		const bool configFirst = !named.configFile.empty() && (named.dataFolder.empty() || !folderHolds(named.dataFolder, named.configFile));
		if (configFirst) {
			if (pieces.files({ named.configFile }, L"database engine's configuration") != S_OK) global = S_FALSE;
			if (storeToWorking() != S_OK) global = S_FALSE;
		}
	}
	for (const DatabaseEngine& e : readDatabaseEngines()) {
		if (e.dataFolder.size() <= 3) {
			log(2, L"🔥" + e.product + L" (" + e.service + L"): data folder not known, or a volume's root: " + e.dataFolder);
			continue;
		}
		const std::wstring path = pathRelativeToVolume(e.dataFolder);
		const uint64_t size = rawTreeSize(volumeOfPath(e.dataFolder), path, DATA_DEPTH);
		const int ceiling = conf.webServerSettings.maxDatabaseMib;
		if (size <= AppliConf::ceilingBytes(ceiling)) {
			if (pieces.tree(e.dataFolder, {}, DATA_DEPTH, L"database engine's data folder") != S_OK) global = S_FALSE;
			continue;
		}
		auditRecord(L"Data folder of " + e.product + L" (" + e.service + L") not copied: " + std::to_wstring(size >> 20)
		            + L" MiB, above max_database_mib (" + std::to_wstring(ceiling) + L"); its configuration and logs taken",
		            e.dataFolder, ERROR_SUCCESS, Footprint::VOLUME_BRUT);
		if (pieces.tree(e.dataFolder, { L".ini", L".cnf", L".conf", L".log", L".err" }, DATA_DEPTH, L"database engine's configuration and logs") != S_OK)
			global = S_FALSE;
	}
	return global;
}

/*! Everything of the artefact web_server: IIS, the other web servers, the
 *  database engines, each piece once.
 *  @param total incremented by the files taken
 *  @return S_OK, S_FALSE if a part could not be taken */
HRESULT extractWebServers(size_t& total) {
	WebPieces pieces(total);
	HRESULT global = extractIis(pieces, total);
	if (extractWebInstallations(pieces) != S_OK) global = S_FALSE;
	if (extractDatabaseEngines(pieces) != S_OK) global = S_FALSE;
	if (storeToWorking() != S_OK) global = S_FALSE;
	return global;
}

} // namespace

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
	// Written as Vista lays its folders out, taken where the examined Windows keeps them.
	auto addTarget = [&](const std::wstring& written,
	                    const std::vector<std::wstring>& ext) {
		const std::wstring absolute = examinedLayout(written);
		targets.push_back({ volumeOfPath(absolute), pathRelativeToVolume(absolute),
		                   exhibitTarget(absolute), ext });
	};

	// Each artefact as the configuration asks (wac.yml, artefacts:): what is switched off is not read at all.
	if (conf.artefacts.prefetch) addTarget(L"\\Windows\\Prefetch", { L".pf" });
	// Windows XP and Server 2003 keep their scheduled tasks as .job files (scheduledTasks.h).
	if (conf.artefacts.scheduledTasks) addTarget(L"\\Windows\\Tasks", { L".job" });
	// RecentFileCache.bcf: Windows 7's list of the executables run lately (reg_amcache.h).
	if (conf.artefacts.amcache) addTarget(L"\\Windows\\AppCompat\\Programs", { L".bcf" });

	/* Event logs: extracted ONLY on request (--events). They are the system's
	   largest artefacts — over a hundred megabytes on an ordinary installation,
	   more on a server. Extracting them systematically would lengthen every
	   collection and fill the medium with data the operator did not ask for.
	   Reading them offline replaces the EventLog API (see events.h). */
	// The event logs: for events.json, and for the incoming RDP connections read in them.
	/* Before Vista they are the .evt files kept next to the hives (evt.h). */
	if (conf.artefacts.needsEventLogs()) {
		if (classicEventLogs(conf.examinedVersion)) addTarget(L"\\Windows\\System32\\config", { L".evt" });
		else addTarget(L"\\Windows\\System32\\winevt\\Logs", { L".evtx" });
	}
	/* The System log alone otherwise, and always: a dependency of every local
	   time of the collection. It tells the zone in force when each was written
	   (time_zone_history.h) — an installation in Pacific time, set to Paris
	   afterwards, dated its first logs 8 h off without it. Its archives too,
	   and TZUtil's log: before Windows 10, the zones tzutil set are there.
	   XP and Server 2003: SysEvent.evt, whose 6005 and 6006 give the zone. */
	else if (classicEventLogs(conf.examinedVersion))
		addTarget(L"\\Windows\\System32\\config", { L"SysEvent.evt" });
	else
		addTarget(L"\\Windows\\System32\\winevt\\Logs",
		          { L"System.evtx", L"Archive-System-*.evtx", L"Microsoft-Windows-TZUtil%4Operational.evtx" });
	/* setupapi.dev.log and its rotations, with the other setup logs of the
	   folder (a few, small): the folder the artefact table gives for the
	   examined Windows — INF since Vista, Windows itself for XP's setupapi.log. */
	if (conf.artefacts.setupApi) {
		const ArtefactEntry* setupApi = artefactEntry("setupapi");
		const std::wstring location = setupApi ? formOf(*setupApi, conf.examinedVersion).location : L"Windows\\INF\\setupapi.dev.log";
		addTarget(L"\\" + location.substr(0, location.rfind(L'\\')), { L".log" });
	}
	/* The firewall's logs, each with its rotation, where the examined
	   registry puts them: their folder, filtered by their two names. */
	if (conf.artefacts.firewallLog)
		for (const std::wstring& file : firewallLogFiles()) {
			const std::wstring name = file.substr(file.rfind(L'\\') + 1);
			addTarget(file.substr(0, file.rfind(L'\\')), { name, name + L".old" });
		}
	/* The server roles, where the examined registry puts their logs. Each
	   folder filtered: the DHCP database's own folder is a tree of its own below. */
	if (conf.artefacts.dnsServer) {
		addTarget(L"\\Windows\\System32\\dns", { L".dns", L".log" });
		addTarget(L"\\Windows\\System32\\dns\\backup", { L".dns" });
		const std::wstring log = dnsServerLogFile();
		addTarget(log.substr(0, log.rfind(L'\\')), { log.substr(log.rfind(L'\\') + 1) });
	}
	/* The Remote Desktop licensing server's database: the licences issued, to which
	   machine and user. Taken raw, not converted: the table of the sessions and the
	   logs already say who connected; WAE or an ESE tool reads it if it matters. */
	if (conf.artefacts.rdpServer) addTarget(L"\\Windows\\System32\\lserver", { L"TLSLic.edb" });
	if (conf.artefacts.hyperV) {
		const std::wstring root = hyperVFolder();
		addTarget(root, { L"data.vmcx" });
		addTarget(root + L"\\Virtual Machines", { L".vmcx", L".xml" });
		addTarget(root + L"\\Snapshots", { L".vmcx", L".xml" });
		addTarget(root + L"\\Virtual Machines Cache", { L".vmcx" });
	}
	// IIS 5.1 and 6 (XP, Server 2003): their metabase, collected raw.
	if (conf.artefacts.webServer) addTarget(L"\\Windows\\System32\\inetsrv", { L"MetaBase.xml", L"MBSchema.xml" });
	// The Intune Management Extension's logs, where it is installed.
	if (conf.artefacts.intuneLogs) addTarget(INTUNE_LOGS_FOLDER, { L".log" });
	// hosts has no extension: the whole folder, a handful of small files.
	if (conf.artefacts.hosts) addTarget(L"\\Windows\\System32\\drivers\\etc", {});
	/* RegBack: the copies Windows made of the hives (task RegIdleBackup) —
	   an older state of the registry. Empty files since Windows 10 1803 unless
	   the task was switched back on; collected as they are, not converted. */
	if (conf.artefacts.registryBackups) addTarget(L"\\Windows\\System32\\config\\RegBack", {});
	/* Defender's support folder: the MPLog text logs, converted, and the WPP
	   traces (.bin), copied raw only — their format, ETW binary traces decoded
	   with Microsoft's private symbols, is not documented. */
	if (conf.artefacts.defender) {
		addTarget(L"\\ProgramData\\Microsoft\\Windows Defender\\Support", { L".log", L".bin" });
		// What MpCmdRun.exe was asked to do, a removal of the definitions among it. This one file of the folder, by name.
		addTarget(L"\\Windows\\Temp", { L"MpCmdRun.log" });
	}
	// The WMI repository: INDEX.BTR, OBJECTS.DATA and the MAPPING files, open by WMI, read raw.
	/* The repository's folder as the artefact table gives it for the examined
	   Windows: Repository, or Repository\\FS on Windows XP. */
	if (conf.artefacts.wmi) {
		const ArtefactEntry* wmi = artefactEntry("wmi");
		addTarget(L"\\" + std::wstring(wmi ? formOf(*wmi, conf.examinedVersion).location : L"Windows\\System32\\wbem\\Repository"), {});
	}
	// The ESE databases with their transaction logs and checkpoint, for a
	// replay by the analyst: copied live, what the last minutes changed is
	// only in the logs.
	if (conf.artefacts.srum) addTarget(L"\\Windows\\System32\\sru", {});
	if (conf.artefacts.bits) addTarget(L"\\ProgramData\\Microsoft\\Network\\Downloader", {});
	// Whatever the startup folders hold runs at logon: everything, whatever its extension.
	if (conf.artefacts.startupFolders) addTarget(STARTUP_ALL_USERS, {});

	/* PowerShell profiles: the folders of the machine's PowerShells and of
	   each user's documents — those PowerShell 7 names after its version
	   listed on the volume (powershell_profiles.h). Every .ps1 of these
	   folders, a handful: the conversion keeps the profiles. */
	if (conf.artefacts.powershellProfiles) {
		RawReader reader;
		auto listVolume = [&reader](const std::wstring& absolute) {
			std::vector<std::wstring> names;
			std::vector<RawDirEntry> entries;
			if (SUCCEEDED(reader.list(absolute, entries)))
				for (const RawDirEntry& e : entries) if (e.isDirectory) names.push_back(e.name);
			return names;
		};
		for (const PowerShellProfileFolder& folder : powerShellProfileFolders(listVolume)) addTarget(folder.path, { L".ps1" });
	}

	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring profile = std::get<1>(profileEntry);   // absolute, with its letter
		const std::wstring recent = profile + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
		if (conf.artefacts.jumpLists) {
			addTarget(recent + L"\\AutomaticDestinations", { L".automaticDestinations-ms" });
			addTarget(recent + L"\\CustomDestinations",    { L".customDestinations-ms" });
		}
		if (conf.artefacts.recentDocuments) {
			addTarget(recent,                              { L".lnk", L".url" });
			addTarget(profile + L"\\AppData\\Roaming\\Microsoft\\Office\\Recent",
			                                              { L".lnk", L".url" });
		}
		if (conf.artefacts.powershellHistory) addTarget(profile + PSREADLINE_FOLDER, { L".txt" });
		if (conf.artefacts.startupFolders) addTarget(profile + STARTUP_PROFILE, {});
		/* The WebCache of Internet Explorer and Edge Legacy: an ESE database in
		   use, copied raw with its transaction logs and checkpoint. */
		if (conf.artefacts.webClient) addTarget(profile + WEBCACHE_FOLDER, {});
		/* Outgoing RDP: the bitmap cache, .bin and .bmc, and the connection
		   files of the Documents. */
		if (conf.artefacts.rdpClient) {
			addTarget(profile + RDP_CACHE_FOLDER, { L".bin", L".bmc" });
			addTarget(profile + L"\\Documents", { L".rdp" });
		}
		// Explorer's thumbnail and icon caches, with their index.
		if (conf.artefacts.thumbcache) addTarget(profile + THUMBCACHE_FOLDER, { L".db" });
		// Outlook's mailboxes: PST archives and the OST of an Exchange or Microsoft 365 account.
		if (conf.artefacts.emails) {
			addTarget(profile + OUTLOOK_FILES_FOLDER, { L".pst" });
			addTarget(profile + OUTLOOK_DATA_FOLDER, { L".pst", L".ost" });
		}
	}

	HRESULT global = S_OK;
	size_t total = 0;
	RawHiveSetProgress(&reportProgress);

	/* TREES, extracted recursively, their structure reproduced.
	   Scheduled task definitions: the files have NO extension — hence no
	   filter. It replaces reading through the Task Scheduler COM interface,
	   which removes both the execution trace and the dependency on COM.
	   Error reports: one folder per report, Report.wer inside. */
	//! Deepest folder walked for Thumbs.db: far below any folder a user browses.
	const unsigned THUMBS_DB_DEPTH = 32;
	std::vector<Tree> trees;
	if (conf.artefacts.webServer && extractWebServers(total) != S_OK) global = S_FALSE;
	/* A domain controller's directory, wherever the registry says: open by
	   the directory service, read raw, its logs and checkpoint with it —
	   what the last minutes changed is only there (active_directory.h). */
	if (conf.artefacts.activeDirectory) {
		std::wstring database, logFolder;
		if (directoryDatabaseLocation(database, logFolder)) {
			const std::wstring folder = database.substr(0, database.rfind(L'\\'));
			trees.push_back({ folder, {}, 1, L"directory database" });
			if (!logFolder.empty() && toLower(logFolder) != toLower(folder)) trees.push_back({ logFolder, {}, 1, L"directory database's logs" });
		}
	}
	/* The DHCP server's database with its logs and checkpoint, as the directory's:
	   open by the service, read raw; a backup is left out, its copy is the same data. */
	if (conf.artefacts.dhcpServer) {
		std::wstring database;
		std::vector<std::wstring> logs;
		dhcpServerFolders(database, logs);
		trees.push_back({ database, { L".mdb", L".log", L".chk", L".jfm" }, 1, L"DHCP server's database and logs" });
		for (const std::wstring& folder : logs)
			if (toLower(folder) != toLower(database)) trees.push_back({ folder, { L".log" }, 1, L"DHCP server's audit logs" });
	}
	/* User Access Logging, open by its service: every file of the folder, not a list of
	   extensions. Measured on Server 2016: the service names each past period's database
	   with three random UTF-16 units, no ".mdb", while CHAINED_DATABASES says
	   {GUID}.mdb — the accesses moved there at each restart of the service. */
	if (conf.artefacts.userAccessLog)
		trees.push_back({ conf.systemDrive.substr(0, 2) + L"\\Windows\\System32\\LogFiles\\Sum", {}, 1, L"User Access Logging" });
	// SYSVOL's real folder, whole: a policy's scripts and what replication keeps of deleted ones.
	if (conf.artefacts.groupPolicies) {
		std::wstring sysvol;
		if (sysvolDomainFolder(sysvol)) trees.push_back({ sysvol, {}, 32, L"group policies (SYSVOL)" });
	}
	if (conf.artefacts.scheduledTasks)
		trees.push_back({ L"\\Windows\\System32\\Tasks", {}, 8, L"scheduled task definitions" });
	if (conf.artefacts.errorReports) {
		trees.push_back({ L"\\ProgramData\\Microsoft\\Windows\\WER", { L".wer" }, 3, L"error reports" });
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
			trees.push_back({ std::get<1>(profileEntry) + L"\\AppData\\Local\\Microsoft\\Windows\\WER",
			                  { L".wer" }, 3, L"error reports" });
	}
	/* Defender: one DetectionHistory file per detection, and the quarantine —
	   its entries and the removed files, copied ENCRYPTED as Defender keeps
	   them: nothing malicious in clear on the collection medium. */
	if (conf.artefacts.defender) {
		trees.push_back({ L"\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory", {}, 2,
		                  L"Defender detection history" });
		trees.push_back({ L"\\ProgramData\\Microsoft\\Windows Defender\\Quarantine", {}, 3, L"Defender quarantine" });
	}
	/* WinINet's cache of each profile — Internet Explorer's engine, which
	   mshta.exe still uses —, its active content only: what was run or opened
	   from the web, not the pages' images. */
	if (conf.artefacts.webClient)
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
			trees.push_back({ std::get<1>(profileEntry) + INETCACHE_FOLDER, INETCACHE_EXTENSIONS, 2, L"WinINet cache" });
	/* Internet Explorer's local folder and WinINet's containers, whole and
	   small: what KAPE took and WAC did not (B-048). */
	if (conf.artefacts.webClient)
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
			trees.push_back({ std::get<1>(profileEntry) + IE_LOCAL_FOLDER, {}, 3, L"Internet Explorer's local folder" });
			for (const std::wstring& folder : WININET_LOCAL_FOLDERS)
				trees.push_back({ std::get<1>(profileEntry) + folder, {}, 3, L"WinINet containers" });
		}
	/* Internet Explorer 5 to 9's index.dat files (Windows 7 and earlier): the
	   cache with its active content, the history and its MSHist01 folders,
	   the cookies' and the downloads' index. */
	if (conf.artefacts.webClient)
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
			for (const IeIndexFolder& f : IE_INDEX_FOLDERS) {
				std::vector<std::wstring> extensions = { L".dat" };
				if (f.cache) extensions.insert(extensions.end(), INETCACHE_EXTENSIONS.begin(), INETCACHE_EXTENSIONS.end());
				trees.push_back({ std::get<1>(profileEntry) + f.relative, extensions, 1, L"Internet Explorer index.dat" });
			}
	/* DPAPI master keys, copied as they are — encrypted by the user's password
	   or the system's DPAPI secret —, with Preferred and CREDHIST beside them:
	   with that password, the analysis decrypts the user's saved secrets. */
	if (conf.artefacts.dpapiMasterKeys) {
		trees.push_back({ DPAPI_SYSTEM_FOLDER, {}, 3, L"DPAPI master keys" });
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
			trees.push_back({ std::get<1>(profileEntry) + DPAPI_PROFILE_FOLDER, {}, 2, L"DPAPI master keys" });
	}
	/* The Timeline: the Connected Devices Platform folder of each profile,
	   whole and small — ActivitiesCache.db with its -wal (the last activities
	   are often only there) in one folder per account, and the platform's
	   settings files beside them. */
	if (conf.artefacts.activitiesCache)
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
			trees.push_back({ std::get<1>(profileEntry) + CONNECTED_DEVICES_FOLDER, {}, 2, L"Timeline (ActivitiesCache.db)" });
	/* The files Outlook opened from a message: one random folder per batch, the
	   copies inside, whatever their kind. */
	if (conf.artefacts.emails)
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
			trees.push_back({ std::get<1>(profileEntry) + OUTLOOK_OPENED_FOLDER, {}, 2, L"attachments opened from Outlook" });
			// Thunderbird's profiles whole: the mbox folders, the address book, the accounts' settings.
			trees.push_back({ std::get<1>(profileEntry) + THUNDERBIRD_FOLDER, {}, 12, L"Thunderbird profiles" });
			trees.push_back({ std::get<1>(profileEntry) + OUTLOOK_NEW_FOLDER, {}, 8, L"new Outlook's local data" });
		}
	/* The Windows Search index: its SQLite databases with their -wal (Windows
	   11), Windows.edb with its ESE logs and checkpoint (Windows 10 and
	   earlier, collected, not converted), and the crawler's logs. */
	if (conf.artefacts.searchIndex)
		trees.push_back({ SEARCH_INDEX_FOLDER, { L".db", L".db-wal", L".db-journal", L".edb", L".log", L".chk", L".jrs",
		                                         L".crwl", L".gthr" }, 4, L"Windows Search index" });
	// The browsers: their profiles found by listing, their databases only.
	if (conf.artefacts.webClient && extractBrowserFiles() != S_OK) global = S_FALSE;
	/* Shortcuts outside Recent: the Start menu and Quick Launch are trees, the
	   desktops plain folders. The Startup folder inside the Start menu is left
	   to the startup folders, which take it whole. */
	if (conf.artefacts.shortcuts)
		for (const ShortcutLocation& where : shortcutLocations()) {
			if (where.folder->recursive)
				trees.push_back({ where.absolute, { L".lnk", L".url" }, SHORTCUT_TREE_DEPTH, L"shortcuts", where.startup });
			else addTarget(where.absolute, { L".lnk", L".url" });
		}
	/* Windows XP and Server 2003 keep a folder's thumbnails in the folder
	   itself, Thumbs.db, wherever it was shown as thumbnails: every fixed
	   NTFS volume is walked for that name alone. Later versions keep them in
	   the profile (thumbcache_*.db, taken with the profile). */
	if (conf.artefacts.thumbcache) {
		const ArtefactEntry* thumbcache = artefactEntry("thumbcache");
		if (thumbcache && std::wstring(formOf(*thumbcache, conf.examinedVersion).location).compare(0, 9, L"Thumbs.db") == 0)
			for (const std::wstring& drive : fixedNtfsVolumes()) {
				/* The collection's own output, when it lies on that volume, is
				   not walked: the Thumbs.db it is copying would be taken again. */
				std::error_code ec;
				const std::wstring output = std::filesystem::absolute(conf._outputDir, ec).wstring();
				const bool here = output.size() > 2 && _wcsnicmp(output.c_str(), drive.c_str(), 2) == 0;
				trees.push_back({ drive + L"\\", { L"Thumbs.db" }, THUMBS_DB_DEPTH, L"thumbnail databases (Thumbs.db)",
				                  here ? output : L"" });
			}
	}
	/* The ETW trace files Windows writes to its own disk — the boot sessions
	   (LogFiles\\WMI), the diagnostics of boot and shutdown (WDI), Windows
	   Update and setup (Logs), the telemetry's (Diagnosis\\ETLLogs) —, raw. */
	if (conf.artefacts.etwLogs) {
		trees.push_back({ L"\\Windows\\System32\\LogFiles\\WMI", { L".etl" }, 2, L"ETW trace files (boot sessions)" });
		trees.push_back({ L"\\Windows\\System32\\WDI", { L".etl" }, 4, L"ETW trace files (diagnostics)" });
		trees.push_back({ L"\\Windows\\Logs", { L".etl" }, 3, L"ETW trace files (Windows logs)" });
		trees.push_back({ L"\\ProgramData\\Microsoft\\Diagnosis\\ETLLogs", { L".etl" }, 3, L"ETW trace files (telemetry)" });
	}
	/* Defender for Endpoint's local folder, where it is onboarded: its
	   formats undocumented, taken raw — the sensor's own binaries
	   (Platform) left out. */
	if (conf.artefacts.defenderEndpoint)
		trees.push_back({ DEFENDER_ENDPOINT_FOLDER, {}, 5, L"Defender for Endpoint",
		                  std::wstring(DEFENDER_ENDPOINT_FOLDER) + L"\\Platform" });
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring& profile = std::get<1>(profileEntry);
		/* OneDrive: its logs (.odl, with the keystore that unscrambles them)
		   and its settings, the sync database among them; SharePoint list
		   sync's logs, the bulk and of little use, left out. */
		if (conf.artefacts.onedrive) {
			trees.push_back({ profile + ONEDRIVE_FOLDER + L"\\logs", {}, 3, L"OneDrive logs", profile + ONEDRIVE_FOLDER + L"\\logs\\ListSync" });
			trees.push_back({ profile + ONEDRIVE_FOLDER + L"\\settings", {}, 3, L"OneDrive settings" });
		}
		// The accounts' token caches, encrypted by DPAPI as Windows keeps them.
		if (conf.artefacts.cloudIdentity)
			for (const wchar_t* folder : CLOUD_TOKEN_FOLDERS)
				trees.push_back({ profile + folder, {}, 4, L"Entra ID token caches" });
	}
	/* Sysmon's archives: the files deleted under a FileDelete rule, kept by
	   Sysmon under their fingerprint — taken whole, as Defender's quarantine. */
	if (conf.artefacts.sysmon)
		for (const SysmonInstallation& s : sysmonInstallations())
			if (!s.archiveFolder.empty()) trees.push_back({ s.archiveFolder, {}, 2, L"Sysmon archives" });
	addApplicationTraces(trees);
	for (const Tree& tree : trees)
		if (extractTree(tree, total) != S_OK) global = S_FALSE;

	for (const Target& target : targets) {
		size_t extractedFiles = 0;
		std::wstring diagnostic;
		std::vector<RawHiveExtraction> reading;
		const HRESULT hr = ExtractDirectoryRaw(target.volume, target.path,
		                                       target.output,
		                                       target.extensions, &extractedFiles, &diagnostic,
		                                       &reading);
		ExhibitStoreAdd(reading, L"Raw NTFS reading (\\\\.\\" + target.volume
		                        + L": — $MFT, directory indexes, $DATA attribute); "
		                        L"no file opened by the system");
		if (FAILED(hr)) {
			/* Inaccessible volume. We NO LONGER stop: with several volumes, an
			   unreadable disk took all the following targets down with it, the
			   system volume's included. */
			log(2, L"🔥Raw extraction impossible: " + target.volume + L":"
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
		auditRecord(L"Raw extraction of a directory (" + std::to_wstring(extractedFiles)
		            + L" file(s) — " + diagnostic + L")",
		            std::wstring(L"\\\\.\\") + target.volume + L":" + target.path,
		            hr, Footprint::VOLUME_BRUT);
		log(1, L"➕Directory");
		log(2, L"❇️" + target.path + L" : " + std::to_wstring(extractedFiles)
		     + L" file(s) [" + diagnostic + L"]");
	}
	{
		std::vector<std::wstring> files;
		for (const MovedEventLog& moved : movedEventLogFiles()) {
			// Without the event logs asked for, the System log alone: the time zones' history (see above).
			if (!conf.artefacts.needsEventLogs() && toLower(moved.channel) != L"system") continue;
			files.push_back(moved.file);
			log(2, L"❇️Event log moved: " + moved.channel + L" → " + moved.file);
		}
		if (extractFiles(files, L"the event logs kept outside winevt\\Logs", total) != S_OK) global = S_FALSE;
	}
	if (conf.artefacts.sysmon) {
		std::vector<std::wstring> files;
		for (const SysmonInstallation& s : sysmonInstallations())
			if (!s.configFile.empty()) files.push_back(s.configFile);
		if (extractFiles(files, L"Sysmon's configuration file", total) != S_OK) global = S_FALSE;
	}
	/* RECYCLE BINS: the `$I` of every user folder, on every fixed NTFS volume
	   (each has its own `\$Recycle.Bin`), and before Vista the INFO2 of
	   `\RECYCLER`. Only the indexes: the `$R` and `Dc<n>` are the deleted
	   files themselves, of any size (see recycle_bin.h). */
	if (conf.artefacts.recycleBin) {
		auto isIndex = [](const std::wstring& name) {
			return (name.size() > 2 && (name.compare(0, 2, L"$I") == 0 || name.compare(0, 2, L"$i") == 0))
			       || _wcsicmp(name.c_str(), L"INFO2") == 0;
		};
		for (const std::wstring& drive : fixedNtfsVolumes())
		for (const std::wstring& bin : { std::wstring(L"\\$Recycle.Bin"), std::wstring(L"\\RECYCLER") }) {
			const std::wstring volume = drive.substr(0, 1);
			std::vector<RawDirEntry> users;
			if (FAILED(ListDirectoryRaw(volume, bin, users))) continue;   // no bin of this form on this volume
			std::vector<std::pair<std::wstring, std::wstring>> items;
			for (const RawDirEntry& user : users) {
				if (!user.isDirectory) continue;
				std::vector<RawDirEntry> files;
				if (FAILED(ListDirectoryRaw(volume, bin + L"\\" + user.name, files))) continue;
				for (const RawDirEntry& f : files)
					if (!f.isDirectory && isIndex(f.name)) {
						const std::wstring onVolume = bin + L"\\" + user.name + L"\\" + f.name;
						items.emplace_back(onVolume, exhibitTarget(drive + onVolume));
					}
			}
			// ExtractFilesRaw writes into existing folders only, as for the hives.
			for (const auto& item : items) createFolders(parentFolder(item.second));
			std::vector<RawHiveExtraction> reading;
			const HRESULT hrBin = items.empty() ? S_OK : ExtractFilesRaw(volume, items, nullptr, &reading);
			ExhibitStoreAdd(reading, L"Raw NTFS reading (\\\\.\\" + volume
			                        + L": — $MFT, directory indexes, $DATA attribute); no file opened by the system");
			auditRecord(L"Raw extraction of the recycle bin indexes, $I or INFO2 (" + std::to_wstring(items.size()) + L" file(s))",
			            std::wstring(L"\\\\.\\") + volume + L":" + bin, hrBin, Footprint::VOLUME_BRUT);
			total += items.size();
			if (hrBin == S_FALSE) global = S_FALSE;
		}
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
		const HRESULT hrCopy = storeToWorking();
		if (FAILED(hrCopy)) return hrCopy;
		if (hrCopy == S_FALSE) global = S_FALSE;
	}
	return global;
}

HRESULT ExtractNtfsMetadataRaw() {
	/* The $MFT serves mft.json, the change journal's paths, the Zone.Identifier
	   streams, and the choice of the deleted files to recover. */
	const bool mft = conf.artefacts.mft || conf.artefacts.usnJournal || conf.artefacts.zoneIdentifiers
	              || conf.artefacts.deletedFiles;
	if (!mft && !conf.artefacts.logFile && !conf.artefacts.securityDescriptors && !conf.artefacts.ntfsVolumes)
		return HRESULT_FROM_WIN32(ERROR_EMPTY);
	HRESULT global = S_OK;
	/* EVERY fixed NTFS volume, not only the system's: a data disk, a profile
	   on D: have their own $MFT and journal, and what happened there is not in
	   C:'s. Each volume's copies go under its own folder of the store. */
	for (const std::wstring& drive : fixedNtfsVolumes()) {
		const std::wstring volume = drive.substr(0, 1);
		const std::wstring method = L"Raw NTFS reading (\\\\.\\" + volume
		                          + L": — $MFT record, $DATA attribute); no file opened by the system";
		RawHiveSetProgress(&reportProgress);
		std::vector<std::pair<std::wstring, std::wstring>> items;
		if (mft) items.push_back({ L"\\$MFT", exhibitTarget(drive + L"\\$MFT") });
		if (conf.artefacts.logFile) items.push_back({ L"\\$LogFile", exhibitTarget(drive + L"\\$LogFile") });
		if (conf.artefacts.ntfsVolumes) items.push_back({ L"\\$Boot", exhibitTarget(drive + L"\\$Boot") });
		createFolders(exhibitTarget(drive + L"\\$Extend"));   // the store's folder of the volume included
		std::vector<RawHiveExtraction> reading;
		HRESULT result = ExtractFilesRaw(volume, items, nullptr, &reading);
		if (conf.artefacts.usnJournal) {
			/* The journal's stream is copied from its first allocated byte: before
			   it, gigabytes of zeros NTFS freed (see ExtractStreamRaw). A volume
			   whose journal is disabled has no $UsnJrnl: recorded as not found. */
			RawHiveExtraction journal;
			if (FAILED(ExtractStreamRaw(volume, L"\\$Extend\\$UsnJrnl", L"$J",
			                            exhibitTarget(drive + L"\\$Extend\\$J"), true, journal))) result = S_FALSE;
			reading.push_back(std::move(journal));
		}
		if (conf.artefacts.securityDescriptors) {
			// $Secure:$SDS: every distinct security descriptor of the volume, files point to them by number.
			RawHiveExtraction descriptors;
			if (FAILED(ExtractStreamRaw(volume, L"\\$Secure", L"$SDS",
			                            exhibitTarget(drive + L"\\$Secure_$SDS"), false, descriptors))) result = S_FALSE;
			reading.push_back(std::move(descriptors));
		}
		if (conf.artefacts.ntfsVolumes) {
			/* $UsnJrnl:$Max, the journal's header: its identifier is its creation
			   date. A volume whose journal is disabled has none: recorded as not
			   found, as $J. */
			RawHiveExtraction header;
			if (FAILED(ExtractStreamRaw(volume, L"\\$Extend\\$UsnJrnl", L"$Max",
			                            exhibitTarget(drive + L"\\$Extend\\$Max"), false, header))) result = S_FALSE;
			reading.push_back(std::move(header));
		}
		if (conf.artefacts.logFile) {
			/* $TxfLog: the journal of transactional NTFS (TxF), a CLFS log and its
			   containers. Copied raw only, as $LogFile: no conversion. */
			size_t extracted = 0;
			if (FAILED(ExtractDirectoryTreeRaw(volume, L"\\$Extend\\$RmMetadata\\$TxfLog",
			                                   exhibitTarget(drive + L"\\$Extend\\$RmMetadata\\$TxfLog"),
			                                   {}, &extracted, 0, &reading))) result = S_FALSE;
			/* $Tops keeps its content in a NAMED stream, $T, which the tree's
			   copy of the unnamed one leaves out. A volume without TxF metadata
			   has none: not an error. */
			RawHiveExtraction tops;
			if (SUCCEEDED(ExtractStreamRaw(volume, L"\\$Extend\\$RmMetadata\\$TxfLog\\$Tops", L"$T",
			                               exhibitTarget(drive + L"\\$Extend\\$RmMetadata\\$TxfLog\\$Tops_$T"), false, tops)))
				reading.push_back(std::move(tops));
		}
		RawHiveSetProgress(nullptr);
		printProgressEnd();
		ExhibitStoreAdd(reading, method);
		for (const RawHiveExtraction& line : reading) {
			auditRecord(L"Raw extraction of NTFS metadata (" + std::to_wstring(line.fingerprints.bytes / 1024 / 1024)
			            + L" MiB)", L"\\\\.\\" + line.volumePath, line.result, Footprint::VOLUME_BRUT);
			if (FAILED(line.result)) log(2, L"🔥Raw extraction impossible: " + line.volumePath, line.result);
		}
		if (result != S_OK) global = S_FALSE;
	}
	return global;
}

namespace {

//! The VSS catalog, a file of System Volume Information named after VSS's identifier.
const wchar_t VSS_CATALOG[] = L"\\System Volume Information\\{3808876b-c176-4e48-b7ae-04046e6cc752}";

//! Names of VSS_VOLUME_SNAPSHOT_ATTRIBUTES' bits, as vssadmin shows them.
const std::pair<uint32_t, const wchar_t*> COPY_ATTRIBUTES[] = {
	{ 0x1, L"Persistent" }, { 0x2, L"NoAutoRecovery" }, { 0x4, L"ClientAccessible" }, { 0x8, L"NoAutoRelease" },
	{ 0x10, L"NoWriters" }, { 0x20, L"Transportable" }, { 0x40, L"NotSurfaced" }, { 0x80, L"NotTransacted" },
	{ 0x10000, L"HardwareAssisted" }, { 0x20000, L"Differential" }, { 0x40000, L"Plex" }, { 0x80000, L"Imported" },
	{ 0x100000, L"ExposedLocally" }, { 0x200000, L"ExposedRemotely" }, { 0x400000, L"AutoRecover" },
	{ 0x800000, L"RollbackRecovery" }, { 0x1000000, L"DelayedPostSnapshot" }, { 0x2000000, L"TxFRecovery" } };

//! Names of the VSS_SNAPSHOT_CONTEXT values.
const std::pair<uint32_t, const wchar_t*> COPY_CONTEXTS[] = {
	{ 0x0, L"Backup" }, { 0x9, L"AppRollback" }, { 0xD, L"ClientAccessibleWriters" }, { 0x10, L"FileShareBackup" },
	{ 0x19, L"NasRollback" }, { 0x1D, L"ClientAccessible" } };

/*! The folder of the exhibit store a copy's files go to: its creation time
 *  then its identifier, so that the folders sort in time order.
 *  @param copy the copy
 *  @return "vss\\20261021T122107Z_9aa8315b-…" */
std::wstring shadowCopyFolder(const ShadowCopyInfo& copy) {
	const FILETIME created = { (DWORD)copy.creationTime, (DWORD)(copy.creationTime >> 32) };
	std::wstring stamp;
	for (wchar_t c : timeToIso8601Utc(created, Precision::Second)) if (c != L'-' && c != L':') stamp += c;
	std::wstring id = toLower(guid_to_wstring(copy.copyId.data()));
	id.erase(std::remove(id.begin(), id.end(), L'{'), id.end());
	id.erase(std::remove(id.begin(), id.end(), L'}'), id.end());
	return L"vss\\" + stamp + L"_" + id;
}

/*! The files a copy kept that the collection reads: the system hives and
 *  Amcache (system volume), the profiles' hives (every volume's \\Users),
 *  the event logs — each hive with its two transaction logs.
 *  @param reader the copy's reader
 *  @param drive the volume, "C:"
 *  @return their paths on the volume, "\\Windows\\…" */
std::vector<std::wstring> shadowCopyTargets(RawReader& reader, const std::wstring& drive) {
	std::vector<std::wstring> paths;
	auto hive = [&](const std::wstring& path) {
		for (const wchar_t* suffix : { L"", L".LOG1", L".LOG2" }) paths.push_back(path + suffix);
	};
	const bool system = toLower(drive) == toLower(conf.systemDrive.substr(0, 2));
	if (system) {
		for (const wchar_t* name : { L"SYSTEM", L"SOFTWARE", L"SAM", L"SECURITY", L"DEFAULT" })
			hive(std::wstring(L"\\Windows\\System32\\config\\") + name);
		if (conf.artefacts.amcache) hive(L"\\Windows\\AppCompat\\Programs\\Amcache.hve");
	}
	if (conf.artefacts.needsUserHives()) {
		std::vector<RawDirEntry> profiles;
		if (SUCCEEDED(reader.list(drive + L"\\Users", profiles)))
			for (const RawDirEntry& p : profiles) {
				if (!p.isDirectory) continue;
				std::vector<RawDirEntry> files;
				const std::wstring profile = L"\\Users\\" + p.name;
				if (FAILED(reader.list(drive + profile, files))) continue;
				for (const RawDirEntry& f : files)
					if (!f.isDirectory && toLower(f.name) == L"ntuser.dat") hive(profile + L"\\" + f.name);
				hive(profile + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat");
			}
	}
	if (system && conf.artefacts.events) {
		std::vector<RawDirEntry> logs;
		if (SUCCEEDED(reader.list(drive + L"\\Windows\\System32\\winevt\\Logs", logs)))
			for (const RawDirEntry& l : logs)
				if (!l.isDirectory && l.name.size() > 5 && toLower(l.name.substr(l.name.size() - 5)) == L".evtx")
					paths.push_back(L"\\Windows\\System32\\winevt\\Logs\\" + l.name);
	}
	return paths;
}

/*! A copy, as the live snapshot records it: what the catalog and its store's
 *  header say, and where its files went. */
Json shadowCopyJson(const std::wstring& drive, const ShadowCopyInfo& copy, const std::wstring& folder) {
	const FILETIME created = { (DWORD)copy.creationTime, (DWORD)(copy.creationTime >> 32) };
	Json o = Json::obj();
	o.add(L"Volume", Json::str(drive));
	o.add(L"ShadowCopyId", Json::str(guid_to_wstring(copy.copyId.data())));
	o.add(L"ShadowCopySetId", Json::str(guid_to_wstring(copy.copySetId.data())));
	o.add(L"StoreId", Json::str(guid_to_wstring(copy.storeId.data())));
	o.add(L"CreationTimeUtc", Json::str(timeToIso8601Utc(created)));
	if (copy.deleted) o.add(L"Deleted", Json::boolean(true));
	o.add(L"VolumeSize", Json::num(copy.volumeSize));
	for (const auto& [value, name] : COPY_CONTEXTS)
		if (copy.hasStore && copy.context == value) o.add(L"Context", Json::str(name));
	Json attributes = Json::arr();
	for (const auto& [bit, name] : COPY_ATTRIBUTES) if (copy.attributes & bit) attributes.push(Json::str(name));
	if (!attributes.members().empty()) o.add(L"Attributes", std::move(attributes));
	if (!copy.operatingMachine.empty()) o.add(L"OperatingMachine", Json::str(copy.operatingMachine));
	if (!copy.serviceMachine.empty()) o.add(L"ServiceMachine", Json::str(copy.serviceMachine));
	if (copy.hasStore) {
		o.add(L"StoredBlocks", Json::num(copy.storedBlocks));
		o.add(L"ExhibitFolder", Json::str(folder));
	}
	return o;
}

} // namespace

HRESULT ExtractShadowCopiesRaw() {
	if (!conf.artefacts.shadowCopies) return HRESULT_FROM_WIN32(ERROR_EMPTY);
	HRESULT global = S_OK;
	Json listed = Json::arr();
	for (const std::wstring& drive : fixedNtfsVolumes()) {
		const std::wstring volume = drive.substr(0, 1);
		std::vector<ShadowCopyInfo> copies;
		std::wstring diagnostic;
		const HRESULT hr = RawShadowCopies(volume, copies, diagnostic);
		auditRecord(L"Raw reading of the shadow copy catalog and stores (" + diagnostic + L")",
		            L"\\\\.\\" + drive, hr, Footprint::VOLUME_BRUT);
		if (FAILED(hr)) { global = S_FALSE; continue; }
		if (copies.empty()) continue;
		/* The catalog itself, raw: what the list recorded below was read from. */
		std::vector<RawHiveExtraction> catalog;
		createFolders(parentFolder(exhibitTarget(drive + VSS_CATALOG)));
		if (ExtractFilesRaw(volume, { { VSS_CATALOG, exhibitTarget(drive + VSS_CATALOG) } }, nullptr, &catalog) != S_OK) global = S_FALSE;
		ExhibitStoreAdd(catalog, L"Raw NTFS reading (\\\\.\\" + volume + L": — $MFT record, $DATA attribute); no file opened by the system");

		/* NEWEST FIRST: each file is compared with its next newer version —
		   the volume as it is now for the newest copy, the copy after it for
		   the others — and stored only if it differs. */
		std::map<std::wstring, RawHiveExtraction> newer;   // by lower-case path on the volume
		for (size_t i = copies.size(); i-- > 0;) {
			const ShadowCopyInfo& copy = copies[i];
			const std::wstring folder = shadowCopyFolder(copy);
			listed.push(shadowCopyJson(drive, copy, folder));
			if (!copy.hasStore) continue;
			const std::wstring root = exhibitStoreFolder() + L"\\" + folder;
			const std::wstring method = L"Raw NTFS reading through shadow copy " + guid_to_wstring(copy.copyId.data())
			                          + L" of \\\\.\\" + volume + L": (catalog and stores read raw, without the VSS service)";
			RawReader reader((int)i);
			unsigned stored = 0, shared = 0, failed = 0;
			RawHiveSetProgress(&reportProgress);
			for (const std::wstring& path : shadowCopyTargets(reader, drive)) {
				RawHiveExtraction probe;
				if (FAILED(reader.read(drive + path, std::wstring(), probe))) continue;   // not in this copy
				const std::wstring key = toLower(path);
				RawHiveExtraction previous;
				const auto found = newer.find(key);
				const bool known = found != newer.end() ? (previous = found->second, true)
				                                        : ExhibitStoreCurrent(drive + path, previous);
				if (known && previous.fingerprints.sha256 == probe.fingerprints.sha256) {
					probe.outputPath = previous.outputPath;
					ExhibitStoreAddDuplicate(probe, method + L"; identical to the newer version");
					++shared;
					continue;
				}
				const std::wstring target = pathUnder(root, drive + path);
				createFolders(parentFolder(target));
				std::vector<RawHiveExtraction> reading;
				const HRESULT extracted = ExtractFilesRaw(volume, { { path, target } }, nullptr, &reading, (int)i);
				ExhibitStoreAdd(reading, method);
				// One item asked: its record, failed or not, is the only one.
				const HRESULT result = reading.empty() ? (FAILED(extracted) ? extracted : E_FAIL) : reading.front().result;
				if (SUCCEEDED(result)) { newer[key] = reading.front(); ++stored; }
				else { ++failed; global = S_FALSE; log(2, L"🔥Shadow copy " + folder + L": " + path + L" not read", result); }
			}
			RawHiveSetProgress(nullptr);
			printProgressEnd();
			auditRecord(L"Raw extraction through shadow copy " + folder + L" (" + std::to_wstring(stored) + L" file(s) stored, "
			            + std::to_wstring(shared) + L" identical to the newer version, " + std::to_wstring(failed) + L" failed)",
			            L"\\\\.\\" + drive, failed ? S_FALSE : S_OK, Footprint::VOLUME_BRUT);
		}
	}
	const HRESULT written = writeLiveSnapshot("shadow_copies.json", listed, L"shadow copies of the fixed NTFS volumes, read raw");
	return FAILED(written) ? written : global;
}

HRESULT RepairWorkingHives() {
	if (const size_t refused = rawEntriesRefused())
		auditRecord(L"Directory entries left out, their name is no file name (a forged index; see mft.json): " + std::to_wstring(refused),
		            L"", ERROR_INVALID_NAME, Footprint::VOLUME_BRUT);
	/* The hives of the working copy, found by their names: the same set the
	   collection extracts (system hives, and each profile's ntuser.dat and
	   UsrClass.dat), whatever the profiles' paths. */
	static const std::set<std::wstring> NAMES = { L"system", L"software", L"sam", L"amcache.hve",
	                                              L"security", L"default", L"ntuser.dat", L"usrclass.dat" };
	std::vector<std::wstring> hives;
	const std::wstring working = workingFolder();
	forEachFileBelow(working, [&](const std::wstring& relative) {
		const size_t cut = relative.find_last_of(L'\\');
		const std::wstring name = toLower(relative.substr(cut == std::wstring::npos ? 0 : cut + 1));
		const std::wstring folder = toLower(parentFolder(relative));
		// The RegBack copies are exhibits, not hives to replay: they have no logs of their own.
		const bool regBack = folder == L"regback" || (folder.size() > 8 && folder.compare(folder.size() - 8, 8, L"\\regback") == 0);
		if (NAMES.count(name) && !regBack) hives.push_back(working + L"\\" + relative);
	});
	log(2, L"❇️Hives of the working copy to repair: " + std::to_wstring(hives.size()));
	return repairHives(hives, {});
}
