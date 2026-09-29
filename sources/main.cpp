/*! \file
 *  \brief Entry point: parses the command line, then runs the collection phases in order — prerequisites, live artefacts, raw extraction, registry, files, event logs, sealing of the exhibit store, investigation log.
 */
// main.cpp: holds the 'main' function. The program starts and ends here.
//

#include <iostream>
#include <filesystem>
#include <windows.h>
#include <string>
#include <stdio.h>
#include "offline_registry.h"
#include <io.h>
#include <fcntl.h>
#include "asciiart.h"
#include "tools.h"
#include "audit.h"
#include "raw_hive.h"
#include "raw_collect.h"
#include "consigne.h"
#include "binaires.h"
#include "reg_usbstors.h"
#include "reg_mounted_devices.h"
#include "reg_bams.h"
#include "reg_muicache.h"
#include "reg_amcache_application.h"
#include "reg_amcache_applicationfile.h"
#include "reg_userassists.h"
#include "reg_run.h"
#include "reg_shimcache.h"
#include "reg_shellbags.h"
#include "reg_mru.h"
#include "reg_mru_apps.h"
#include "prefetchs.h"
#include "mft.h"
#include "usn_journal.h"
#include "powershell_history.h"
#include "setupapi_log.h"
#include "recycle_bin.h"
#include "hosts_file.h"
#include "error_reports.h"
#include "defender_log.h"
#include "startup_folders.h"
#include "recent_docs.h"
#include "jumplist_automatic.h"
#include "jumplist_custom.h"
#include "scheduledTasks.h"
#include "system.h"
#include "sessions.h"
#include "processes.h"
#include "network.h"
#include "account_names.h"
#include "services.h"
#include "users.h"
#include "events.h"
#include "event_messages.h"
#include "running_machine.h"
#include "trust_update.h"
#include "trust_set.h"
#include "config.h"

AppliConf conf; //!< the application's configuration, shared by every collector

//! Prints the command-line help.
void showHelp() {
	SetConsoleTextAttribute(conf.hConsole, 7); // white
	writeConsole(text(Text::Help, { conf.name }));
}

/*! Checks that WAC runs elevated: the raw reading of a volume requires it.
 * @return 0 if so, otherwise the exit code of the refusal */
int checkElevation() {
	log(1, L"➕Check administrator rights");
	printStep(Text::StepAdministratorRights);
	/* A program using VSS must run in elevated mode */
	HANDLE hToken;
	log(3, L"🔈GetCurrentProcess()");
	log(3, L"🔈OpenProcessToken");
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken)) {
		DWORD infoLen;

		TOKEN_ELEVATION elevation = { 0 };
		log(3, L"🔈GetTokenInformation");
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &infoLen)) {
			if (!elevation.TokenIsElevated)
			{
				printError(ERROR_ELEVATION_REQUIRED);
				CloseHandle(hToken);
				return 3;
			}
			CloseHandle(hToken);
			printSuccess();
		}
		else {
			log(2, L"🔈GetTokenInformation", GetLastError());
			printError(GetLastError());
			CloseHandle(hToken);
			return GetLastError();
		}
	}
	else {
		log(2, L"🔈OpenProcessToken", GetLastError());
		printError(GetLastError());
		return GetLastError();
	}
	return 0;
}

/*! Checks the collection medium before the very first write (see
 *  ExhibitStoreCheckLocation).
 * @return ERROR_SUCCESS, or the reason of the refusal */
HRESULT checkCollectionLocation() {
	printStep(Text::StepCollectionMedium);
	unsigned long long need = 250ULL * 1024 * 1024;           // hives
	if (conf._events) need += 150ULL * 1024 * 1024;           // event logs
	if (conf.binary)     need += 1024ULL * 1024 * 1024;          // cited binaries
	const HRESULT hrLieu = ExhibitStoreCheckLocation(need);
	auditRecord(L"Check of the collection location ("
	            + std::to_wstring(ExhibitStoreFreeSpace() / 1024 / 1024)
	            + L" MiB free)",
	            conf._outputDir,
	            hrLieu, Footprint::USB_WRITE);
	if (FAILED(hrLieu)) {
		printError(hrLieu);
		return hrLieu;
	}
	printSuccess();
	return ERROR_SUCCESS;
}

/*! --convert: checks the collection before anything is read from it — the
 *  seal, then every exhibit's fingerprint —, then rebuilds the working copy
 *  from the exhibit store, as the collection made it: copies verified against
 *  the manifest, hives repaired. The working directory is derived data: an
 *  earlier one, possibly altered by an analysis, is deleted rather than
 *  trusted.
 * @return ERROR_SUCCESS, or the reason of the refusal */
HRESULT prepareConversion() {
	printHeading(Text::HeadingCheckingCollection);
	printStep(Text::StepSealAndFingerprints);
	ExhibitStoreCheck check;
	HRESULT hr = ExhibitStoreLoad(check);
	auditRecord(L"Check of the exhibit store (" + std::to_wstring(check.verified) + L" exhibit(s) verified, "
	            + std::to_wstring(check.failedAtCollection) + L" failed at collection"
	            + (check.reason.empty() ? L"" : L"; refused: " + check.reason) + L")",
	            exhibitStoreFolder() + L"\\MANIFEST.json (SHA-256 " + check.manifestSha256 + L")",
	            hr, Footprint::EXHIBIT_READ);
	if (FAILED(hr)) {
		printError(hr);
		writeConsole(L"   " + check.reason + L"\n");
		return hr;
	}
	printSuccess();

	printStep(Text::StepRebuildWorkingCopy);
	std::error_code ec;
	std::filesystem::remove_all(workingFolder(), ec);
	if (ec) {
		hr = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
		auditRecord(L"Deletion of the previous working copy", workingFolder(), hr, Footprint::USB_WRITE);
		printError(hr);
		return hr;
	}
	size_t copies = 0;
	unsigned long long bytes = 0;
	hr = ExhibitStoreToWorking(&copies, &bytes, true);   // the binaries are read in the store
	auditRecord(L"Copy of the exhibit store into the working directory (" + std::to_wstring(copies)
	            + L" file(s), " + std::to_wstring(bytes / 1024 / 1024) + L" MiB)",
	            exhibitStoreFolder() + L" -> " + workingFolder(), hr, Footprint::USB_WRITE);
	// A copy that does not match the manifest: the conversion would bear on something else.
	if (hr != ERROR_SUCCESS) {
		if (!FAILED(hr)) hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		printError(hr);
		return hr;
	}
	conf.mountpoint = workingFolder();
	printSuccess();

	printStep(Text::StepRepairWorkingHives);
	hr = RepairWorkingHives();          // S_FALSE = a hive stays unusable (tolerated, as in a collection)
	auditRecord(L"Repair of the working hives (transaction logs)", workingFolder(), hr, Footprint::HIVE_REPLAY);
	if (FAILED(hr)) printError(hr);
	else printSuccess();

	// The examined machine's system drive, as observed at collection time.
	const std::wstring systemDrive = runningMachine().systemDrive;
	if (!systemDrive.empty()) conf.systemDrive = systemDrive;
	else log(2, L"🔥System drive of the examined machine not recorded: " + conf.systemDrive + L" assumed");
	return ERROR_SUCCESS;
}

/*! Live phase: what can only be observed on the running system — sessions,
 *  processes, service states, clock, settings —, recorded as sealed snapshots
 *  (live_snapshot.h) that the conversion reads back. */
/*! Whether the configuration asks for an artefact (wac.yml, artefacts:);
 *  when it does not, says so on the console and in the artefact's file —
 *  switched off, not failed, not empty.
 *  @param wanted the switch
 *  @param file the artefact's JSON file
 *  @param label the artefact's name
 *  @param key its configuration key
 *  @return `wanted` */
bool requested(bool wanted, const char* file, Text label, const wchar_t* key) {
	if (wanted) return true;
	printStep(L" - " + text(label) + L" : ");
	writeConsole(text(Text::NotRequested, { key }) + L"\n");
	// The artefact's file is in English, like every JSON, whatever the console's language.
	writeNotRequested(file, text(label, Language::English).c_str(), key);
	return false;
}

/*! Converts one file artefact read from the working copy or the exhibit
 *  store: getData, then its JSON file — the same sequence for each of them.
 *  An artefact that could not be read says so in its file (writeNotCollected).
 *  @tparam Collector the artefact's class: getData(), toJson(), clear()
 *  @param wanted the configuration's switch
 *  @param file its JSON file
 *  @param label its name, for the console and the file
 *  @param key its configuration key
 *  @param step the console's step */
template <class Collector>
void convertFileArtefact(bool wanted, const char* file, Text label, const wchar_t* key, Text step) {
	if (!requested(wanted, file, label, key)) return;
	Collector collector;
	printStep(step);
	HRESULT hresult = collector.getData();
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		writeNotCollected(file, text(label, Language::English), hresult);
		return;
	}
	hresult = collector.toJson();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else printSuccess();
	collector.clear();
}

void observeLiveState() {
	HRESULT hresult;
	Sessions sessions;
	Processes processes;
	NetworkState network;
	/************************
	* WIN32 API
	*************************/
	printHeading(Text::HeadingLiveState);

	/* SYSTEM INFORMATION has left this phase: the collection is now offline
	   (SYSTEM and SOFTWARE hives) and therefore happens AFTER they are opened,
	   at the end of the registry phase. See system.h. */

	/* LIVE OBSERVATIONS, recorded as sealed snapshots (live_snapshot.h): the
	   conversion reads them back, here or on an analysis workstation. What is
	   interpretation — the owner's name of a process — is left to it. */
	/* First: the other observations and their conversion fall back on it
	   (time zone, code page) when the hives cannot be read. */
	printStep(Text::StepRunningMachine);
	hresult = snapshotRunningMachine();
	auditRecord(L"RUNNING MACHINE SETTINGS collection",
	            L"GetSystemDirectoryW, GetACP, GetTimeZoneInformation, FindFirstVolumeW, GetVolumeInformationW",
	            hresult, Footprint::SETTINGS);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else printSuccess();

	// Live observations switched off by the configuration are not made at all: no query, no trace.
	if (conf.artefacts.sessions) {
		printStep(Text::StepSessions);
		hresult = sessions.getData();
		auditRecord(L"SESSIONS collection", L"LSA / WTS", hresult, Footprint::SESSIONS);
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else {
			hresult = sessions.snapshot();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else printSuccess();
			sessions.clear();// free memory
		}
	}

	if (conf.artefacts.processes) {
		printStep(Text::StepProcesses);
		hresult = processes.getData();
		auditRecord(L"PROCESS collection", L"CreateToolhelp32Snapshot", hresult, Footprint::PROCESSES);
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else {
			hresult = processes.snapshot();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else printSuccess();
			processes.clear(); // free memory
		}
	}

	if (conf.artefacts.network) {
		printStep(Text::StepNetworkState);
		hresult = network.getData();
		auditRecord(L"NETWORK STATE collection",
		            L"iphlpapi: GetExtendedTcpTable, GetExtendedUdpTable, GetIpNetTable2, GetAdaptersAddresses, GetIpForwardTable2",
		            hresult, Footprint::NETWORK);
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else {
			hresult = network.snapshot();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else printSuccess();
			network.clear(); // free memory
		}
	}

	if (conf.artefacts.services) {
		printStep(Text::StepServiceStates);
		hresult = snapshotServiceStates();
		auditRecord(L"SERVICE STATES collection", L"EnumServicesStatusExW", hresult, Footprint::SCM);
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}


	printStep(Text::StepSystemClock);
	hresult = snapshotSystemClock();
	auditRecord(L"SYSTEM CLOCK collection",
	            L"GetSystemTimeAsFileTime, NtQuerySystemInformation(SystemTimeOfDayInformation), GetTickCount64",
	            hresult, Footprint::CLOCK);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else printSuccess();




	/* SERVICES has left this phase: the configuration is now read in
	   SYSTEM\CurrentControlSet\Services, hence after the hive is opened. Only
	   the current state is still read live, in a single enumeration.
	   See services.h. */




	// The event logs are handled AT THE END of the collection: they live on the
	// disk, so they are among the least volatile artefacts, and extracting them
	// takes about twenty minutes under Windows 11.
	// Putting them here delayed the raw copy of the disk by as much.
}

/*! Raw extraction of the system hives into the exhibit store and the
 *  working copy.
 * @return the result; a failure (the volume) stops the collection */
HRESULT extractSystemHives() {
	HRESULT hresult;
	/************************
	*  RAW EXTRACTION (offline, no VSS, output on the USB medium)
	*************************/
	printHeading(Text::HeadingRawExtraction);

	printStep(Text::StepSystemHives);
	log(3, L"🔈ExtractSystemHivesRaw");
	hresult = ExtractSystemHivesRaw();    // S_FALSE = some hives missing (tolerated)
	                                       // (recorded in the log by raw_collect)
	if (FAILED(hresult)) {                 // only a hard failure (the volume) stops the collection
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}
	return hresult;
}

/*! Raw extraction of the user hives and of the file artefacts (Prefetch,
 *  jump lists, recent documents, tasks, event logs). Requires the profile
 *  list, read from the SOFTWARE hive. */
void extractProfileArtefacts() {
	HRESULT hresult;
	printStep(Text::StepUserHives);
	log(3, L"🔈ExtractUserHivesRaw");
	if (!conf.artefacts.registry) writeConsole(text(Text::NotRequested, { L"artefacts.registry" }) + L"\n");
	else {
		hresult = ExtractUserHivesRaw();      // S_FALSE = no profile, or missing files (tolerated)
		if (FAILED(hresult)) printError(hresult);   // the other artefacts stay collectable
		else printSuccess();
	}

	// Prefetch, jump lists and recent documents: without this extraction their
	// collectors find no file and return an empty artefact, which reads wrongly
	// as an absence of traces.
	printStep(Text::StepFileArtefacts);
	log(3, L"🔈ExtractFileArtefactsRaw");
	hresult = ExtractFileArtefactsRaw();  // S_FALSE = some files unreadable (tolerated)
	                                       // (recorded per directory by raw_collect)
	/* A failure here must no longer stop the collection: the hives are already in
	   the exhibit store, and a `return` left them without a manifest or a seal.
	   The registry artefacts stay collectable. */
	if (FAILED(hresult)) printError(hresult);
	else printSuccess();

	// $MFT, change journal, $LogFile: the file system's timeline (read in place by the conversion).
	if (conf.artefacts.mft || conf.artefacts.usnJournal || conf.artefacts.logFile) {
		printStep(Text::StepNtfsMetadata);
		log(3, L"🔈ExtractNtfsMetadataRaw");
		hresult = ExtractNtfsMetadataRaw();   // S_FALSE = one could not be read (tolerated)
		if (FAILED(hresult)) printError(hresult);
		else printSuccess();
	}
}

/*! Loads the trust set of the key, which clears third-party signatures
 *  (--binary), and records what it is — or that there is none, and why: the
 *  third-party binaries are then all collected. Loaded before the first
 *  executable is read, so that one set judges them all. */
void loadTrustSet() {
	if (!conf.binary || conf.mode == RunMode::Convert) return;
	printStep(Text::StepTrustSet);
	const TrustSet& set = CollectionTrustSet();
	if (set.usable) {
		printSuccess();
		auto isoUtcDate = [](uint64_t filetime) {
			const FILETIME f = { (DWORD)filetime, (DWORD)(filetime >> 32) };
			return timeToIso8601Utc(f, Precision::Second);
		};
		std::wstring lists = L"authroot.stl of " + isoUtcDate(set.roots.thisUpdate) + L", disallowedcert.stl of "
		                   + isoUtcDate(set.disallowed.thisUpdate) + L", " + std::to_wstring(set.rootCertificates.size())
		                   + L" roots, " + std::to_wstring(set.driverHashes.size()) + L" vulnerable driver fingerprints, "
		                   + std::to_wstring(set.revocationLists.byUrl.size()) + L" revocation lists";
		for (const std::wstring& missing : set.driverListsMissing) lists += L"; driver list missing: " + missing;
		auditRecord(L"Trust set of " + set.createdUtc + L" (" + lists + L"; manifest SHA-256 " + set.manifestSha256
		            + L"): third-party signatures are checked against it", set.folder, S_OK, Footprint::TRUST_SET);
		return;
	}
	writeConsole(decodeText(set.reason, CP_UTF8) + L"\n");
	auditRecord(L"No usable trust set (" + decodeText(set.reason, CP_UTF8)
	            + L"): third-party binaries cannot be cleared, and are all collected",
	            set.folder, S_FALSE, Footprint::TRUST_SET);
}

/*! Closes the phase of the cited binaries: the volumes kept open to read them
 *  are closed, the phase is recorded and, in a full run, the collected
 *  exhibits are copied to the working directory — like any exhibit, even an
 *  unmodified one: that is the procedure. A --collect run records its
 *  collection itself (collectForConversion) and makes no working copy. */
void closeBinaries() {
	if (!conf.binary) return;
	BinariesFinish();
	if (conf.mode == RunMode::Collect) return;
	const BinarySummary b = BinariesSummary();
	std::wstring summary = std::to_wstring(b.files) + L" cited, " + std::to_wstring(b.read)
	                   + L" read, " + std::to_wstring(b.authenticated) + L" authenticated as Microsoft, "
	                   + std::to_wstring(b.thirdPartyCleared) + L" third-party cleared by their chain";
	if (conf.mode == RunMode::Full) {
		summary += L" and not collected (" + std::to_wstring(b.authenticatedBytes / 1024 / 1024)
		         + L" MiB saved), " + std::to_wstring(b.collectedCount) + L" collected ("
		         + std::to_wstring(b.collectedBytes / 1024 / 1024) + L" MiB)";
		if (b.duplicates) summary += L", " + std::to_wstring(b.duplicates) + L" duplicate content(s) not copied again";
		if (b.sansPlace) summary += L", " + std::to_wstring(b.sansPlace) + L" hashed without a copy, medium full";
	}
	summary += L"; signature catalogs: " + std::to_wstring(b.catalogsRead) + L" read into memory";
	if (conf.mode == RunMode::Full)
		summary += L", " + std::to_wstring(b.catalogsUsed) + L" recorded as exhibit(s)";
	if (conf.mode == RunMode::Convert) {
		auditRecord(L"Fingerprints of the files cited by the artefacts (" + summary + L")",
		            L"exhibit store of the collection, read-only; authenticity verified in memory "
		            L"with the collected catalogs; a file the collection does not hold has no fingerprint",
		            ERROR_SUCCESS, Footprint::EXHIBIT_READ);
		return;
	}
	auditRecord(L"Fingerprints of the files cited by the artefacts (" + summary + L")",
	            L"raw NTFS reading; authenticity verified in memory (Windows catalogs, "
	            L"embedded signatures), with no API and no service; unauthenticated binaries "
	            L"copied into " + exhibitStoreFolder(),
	            ERROR_SUCCESS, Footprint::VOLUME_BRUT);
	printStep(Text::StepCopyBinaries);
	size_t copies = 0;
	unsigned long long copiedBytes = 0;
	// What the conversion reads in place ($MFT, change journal) stays in the store.
	const HRESULT hrCopy = ExhibitStoreToWorking(&copies, &copiedBytes, true);
	auditRecord(L"Copy of the exhibit store into the working directory ("
	            + std::to_wstring(copies) + L" file(s), "
	            + std::to_wstring(copiedBytes / 1024 / 1024) + L" MiB)",
	            exhibitStoreFolder() + L" -> " + workingFolder(),
	            hrCopy, Footprint::USB_WRITE);
	if (FAILED(hrCopy)) printError(hrCopy);
	else printSuccess();
}

/*! Writes the manifest and its seal: the last operation on the exhibit store
 *  (see ExhibitStoreWriteManifest). */
void sealExhibitStore() {
	printStep(Text::StepSealExhibitStore);
	log(3, L"🔈ExhibitStoreWriteManifest");
	{
		size_t exhibits = 0, failures = 0;
		unsigned long long bytes = 0;
		ExhibitStoreSummary(&exhibits, &failures, &bytes);
		const HRESULT hrManifest = ExhibitStoreWriteManifest();
		auditRecord(L"Sealing of the exhibit store (" + std::to_wstring(exhibits)
		            + L" exhibit(s), " + std::to_wstring(failures) + L" failure(s), "
		            + std::to_wstring(bytes / 1024 / 1024) + L" MiB)",
		            exhibitStoreFolder() + L"\\MANIFEST.json (+ .sha256)",
		            hrManifest, Footprint::USB_WRITE);
		if (FAILED(hrManifest)) printError(hrManifest);
		else printSuccess();
	}
}

/*! --collect: what the conversion will need and only it can tell — the
 *  resource files of the event providers (--events) and the executables with
 *  the signature catalogs (--binary) —, taken now, whole, since which of them
 *  the artefacts cite is only known once they are converted. */
void collectForConversion() {
	printHeading(Text::HeadingForConversion);
	if (conf._events) {
		printStep(Text::StepEventResources);
		const HRESULT hr = MessagesCollectAll();
		size_t providers = 0, failures = 0;
		unsigned long long resolved = 0, bytes = 0;
		MessagesSummary(&providers, &failures, &resolved, &bytes);
		auditRecord(L"Raw extraction of the resource files of the event providers ("
		            + std::to_wstring(providers) + L" provider(s), " + std::to_wstring(failures)
		            + L" without usable resources, " + std::to_wstring(bytes / 1024 / 1024) + L" MiB)",
		            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers (copied hive); raw NTFS reading",
		            hr, Footprint::VOLUME_BRUT);
		MessagesRelease();
		if (FAILED(hr)) printError(hr);
		else printSuccess();
	}
	if (conf.binary) {
		printStep(Text::StepAllExecutables);
		const HRESULT hr = BinariesCollectAll();
		const BinarySummary b = BinariesSummary();
		auditRecord(L"Raw reading of the executables, libraries, drivers, scripts and macro documents ("
		            + std::to_wstring(b.read) + L" read, " + std::to_wstring(b.authenticated)
		            + L" authenticated as Microsoft in memory and fingerprinted only, "
		            + std::to_wstring(b.thirdPartyCleared) + L" third-party cleared by their chain and fingerprinted only, "
		            + std::to_wstring(b.collectedCount) + L" collected ("
		            + std::to_wstring(b.collectedBytes / 1024 / 1024) + L" MiB), "
		            + std::to_wstring(b.duplicates) + L" identical content(s) not copied again; "
		            + std::to_wstring(b.catalogsUsed) + L" signature catalog(s) recorded)",
		            L"every fixed NTFS volume, raw reading; authenticity verified in memory, with no API and no service",
		            hr, Footprint::VOLUME_BRUT);
		if (FAILED(hr)) printError(hr);
		else printSuccess();
	}
}

/*! Converts the artefacts into JSON, from the working copy: registry, files,
 *  event logs. Runs in a full run and under --convert; a --collect run stops
 *  before it (see RunMode).
 * @param systemAvailable the SYSTEM hive is open (conf.System) */
void convertArtefacts(bool systemAvailable) {
	HRESULT hresult;
	Services services;
	Usbstors usbs;
	MountedDevices mounteddevices;
	Bams bams;
	Muicaches muicaches;
	AmcacheApplications amcacheapplications;
	AmcacheApplicationFiles amcacheapplicationfiles;
	UserAssists userassists;
	Runs runs;
	Shimcaches shimcaches;
	Prefetchs prefetchs;
	Mft mft;
	UsnJournal usnJournal;
	RecentDocs recentdocs;
	Shellbags shellbags;
	Mrus mrus;
	MruApps mruapps;
	JumplistAutomatics jumplistAutomatics;
	JumplistCustoms jumplistCustoms;
	ScheduledTasks scheduledTasks;
	SystemInfo systemInfo;
	Users users;
	Events events;
	ORHKEY hKey = NULL;
	DWORD valueType = 0;
	DWORD size = 0;

	/* processes.json is published once the account names are loaded from the
	   hives, or at the latest before the event logs if the SYSTEM hive could
	   not be opened. */
	bool processesPending = true;
	auto writeProcesses = [&processesPending]() {
		if (!processesPending) return;
		processesPending = false;
		HRESULT written = ERROR_SUCCESS, sessionsWritten = ERROR_SUCCESS, networkWritten = ERROR_SUCCESS;
		const bool processesWanted = requested(conf.artefacts.processes, "processes.json", Text::ArtefactProcesses, L"artefacts.processes");
		const bool sessionsWanted = requested(conf.artefacts.sessions, "sessions.json", Text::ArtefactSessions, L"artefacts.sessions");
		const bool networkWanted = requested(conf.artefacts.network, "network.json", Text::ArtefactNetwork, L"artefacts.network");
		if (!processesWanted && !sessionsWanted && !networkWanted) return;
		printStep(Text::StepWriteLiveState);
		if (processesWanted) written = writeProcessesFromSnapshot();
		if (sessionsWanted) sessionsWritten = writeSessionsFromSnapshot();
		// The network last: its connections are named from the processes snapshot.
		if (networkWanted) networkWritten = writeNetworkFromSnapshot();
		if (written == ERROR_SUCCESS) written = sessionsWritten;
		if (written == ERROR_SUCCESS) written = networkWritten;
		if (written != ERROR_SUCCESS) printError(written);
		else printSuccess();
	};

	/************************
	*  REGISTRY
	*************************/

	printHeading(Text::HeadingRegistry);
	// A single entry for the whole phase: these reads bear on the COPIES extracted
	// onto the collection medium, never on the target's registry. They therefore
	// leave no trace to be told apart in the artefacts.
	auditRecord(L"Reading of the registry artefacts (copied hives, WAC's hive reader)",
	            conf.mountpoint, ERROR_SUCCESS, Footprint::HIVE_COPY);

	/* Registry phase bracketed by a single-exit block: a failure leaves it by
	   `break` instead of giving up the collection. The file artefacts and the
	   event logs, which do not depend on those hives, are still collected. */
	do {
	if (!systemAvailable) break;   // without SYSTEM, the registry phase is meaningless

	// find the ControlSet subkey that CurrentControlSet points to
	printStep(Text::StepFindControlSet);
	log(3, L"🔈OROpenKey System/Select");
	hresult = OROpenKey(conf.System, L"Select", &hKey);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		break;
	}
	hresult = ORGetValue(hKey, nullptr, L"Current", &valueType, nullptr, &size);
	if (hresult != ERROR_SUCCESS)
	{
		printError(hresult);
		break;
	}

	DWORD current = 0;

	log(3, L"🔈ORGetValue System/Select/Current");
	hresult = ORGetValue(hKey, nullptr, L"Current", &valueType, &current, &size);
	if (hresult != ERROR_SUCCESS)
	{
		printError(hresult);
		break;
	}
	else {

		// the ControlSet number is on 3 digits, of the form 001
		std::wstring controlSet;
		if ((int)(current) < 10) {
			controlSet = L"00" + std::to_wstring(current);
		}
		else if ((int)(current) < 100) {
			controlSet = L"0" + std::to_wstring(current);
		}
		else {
			controlSet = std::to_wstring(current);
		}
		// full name of the ControlSet key we are interested in
		std::wstring subkey = L"ControlSet" + controlSet;
		printSuccess();

		// open the HKLM\\SYSTEM\\CurrentControlSet key
		printStep(Text::StepOpenControlSet);
		log(3, L"🔈OROpenKey System/CurrentControlSet");
		hresult = OROpenKey(conf.System, subkey.c_str(), &conf.CurrentControlSet);
		if (hresult != ERROR_SUCCESS) {
			printError(hresult);
			break;
		}
		else {
			printSuccess();

			/* Time zone of the SUSPECT, read in his SYSTEM hive.
			   Done as soon as CurrentControlSet is opened: every local timestamp
			   formatted afterwards carries his offset, and not that of the
			   machine running WAC. Indispensable to interpret the artefacts that
			   store a local time (FAT dates, Amcache, BAM, shimcache, USBSTOR,
			   UserAssist). */
			printStep(Text::StepSuspectTimeZone);
			log(3, L"🔈loadSuspectTimeZone");
			hresult = loadSuspectTimeZone();
			if (hresult != ERROR_SUCCESS) {
				// Not blocking: falls back on the collecting machine's time zone,
				// which is right in a live collection since it is the same machine.
				printError(hresult);
			}
			else printSuccess();
			auditRecord(L"Reading of the suspect's time zone",
			            L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
			            hresult, Footprint::HIVE_COPY);

			/* ANSI code page of the SUSPECT, for the same reason: shortcuts,
			   shell items and DestList host names store text in the code page
			   of the machine that wrote them. */
			printStep(Text::StepSuspectCodePage);
			log(3, L"🔈loadSuspectAnsiCodePage");
			hresult = loadSuspectAnsiCodePage();
			if (hresult != ERROR_SUCCESS) printError(hresult);   // not blocking: the running machine's is used
			else printSuccess();
			auditRecord(L"Reading of the suspect's ANSI code page",
			            L"SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage",
			            hresult, Footprint::HIVE_COPY);

			/* Names of the SIDs, from the evidence only (SAM, well-known SIDs,
			   services, profiles): no LookupAccountSidW, which would query the
			   domain controller. Before any artefact that names an account. */
			printStep(Text::StepAccountNames);
			log(3, L"🔈loadAccountNames");
			hresult = loadAccountNames();
			if (hresult != ERROR_SUCCESS) printError(hresult);   // not blocking: the other sources are loaded
			else printSuccess();
			auditRecord(L"Offline naming of the SIDs",
			            L"SAM (Names indexes), SYSTEM (Services), SOFTWARE (ProfileList)",
			            hresult, Footprint::HIVE_COPY);

			writeProcesses();

			if (conf.artefacts.registry) {
			printStep(Text::StepUsbstor);
			hresult = usbs.getData();
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
				// The Enum\USBSTOR key is absent from the systems where no mass
				// storage device was ever plugged in: a legitimate failure, but
				// one that must appear in the output rather than leave a missing
				// file (see writeNotCollected).
				writeNotCollected("Usbstor.json", L"USBSTOR (registry)", hresult);
			}
			else {
				hresult = usbs.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				usbs.clear();
			}

			printStep(Text::StepMountedDevices);
			hresult = mounteddevices.getData();
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
			}
			else {
				hresult = mounteddevices.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mounteddevices.clear();
			}


			printStep(Text::StepBam);
			hresult = bams.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = bams.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				bams.clear();
			}

			printStep(Text::StepMuiCache);
			hresult = muicaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = muicaches.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				muicaches.clear();
			}

			printStep(Text::StepAmcacheApplications);
			hresult = amcacheapplications.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplications.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			printStep(Text::StepAmcacheApplicationFiles);
			hresult = amcacheapplicationfiles.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplicationfiles.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			printStep(Text::StepUserAssist);
			hresult = userassists.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = userassists.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				userassists.clear();
			}

			printStep(Text::StepRunKeys);
			hresult = runs.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = runs.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				runs.clear();
			}

			printStep(Text::StepShimcache);
			hresult = shimcaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shimcaches.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shimcaches.clear();
			}

			printStep(Text::StepShellbags);
			hresult = shellbags.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shellbags.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shellbags.clear();
			}

			printStep(Text::StepMru);
			hresult = mrus.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mrus.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mrus.clear();
			}

			printStep(Text::StepMruApps);
			hresult = mruapps.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mruapps.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mruapps.clear();
			}
			}   // artefacts.registry
		}
	}
	} while (0);   // end of the registry phase (see the single-exit block above)
	if (!conf.artefacts.registry) {
		const std::pair<const char*, Text> REGISTRY[] = {
			{ "Usbstor.json", Text::ArtefactUsbDevices }, { "mounted_device.json", Text::ArtefactMountedDevices },
			{ "bams.json", Text::ArtefactBam }, { "muicache.json", Text::ArtefactMuiCache },
			{ "amcache_applications.json", Text::ArtefactAmcacheApplications },
			{ "amcache_application_files.json", Text::ArtefactAmcacheApplicationFiles },
			{ "userassists.json", Text::ArtefactUserAssist }, { "run.json", Text::ArtefactRunKeys },
			{ "shimcache.json", Text::ArtefactShimcache }, { "shellbags.json", Text::ArtefactShellbags },
			{ "mrus.json", Text::ArtefactMru }, { "mruApps.json", Text::ArtefactMruApps },
		};
		for (const auto& [file, label] : REGISTRY) requested(false, file, label, L"artefacts.registry");
	}

	/* SYSTEM INFORMATION, offline.
	   OUTSIDE the single-exit block above, and not inside it: even without a
	   usable hive the collector stays useful, since it records the instant of the
	   collection and the uptime. It degrades its output instead of being
	   skipped. */
	printStep(Text::StepSystemInformation);
	hresult = systemInfo.getData();
	auditRecord(L"SYSTEM INFORMATION collection",
	            L"extracted SYSTEM and SOFTWARE hives + system time",
	            hresult, Footprint::HIVE_COPY);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = systemInfo.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		systemInfo.clear();// free memory
	}

	/* SERVICES, offline configuration + current state.
	   Also outside the single-exit block: without a hive, getData() fails
	   cleanly and writeNotCollected has already recorded the absence. */
	if (requested(conf.artefacts.services, "services.json", Text::ArtefactServices, L"artefacts.services")) {
	printStep(Text::StepServices);
	hresult = services.getData();
	auditRecord(L"SERVICES collection",
	            L"SYSTEM\\CurrentControlSet\\Services hive + EnumServicesStatusExW",
	            hresult, Footprint::SCM);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = services.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		services.clear();//free memory
	}
	}   // artefacts.services

	/* USERS, offline from the SAM hive. Independent of the SYSTEM and SOFTWARE
	   hives: it opens its own. */
	if (requested(conf.artefacts.registry, "users.json", Text::ArtefactUsers, L"artefacts.registry")) {
	printStep(Text::StepUsers);
	hresult = users.getData();
	auditRecord(L"USERS collection", L"extracted SAM hive", hresult, Footprint::HIVE_COPY);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		writeNotCollected("users.json", L"depends on the SAM hive, which is unavailable", hresult);
	}
	else {
		hresult = users.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		users.clear(); // free memory
	}
	}   // artefacts.registry


	/************************
	*  FILES
	*************************/
	printHeading(Text::HeadingFiles);
	// As for the registry: the COPIES extracted are read, not the target's files —
	// so no access timestamp is changed on the examined system.
	auditRecord(L"Reading of the file artefacts (extracted copies)",
	            conf.mountpoint, ERROR_SUCCESS, Footprint::HIVE_COPY);
	/* Scheduled tasks: read from the XML files extracted raw and from the
	   registry's TaskCache. Moved from the "WINDOWS API" phase to here, since
	   the collection now depends on the raw extraction — no longer on the
	   Schedule service. */
	if (requested(conf.artefacts.scheduledTasks, "ScheduledTasks.json", Text::ArtefactScheduledTasks, L"artefacts.scheduled_tasks")) {
	printStep(Text::StepScheduledTasks);
	hresult = scheduledTasks.getData();
	auditRecord(L"SCHEDULED TASKS collection",
	            L"\\Windows\\System32\\Tasks (XML) + SOFTWARE\\...\\TaskCache",
	            hresult, Footprint::HIVE_COPY);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		writeNotCollected("ScheduledTasks.json",
		                  L"task definitions not extracted", hresult);
	}
	else {
		hresult = scheduledTasks.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		scheduledTasks.clear(); // free memory
	}
	}   // artefacts.scheduled_tasks

	if (requested(conf.artefacts.recentDocuments, "recentdocs.json", Text::ArtefactRecentDocuments, L"artefacts.recent_documents")) {
	printStep(Text::StepRecentDocuments);
	hresult = recentdocs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = recentdocs.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		recentdocs.clear();
	}
	}   // artefacts.recent_documents

	if (requested(conf.artefacts.prefetch, "prefetchs.json", Text::ArtefactPrefetch, L"artefacts.prefetch")) {
	printStep(Text::StepPrefetch);
	hresult = prefetchs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = prefetchs.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		prefetchs.clear();
	}
	}   // artefacts.prefetch

	/* The $MFT is loaded once for both artefacts: the change journal names
	   its files through it. */
	const bool mftWanted = requested(conf.artefacts.mft, "mft.json", Text::ArtefactMft, L"artefacts.mft");
	const bool usnWanted = requested(conf.artefacts.usnJournal, "usn_journal.json", Text::ArtefactUsnJournal, L"artefacts.usn_journal");
	if (mftWanted || usnWanted) {
	printStep(Text::StepReadMft);
	hresult = mft.getData();
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		if (mftWanted) writeNotCollected("mft.json", L"$MFT", hresult);
	}
	else {
		printSuccess();
		if (mftWanted) {
			printStep(Text::StepWriteMft);
			hresult = mft.toJson();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else printSuccess();
		}
	}
	if (usnWanted) {
		printStep(Text::StepUsnJournal);
		hresult = usnJournal.getData();
		if (hresult != ERROR_SUCCESS) {
			printError(hresult);
			writeNotCollected("usn_journal.json", L"Change journal ($UsnJrnl:$J)", hresult);
		}
		else {
			hresult = usnJournal.toJson(mft);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else printSuccess();
			usnJournal.clear();
		}
	}
	mft.clear();
	}   // artefacts.mft, artefacts.usn_journal

	if (requested(conf.artefacts.jumpLists, "jumplistAutomaticDestinations.json", Text::ArtefactJumpListsAutomatic, L"artefacts.jump_lists")) {
	printStep(Text::StepJumpListsAutomatic);
	hresult = jumplistAutomatics.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistAutomatics.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		jumplistAutomatics.clear();
	}
	}   // artefacts.jump_lists

	if (requested(conf.artefacts.jumpLists, "jumplistCustomDestinations.json", Text::ArtefactJumpListsCustom, L"artefacts.jump_lists")) {
	printStep(Text::StepJumpListsCustom);
	hresult = jumplistCustoms.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistCustoms.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		jumplistCustoms.clear();
	}
	}   // artefacts.jump_lists
	convertFileArtefact<PowerShellHistories>(conf.artefacts.powershellHistory, "powershell_history.json",
	                                         Text::ArtefactPowerShellHistory, L"artefacts.powershell_history",
	                                         Text::StepPowerShellHistory);
	convertFileArtefact<SetupApiLogs>(conf.artefacts.setupApi, "setupapi.json", Text::ArtefactSetupApi,
	                                  L"artefacts.setupapi", Text::StepSetupApi);
	convertFileArtefact<RecycleBin>(conf.artefacts.recycleBin, "recycle_bin.json", Text::ArtefactRecycleBin,
	                                L"artefacts.recycle_bin", Text::StepRecycleBin);
	convertFileArtefact<HostsFile>(conf.artefacts.hosts, "hosts.json", Text::ArtefactHosts,
	                               L"artefacts.hosts", Text::StepHosts);
	convertFileArtefact<ErrorReports>(conf.artefacts.errorReports, "error_reports.json", Text::ArtefactErrorReports,
	                                  L"artefacts.error_reports", Text::StepErrorReports);
	convertFileArtefact<DefenderLogs>(conf.artefacts.defender, "defender_log.json", Text::ArtefactDefenderLogs,
	                                  L"artefacts.defender", Text::StepDefenderLogs);
	convertFileArtefact<StartupFolders>(conf.artefacts.startupFolders, "startup_folders.json",
	                                    Text::ArtefactStartupFolders, L"artefacts.startup_folders",
	                                    Text::StepStartupFolders);
	writeProcesses();   // if the names could not be loaded (SYSTEM hive unreadable)

	/************************
	*  EVENT LOGS (the least volatile: handled last)
	*************************/
	if (conf._events) {
		printHeading(Text::HeadingEventLogs);
		printStep(Text::StepEvents);

		hresult = events.getData();
		/* The source is no longer the EventLog service but the .evtx files extracted
		   by raw reading: the record must say which ones, otherwise the report
		   lets one believe the API was solicited again. */
		auditRecord(L"EVENT LOGS collection (" + std::to_wstring(events.read)
		            + L" event(s) in " + std::to_wstring(events.files)
		            + L" log(s))",
		            L"\\Windows\\System32\\winevt\\Logs\\*.evtx (extracted copies)",
		            hresult, Footprint::FILE_COPY);
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else {
			hresult = events.toJson();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else printSuccess();
			events.clear(); // free memory
		}
	}

}

/*! Runs a collection.
 *  wmain: the runtime hands the arguments in UTF-16, as Windows holds them —
 *  CommandLineToArgvW (shell32) is no longer needed for that.
 * @param argc,argv the command line (see showHelp())
 * @return 0 once the collection has run to the end, an error code otherwise */
int wmain(int argc, wchar_t* argv[])
{
	HRESULT hresult;

	time_t start = 0, end = 0;

	/************************
	* useful functions
	*************************/
	//ASCII ART
	SetConsoleOutputCP(CP_UTF8); // UTF-8, so that accented characters come out right in the console

	/* UNBUFFERED output.
	 * wprintf goes through a buffer, whereas SetConsoleTextAttribute (colours)
	 * acts at once: the text therefore came out out of step with its colour and
	 * with the progress display, which does force an fflush. One saw "OK" then
	 * the label of the step, in the wrong order.
	 * Step labels are written without a newline, waiting for their "OK": a line
	 * buffer would therefore not be enough. */
	setvbuf(stdout, NULL, _IONBF, 0);

	system("cls");//clear screen

	log(3, L"🔈asciiart");
	asciiart();

	start = time(nullptr);// start time of the program, for the benchmark

	/************************
	* Arguments
	*************************/

	conf.name = argv[0];
	/* The arguments in UTF-16: through a narrow `argv` they were converted to
	   the process's ANSI code page, and an output directory whose name the
	   code page cannot represent was lost. */
	const std::vector<std::wstring> commandLine(argv, argv + argc);
	/* THE LANGUAGE first: every message, refusals included, is shown in it.
	   --language= is read before anything else; without it, the configuration
	   file's `language:` decides once read, and French until then. */
	bool languageGiven = false;
	for (size_t i = 1; i < commandLine.size(); ++i) {
		if (commandLine[i].substr(0, 11) != L"--language=") continue;
		if (!languageFromCode(commandLine[i].substr(11), conf.language)) {
			printError(text(Text::InvalidLanguage, { commandLine[i].substr(11) }));
			return 1;
		}
		languageGiven = true;
	}
	setLanguage(conf.language);
	/* --update-trust runs ALONE, on the analysis workstation: it is not a
	   collection — no investigation log, no elevation — and the only mode of
	   WAC that uses the network. Combined with anything, it is refused: a
	   collection that would download would reach the network from the examined
	   machine. */
	for (size_t i = 1; i < commandLine.size(); ++i) {
		const std::wstring& arg = commandLine[i];
		if (arg != L"--update-trust" && arg.substr(0, 15) != L"--update-trust=") continue;
		// Alone, the choice of the language apart.
		if (commandLine.size() != (languageGiven ? 3u : 2u) || arg == L"--update-trust=") {
			printError(text(Text::UpdateTrustAlone));
			showHelp();
			return 1;
		}
		return UpdateTrust(arg.size() > 15 ? arg.substr(15) : DefaultTrustFolder());
	}
	/* THE CONFIGURATION FILE first (see config.h), the command line after:
	   an option given overrides the file. --write-config writes the reference
	   file, commented, and stops; --config=<file> reads another one. */
	std::wstring configurationPath = DefaultConfigurationPath();
	for (size_t i = 1; i < commandLine.size(); ++i) {
		if (commandLine[i] == L"--write-config") {
			std::error_code ec;
			if (std::filesystem::exists(configurationPath, ec)) {
				printError(text(Text::ConfigurationExists, { configurationPath }));
				return 1;
			}
			const std::string reference = DefaultConfiguration();
			if (reference.empty()) { printError(text(Text::ReferenceConfigurationMissing)); return 1; }
			std::ofstream out(std::filesystem::path(configurationPath), std::ios::binary);
			out << reference;
			if (!out) { printError(text(Text::FileNotWritten, { configurationPath })); return 1; }
			writeConsole(text(Text::FileWritten, { configurationPath }) + L"\n");
			return 0;
		}
		if (commandLine[i].substr(0, 9) == L"--config=" && commandLine[i].size() > 9) configurationPath = commandLine[i].substr(9);
	}
	ConfigurationFile configuration;
	{
		std::string error;
		const Language chosen = conf.language;
		if (!LoadConfiguration(configurationPath, conf, configuration, error)) {
			printError(configurationPath + L": " + decodeText(error, CP_UTF8));
			return 1;
		}
		// The command line overrides the file, as for every other setting.
		if (languageGiven) conf.language = chosen;
		setLanguage(conf.language);
	}
	bool collect = conf.mode == RunMode::Collect, outputGiven = false;
	std::wstring convertFolder;
	if (commandLine.size() > 1) { // at least one argument, the first being the program's own name
		// command-line arguments
		for (size_t i = 1; i < commandLine.size(); ++i) {
			const std::wstring& arg = commandLine[i];

			if (arg == L"--debug") conf._debug = true;
			else if (arg == L"--dump") conf._dump = true;
			else if (arg == L"--events") conf._events = true;
			else if (arg == L"--binary") conf.binary = true;
			else if (arg == L"--binary-all") conf.binary = conf.binaryAll = true;
			else if (arg.substr(0, 10) == L"--threads=") {
				try {
					const int threads = std::stoi(arg.substr(10));
					if (threads < 1 || threads > 256) throw std::out_of_range("threads");
					conf.threads = (unsigned)threads;
				}
				catch (...) {
					printError(text(Text::InvalidThreads, { arg }));
					showHelp();
					exit(1);
				}
			}
			else if (arg == L"--collect") collect = true;
			else if (arg.substr(0, 9) == L"--config=") continue;         // read above
			else if (arg.substr(0, 11) == L"--language=") continue;      // read above
			else if (arg == L"--full") collect = false;                    // the file said collect only: not this time
			else if (arg.substr(0, 10) == L"--convert=" && arg.size() > 10) convertFolder = arg.substr(10);
			else if (arg.substr(0, 9) == L"--output=") {
				outputGiven = true;
				std::wstring temp = arg.substr(9);
				if (temp.length() > 0) conf._outputDir = temp;
				else {
					printError(text(Text::InvalidOutput, { arg }));
					log(3, L"🔈showHelp");
					showHelp();
					exit(1);
				}
				if (conf._outputDir.find(L"\\") != std::wstring::npos) {
					printError(text(Text::InvalidOutputCharacter, { arg }));
					log(3, L"🔈showHelp");
					showHelp();
					exit(1);
				}
			}
			else if (arg.substr(0, 11) == L"--loglevel=") {
				std::wstring temp = arg.substr(11);
				try {
					conf.loglevel = std::stoi(temp);
				}
				catch (...)
				{
					printError(text(Text::InvalidLogLevel, { arg }));
					log(3, L"🔈showHelp");
					showHelp();
					exit(1);
				}
			}

			else { // unknown argument
				if (arg != L"--help" && arg != L"/?") { // anything that is neither --help nor /? is an invalid argument
					printError(text(Text::InvalidArgument, { arg }));
				}
				log(3, L"🔈showHelp");
				showHelp();
				exit(1);
			}
		}
	}

	/* The mode. A conversion reads a collection and writes next to it: the
	   collection's folder IS its output, hence --output makes no sense with it. */
	if (!convertFolder.empty()) {
		if (collect || outputGiven) {
			printError(text(Text::ConvertExcludesCollect));
			showHelp();
			exit(1);
		}
		conf.mode = RunMode::Convert;
		conf._outputDir = convertFolder;
	}
	else conf.mode = collect ? RunMode::Collect : RunMode::Full;   // the file's convert:, unless --collect or --full

	// Investigation log: opened as early as possible, so that the start timestamp
	// really brackets the whole collection (see audit.h).
	auditInit(commandLine);
	auditConfiguration(configurationPath, configuration.present, configuration.sha256, configuration.text);

	/* Trace of the NTFS parser: SILENT by default, turned on by --debug.
	   It writes to STDERR, hence separable from the normal output:
	   WAC.exe --debug 2> raw.log
	   It is what allowed the split `$INDEX_ALLOCATION` defect to be located; in
	   ordinary use it would drown the console. */
	RawHiveSetVerbose(conf._debug);

	// System drive: read before any extraction, since it decides which volume is
	// read raw AND how the original paths are restored. Windows is not always
	// installed on C:.
	// Under --convert, the examined machine's is read from its snapshot (prepareConversion).
	if (conf.mode != RunMode::Convert) {
		log(3, L"🔈loadSystemDrive");
		loadSystemDrive();
	}

	/************************
	* Prerequisites
	*************************/

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Prerequisites :");
	log(0, L"*******************************************************************************************************************");

	log(1, L"➕Check OS");
	printHeading(Text::HeadingPrerequisites);
	printStep(Text::StepWindowsVersion);
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	printSuccess();
#else
	printError(ERROR_APP_WRONG_OS);
	return 1;
#endif
	if (conf.mode != RunMode::Convert) {
		const int refused = checkElevation();
		if (refused) return refused;
	}

	/* COM DROPPED (2026-09-15).
	 * `scheduledTasks` was the ONLY consumer of COM in WAC: it now reads the XML
	 * definitions of \Windows\System32\Tasks and the TaskCache history, offline.
	 * Nothing justified CoInitializeEx / CoInitializeSecurity any more, and
	 * dropping them removes:
	 *   - the Schedule service being solicited;
	 *   - the entries in Microsoft-Windows-TaskScheduler/Operational;
	 *   - the COM walk task by task (several interface calls x 217).
	 * The other live collectors (processes, sessions, services, users,
	 * systemInfo) use direct Win32 API calls only.
	 */

	/************************
	*  COLLECTION LOCATION, checked BEFORE the very first write
	*************************/
	/* Two refusals, both preferable to a collection that goes wrong midway: a
	   working directory already populated would have a previous collection
	   analysed, and a medium too small would give truncated copies.
	   Checked HERE and no longer at the start of the raw extraction: with
	   --binary, the first write is the collection of a process's executable, in
	   the very next phase. The estimate is deliberately rough — hives, event
	   logs and cited binaries when they are asked for; it does not have to be
	   right, only to rule out a manifestly insufficient medium. Running out of
	   space during the collection does not fail it: the binaries are then hashed
	   without being copied.
	   A conversion writes no exhibit: it checks the collection instead. */
	{
		const HRESULT refused = conf.mode == RunMode::Convert ? prepareConversion() : checkCollectionLocation();
		if (FAILED(refused)) {
			// A refused conversion leaves its log, which says why.
			if (conf.mode == RunMode::Convert && auditWrite() != ERROR_SUCCESS) printError(text(Text::ConversionLogNotWritten));
			return refused;
		}
	}

	loadTrustSet();
	if (conf.mode != RunMode::Convert) observeLiveState();

	if (conf.mode != RunMode::Convert) {
		hresult = extractSystemHives();
		if (FAILED(hresult)) return hresult;
	}

	/* The SYSTEM and SOFTWARE hives are opened ON the first pass: SOFTWARE gives
	   the list of profiles, without which the per-user hives cannot be
	   extracted. */

	// load the HKLM\SYSTEM key
	printStep(Text::StepOpenSystemHive);
	std::wstring systemHive = conf.mountpoint + L"\\Windows\\system32\\config\\SYSTEM";
	/* An unavailable hive must NOT stop the collection.
	   Seen on a real system: SOFTWARE could not be extracted, and the `return`
	   that followed gave up everything — including SYSTEM's artefacts, the files
	   and the event logs, all of them collectable. The principle is to gather
	   everything reachable and to record what is missing. */
	log(3, L"🔈OROpenHive System");
	hresult = OROpenHive(systemHive.c_str(), &conf.System);
	const bool systemAvailable = (hresult == ERROR_SUCCESS);
	if (!systemAvailable) {
		printError(hresult);
		log(2, L"🔥SYSTEM hive unavailable: the artefacts that depend on it are not collected", hresult);
		auditRecord(L"Opening of the SYSTEM hive", systemHive, hresult, Footprint::HIVE_COPY);
		if (conf.mode != RunMode::Collect)      // --collect converts nothing
		for (const char* f : { "Usbstor.json", "mounted_device.json", "bams.json",
		                       "shimcache.json", "services.json" })
			writeNotCollected(f, L"depends on the SYSTEM hive, which is unavailable", hresult);
	}
	else printSuccess();

	// load the HKLM\SOFTWARE key
	printStep(Text::StepOpenSoftwareHive);
	std::wstring softwareHive = conf.mountpoint + L"\\Windows\\system32\\config\\SOFTWARE";
	log(3, L"🔈OROpenHive Software");
	hresult = OROpenHive(softwareHive.c_str(), &conf.Software);
	const bool softwareAvailable = (hresult == ERROR_SUCCESS);
	if (!softwareAvailable) {
		printError(hresult);
		log(2, L"🔥SOFTWARE hive unavailable: the artefacts that depend on it are not collected", hresult);
		auditRecord(L"Opening of the SOFTWARE hive", softwareHive, hresult, Footprint::HIVE_COPY);
		if (conf.mode != RunMode::Collect)
			writeNotCollected("run.json", L"depends on the SOFTWARE hive, which is unavailable", hresult);
	}
	else printSuccess();

	/* USER PROFILES, OFFLINE. The list is read in the SOFTWARE hive just opened,
	   and no longer in the live registry: that is what makes the hives be
	   extracted in two passes. See raw_collect.h. */
	printStep(Text::StepUserProfiles);
	log(3, L"🔈loadProfileList");
	hresult = loadProfileList();
	auditRecord(L"Reading of the user profiles",
	            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList (copied hive, WAC's hive reader)",
	            hresult, Footprint::HIVE_COPY);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else printSuccess();

	if (conf.mode != RunMode::Convert) extractProfileArtefacts();

	if (conf.mode == RunMode::Collect) collectForConversion();
	else convertArtefacts(systemAvailable);

	printHeading(Text::HeadingExhibitStore);
	/************************
	*  SEALING OF THE EXHIBIT STORE (after the LAST exhibit added)
	*************************/
	/* The manifest must cover every exhibit, and it seals the store. Without it
	   the raw copies are identified by nothing, and the procedure is worth no
	   more than a plain directory of files.
	
	   WHAT WAS WRONG. It was written at the end of the raw extraction phase. But
	   exhibits enter the store AFTER that: the resource binaries of the event
	   providers, extracted on demand during the event-log phase. Seen in a VM:
	   121 binaries (~121 MiB) present in the exhibit store and absent from the sealed
	   manifest — exhibits that nothing identified. The suspect's time zone was
	   also recorded there as "not read", the SYSTEM hive being read only
	   afterwards. Sealing is therefore the last operation on the store, just
	   before the investigation log. */
	closeBinaries();
	// Under --convert the exhibit store is only read: its seal stays the collection's.
	if (conf.mode != RunMode::Convert) sealExhibitStore();

	/************************
	*  INVESTIGATION LOG (last: it records the whole collection)
	*************************/
	printHeading(Text::HeadingInvestigationLog);
	/* WRITING to the collection medium is itself an operation to record: it is
	   the only write WAC performs, and an audit log that does not mention it
	   lets one believe nothing was written. Recorded BEFORE auditWrite(),
	   without which it would be missing from the log. */
	auditRecord(L"Writing of the collection results",
	            conf._outputDir, ERROR_SUCCESS,
	            Footprint::USB_WRITE);

	printStep(conf.mode == RunMode::Convert ? Text::StepWriteConversionLog : Text::StepWriteInvestigationLog);
	log(3, L"🔈auditWrite");
	hresult = auditWrite();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else printSuccess();

	end = time(nullptr);

	writeConsole(text(Text::TimeElapsed, { std::to_wstring(end - start) }) + L"\n");
	writeConsole(text(Text::PressAnyKey) + L"\n");
	getchar();
	CloseHandle(conf.hConsole);

	return ERROR_SUCCESS;
}