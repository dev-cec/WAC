/*! \file
 *  \brief Collection of the running processes, their owners and their modules (see processes.h).
 */
#include "processes.h"
#include "live_snapshot.h"

#include <wtsapi32.h>
/* PSAPI_VERSION 1: EnumProcessModules and GetModuleFileNameExW from psapi.dll,
   which every Windows has since XP. Version 2, the default for Windows 7 and
   later, names them K32… in kernel32.dll, absent from XP: WAC32 would not load. */
#define PSAPI_VERSION 1
#include <psapi.h>

namespace {

/*! Reads the owner's SID and the session of ALL the processes, in one call,
* without opening any process handle.
*
* `WTSEnumerateProcessesW` queries the Terminal Services service, already
* solicited by `sessions`. It returns the SID even for the protected processes
* that `OpenProcess` refuses — including lsass, services.exe and Defender's
* processes, whose impersonation is precisely what an investigation looks for.
*
* @param byPid receives, for each PID, the SID and the session identifier
* @return ERROR_SUCCESS if the enumeration succeeded
*/
HRESULT readOwners(std::map<DWORD, std::pair<std::wstring, DWORD>>& byPid) {
	/* WTSEnumerateProcessesW, not its "Ex" successor: the same rows —
	   session, PID, name, SID, for every session — and it exists since
	   Windows XP, where the Ex one came with Windows 7: imported, that one
	   kept a 32-bit WAC from linking, and would keep it from loading under XP
	   and Vista. */
	PWTS_PROCESS_INFOW infos = NULL;
	DWORD count = 0;
	log(3, L"🔈WTSEnumerateProcessesW");
	if (!WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &infos, &count)) {
		const HRESULT error = GetLastError();
		log(2, L"🔥WTSEnumerateProcessesW: owners not read", error);
		return error;
	}

	for (DWORD i = 0; i < count; ++i) {
		std::wstring sid;
		if (infos[i].pUserSid) {
			log(3, L"🔈sidToText");
			if (IsValidSid(infos[i].pUserSid))
				sid = sidToText(static_cast<const BYTE*>(infos[i].pUserSid), GetLengthSid(infos[i].pUserSid));
			else
				log(2, L"🔥sidToText: invalid SID", ERROR_INVALID_SID);
		}
		/* An empty SID is a fact, not a failure: the purely kernel processes
		   (System, Registry) have no user token. The session, for its part, is
		   always returned. */
		byPid[infos[i].ProcessId] = { sid, infos[i].SessionId };
	}
	log(2, L"❇️Owners read for " + std::to_wstring(byPid.size()) + L" processes");
	log(3, L"🔈WTSFreeMemory");
	WTSFreeMemory(infos);
	return ERROR_SUCCESS;
}

} // namespace

Process::Process(const PROCESSENTRY32W* pe32) {
	processName        = pe32->szExeFile;
	processId          = pe32->th32ProcessID;
	processParentId    = pe32->th32ParentProcessID;
	processThreadCount = pe32->cntThreads;

	log(2, L"❇️Process Name : " + processName + L" (PID " + std::to_wstring(processId) + L")");

	/* PID 0 — THE TRAP NOT TO REPRODUCE.
	   The Toolhelp module snapshot once used here read PID 0 as "the CURRENT
	   PROCESS": the Idle process was credited with the 25 modules of WAC.exe
	   itself, WAC.exe first, and an investigation report stated that the system
	   process had loaded the collection tool. The Idle process has neither an
	   image nor a module: it is not asked. */
	if (processId == 0) {
		processModulesAccess = L"Idle process: no module by nature";
		return;
	}

	/* The modules are read independently of the owner. In the original version, a
	   failure to read the token caused a `return` before this call: the 16
	   protected processes therefore also came out with NO module at all, while
	   the module list does not depend on the token. */
	log(3, L"🔈ListProcessModules");
	const HRESULT result = ListProcessModules();
	if (result != ERROR_SUCCESS)
		log(2, L"🔥ListProcessModules : ", result);
}

/*! The modules of the process, through a handle opened with the least the
 *  listing needs.
 *
 *  WHY NOT TOOLHELP ANY MORE. `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`
 *  opens the process itself, inside kernel32, with every right it can get:
 *  measured under Sysmon (event 10) on Windows 11, 42 processes of the session
 *  opened with 0x1FFFFF, PROCESS_ALL_ACCESS — the footprint processes.h
 *  explains WAC gave up, asked for by the API in its place. Reading the module
 *  list needs PROCESS_QUERY_INFORMATION and PROCESS_VM_READ (0x410), nothing
 *  more: no write, no thread, no injection right. A protected process (lsass
 *  under LSA protection, services, csrss, Defender) refuses it, as it refused
 *  Toolhelp; the refusal is recorded.
 *
 *  The modules are those of the process's own bitness, as Toolhelp gave them
 *  (LIST_MODULES_DEFAULT): the same list as before, for each process. */
HRESULT Process::ListProcessModules() {
	log(3, L"🔈OpenProcess (query, memory read)");
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (!process) {
		// Taken once: log() opens its file, which sets another error.
		const DWORD error = GetLastError();
		processModulesAccess = getErrorMessage(error);
		log(2, L"🔥OpenProcess (query, memory read)", error);
		return ERROR_INVALID_HANDLE;
	}

	/* The list, as large as the process says it is. A process that is starting
	   or loading a library answers ERROR_PARTIAL_COPY while its loader list
	   moves: asked again, a few times, as Toolhelp did. */
	std::vector<HMODULE> modules(256);
	DWORD needed = 0;
	DWORD error = ERROR_SUCCESS;
	for (int attempt = 0; attempt < 4; ++attempt) {
		const DWORD bytes = (DWORD)(modules.size() * sizeof(HMODULE));
		log(3, L"🔈EnumProcessModules");
		if (!EnumProcessModules(process, modules.data(), bytes, &needed)) {
			error = GetLastError();
			if (error == ERROR_PARTIAL_COPY) continue;
			break;
		}
		error = ERROR_SUCCESS;
		if (needed <= bytes) break;
		modules.resize(needed / sizeof(HMODULE));   // grown: asked again
		error = ERROR_INSUFFICIENT_BUFFER;
	}
	if (error != ERROR_SUCCESS) {
		processModulesAccess = getErrorMessage(error);
		log(2, L"🔥EnumProcessModules", error);
		CloseHandle(process);
		return ERROR_INVALID_HANDLE;
	}
	modules.resize(needed / sizeof(HMODULE));

	/* Each module's path, bounded by the buffer: a path past MAX_PATH is held
	   by the extended length of the API (32 767 characters). */
	std::vector<wchar_t> path(32768);
	for (size_t i = 0; i < modules.size(); ++i) {
		log(3, L"🔈GetModuleFileNameExW");
		const DWORD length = GetModuleFileNameExW(process, modules[i], path.data(), (DWORD)path.size());
		if (length == 0) {
			log(2, L"🔥GetModuleFileNameExW", GetLastError());   // unloaded meanwhile: left out
			continue;
		}
		std::wstring name(path.data(), length);
		// The first module is the executable.
		if (i == 0 && conf.binary) {
			log(3, L"🔈FingerprintFile");
			fingerprint = FingerprintFile(name);
		}
		log(2, L"❇️Module exePath : " + name);
		processModules.push_back(std::move(name));
	}
	CloseHandle(process);
	return ERROR_SUCCESS;
}

Json Process::toJson() const {
	log(3, L"🔈process toJson");
	Json o = Json::obj();
	// "Nom" was the only key in French of the whole output, among SID, Owner,
	// ProcessId… One single language for the keys (naming pass).
	o.add(L"Name",           Json::str(processName));
	addFingerprints(o, fingerprint);
	// The owner's NAME is added by the conversion (writeProcessesFromSnapshot),
	// from the hives: the snapshot keeps what was observed, the SID.
	o.add(L"SID",            Json::str(processSID));
	/* Harmonised naming (naming pass): `PID` and `PPId` coexisted in the SAME
	   object with two case conventions, and `services.json` called the same
	   notion `ProcessId`. One spelling for one notion, explicit like
	   `SessionId`. */
	o.add(L"ProcessId",       Json::num(processId));
	o.add(L"ParentProcessId", Json::num(processParentId));
	o.add(L"ThreadCount",    Json::num(processThreadCount));   // was parsed but never emitted
	// Makes it possible to tie a process to an entry of Sessions.json.
	if (sessionKnown) o.add(L"SessionId", Json::num(sessionId));
	/* Carries ONLY the error of the module reading. It used to carry the token's
	   too, so that an access denied on the process showed up here as a problem
	   with the modules. */
	o.add(L"ModulesMessage", Json::str(processModulesAccess));
	Json modules = Json::arr();
	for (const std::wstring& m : processModules) modules.push(Json::str(m));
	o.add(L"Modules", std::move(modules));
	return o;
}

void Process::clear() {
	log(3, L"🔈process clear");
}

HRESULT Processes::getData() {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Processes : ");
	log(0, L"*******************************************************************************************************************");

	// Take a snapshot of all processes in the system.
	log(3, L"🔈CreateToolhelp32Snapshot");
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		log(2, L"🔥CreateToolhelp32Snapshot (of processes)", GetLastError());
		return ERROR_INVALID_HANDLE;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	log(3, L"🔈Process32First");
	if (!Process32First(hProcessSnap, &pe32))
	{
		log(2, L"🔥Process32First", GetLastError());// show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return ERROR_INVALID_HANDLE;
	}
	/* Process32Next does not give the number of processes in advance, which
	   deprived the progress display of its percentage. They are therefore
	   counted first, by a first walk of the SAME snapshot: it is already in
	   memory and that pass opens no handle and reads no module, so its cost is
	   negligible next to the collection itself. */
	unsigned long long totalProcess = 0;
	do { ++totalProcess; } while (Process32Next(hProcessSnap, &pe32));

	// Back to the start of the snapshot for the real collection.
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		log(2, L"🔥Process32First (2nd pass)", GetLastError());
		CloseHandle(hProcessSnap);
		return ERROR_INVALID_HANDLE;
	}

	/* Owners and sessions in ONE go, before the walk: a failure here does not
	   prevent the collection, it only leaves the SIDs empty. */
	std::map<DWORD, std::pair<std::wstring, DWORD>> owners;
	readOwners(owners);

	unsigned long long nbProcess = 0;
	processes.reserve((size_t)totalProcess);
	do
	{
		log(1, L"➕Process");
		printProgressStep(L"Process", ++nbProcess, totalProcess);
		Process p(&pe32);
		const auto it = owners.find(p.processId);
		if (it != owners.end()) {
			p.processSID     = it->second.first;
			p.sessionId      = it->second.second;
			p.sessionKnown  = true;
		}
		processes.push_back(std::move(p));
		log(3, L"🔈Process32Next");
	} while (Process32Next(hProcessSnap, &pe32));


	CloseHandle(hProcessSnap);
	return(ERROR_SUCCESS);
}

HRESULT Processes::snapshot() {
	log(3, L"🔈processes snapshot");
	Json arr = Json::arr();
	for (const Process& p : processes) arr.push(p.toJson());
	return writeLiveSnapshot("processes.json", arr, L"running processes (Toolhelp snapshot, WTS)");
}

HRESULT writeProcessesFromSnapshot() {
	Json snapshot = Json::null();
	const HRESULT hresult = readLiveSnapshot("processes.json", snapshot);
	if (hresult != ERROR_SUCCESS) return hresult;
	/* Each process as observed, with the name of its owner inserted after its
	   SID — named from the hives (account_names.h), not by asking the system. */
	Json arr = Json::arr();
	for (const auto& process : snapshot.members()) {
		Json o = Json::obj();
		for (const auto& field : process.second.members()) {
			o.add(field.first, field.second);
			if (field.first == L"SID") o.add(L"Owner", Json::str(getNameFromSid(field.second.text())));
		}
		arr.push(std::move(o));
	}
	return writeJsonFile("processes.json", arr);
}

void Processes::clear() {
	log(3, L"🔈processes clear");
	processes.clear();   // destroys the elements -> really releases them
}
