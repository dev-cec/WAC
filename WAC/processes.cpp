#include "processes.h"

#include <wtsapi32.h>

/* A DECLARATION MISSING FROM THE MINGW-W64 HEADER.
 *
 * `WTSEnumerateProcessesExW` has been exported by wtsapi32.dll since Windows
 * Vista and the symbol is present in libwtsapi32.a, but mingw-w64's
 * `wtsapi32.h` does not declare it (unlike `WTSEnumerateSessionsExW`, right
 * next to it). The prototype is therefore taken as it is documented.
 *
 * Preferred to a dynamic load through `GetProcAddress`: that would require a
 * `LoadLibrary` on wtsapi32.dll, while the DLL is already linked to the program
 * for `sessions`.
 */
#ifndef WTS_ANY_SESSION
#define WTS_ANY_SESSION ((DWORD)-2)
#endif
extern "C" WINBOOL WINAPI WTSEnumerateProcessesExW(HANDLE hServer, DWORD* pLevel,
                                                   DWORD SessionId,
                                                   LPWSTR* ppProcessInfo,
                                                   DWORD* pCount);

namespace {

/*! Reads the owner's SID and the session of ALL the processes, in one call,
* without opening any process handle.
*
* `WTSEnumerateProcessesExW` queries the Terminal Services service, already
* solicited by `sessions`. It returns the SID even for the protected processes
* that `OpenProcess` refuses — including lsass, services.exe and Defender's
* processes, whose impersonation is precisely what an investigation looks for.
*
* @param byPid receives, for each PID, the SID and the session identifier
* @return ERROR_SUCCESS if the enumeration succeeded
*/
HRESULT readOwners(std::map<DWORD, std::pair<std::wstring, DWORD>>& byPid) {
	DWORD level = 0;                 // level 0: SessionId, ProcessId, name, SID
	PWTS_PROCESS_INFOW infos = NULL;
	DWORD count = 0;
	log(3, L"🔈WTSEnumerateProcessesExW");
	if (!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level, WTS_ANY_SESSION,
	                              (LPWSTR*)&infos, &count)) {
		const HRESULT error = GetLastError();
		log(2, L"🔥WTSEnumerateProcessesExW: owners not read", error);
		return error;
	}

	for (DWORD i = 0; i < count; ++i) {
		std::wstring sid;
		if (infos[i].pUserSid) {
			LPWSTR text = NULL;
			log(3, L"🔈ConvertSidToStringSidW");
			if (ConvertSidToStringSidW(infos[i].pUserSid, &text) && text) {
				sid = text;
				LocalFree(text);
			}
			else
				log(2, L"🔥ConvertSidToStringSidW", GetLastError());
		}
		/* An empty SID is a fact, not a failure: the purely kernel processes
		   (System, Registry) have no user token. The session, for its part, is
		   always returned. */
		byPid[infos[i].ProcessId] = { sid, infos[i].SessionId };
	}
	log(2, L"❇️Owners read for " + std::to_wstring(byPid.size()) + L" processes");
	log(3, L"🔈WTSFreeMemoryExW");
	WTSFreeMemoryExW(WTSTypeProcessInfoLevel0, infos, count);
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
	   `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)` does not mean "process 0"
	   but "the CURRENT PROCESS". The Idle process was therefore credited with
	   the 25 modules of WAC.exe itself, WAC.exe first: an investigation report
	   stated that the system process had loaded the collection tool. The Idle
	   process has neither an image nor a module anyway. */
	if (processId == 0) {
		processModulesAccess = L"Idle process: no module by nature";
		return;
	}

	/* The modules are read independently of the owner. In the original version, a
	   failure to read the token caused a `return` before this call: the 16
	   protected processes therefore also came out with NO module at all, while
	   the Toolhelp snapshot does not depend on the token. */
	log(3, L"🔈ListProcessModules");
	const HRESULT result = ListProcessModules();
	if (result != ERROR_SUCCESS)
		log(2, L"🔥ListProcessModules : ", result);
}

HRESULT Process::ListProcessModules() {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	log(3, L"🔈CreateToolhelp32Snapshot");
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		HRESULT error = GetLastError();
		log(3, L"🔈getErrorMessage error");
		processModulesAccess = getErrorMessage(error);
		log(2, L"🔥CreateToolhelp32Snapshot (of modules)", error);
		return(ERROR_INVALID_HANDLE);
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	log(3, L"🔈Module32First");
	if (!Module32First(hModuleSnap, &me32)) {
		log(2, L"🔥Module32First", GetLastError());
		processModulesAccess = getErrorMessage(GetLastError());
		CloseHandle(hModuleSnap);
		return ERROR_INVALID_HANDLE;
	}

	if (conf.binary) {
		// The first module returns the executable's path
		log(3, L"🔈EmpreinteFichier");
		fingerprint = FingerprintFile(me32.szExePath);
	}

	// Now walk the module list of the process,
	// and display information about each module

	do {
		std::wstring path = me32.szExePath;
		log(2, L"❇️Module exePath : " + path);
		processModules.push_back(std::move(path));
		log(3, L"🔈Module32Next");
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(ERROR_SUCCESS);
}

Json Process::toJson() const {
	log(3, L"🔈process toJson");
	Json o = Json::obj();
	// "Nom" was the only key in French of the whole output, among SID, Owner,
	// ProcessId… One single language for the keys (naming pass).
	o.add(L"Name",           Json::str(processName));
	addFingerprints(o, fingerprint);
	o.add(L"SID",            Json::str(processSID));
	o.add(L"Owner",          Json::str(processSidName));
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
		log(2, L"🔥Process32First (2e passe)", GetLastError());
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
			if (!p.processSID.empty()) {
				log(3, L"🔈getNameFromSid");
				p.processSidName = getNameFromSid(p.processSID);
			}
		}
		processes.push_back(std::move(p));
		log(3, L"🔈Process32Next");
	} while (Process32Next(hProcessSnap, &pe32));


	CloseHandle(hProcessSnap);
	return(ERROR_SUCCESS);
}

HRESULT Processes::toJson() {
	log(3, L"🔈processes toJson");
	Json arr = Json::arr();
	for (const Process& p : processes) arr.push(p.toJson());
	return writeJsonFile("processes.json", arr);
}

void Processes::clear() {
	log(3, L"🔈processes clear");
	processes.clear();   // destroys the elements -> really releases them
}
