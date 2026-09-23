#include "processes.h"

#include <wtsapi32.h>

/* DÉCLARATION MANQUANTE DANS L'EN-TÊTE MINGW-W64.
 *
 * `WTSEnumerateProcessesExW` est exporté par wtsapi32.dll depuis Windows Vista
 * et le symbole est bien présent dans libwtsapi32.a, mais `wtsapi32.h` de
 * mingw-w64 ne le déclare pas (contrairement à `WTSEnumerateSessionsExW`, juste
 * à côté). Le prototype est donc repris tel qu'il est documenté.
 *
 * Préféré à un chargement dynamique par `GetProcAddress` : celui-ci imposerait
 * un `LoadLibrary` sur wtsapi32.dll, alors que la DLL est déjà liée au
 * programme pour `sessions`.
 */
#ifndef WTS_ANY_SESSION
#define WTS_ANY_SESSION ((DWORD)-2)
#endif
extern "C" WINBOOL WINAPI WTSEnumerateProcessesExW(HANDLE hServer, DWORD* pLevel,
                                                   DWORD SessionId,
                                                   LPWSTR* ppProcessInfo,
                                                   DWORD* pCount);

namespace {

/*! Relève le SID du propriétaire et la session de TOUS les processus, en un
* appel, sans ouvrir aucun handle de processus.
*
* `WTSEnumerateProcessesExW` interroge le service Terminal Services, déjà
* sollicité par `sessions`. Il rend le SID même pour les processus protégés, que
* `OpenProcess` refuse — y compris lsass, services.exe et les processus de
* Defender, dont l'usurpation est précisément ce qu'une investigation cherche.
*
* @param parPid reçoit, pour chaque PID, le SID et l'identifiant de session
* @return ERROR_SUCCESS si l'énumération a abouti
*/
HRESULT readOwners(std::map<DWORD, std::pair<std::wstring, DWORD>>& parPid) {
	DWORD level = 0;                 // niveau 0 : SessionId, ProcessId, nom, SID
	PWTS_PROCESS_INFOW infos = NULL;
	DWORD count = 0;
	log(3, L"🔈WTSEnumerateProcessesExW");
	if (!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &level, WTS_ANY_SESSION,
	                              (LPWSTR*)&infos, &count)) {
		const HRESULT error = GetLastError();
		log(2, L"🔥WTSEnumerateProcessesExW : proprietaires non releves", error);
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
		/* Un SID vide est un fait, pas un echec : les processus purement noyau
		   (System, Registry) n'ont pas de jeton utilisateur. La session, elle,
		   est toujours rendue. */
		parPid[infos[i].ProcessId] = { sid, infos[i].SessionId };
	}
	log(2, L"❇️Proprietaires releves pour " + std::to_wstring(parPid.size()) + L" processus");
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

	/* PID 0 — LE PIÈGE À NE PAS REPRODUIRE.
	   `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)` ne signifie pas « le
	   processus 0 » mais « le PROCESSUS COURANT ». Le processus Idle se voyait
	   donc attribuer les 25 modules de WAC.exe lui-même, WAC.exe en tête : un
	   rapport d'enquête affirmait que le processus système avait chargé l'outil
	   de collecte. Le processus Idle n'a de toute façon ni image ni module. */
	if (processId == 0) {
		processModulesAccess = L"processus Idle : aucun module par nature";
		return;
	}

	/* Les modules sont relevés indépendamment du propriétaire. Dans la version
	   d'origine, un échec de lecture du jeton provoquait un `return` avant cet
	   appel : les 16 processus protégés sortaient donc aussi sans AUCUN module,
	   alors que l'instantané Toolhelp ne dépend pas du jeton. */
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
		//Le premier module retourne le exe path
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
	// « Nom » etait la seule cle en francais de toute la sortie, au milieu de
	// SID, Owner, ProcessId… Une seule langue pour les cles (passe de nommage).
	o.add(L"Name",           Json::str(processName));
	addFingerprints(o, fingerprint);
	o.add(L"SID",            Json::str(processSID));
	o.add(L"Owner",          Json::str(processSidName));
	/* Nommage harmonise (passe de nommage) : `PID` et `PPId` coexistaient dans
	   le MEME objet avec deux conventions de casse, et `services.json` appelait
	   `ProcessId` la meme notion. Une seule orthographe pour une seule notion,
	   explicite comme `SessionId`. */
	o.add(L"ProcessId",       Json::num(processId));
	o.add(L"ParentProcessId", Json::num(processParentId));
	o.add(L"ThreadCount",    Json::num(processThreadCount));   // etait parse mais jamais emis
	// Permet de rattacher un processus a une entree de Sessions.json.
	if (sessionKnown) o.add(L"SessionId", Json::num(sessionId));
	/* Ne porte QUE l'erreur de lecture des modules. Elle portait auparavant
	   celle du jeton, si bien qu'un refus d'acces au processus s'affichait ici
	   comme un probleme de modules. */
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
	/* Process32Next ne donne pas le nombre de processus a l'avance, ce qui
	   privait la progression de son pourcentage. On compte donc d'abord, par un
	   premier parcours du MEME snapshot : il est deja en memoire et ce passage
	   n'ouvre aucun handle ni ne lit aucun module, son cout est negligeable
	   devant la collecte elle-meme. */
	unsigned long long totalProcess = 0;
	do { ++totalProcess; } while (Process32Next(hProcessSnap, &pe32));

	// Repositionnement au debut du snapshot pour la collecte reelle.
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		log(2, L"🔥Process32First (2e passe)", GetLastError());
		CloseHandle(hProcessSnap);
		return ERROR_INVALID_HANDLE;
	}

	/* Propriétaires et sessions en UNE fois, avant le parcours : un échec ici
	   n'empêche pas la collecte, il laisse seulement les SID vides. */
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
	processes.clear();   // detruit les elements -> libere reellement
}
