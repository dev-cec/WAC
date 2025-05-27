#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include <sddl.h>
#include "tools.h"



/*! structure représentant un process */
struct Process {
	std::wstring processName = L""; //!< Nom du processus
	DWORD processId = 0; //!< Id du processus
	std::wstring md5 = L""; //!< hash md5 du process exe
	DWORD processParentId = 0;//!< Id du processus Parent
	DWORD processThreadCount = 0;//!< Nombre de threads
	std::wstring processSidName = L"";//!< nom de l'utilisateur propriétaire du processus
	std::wstring processSID = L"";//!< sid de l'utilisateur propriétaire du processus
	std::wstring processModulesAccess = L"OK";
	std::vector<std::wstring> processModules; //!< Liste des Dlls chargées par le programme. La première entrée contient le chemin de l’exécutable
	/*! Constructeur
	* @param pe32 est un pointeur sur le processus

	*/
	Process(PROCESSENTRY32W* pe32, HANDLE handle) {
		HANDLE tokenHandle = NULL;
		LPVOID  infos = NULL;
		DWORD returnSize = 0;
		LPWSTR lpsid_wstring = NULL;

		processName = std::wstring(pe32->szExeFile).data();
		processId = pe32->th32ProcessID;

		log(2, L"❇️Process Name : " + processName + L" (PID " + std::to_wstring(processId) + L")");
		processParentId = pe32->th32ParentProcessID;
		processThreadCount = pe32->cntThreads;
		//get owner of process
		log(3, L"🔈OpenProcessToken");
		if (OpenProcessToken(handle, TOKEN_ALL_ACCESS, &tokenHandle)) {
			log(3, L"🔈GetTokenInformation");
			GetTokenInformation(tokenHandle, TokenOwner, NULL, 0, &returnSize);  // get data size
			infos = (LPVOID)malloc(returnSize);
			if (GetTokenInformation(tokenHandle, TokenOwner, infos, returnSize, &returnSize)) { // get data
				log(3, L"🔈ConvertSidToStringSid");
				if (ConvertSidToStringSid(((PTOKEN_OWNER)infos)->Owner, &lpsid_wstring) != 0) {
					processSID = std::wstring(lpsid_wstring).data();
					log(3, L"🔈getNameFromSid lpsid_wstring");
					processSidName = getNameFromSid(processSID);
				}
				else
					log(2, L"🔥ConvertSidToStringSid : ", GetLastError());
			}
			else
				log(2, L"🔥GetTokenInformation : ", GetLastError());
			free(infos);
		}
		else {
			log(2, L"🔥OpenProcessToken : ", GetLastError());
			log(3, L"🔈getErrorMessage error");
			processModulesAccess = getErrorMessage(GetLastError());
			return;
		}

		// List the modules and threads associated with this process
		log(3, L"🔈ListProcessModules");
		HRESULT result = ListProcessModules();
		if (result != ERROR_SUCCESS)
			log(2, L"🔥ListProcessModules : ", result);
		CloseHandle(tokenHandle);
	}

	/*! Fonction récupérant la liste des modules (Dlls) du processus

	*/
	HRESULT ListProcessModules()
	{
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
		bool result = false;
		log(3, L"🔈Module32First");
		if (!Module32First(hModuleSnap, &me32)) {
			log(2, L"🔥Module32First", GetLastError());
			processModulesAccess = getErrorMessage(GetLastError());
			CloseHandle(hModuleSnap);
			return ERROR_INVALID_HANDLE;
		}

		if (conf.md5) {
			//Le premier module retourne le exe path
			log(3, L"🔈fileToHash md5Source");
			md5 = QuickDigest5::fileToHash(wstring_to_string(me32.szExePath));
		}

		// Now walk the module list of the process,
		// and display information about each module

		do {
			std::wstring temp = std::wstring(me32.szExePath).data();
			log(3, L"🔈replaceAll szExePath");
			temp = replaceAll(temp, L"\\", L"\\\\");
			log(2, L"❇️Module exePath : " + temp);
			processModules.push_back(temp);
			log(3, L"🔈Module32Next");
		} while (Module32Next(hModuleSnap, &me32));

		CloseHandle(hModuleSnap);
		return(ERROR_SUCCESS);
	}

	/*! conversion de l'objet au format json
	*/
	std::wstring to_json() {
		std::wstring result = L"";

		log(3, L"🔈process to_json");
		result += tab(1) + L"{ \n";
		result += tab(2) + L"\"Nom\":\"" + processName + L"\", \n";
		result += tab(2) + L"\"md5\":\"" + md5 + L"\", \n";
		result += tab(2) + L"\"SID\":\"" + processSID + L"\", \n";
		result += tab(2) + L"\"Owner\":\"" + processSidName + L"\", \n";
		result += tab(2) + L"\"PID\":\"" + std::to_wstring(processId) + L"\", \n";
		result += tab(2) + L"\"PPId\":\"" + std::to_wstring(processParentId) + L"\", \n";
		result += tab(2) + L"\"ModulesMessage\":\"" + processModulesAccess + L"\", \n";
		result += tab(2) + L"\"Modules\":[\n";
		std::vector<std::wstring>::iterator it;
		for (it = processModules.begin(); it != processModules.end(); it++) {
			result += tab(3) + L"\"" + it->data() + L"\"";
			if (it != processModules.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(2) + L"]\n";
		result += tab(1) + L"} \n";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈process clear");
	}
};

/*! structure contenant l'ensemble des objets
*/
struct Processes {
	std::vector<Process> processes; //!< tableau contenant tout les processus


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData()
	{
		HANDLE hProcessSnap;
		HANDLE hProcess;
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
		// Now walk the snapshot of processes, and
		// display information about each process in turn
		do
		{
			log(1, L"➕Process");
			log(3, L"🔈OpenProcess");
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			DWORD r = GetLastError();
			if (hProcess == NULL)
				log(2, L"🔥OpenProcess", r);// show cause of failure
			if (r != 87) { // ERROR_INVALID_PARAMETER, si hProcess est null on push tout de meme
				processes.push_back(Process(&pe32, hProcess));
				CloseHandle(hProcess);
			}
			log(3, L"🔈Process32Next");
		} while (Process32Next(hProcessSnap, &pe32));


		CloseHandle(hProcessSnap);
		return(ERROR_SUCCESS);
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		std::wstring result = L"[ \n";
		std::vector<Process>::iterator it;
		log(3, L"🔈processes to_json");
		for (it = processes.begin(); it != processes.end(); it++) {
			result += it->to_json();
			if (it != processes.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/processes.json");
		log(3, L"🔈ansi_to_utf8 result");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈processes clear");
		for (Process temp : processes)
			temp.clear();
	}
};





