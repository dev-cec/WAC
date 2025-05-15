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

struct Process {
	std::wstring processName = L""; //!< Nom du processus
	DWORD processId = 0; //!< Id du processus
	DWORD processParentId = 0;//!< Id du processus Parent
	DWORD processThreadCount = 0;//!< Nombre de threads
	std::wstring processSidName = L"";//!< nom de l'utilisateur propriétaire du processus
	std::wstring processSID = L"";//!< sid de l'utilisateur propriétaire du processus
	std::wstring processModulesAccess = L"OK";
	std::vector<std::wstring> processModules; //!< Liste des Dlls chargées par le programme. La première entrée contient le chemin de l’exécutable
	/*! Constructeur
	* @param pe32 est un pointeur sur le processus
	* @param errors est un vector contenant les erreurs de traitement
	*/
	Process(PROCESSENTRY32W* pe32, HANDLE handle, std::vector<std::tuple<std::wstring, HRESULT>>* errors) {
		HANDLE tokenHandle = NULL;
		LPVOID  infos = NULL;
		DWORD returnSize = 0;
		LPWSTR lpsid_wstring = NULL;

		processName = std::wstring(pe32->szExeFile);
		processId = pe32->th32ProcessID;
		processParentId = pe32->th32ParentProcessID;
		processThreadCount = pe32->cntThreads;
		//get owner of process

		if (OpenProcessToken(handle, TOKEN_ALL_ACCESS, &tokenHandle)) {
			GetTokenInformation(tokenHandle, TokenOwner, NULL, 0, &returnSize);  // get data size
			infos = (LPVOID)malloc(returnSize);
			if (GetTokenInformation(tokenHandle, TokenOwner, infos, returnSize, &returnSize)) { // get data
				if (ConvertSidToStringSid(((PTOKEN_OWNER)infos)->Owner, &lpsid_wstring) != 0) {
					processSID = std::wstring(lpsid_wstring);
					processSidName = getNameFromSid(processSID);
				}
				else
					errors->push_back({ L"Process" + processName + L" ConvertSidToStringSid : ", GetLastError() });
			}
			else
				errors->push_back({ L"Process" + processName + L" GetTokenInformation : ", GetLastError() });
			free(infos);
		}
		else
			errors->push_back({ L"Process" + processName + L" OpenProcessToken : ", GetLastError() });

		// List the modules and threads associated with this process
		HRESULT result = ListProcessModules(errors);

	}

	/*! Fonction récupérant la liste des modules (Dlls) du processus
	 * @param errors est un vector contenant les erreurs de traitement
	*/
	HRESULT ListProcessModules(std::vector<std::tuple<std::wstring, HRESULT>>* errors)
	{
		HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
		MODULEENTRY32 me32;

		// Take a snapshot of all modules in the specified process.
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			HRESULT error = GetLastError();

			processModulesAccess = ansi_to_utf8(getErrorWstring(error));

			errors->push_back({ L"Error " + processName + L" : CreateToolhelp32Snapshot (of modules)",error });

			return(ERROR_INVALID_HANDLE);
		}

		// Set the size of the structure before using it.
		me32.dwSize = sizeof(MODULEENTRY32);

		// Retrieve information about the first module,
		// and exit if unsuccessful
		HRESULT result;
		do {
			result = Module32First(hModuleSnap, &me32);
		} while (result == ERROR_BAD_LENGTH);

		// Now walk the module list of the process,
		// and display information about each module
		do
		{
			std::wstring temp = ansi_to_utf8(std::wstring(me32.szExePath));
			temp = replaceAll(temp, L"\\", L"\\\\");
			processModules.push_back(temp);
			do {
				result = Module32Next(hModuleSnap, &me32);
			} while (result == ERROR_BAD_LENGTH);

		} while (result);

		CloseHandle(hModuleSnap);
		return(ERROR_SUCCESS);
	}

	/*! conversion de l'objet au format json
	*/
	std::wstring to_json() {
		std::wstring result = L"";

		result += tab(1) + L"{ \n"
			+ tab(2) + L"\"Nom\":\"" + processName + L"\", \n"
			+ tab(2) + L"\"SID\":\"" + processSID + L"\", \n"
			+ tab(2) + L"\"Owner\":\"" + processSidName + L"\", \n"
			+ tab(2) + L"\"PID\":\"" + std::to_wstring(processId) + L"\", \n"
			+ tab(2) + L"\"PPId\":\"" + std::to_wstring(processParentId) + L"\", \n"
			+ tab(2) + L"\"ModulesMessage\":\"" + processModulesAccess + L"\", \n"
			+ tab(2) + L"\"Modules\":[\n";
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
};

/*! structure contenant l'ensemble des objets
*/
struct Processes {
	std::vector<Process> processes; //!< tableau contenant tout les processus
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(AppliConf conf)
	{
		HANDLE hProcessSnap;
		HANDLE hProcess;
		PROCESSENTRY32 pe32;

		_conf = conf;
		// Take a snapshot of all processes in the system.
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			errors.push_back({ L"Error CreateToolhelp32Snapshot (of processes)" ,GetLastError() });

		// Set the size of the structure before using it.
		pe32.dwSize = sizeof(PROCESSENTRY32);

		// Retrieve information about the first process,
		// and exit if unsuccessful
		if (!Process32First(hProcessSnap, &pe32))
		{

			errors.push_back({ L"Error " + std::wstring(pe32.szExeFile) + L" : Process32First" ,GetLastError() });// show cause of failure
			CloseHandle(hProcessSnap);          // clean the snapshot object
		}

		// Now walk the snapshot of processes, and
		// display information about each process in turn
		do
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess == NULL)
				errors.push_back({ L"Error " + std::wstring(pe32.szExeFile) + L" : OpenProcess" ,GetLastError() });// show cause of failure
			if (GetLastError() != 87) { // ERROR_INVALID_PARAMETER
				processes.push_back(Process(&pe32, hProcess, &errors));

			}
			CloseHandle(hProcess);
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
		for (it = processes.begin(); it != processes.end(); it++) {
			result += it->to_json();
			if (it != processes.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/processes.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/processes_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}
};





