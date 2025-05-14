// main.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include <filesystem>
#include <windows.h>
#include <string>
#include <stdio.h>
#include <offreg.h>
#include <io.h>
#include <fcntl.h>
#include "tools.h"
#include "vss.h"
#include "com.hpp"
#include "reg_usbstors.hpp"
#include "reg_mounted_devices.hpp"
#include "reg_bams.hpp"
#include "reg_muicache.hpp"
#include "reg_amcache_application.hpp"
#include "reg_amcache_applicationfile.hpp"
#include "reg_userassists.hpp"
#include "reg_run.hpp"
#include "reg_shimcache.hpp"
#include "reg_shellbags.hpp"
#include "reg_mru.hpp"
#include "reg_mru_apps.hpp"
#include "prefetchs.hpp"
#include "recent_docs.hpp"
#include "jumplist_automatic.hpp"
#include "jumplist_custom.hpp"
#include "schedulesTasks.hpp"
#include "system.hpp"
#include "sessions.hpp"
#include "processes.hpp"
#include "services.hpp"
#include "users.hpp"
#include "events.hpp"


int main(int argc, char* argv[])
{
	HRESULT hresult;
	COM com;
	Services services;
	Usbstors usbs;
	MountedDevices mouteddevices;
	Bams bams;
	Muicaches muicaches;
	AmcacheApplications amcacheapplications;
	AmcacheApplicationFiles amcacheapplicationfiles;
	UserAssists userassists;
	Runs runs;
	Shimcaches shimcaches;
	Prefetchs prefetchs;
	RecentDocs recentdocs;
	Shellbags shellbags;
	Mrus mrus;
	MruApps mruapps;
	JumplistAutomatics jumplistAutomatics;
	JumplistCustoms jumplistCustoms;
	ScheduledTasks scheduledTasks;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	System system;
	Sessions sessions;
	Processes processes;
	Users users;
	Events events;

	SetConsoleOutputCP(CP_UTF8); // format UTF8 pour la prise en compte des accents dans la console car retour en UTF8

	/************************
	* Variables utiles
	*************************/
	bool _debug = false;
	bool _dump = false;
	bool _events = false;

	/************************
	* Arguments
	*************************/

	if (argc > 1) { // au moins un argument, argv[0] étant le chemin absolu du logiciel
		//Prise en compte des arguments de la ligne de commande
		const std::vector<std::string_view> args(argv + 1, argv + argc);
		for (const auto& arg : args) {

			if (arg == "--dump") _dump = true;
			else if (arg == "--debug") _debug = true;
			else if (arg == "--events") _events = true;
			else { //argument inconnu
				SetConsoleTextAttribute(hConsole, 12);
				SetConsoleOutputCP(CP_UTF8);
				std::cerr << "Invalid argument " << arg << "\n";
				std::cerr << "usage: RegParser.exe [--dump] [--debug] \n";
				std::cerr << "\t--dump : add std::hexa value in json files for shellbags and LNK files \n";
				std::cerr << "\t--debug : add error output files\n";
				std::cerr << "\t--events : converts events to json (long time)\n";
				SetConsoleTextAttribute(hConsole, 7);
				exit(1);
			}
		}
	}

	/************************
	* Prérequis
	*************************/

	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << "[PREREQUISITE VERIFICATION]" << std::endl;
	SetConsoleTextAttribute(hConsole, 7);
	std::wcout << " - Check OS >= Windows 10 : ";
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	printSuccess();
	std::wcout << " - Check administrator rights : ";
	/* A program using VSS must run in elevated mode */
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);
	DWORD infoLen;

	TOKEN_ELEVATION elevation = { 0 };
	GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &infoLen);
	if (!elevation.TokenIsElevated)
	{
		printError(ERROR_ELEVATION_REQUIRED);
		return 3;
	}
	printSuccess();
#else
	printError(ERROR_APP_WRONG_OS);
	return 1;
#endif

	/**********************************
	* CONNECTION COM
	**********************************/
	std::wcout << " - Connection to COM : ";
	hresult = com.connect();
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return 1;
	}
	printSuccess();

	/************************
	* WIN32 API
	*************************/
	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << "[SEARCHING FOR ARTIFACTS IN WINDOWS API]" << std::endl;
	SetConsoleTextAttribute(hConsole, 7);

	std::wcout << " - Extraction of SYSTEM INFORMATION: ";
	hresult = system.getData(_debug);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = system.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of SCHEDULED TASKS: ";
	hresult = scheduledTasks.getData(_debug);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = scheduledTasks.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of SESSIONS: ";
	hresult = sessions.getData(_debug);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = sessions.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of PROCESS: ";
	hresult = processes.getData(_debug);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = processes.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of SERVICES: ";
	std::wcout.flush();
	hresult = services.getData(_debug);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = services.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of USERS: ";
	std::wcout.flush();
	hresult = users.getData(_debug);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = users.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	if (_events) {
		std::wcout << " - Extraction of EVENTS: ";
		std::wcout.flush();
		hresult = events.getData(_debug);
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else {
			hresult = events.to_json();
			if (hresult != ERROR_SUCCESS) printError(hresult);
		}
	}
	/************************
	*  BASE DE REGISTRE
	*************************/

	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << "[SEARCHING FOR ARTIFACTS IN THE REGISTRY]" << std::endl;
	SetConsoleTextAttribute(hConsole, 7);
	//variables
	ORHKEY System;
	ORHKEY CurrentControlSet;
	ORHKEY Software;
	ORHKEY hKey;
	LPTSTR errorText = NULL;
	DWORD nSubkeys = 0;
	DWORD nValues = 0;
	DWORD nSize = 0;
	DWORD dwType = 0;
	DWORD cbData = 0;
	ORHKEY OffKeyNext;
	WCHAR szValue[MAX_VALUE_NAME];
	WCHAR szSubKey[MAX_KEY_NAME];
	WCHAR szNextKey[MAX_KEY_NAME];
	DWORD dwSize = 0;



	// création du VSS
	IVssBackupComponents* pBackup = NULL; // pointeur sur le snapshot
	VSS_ID snapshotSetId;
	LPCWSTR mountpoint = L".\\vss";
	LPCWSTR mountpoint2 = L".\\vss";


	std::wcout << " - Creating the snapshot : ";
	hresult = GetSnapshots(&mountpoint, &snapshotSetId, pBackup);
	if (hresult != S_OK) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}


	//chargement de la clé HKLM\SYSTEM
	std::wcout << " - loading the HKLM\\SYSTEM key : ";
	std::wstring rucheSystem = (std::wstring)mountpoint + L"\\Windows\\system32\\config\\SYSTEM";
	hresult = OROpenHive(rucheSystem.c_str(), &System);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	//chargement de la clé HKLM\SOFTWARE
	std::wcout << " - loading the HKLM\\SOFTWARE key : ";
	std::wstring rucheSoftware = (std::wstring)mountpoint + L"\\Windows\\system32\\config\\SOFTWARE";
	hresult = OROpenHive(rucheSoftware.c_str(), &Software);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	//recherche de la bonne sous-clé ControlSet correspondant à CurrentControlSet
	std::wcout << " - Searching for the CurrentControlSet subkey : ";
	hresult = OROpenKey(System, L"Select", &hKey);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return(hresult);
	}


	hresult = ORGetValue(hKey, nullptr, L"Current", &dwType, nullptr, &dwSize);
	if (hresult != ERROR_SUCCESS)
	{
		printError(hresult);
		return(hresult);
	}
	DWORD current;
	hresult = ORGetValue(hKey, nullptr, L"Current", &dwType, &current, &dwSize);
	if (hresult != ERROR_SUCCESS)
	{
		printError(hresult);
		return(hresult);
	}
	else {

		//le numéro de la clé ControlSet est sur 3 digit de la forme 001
		std::wstring controleSet;
		if ((int)(current) < 10) {
			controleSet = L"00" + std::to_wstring(current);
		}
		else if ((int)(current) < 100) {
			controleSet = L"0" + std::to_wstring(current);
		}
		else {
			controleSet = std::to_wstring(current);
		}
		//nom complet de la clé controlSet qui nous intéresse
		std::wstring subkey = L"ControlSet" + controleSet;
		PCWSTR s = subkey.c_str();
		printSuccess();

		//ouverture de la clé HKLM\\SYSTEM\\CurrentControlSet
		std::wcout << " - Opening the CurrentControlSet subkey : ";
		hresult = OROpenKey(System, subkey.c_str(), &CurrentControlSet);
		if (hresult != ERROR_SUCCESS) {
			printError(hresult);
			return(hresult);
		}
		else {
			printSuccess();

			std::wcout << " - Extracting USBSTOR Registry Keys : ";
			hresult = usbs.getData(CurrentControlSet, _debug);
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
			}
			else {
				hresult = usbs.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting the MOUNTED DEVICE registry keys : ";
			hresult = mouteddevices.getData(System, _debug);
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
			}
			else {
				hresult = mouteddevices.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}


			std::wcout << " - Extracting BAM Registry Keys : ";
			hresult = bams.getData(CurrentControlSet, users, _debug);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = bams.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting MUICACHE Registry Keys : ";
			hresult = muicaches.getData((std::wstring)mountpoint, users, _debug);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = muicaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting AMCACHE APPLICATION Registry Keys : ";
			hresult = amcacheapplications.getData((std::wstring)mountpoint, _debug);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplications.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting AMCACHE APPLICATIONFILE Registry Keys : ";
			hresult = amcacheapplicationfiles.getData((std::wstring)mountpoint, _debug);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplicationfiles.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting USERASSIST Registry Keys : ";
			hresult = userassists.getData((std::wstring)mountpoint, users, _debug);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = userassists.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting RUN Registry Keys : ";
			hresult = runs.getData((std::wstring)mountpoint, Software, users, _debug);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = runs.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting SHIMCACHE Registry Keys : ";
			hresult = shimcaches.getData(CurrentControlSet, _debug);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shimcaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting SHELLBAGS Registry Keys : ";
			hresult = shellbags.getData(mountpoint, users, _debug, _dump);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shellbags.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting MRU Registry Keys : ";
			hresult = mrus.getData(mountpoint, users, _debug, _dump);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mrus.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting MRUAPPS Registry Keys : ";
			hresult = mruapps.getData(mountpoint, users, _debug, _dump);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mruapps.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}
		}
	}
	std::wcout << " - Snapshot disassembly : ";
	if (!RemoveDirectory(mountpoint)) printError(GetLastError());
	else printSuccess();

	/**************************************************
	* DECONNEXION COM
	***************************************************/
	std::wcout << " - Disconnecting COM : ";
	std::wcout.flush();
	com.clear();
	printSuccess();

	/************************
	*  FICHIERS
	*************************/
	SetConsoleTextAttribute(hConsole, 14);
	std::wcout << "[SEARCHING FOR ARTIFACTS IN FILES]" << std::endl;
	SetConsoleTextAttribute(hConsole, 7);
	std::wcout << " - Extracting RECENT DOCS : ";
	hresult = recentdocs.getData(users, _debug, _dump);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = recentdocs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extracting PREFETCHS : ";
	hresult = prefetchs.getData(_debug);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = prefetchs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extracting JUMPLIST AUTOMATIC: ";
	hresult = jumplistAutomatics.getData(users, _debug, _dump);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistAutomatics.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extracting JUMPLIST CUSTOM: ";
	hresult = jumplistCustoms.getData(users, _debug, _dump);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistCustoms.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::cout.flush();
	std::wcout << L"END" << std::endl;
	return ERROR_SUCCESS;
}