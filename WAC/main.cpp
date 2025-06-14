﻿// main.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include <filesystem>
#include <windows.h>
#include <string>
#include <stdio.h>
#include <offreg.h>
#include <io.h>
#include <fcntl.h>
#include "asciiart.hpp"
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

AppliConf conf;// variable globale pour la conf de l'application

void showHelp() {
	SetConsoleTextAttribute(conf.hConsole, 7); // blanc
	wprintf(L"%s%S%s\n", L"\nusage: ", conf.name, L" [--dump] [--events] [ --md5] [--output=output] [--loglevel=2]");
	wprintf(L"%s\n", L"\t--help or /? : show this help ");
	wprintf(L"%s\n", L"\t--dump : add hexa value in json files for shellbags and LNK files ");
	wprintf(L"%s\n", L"\t--events : converts events to json (long time)");
	wprintf(L"%s\n", L"\t--md5 : activate hash md5 computing for files referenced in artfacts");
	wprintf(L"%s\n", L"\t--output=[directory name] : directory name to store output files starting from current directory. By default the directory is 'output'");
	wprintf(L"%s%S%s\n", L"\t--loglevel=[0] : define level of details in logfile and activate logging in ", conf.name, L".log");
	wprintf(L"\n");
	wprintf(L"%s\n", L"\t loglevel = 0 => no logging");
	wprintf(L"%s\n", L"\t loglevel = 1 => activate logging for each artefact type treated");
	wprintf(L"%s\n", L"\t loglevel = 2 => activate logging for each artefact treated");
	wprintf(L"%s\n", L"\t loglevel = 3 => activate logging for each subfunction called (used for debug only)");
};

int main(int argc, char* argv[])
{
	HRESULT hresult;
	COM com;
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
	RecentDocs recentdocs;
	Shellbags shellbags;
	Mrus mrus;
	MruApps mruapps;
	JumplistAutomatics jumplistAutomatics;
	JumplistCustoms jumplistCustoms;
	ScheduledTasks scheduledTasks;
	SystemInfo systemInfo;
	Sessions sessions;
	Processes processes;
	Users users;
	Events events;

	time_t start = 0, end = 0;

	/************************
	* fonctions utiles
	*************************/
	//ASCII ART
	SetConsoleOutputCP(CP_UTF8); // format UTF8 pour la prise en compte des accents dans la console car retour en UTF8
	system("cls");//clear screen

	log(3, L"🔈asciiart");
	asciiart();

	start = time(nullptr);//heure de depart du logiciel pour benchmark

	/************************
	* Arguments
	*************************/

	conf.name = argv[0];
	if (argc > 1) { // au moins un argument, argv[0] étant le nom du logiciel
		// Prise en compte des arguments de la ligne de commande
		const std::vector<std::string> args(argv + 1, argv + argc);
		for (const auto& arg : args) {

			if (arg == "--dump") conf._dump = true;
			else if (arg == "--events") conf._events = true;
			else if (arg == "--md5") conf.md5 = true;
			else if (arg.substr(0, 9) == "--output=") {
				std::string temp = std::string(arg.substr(9));
				if (temp.length() > 0) conf._outputDir = temp;
				else {
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					wprintf(L"%s%S\n", L"Invalid length for output param " , arg);
					log(3, L"🔈showHelp");
					showHelp();
					exit(1);
				}
				if (conf._outputDir.find("\\") != std::string::npos) {
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					wprintf(L"%s%S\n", L"Invalid character for param " ,arg);
					log(3, L"🔈showHelp");
					showHelp();
					exit(1);
				}
			}
			else if (arg.substr(0, 11) == "--loglevel=") {
				std::string temp = std::string(arg.substr(11));
				try {
					conf.loglevel = stoi(temp);
				}
				catch (...)
				{
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					wprintf(L"%s%S\n", L"Invalid numeric value for output param " ,arg );
					log(3, L"🔈showHelp");
					showHelp();
					exit(1);
				}
			}

			else { //argument inconnu
				if (arg != "--help" && arg != "/?") { // Si pas argument --help ou /? alors argument invalide
					printError(L"Invalid argument  " + string_to_wstring(arg));
				}
				log(3, L"🔈showHelp");
				showHelp();
				exit(1);
			}
		}
	}

	/************************
	* Prérequis
	*************************/

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Prerequisites :");
	log(0, L"*******************************************************************************************************************");

	log(1, L"➕Check OS");
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[PREREQUISITE VERIFICATION]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	wprintf(L"%s", L" - Check OS >= Windows 10 : ");
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	printSuccess();
#else
	printError(ERROR_APP_WRONG_OS);
	return 1;
#endif
	log(1, L"➕Check administrator rights");
	wprintf(L"%s", L" - Check administrator rights : ");
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


	/**********************************
	* CONNECTION COM
	**********************************/

	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[COM COMPONENT]");
	SetConsoleTextAttribute(conf.hConsole, 7);

	wprintf(L"%s", L" - Connection to COM : ");
	log(3, L"🔈connect com");
	hresult = com.connect();
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return 1;
	}
	printSuccess();

	/************************
	* WIN32 API
	*************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[SEARCHING FOR ARTIFACTS IN WINDOWS API]");
	SetConsoleTextAttribute(conf.hConsole, 7);

	wprintf(L"%s", L" - Extraction of SYSTEM INFORMATION: ");
	hresult = systemInfo.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = systemInfo.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		systemInfo.clear();// free memory
	}


	wprintf(L"%s", L" - Extraction of SCHEDULED TASKS: ");
	hresult = scheduledTasks.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = scheduledTasks.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		scheduledTasks.clear(); // free memory
	}



	wprintf(L"%s", L" - Extraction of SESSIONS: ");
	hresult = sessions.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = sessions.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		sessions.clear();// free memory
	}



	wprintf(L"%s", L" - Extraction of PROCESS: ");
	hresult = processes.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = processes.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		processes.clear(); // free memory
	}



	wprintf(L"%s", L" - Extraction of SERVICES: ");
	
	hresult = services.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = services.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		services.clear();//free memory
	}



	wprintf(L"%s", L" - Extraction of USERS: ");
	
	hresult = users.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = users.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		users.clear(); // free memory
	}



	if (conf._events) {
		wprintf(L"%s", L" - Extraction of EVENTS: ");
		
		hresult = events.getData();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else {
			hresult = events.to_json();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			events.clear(); // free memory
		}

	}

	/************************
	*  CREATION SNAPSHOT
	*************************/
	IVssBackupComponents* pBackup = NULL; // pointeur sur le snapshot
	VSS_ID snapshotSetId = { 0 };

	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[SNAPSHOT]");
	SetConsoleTextAttribute(conf.hConsole, 7);

	wprintf(L"%s", L" - Creating the snapshot : ");
	log(3, L"🔈GetSnapshots pBackup");
	hresult = GetSnapshots(&snapshotSetId, pBackup);
	if (hresult != S_OK) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	/************************
	*  BASE DE REGISTRE
	*************************/

	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[SEARCHING FOR ARTIFACTS IN THE REGISTRY]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	//variables
	ORHKEY hKey = NULL;
	LPTSTR errorText = NULL;
	DWORD nSubkeys = 0;
	DWORD nValues = 0;
	DWORD nSize = 0;
	DWORD dwType = 0;
	DWORD cbData = 0;
	ORHKEY OffKeyNext = NULL;
	WCHAR szValue[MAX_VALUE_NAME] = L"";
	WCHAR szSubKey[MAX_KEY_NAME] = L"";
	WCHAR szNextKey[MAX_KEY_NAME] = L"";
	DWORD dwSize = 0;


	//chargement de la clé HKLM\SYSTEM
	wprintf(L"%s", L" - loading the HKLM\\SYSTEM key : ");
	std::wstring rucheSystem = conf.mountpoint + L"\\Windows\\system32\\config\\SYSTEM";
	log(3, L"🔈OROpenHive System");
	hresult = OROpenHive(rucheSystem.c_str(), &conf.System);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	//chargement de la clé HKLM\SOFTWARE
	wprintf(L"%s", L" - loading the HKLM\\SOFTWARE key : ");
	std::wstring rucheSoftware = conf.mountpoint + L"\\Windows\\system32\\config\\SOFTWARE";
	log(3, L"🔈OROpenHive Software");
	hresult = OROpenHive(rucheSoftware.c_str(), &conf.Software);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	//recherche de la bonne sous-clé ControlSet correspondant à CurrentControlSet
	wprintf(L"%s", L" - Searching for the CurrentControlSet subkey : ");
	log(3, L"🔈OROpenKey System/Select");
	hresult = OROpenKey(conf.System, L"Select", &hKey);
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

	DWORD current = 0;

	log(3, L"🔈ORGetValue System/Select/Current");
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
		wprintf(L"%s", L" - Opening the CurrentControlSet subkey : ");
		log(3, L"🔈OROpenKey System/CurrentControlSet");
		hresult = OROpenKey(conf.System, subkey.c_str(), &conf.CurrentControlSet);
		if (hresult != ERROR_SUCCESS) {
			printError(hresult);
			return(hresult);
		}
		else {
			printSuccess();

			wprintf(L"%s", L" - Extracting USBSTOR Registry Keys : ");
			hresult = usbs.getData();
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
			}
			else {
				hresult = usbs.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				usbs.clear();
			}

			wprintf(L"%s", L" - Extracting the MOUNTED DEVICE registry keys : ");
			hresult = mounteddevices.getData();
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
			}
			else {
				hresult = mounteddevices.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mounteddevices.clear();
			}


			wprintf(L"%s", L" - Extracting BAM Registry Keys : ");
			hresult = bams.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = bams.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				bams.clear();
			}

			wprintf(L"%s", L" - Extracting MUICACHE Registry Keys : ");
			hresult = muicaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = muicaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				muicaches.clear();
			}

			wprintf(L"%s", L" - Extracting AMCACHE APPLICATION Registry Keys : ");
			hresult = amcacheapplications.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplications.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			wprintf(L"%s", L" - Extracting AMCACHE APPLICATIONFILE Registry Keys : ");
			hresult = amcacheapplicationfiles.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplicationfiles.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			wprintf(L"%s", L" - Extracting USERASSIST Registry Keys : ");
			hresult = userassists.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = userassists.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				userassists.clear();
			}

			wprintf(L"%s", L" - Extracting RUN Registry Keys : ");
			hresult = runs.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = runs.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				runs.clear();
			}

			wprintf(L"%s", L" - Extracting SHIMCACHE Registry Keys : ");
			hresult = shimcaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shimcaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shimcaches.clear();
			}

			wprintf(L"%s", L" - Extracting SHELLBAGS Registry Keys : ");
			hresult = shellbags.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shellbags.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shellbags.clear();
			}

			wprintf(L"%s", L" - Extracting MRU Registry Keys : ");
			hresult = mrus.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mrus.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mrus.clear();
			}

			wprintf(L"%s", L" - Extracting MRUAPPS Registry Keys : ");
			hresult = mruapps.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mruapps.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mruapps.clear();
			}
		}
	}


	/**************************************************
	* DECONNEXION COM
	***************************************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[COM COMPONENT]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	wprintf(L"%s", L" - Disconnecting COM : ");
	
	log(3, L"🔈COM clear");
	com.clear();
	printSuccess();

	/************************
	*  FICHIERS
	*************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[SEARCHING FOR ARTIFACTS IN FILES]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	wprintf(L"%s", L" - Extracting RECENT DOCS : ");
	hresult = recentdocs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = recentdocs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		recentdocs.clear();
	}

	wprintf(L"%s", L" - Extracting PREFETCHS : ");
	hresult = prefetchs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = prefetchs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		prefetchs.clear();
	}

	wprintf(L"%s", L" - Extracting JUMPLIST AUTOMATIC: ");
	hresult = jumplistAutomatics.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistAutomatics.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		jumplistAutomatics.clear();
	}

	wprintf(L"%s", L" - Extracting JUMPLIST CUSTOM: ");
	hresult = jumplistCustoms.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistCustoms.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		jumplistCustoms.clear();
	}
	/*****************************************
	*            DEMONTAGE SNAPSHOT
	******************************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%s\n", L"[SNAPSHOT]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	wprintf(L"%s", L" - Snapshot disassembly : ");
	log(3, L"🔈RemoveDirectoryW mountpoint");
	if (!RemoveDirectoryW(conf.mountpoint.c_str())) printError(GetLastError());
	else {
		ReleaseInterface(pBackup);
		printSuccess();
	}


	end = time(nullptr);

	wprintf(L"%s%d%s\n", L"END, Time elapsed : ", end - start , L" s");
	wprintf(L"%s\n", L"<<< Press any key to quit >>>");
	getchar();
	CloseHandle(conf.hConsole);

	return ERROR_SUCCESS;
}