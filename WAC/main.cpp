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

void showHelp(HANDLE hConsole, AppliConf conf) {
	SetConsoleTextAttribute(hConsole, 7); // blanc
	std::cout << "\nusage: " << conf.name << " [--dump] [--debug] [--events] [--ouput=ouput] [--errorOuput=errors]\n";
	std::cout << "\t--help or /? : show this help \n";
	std::cout << "\t--dump : add std::hexa value in json files for shellbags and LNK files \n";
	std::cout << "\t--debug : add error output files\n";
	std::cout << "\t--events : converts events to json (long time)\n";
	std::cout << "\t--output=[path] : relative directory path to store output files starting from current directory. By default the directory is 'output'\n";
	std::cout << "\t--errorOutput=[path] : relative directory path to store error output files starting from current directory. By default the directory is 'errors'\n";
};

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
	SystemInfo systemInfo;
	Sessions sessions;
	Processes processes;
	Users users;
	Events events;
	AppliConf conf;

	time_t start = 0, end = 0;

	SetConsoleOutputCP(CP_UTF8); // format UTF8 pour la prise en compte des accents dans la console car retour en UTF8

	/************************
	* fonctions utiles
	*************************/

	start = time(nullptr);//heure de depart du logiciel pour benchmark

	/************************
	* Arguments
	*************************/

	conf.name = argv[0];
	if (argc > 1) { // au moins un argument, argv[0] étant le nom du logiciel
		//Prise en compte des arguments de la ligne de commande
		const std::vector<std::string_view> args(argv + 1, argv + argc);
		for (const auto& arg : args) {

			if (arg == "--dump") conf._dump = true;
			else if (arg == "--debug") conf._debug = true;
			else if (arg == "--events") conf._events = true;
			else if (arg.substr(0, 9) == "--output=") {
				std::string temp = std::string(arg.substr(9));
				if (temp.length() > 0) conf._outputDir = temp;
				else {
					SetConsoleTextAttribute(hConsole, 12); // rouge
					std::cerr << "Invalid length for output param " << arg << "\n";
					showHelp(hConsole, conf);
					exit(1);
				}
			}
			else if (arg.substr(0, 14) == "--errorOutput=") {
				std::string temp = std::string(arg.substr(14));
				if (temp.length() > 0) conf._errorOutputDir = temp;
				else {
					SetConsoleTextAttribute(hConsole, 12); // rouge
					std::cerr << "Invalid length for errorOutput param " << arg << "\n";
					showHelp(hConsole, conf);
					exit(1);
				}
			}
			else { //argument inconnu
				SetConsoleOutputCP(CP_UTF8);
				if (arg != "--help" && arg !="/?") { // Si pas argument --help ou /? alors argument invalide
					SetConsoleTextAttribute(hConsole, 12); // rouge
					std::cerr << "Invalid argument " << arg << "\n";
				}

				showHelp(hConsole, conf);
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
	hresult = systemInfo.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = systemInfo.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of SCHEDULED TASKS: ";
	hresult = scheduledTasks.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = scheduledTasks.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of SESSIONS: ";
	hresult = sessions.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = sessions.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of PROCESS: ";
	hresult = processes.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = processes.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of SERVICES: ";
	std::wcout.flush();
	hresult = services.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = services.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extraction of USERS: ";
	std::wcout.flush();
	hresult = users.getData(&conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = users.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	if (conf._events) {
		std::wcout << " - Extraction of EVENTS: ";
		std::wcout.flush();
		hresult = events.getData(conf);
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
	VSS_ID snapshotSetId = { 0 };
	LPCWSTR lpMountpoint = L"";

	std::wcout << " - Creating the snapshot : ";
	hresult = GetSnapshots(&lpMountpoint, &snapshotSetId, pBackup);
	if (hresult != S_OK) {
		printError(hresult);
		return(hresult);
	}
	else {
		conf.mountpoint = std::wstring(lpMountpoint);
		printSuccess();
	}


	//chargement de la clé HKLM\SYSTEM
	std::wcout << " - loading the HKLM\\SYSTEM key : ";
	std::wstring rucheSystem = conf.mountpoint + L"\\Windows\\system32\\config\\SYSTEM";
	hresult = OROpenHive(rucheSystem.c_str(), &conf.System);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	//chargement de la clé HKLM\SOFTWARE
	std::wcout << " - loading the HKLM\\SOFTWARE key : ";
	std::wstring rucheSoftware = conf.mountpoint + L"\\Windows\\system32\\config\\SOFTWARE";
	hresult = OROpenHive(rucheSoftware.c_str(), &conf.Software);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	//recherche de la bonne sous-clé ControlSet correspondant à CurrentControlSet
	std::wcout << " - Searching for the CurrentControlSet subkey : ";
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
		hresult = OROpenKey(conf.System, subkey.c_str(), &conf.CurrentControlSet);
		if (hresult != ERROR_SUCCESS) {
			printError(hresult);
			return(hresult);
		}
		else {
			printSuccess();

			std::wcout << " - Extracting USBSTOR Registry Keys : ";
			hresult = usbs.getData(conf);
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
			}
			else {
				hresult = usbs.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting the MOUNTED DEVICE registry keys : ";
			hresult = mouteddevices.getData(conf);
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
			}
			else {
				hresult = mouteddevices.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}


			std::wcout << " - Extracting BAM Registry Keys : ";
			hresult = bams.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = bams.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting MUICACHE Registry Keys : ";
			hresult = muicaches.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = muicaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting AMCACHE APPLICATION Registry Keys : ";
			hresult = amcacheapplications.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplications.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting AMCACHE APPLICATIONFILE Registry Keys : ";
			hresult = amcacheapplicationfiles.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplicationfiles.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting USERASSIST Registry Keys : ";
			hresult = userassists.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = userassists.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting RUN Registry Keys : ";
			hresult = runs.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = runs.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting SHIMCACHE Registry Keys : ";
			hresult = shimcaches.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shimcaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting SHELLBAGS Registry Keys : ";
			hresult = shellbags.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shellbags.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting MRU Registry Keys : ";
			hresult = mrus.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mrus.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}

			std::wcout << " - Extracting MRUAPPS Registry Keys : ";
			hresult = mruapps.getData(conf);
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mruapps.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
			}
		}
	}
	std::wcout << " - Snapshot disassembly : ";
	if (!RemoveDirectory(lpMountpoint)) printError(GetLastError());
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
	hresult = recentdocs.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = recentdocs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extracting PREFETCHS : ";
	hresult = prefetchs.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = prefetchs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extracting JUMPLIST AUTOMATIC: ";
	hresult = jumplistAutomatics.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistAutomatics.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::wcout << " - Extracting JUMPLIST CUSTOM: ";
	hresult = jumplistCustoms.getData(conf);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistCustoms.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
	}

	std::cout.flush();

	end = time(nullptr);

	std::wcout << L"END, Time elapsed : " << end - start << " s" << std::endl;
	return ERROR_SUCCESS;
}