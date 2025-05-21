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

AppliConf conf;// variable globale pour la conf de l'application

void showHelp() {
	SetConsoleTextAttribute(conf.hConsole, 7); // blanc
	std::cout << "\nusage: " << conf.name << " [--dump] [--events] [--output=output] [--loglevel=2]" << std::endl;
	std::cout << "\t--help or /? : show this help " << std::endl;
	std::cout << "\t--dump : add hexa value in json files for shellbags and LNK files " << std::endl;
	std::cout << "\t--events : converts events to json (long time)" << std::endl;
	std::cout << "\t--output=[directory name] : directory name to store output files starting from current directory. By default the directory is 'output'" << std::endl;
	std::cout << "\t--loglevel=[0] : define level of details in logfile and activate logging in " << conf.name << ".log" << std::endl;
	std::cout << std::endl;
	std::cout << "\t loglevel = 0 => no logging" << std::endl;
	std::cout << "\t loglevel = 1 => activate loggin for each artefact type treated" << std::endl;
	std::cout << "\t loglevel = 2 => activate loggin for each artefact treated" << std::endl;
	std::cout << "\t loglevel = 3 => activate loggin for each subfunction called (used for debug only)" << std::endl;
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

	std::cout << R"(
	

	██╗    ██╗██╗███╗   ██╗██████╗  ██████╗ ██╗    ██╗███████╗                 
	██║    ██║██║████╗  ██║██╔══██╗██╔═══██╗██║    ██║██╔════╝                 
	██║ █╗ ██║██║██╔██╗ ██║██║  ██║██║   ██║██║ █╗ ██║███████╗                 
	██║███╗██║██║██║╚██╗██║██║  ██║██║   ██║██║███╗██║╚════██║                 
	╚███╔███╔╝██║██║ ╚████║██████╔╝╚██████╔╝╚███╔███╔╝███████║                 
	 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝                 
	                                                                           
	 █████╗ ██████╗ ████████╗███████╗███████╗ █████╗  ██████╗████████╗███████╗ 
	██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝ 
	███████║██████╔╝   ██║   █████╗  █████╗  ███████║██║        ██║   ███████╗ 
	██╔══██║██╔══██╗   ██║   ██╔══╝  ██╔══╝  ██╔══██║██║        ██║   ╚════██║ 
	██║  ██║██║  ██║   ██║   ███████╗██║     ██║  ██║╚██████╗   ██║   ███████║ 
	╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝ 
	                                                                           
	 ██████╗ ██████╗ ██╗     ██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗ 
	██╔════╝██╔═══██╗██║     ██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
	██║     ██║   ██║██║     ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝
	██║     ██║   ██║██║     ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
	╚██████╗╚██████╔╝███████╗███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
	 ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
	
	=> V 1.1.1 By Reygiss from CEC 

	)" << std::endl;

	std::cout.flush();

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
			else if (arg.substr(0, 9) == "--output=") {
				std::string temp = std::string(arg.substr(9));
				if (temp.length() > 0) conf._outputDir = temp;
				else {
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					std::cerr << "Invalid length for output param " << arg << "\n";
					showHelp();
					exit(1);
				}
				if (conf._outputDir.find("\\") != std::string::npos) {
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					std::cerr << "Invalid character for param " << arg << "\n";
					showHelp();
					exit(1);
				}
			}
			else if (arg.substr(0, 11) == "--loglevel=") {
				std::string temp = std::string(arg.substr(11));
				try {
					conf.loglevel = stoi(temp);
				}catch(...)
				{
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					std::cerr << "Invalid numeric value for output param " << arg << "\n";
					showHelp();
					exit(1);
				}
			}
	
			else { //argument inconnu
				SetConsoleOutputCP(CP_UTF8);
				if (arg != "--help" && arg !="/?") { // Si pas argument --help ou /? alors argument invalide
					printError( L"Invalid argument  " + string_to_wstring(arg));
				}

				showHelp();
				exit(1);
			}
		}
	}

	/************************
	* Prérequis
	*************************/

	SetConsoleTextAttribute(conf.hConsole, 14);
	std::wcout << "[PREREQUISITE VERIFICATION]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
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
		printError( ERROR_ELEVATION_REQUIRED);
		return 3;
	}
	CloseHandle(hToken);
	printSuccess();
#else
	printError(ERROR_APP_WRONG_OS);
	return 1;
#endif

	/**********************************
	* CONNECTION COM
	**********************************/

	SetConsoleTextAttribute(conf.hConsole, 14);
	std::wcout << "[COM COMPONENT]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);

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
	SetConsoleTextAttribute(conf.hConsole, 14);
	std::wcout << "[SEARCHING FOR ARTIFACTS IN WINDOWS API]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
	
	std::wcout << " - Extraction of SYSTEM INFORMATION: ";
	hresult = systemInfo.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = systemInfo.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		systemInfo.clear();// free memory
	}
	

	std::wcout << " - Extraction of SCHEDULED TASKS: ";
	hresult = scheduledTasks.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = scheduledTasks.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		scheduledTasks.clear(); // free memory
	}
	
	

	std::wcout << " - Extraction of SESSIONS: ";
	hresult = sessions.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = sessions.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		sessions.clear();// free memory
	}
	
	

	std::wcout << " - Extraction of PROCESS: ";
	hresult = processes.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = processes.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		processes.clear(); // free memory
	}
	
	

	std::wcout << " - Extraction of SERVICES: ";
	std::wcout.flush();
	hresult = services.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = services.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		services.clear();//free memory
	}

	
	
	std::wcout << " - Extraction of USERS: ";
	std::wcout.flush();
	hresult = users.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = users.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		users.clear(); // free memory
	}
	
	

	if (conf._events) {
		std::wcout << " - Extraction of EVENTS: ";
		std::wcout.flush();
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
	std::wcout << "[SNAPSHOT]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);

	std::wcout << " - Creating the snapshot : ";
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
	std::wcout << "[SEARCHING FOR ARTIFACTS IN THE REGISTRY]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
	//variables
	ORHKEY hKey=NULL;
	LPTSTR errorText = NULL;
	DWORD nSubkeys = 0;
	DWORD nValues = 0;
	DWORD nSize = 0;
	DWORD dwType = 0;
	DWORD cbData = 0;
	ORHKEY OffKeyNext=NULL;
	WCHAR szValue[MAX_VALUE_NAME]=L"";
	WCHAR szSubKey[MAX_KEY_NAME]=L"";
	WCHAR szNextKey[MAX_KEY_NAME]=L"";
	DWORD dwSize = 0;


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
	DWORD current=0;
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

			std::wcout << " - Extracting the MOUNTED DEVICE registry keys : ";
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


			std::wcout << " - Extracting BAM Registry Keys : ";
			hresult = bams.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = bams.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				bams.clear();
			}

			std::wcout << " - Extracting MUICACHE Registry Keys : ";
			hresult = muicaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = muicaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				muicaches.clear();
			}

			std::wcout << " - Extracting AMCACHE APPLICATION Registry Keys : ";
			hresult = amcacheapplications.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplications.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			std::wcout << " - Extracting AMCACHE APPLICATIONFILE Registry Keys : ";
			hresult = amcacheapplicationfiles.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplicationfiles.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			std::wcout << " - Extracting USERASSIST Registry Keys : ";
			hresult = userassists.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = userassists.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				userassists.clear();
			}

			std::wcout << " - Extracting RUN Registry Keys : ";
			hresult = runs.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = runs.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				runs.clear();
			}

			std::wcout << " - Extracting SHIMCACHE Registry Keys : ";
			hresult = shimcaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shimcaches.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shimcaches.clear();
			}

			std::wcout << " - Extracting SHELLBAGS Registry Keys : ";
			hresult = shellbags.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shellbags.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shellbags.clear();
			}

			std::wcout << " - Extracting MRU Registry Keys : ";
			hresult = mrus.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mrus.to_json();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mrus.clear();
			}

			std::wcout << " - Extracting MRUAPPS Registry Keys : ";
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
	std::wcout << "[COM COMPONENT]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
	std::wcout << " - Disconnecting COM : ";
	std::wcout.flush();
	com.clear();
	printSuccess();

	/************************
	*  FICHIERS
	*************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	std::wcout << "[SEARCHING FOR ARTIFACTS IN FILES]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
	std::wcout << " - Extracting RECENT DOCS : ";
	hresult = recentdocs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = recentdocs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		recentdocs.clear();
	}

	std::wcout << " - Extracting PREFETCHS : ";
	hresult = prefetchs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = prefetchs.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		prefetchs.clear();
	}

	std::wcout << " - Extracting JUMPLIST AUTOMATIC: ";
	hresult = jumplistAutomatics.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistAutomatics.to_json();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		jumplistAutomatics.clear();
	}

	std::wcout << " - Extracting JUMPLIST CUSTOM: ";
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
	std::wcout << "[SNAPSHOT]" << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
	std::wcout << " - Snapshot disassembly : ";
	if (!RemoveDirectoryW(conf.mountpoint.c_str())) printError(GetLastError());
	else {
		ReleaseInterface(pBackup);
		printSuccess();
	}


	end = time(nullptr);

	std::wcout << L"END, Time elapsed : " << end - start << " s" << std::endl;

	CloseHandle(conf.hConsole);
	
	return ERROR_SUCCESS;
}