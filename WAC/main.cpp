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
#include "asciiart.h"
#include "tools.h"
#include "audit.h"
#include "raw_hive.h"
#include "raw_collect.h"
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
#include "recent_docs.h"
#include "jumplist_automatic.h"
#include "jumplist_custom.h"
#include "scheduledTasks.h"
#include "system.h"
#include "sessions.h"
#include "processes.h"
#include "services.h"
#include "users.h"
#include "events.h"

AppliConf conf;// variable globale pour la conf de l'application

void showHelp() {
	SetConsoleTextAttribute(conf.hConsole, 7); // blanc
	wprintf(L"%ls%hs%ls\n", L"\nusage: ", conf.name.c_str(), L" [--debug] [--dump] [--events] [--md5] [--output=output] [--loglevel=2]");
	wprintf(L"%ls\n", L"\t--help or /? : show this help ");
	wprintf(L"%ls\n", L"\t--debug : trace the raw NTFS parser on stderr (path resolution, index blocks, data runs)");
	wprintf(L"%ls\n", L"\t--dump : add hexa value in json files for shellbags and LNK files ");
	wprintf(L"%ls\n", L"\t--events : extract and parse the .evtx event logs (adds ~117 MB to the collection)");
	wprintf(L"%ls\n", L"\t--md5 : activate hash md5 computing for files referenced in artfacts");
	wprintf(L"%ls\n", L"\t--output=[directory name] : directory name to store output files starting from current directory. By default the directory is 'output'");
	wprintf(L"%ls%hs%ls\n", L"\t--loglevel=[0] : define level of details in logfile and activate logging in ", conf.name.c_str(), L".log");
	wprintf(L"\n");
	wprintf(L"%ls\n", L"\t loglevel = 0 => no logging");
	wprintf(L"%ls\n", L"\t loglevel = 1 => activate logging for each artefact type treated");
	wprintf(L"%ls\n", L"\t loglevel = 2 => activate logging for each artefact treated");
	wprintf(L"%ls\n", L"\t loglevel = 3 => activate logging for each subfunction called (used for debug only)");
};

int main(int argc, char* argv[])
{
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

	/* Sortie NON TAMPONNÉE.
	 * wprintf passe par un tampon, alors que SetConsoleTextAttribute (couleurs)
	 * agit immédiatement : le texte sortait donc décalé par rapport à sa couleur
	 * et par rapport à la progression, qui elle force un fflush. On voyait ainsi
	 * « OK » puis le libellé de l'étape, dans le mauvais ordre.
	 * Les libellés d'étape sont écrits sans retour à la ligne, en attente de leur
	 * « OK » : un tampon de ligne ne suffirait donc pas. */
	setvbuf(stdout, NULL, _IONBF, 0);

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

			if (arg == "--debug") conf._debug = true;
			else if (arg == "--dump") conf._dump = true;
			else if (arg == "--events") conf._events = true;
			else if (arg == "--md5") conf.md5 = true;
			else if (arg.substr(0, 9) == "--output=") {
				std::string temp = std::string(arg.substr(9));
				if (temp.length() > 0) conf._outputDir = temp;
				else {
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					wprintf(L"%ls%hs\n", L"Invalid length for output param ", arg.c_str());
					log(3, L"🔈showHelp");
					showHelp();
					exit(1);
				}
				if (conf._outputDir.find("\\") != std::string::npos) {
					SetConsoleTextAttribute(conf.hConsole, 12); // rouge
					wprintf(L"%ls%hs\n", L"Invalid character for param ", arg.c_str());
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
					wprintf(L"%ls%hs\n", L"Invalid numeric value for output param ", arg.c_str());
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

	// Journal d'investigation : ouvert au plus tot pour que l'horodatage de debut
	// encadre reellement toute la collecte (cf. audit.h).
	auditInit(argc, argv);

	/* Trace du parseur NTFS : SILENCIEUSE par défaut, activée par --debug.
	   Elle écrit sur STDERR, donc séparable de la sortie normale :
	       WAC.exe --debug 2> raw.log
	   C'est elle qui a permis de localiser le défaut `$INDEX_ALLOCATION` éclaté
	   ; en usage courant elle noierait la console. */
	RawHiveSetVerbose(conf._debug);

	// Lecteur systeme : releve avant toute extraction, car il determine le volume
	// a lire en brut ET la restitution des chemins d'origine. Windows n'est pas
	// toujours installe sur C:.
	log(3, L"🔈loadSystemDrive");
	loadSystemDrive();

	/************************
	* Prérequis
	*************************/

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Prerequisites :");
	log(0, L"*******************************************************************************************************************");

	log(1, L"➕Check OS");
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%ls\n", L"[PREREQUISITE VERIFICATION]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	printStep(L" - Check OS >= Windows 10 : ");
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
	printSuccess();
#else
	printError(ERROR_APP_WRONG_OS);
	return 1;
#endif
	log(1, L"➕Check administrator rights");
	printStep(L" - Check administrator rights : ");
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


	/* COM SUPPRIME (2026-09-15).
	 * `scheduledTasks` etait le SEUL consommateur de COM dans WAC : il lit
	 * desormais les definitions XML de \Windows\System32\Tasks et l'historique du
	 * TaskCache, hors ligne. Plus rien ne justifiait CoInitializeEx /
	 * CoInitializeSecurity, dont la suppression retire :
	 *   - la sollicitation du service Schedule ;
	 *   - les entrees dans Microsoft-Windows-TaskScheduler/Operational ;
	 *   - le parcours COM tache par tache (plusieurs appels d'interface x 217).
	 * Les autres collecteurs live (processes, sessions, services, users,
	 * systemInfo) n'utilisent que des API Win32 directes.
	 */

	/************************
	* WIN32 API
	*************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%ls\n", L"[SEARCHING FOR ARTIFACTS IN WINDOWS API]");
	SetConsoleTextAttribute(conf.hConsole, 7);

	/* SYSTEM INFORMATION a quitte cette phase : la collecte est desormais hors
	   ligne (ruches SYSTEM et SOFTWARE) et se fait donc APRES leur ouverture,
	   a la fin de la phase registre. Cf. et system.h. */

	printStep(L" - Extraction of SESSIONS: ");
	hresult = sessions.getData();
	auditRecord(L"Collecte SESSIONS", L"LSA / WTS", hresult, Footprint::SESSIONS);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = sessions.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		sessions.clear();// free memory
	}



	printStep(L" - Extraction of PROCESS: ");
	hresult = processes.getData();
	auditRecord(L"Collecte PROCESS", L"CreateToolhelp32Snapshot", hresult, Footprint::PROCESSUS);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = processes.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		processes.clear(); // free memory
	}



	/* SERVICES a quitte cette phase : la configuration est desormais lue dans
	   SYSTEM\CurrentControlSet\Services, donc apres l'ouverture de la ruche.
	   Seul l'etat courant reste releve a chaud, en une seule enumeration.
	   Cf. et services.h. */

	/* USERS a quitte cette phase : les comptes locaux sont desormais lus dans la
	   ruche SAM extraite. Seule subsiste ici la liste des PROFILS, indispensable
	   AVANT l'extraction puisqu'elle donne l'emplacement des ruches par
	   utilisateur. Cf., users.h et tools.h (loadProfileList). */
	printStep(L" - Listing USER PROFILES: ");
	hresult = loadProfileList();
	auditRecord(L"Releve des profils utilisateurs",
	            L"HKLM\\SOFTWARE\\...\\ProfileList (registre local, lecture)",
	            hresult, Footprint::COMPTES_LOCAUX);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else printSuccess();



	// Les journaux d'evenements sont traites EN FIN de collecte : ils resident sur
	// disque, donc figurent parmi les artefacts les moins volatils, et leur
	// extraction dure une vingtaine de minutes sous Windows 11.
	// Les placer ici retardait d'autant la copie brute du disque.

	/************************
	*  EXTRACTION BRUTE (offline, sans VSS, sortie sur USB)
	*************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%ls\n", L"[RAW EXTRACTION]");
	SetConsoleTextAttribute(conf.hConsole, 7);

	const wchar_t* etiquetteRuches = L" - Extracting hives (raw NTFS) : ";
	printStep(etiquetteRuches);
	log(3, L"🔈ExtractHivesRaw");
	hresult = ExtractHivesRaw();          // S_FALSE = ruches partiellement manquantes (toléré)
	                                       // (consigne au journal depuis raw_collect)
	if (FAILED(hresult)) {                 // seul un échec dur (volume) interrompt
		printError(hresult);
		return(hresult);
	}
	else {
		printSuccess();
	}

	// Prefetch, jumplists et documents récents : sans cette extraction, leurs
	// collecteurs ne trouvent aucun fichier et rendent un artefact vide, ce qui
	// se lit à tort comme une absence de trace.
	const wchar_t* etiquetteFichiers = L" - Extracting file artefacts (raw NTFS) : ";
	printStep(etiquetteFichiers);
	log(3, L"🔈ExtractFileArtefactsRaw");
	hresult = ExtractFileArtefactsRaw();  // S_FALSE = certains fichiers illisibles (toléré)
	                                       // (consigne par repertoire depuis raw_collect)
	if (FAILED(hresult)) {
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
	wprintf(L"%ls\n", L"[SEARCHING FOR ARTIFACTS IN THE REGISTRY]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	// Une seule entree pour toute la phase : ces lectures portent sur les COPIES
	// extraites sur le support de collecte, jamais sur le registre de la cible.
	// Elles ne laissent donc aucune trace a distinguer dans les artefacts.
	auditRecord(L"Lecture des artefacts du registre (ruches copiees, offreg)",
	            conf.mountpoint, ERROR_SUCCESS, Footprint::RUCHE_COPIE);
	//variables
	ORHKEY hKey = NULL;
	DWORD typeValeur = 0;
	DWORD taille = 0;


	//chargement de la clé HKLM\SYSTEM
	printStep(L" - loading the HKLM\\SYSTEM key : ");
	std::wstring rucheSystem = conf.mountpoint + L"\\Windows\\system32\\config\\SYSTEM";
	/* Une ruche indisponible ne doit PAS interrompre la collecte.
	   Constaté sur un système réel : SOFTWARE n'avait pas pu être extraite, et le
	   `return` qui suivait abandonnait tout — y compris les artefacts de SYSTEM,
	   les fichiers et les journaux, tous collectables. Le principe est de
	   recueillir tout ce qui est accessible et de consigner ce qui manque. */
	log(3, L"🔈OROpenHive System");
	hresult = OROpenHive(rucheSystem.c_str(), &conf.System);
	const bool systemDisponible = (hresult == ERROR_SUCCESS);
	if (!systemDisponible) {
		printError(hresult);
		log(2, L"🔥Ruche SYSTEM indisponible : artefacts correspondants non collectes", hresult);
		auditRecord(L"Ouverture de la ruche SYSTEM", rucheSystem, hresult, Footprint::RUCHE_COPIE);
		for (const char* f : { "Usbstor.json", "mounted_device.json", "bams.json",
		                       "shimcache.json", "services.json" })
			writeNotCollected(f, L"dépend de la ruche SYSTEM, indisponible", hresult);
	}
	else printSuccess();

	//chargement de la clé HKLM\SOFTWARE
	printStep(L" - loading the HKLM\\SOFTWARE key : ");
	std::wstring rucheSoftware = conf.mountpoint + L"\\Windows\\system32\\config\\SOFTWARE";
	log(3, L"🔈OROpenHive Software");
	hresult = OROpenHive(rucheSoftware.c_str(), &conf.Software);
	const bool softwareDisponible = (hresult == ERROR_SUCCESS);
	if (!softwareDisponible) {
		printError(hresult);
		log(2, L"🔥Ruche SOFTWARE indisponible : artefacts correspondants non collectes", hresult);
		auditRecord(L"Ouverture de la ruche SOFTWARE", rucheSoftware, hresult, Footprint::RUCHE_COPIE);
		writeNotCollected("run.json", L"dépend de la ruche SOFTWARE, indisponible", hresult);
	}
	else printSuccess();

	/* Phase registre encadrée par un bloc à sortie unique : un échec en sort par
	   `break` au lieu d'abandonner la collecte. Les artefacts sur fichiers et les
	   journaux, qui ne dépendent pas de ces ruches, restent collectés. */
	do {
	if (!systemDisponible) break;   // sans SYSTEM, la phase registre est vide de sens

	//recherche de la bonne sous-clé ControlSet correspondant à CurrentControlSet
	printStep(L" - Searching for the CurrentControlSet subkey : ");
	log(3, L"🔈OROpenKey System/Select");
	hresult = OROpenKey(conf.System, L"Select", &hKey);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		break;
	}
	hresult = ORGetValue(hKey, nullptr, L"Current", &typeValeur, nullptr, &taille);
	if (hresult != ERROR_SUCCESS)
	{
		printError(hresult);
		break;
	}

	DWORD current = 0;

	log(3, L"🔈ORGetValue System/Select/Current");
	hresult = ORGetValue(hKey, nullptr, L"Current", &typeValeur, &current, &taille);
	if (hresult != ERROR_SUCCESS)
	{
		printError(hresult);
		break;
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
		printSuccess();

		//ouverture de la clé HKLM\\SYSTEM\\CurrentControlSet
		printStep(L" - Opening the CurrentControlSet subkey : ");
		log(3, L"🔈OROpenKey System/CurrentControlSet");
		hresult = OROpenKey(conf.System, subkey.c_str(), &conf.CurrentControlSet);
		if (hresult != ERROR_SUCCESS) {
			printError(hresult);
			break;
		}
		else {
			printSuccess();

			/* Fuseau du SUSPECT, relevé dans sa ruche SYSTEM.
			   Fait dès l'ouverture de CurrentControlSet : tous les horodatages
			   locaux formatés ensuite portent son décalage, et non celui de la
			   machine qui exécute WAC. Indispensable pour interpréter les
			   artefacts qui stockent une heure locale (dates FAT, Amcache, BAM,
			   shimcache, USBSTOR, UserAssist). */
			printStep(L" - Reading suspect time zone (SYSTEM hive) : ");
			log(3, L"🔈loadSuspectTimeZone");
			hresult = loadSuspectTimeZone();
			if (hresult != ERROR_SUCCESS) {
				// Non bloquant : repli sur le fuseau de la machine d'execution,
				// correct en collecte live puisque c'est la meme machine.
				printError(hresult);
			}
			else printSuccess();
			auditRecord(L"Relevé du fuseau horaire du suspect",
			            L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
			            hresult, Footprint::RUCHE_COPIE);

			printStep(L" - Extracting USBSTOR Registry Keys : ");
			hresult = usbs.getData();
			if (hresult != ERROR_SUCCESS) {
				printError(hresult);
				// La cle Enum\USBSTOR est absente des systemes ou aucun
				// peripherique de masse n'a jamais ete branche : echec legitime,
				// mais qui doit apparaitre dans la sortie plutot que de laisser
				// un fichier manquant (cf. writeNotCollected).
				writeNotCollected("Usbstor.json", L"USBSTOR (registre)", hresult);
			}
			else {
				hresult = usbs.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				usbs.clear();
			}

			printStep(L" - Extracting the MOUNTED DEVICE registry keys : ");
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


			printStep(L" - Extracting BAM Registry Keys : ");
			hresult = bams.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = bams.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				bams.clear();
			}

			printStep(L" - Extracting MUICACHE Registry Keys : ");
			hresult = muicaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = muicaches.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				muicaches.clear();
			}

			printStep(L" - Extracting AMCACHE APPLICATION Registry Keys : ");
			hresult = amcacheapplications.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplications.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			printStep(L" - Extracting AMCACHE APPLICATIONFILE Registry Keys : ");
			hresult = amcacheapplicationfiles.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = amcacheapplicationfiles.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				amcacheapplicationfiles.clear();
			}

			printStep(L" - Extracting USERASSIST Registry Keys : ");
			hresult = userassists.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = userassists.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				userassists.clear();
			}

			printStep(L" - Extracting RUN Registry Keys : ");
			hresult = runs.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = runs.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				runs.clear();
			}

			printStep(L" - Extracting SHIMCACHE Registry Keys : ");
			hresult = shimcaches.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shimcaches.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shimcaches.clear();
			}

			printStep(L" - Extracting SHELLBAGS Registry Keys : ");
			hresult = shellbags.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = shellbags.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				shellbags.clear();
			}

			printStep(L" - Extracting MRU Registry Keys : ");
			hresult = mrus.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mrus.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mrus.clear();
			}

			printStep(L" - Extracting MRUAPPS Registry Keys : ");
			hresult = mruapps.getData();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else {
				hresult = mruapps.toJson();
				if (hresult != ERROR_SUCCESS) printError(hresult);
				else printSuccess();
				mruapps.clear();
			}
		}
	}
	} while (0);   // fin de la phase registre (voir le bloc à sortie unique ci-dessus)

	/* SYSTEM INFORMATION, hors ligne.
	   HORS du bloc a sortie unique ci-dessus, et non dedans : meme sans ruche
	   exploitable, le collecteur reste utile puisqu'il consigne l'instant de la
	   collecte et la duree d'activite. Il degrade sa sortie au lieu d'etre
	   saute. */
	printStep(L" - Extraction of SYSTEM INFORMATION: ");
	hresult = systemInfo.getData();
	auditRecord(L"Collecte SYSTEM INFORMATION",
	            L"ruches SYSTEM et SOFTWARE extraites + heure système",
	            hresult, Footprint::RUCHE_COPIE);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = systemInfo.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		systemInfo.clear();// free memory
	}

	/* SERVICES, configuration hors ligne + etat courant.
	   Egalement hors du bloc a sortie unique : sans ruche, getData() echoue
	   proprement et writeNotCollected a deja consigne l'absence. */
	printStep(L" - Extraction of SERVICES: ");
	hresult = services.getData();
	auditRecord(L"Collecte SERVICES",
	            L"ruche SYSTEM\\CurrentControlSet\\Services + EnumServicesStatusExW",
	            hresult, Footprint::SCM);
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = services.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		services.clear();//free memory
	}

	/* USERS, hors ligne depuis la ruche SAM. Independant des
	   ruches SYSTEM et SOFTWARE : il ouvre la sienne. */
	printStep(L" - Extraction of USERS: ");
	hresult = users.getData();
	auditRecord(L"Collecte USERS", L"ruche SAM extraite", hresult, Footprint::RUCHE_COPIE);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		writeNotCollected("users.json", L"dépend de la ruche SAM, indisponible", hresult);
	}
	else {
		hresult = users.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		users.clear(); // free memory
	}


	/************************
	*  FICHIERS
	*************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%ls\n", L"[SEARCHING FOR ARTIFACTS IN FILES]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	// Comme pour le registre : lecture des COPIES extraites, pas des fichiers de
	// la cible — donc aucun horodatage d'acces modifie sur le systeme examine.
	auditRecord(L"Lecture des artefacts sur fichiers (copies extraites)",
	            conf.mountpoint, ERROR_SUCCESS, Footprint::RUCHE_COPIE);
	/* Tâches planifiées : lues depuis les XML extraits en brut et le TaskCache
	   du registre. Déplacé de la phase « WINDOWS API » à ici, car la collecte
	   dépend désormais de l'extraction brute — plus du service Schedule. */
	printStep(L" - Extracting SCHEDULED TASKS (offline) : ");
	hresult = scheduledTasks.getData();
	auditRecord(L"Collecte SCHEDULED TASKS",
	            L"\\Windows\\System32\\Tasks (XML) + SOFTWARE\\...\\TaskCache",
	            hresult, Footprint::RUCHE_COPIE);
	if (hresult != ERROR_SUCCESS) {
		printError(hresult);
		writeNotCollected("ScheduledTasks.json",
		                  L"définitions de tâches non extraites", hresult);
	}
	else {
		hresult = scheduledTasks.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		scheduledTasks.clear(); // free memory
	}

	printStep(L" - Extracting RECENT DOCS : ");
	hresult = recentdocs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = recentdocs.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		recentdocs.clear();
	}

	printStep(L" - Extracting PREFETCHS : ");
	hresult = prefetchs.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = prefetchs.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		prefetchs.clear();
	}

	printStep(L" - Extracting JUMPLIST AUTOMATIC: ");
	hresult = jumplistAutomatics.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistAutomatics.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		jumplistAutomatics.clear();
	}

	printStep(L" - Extracting JUMPLIST CUSTOM: ");
	hresult = jumplistCustoms.getData();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else {
		hresult = jumplistCustoms.toJson();
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else printSuccess();
		jumplistCustoms.clear();
	}
	/************************
	*  JOURNAUX D'ÉVÉNEMENTS (les moins volatils : traités en dernier)
	*************************/
	if (conf._events) {
		SetConsoleTextAttribute(conf.hConsole, 14);
		wprintf(L"%ls\n", L"[SEARCHING FOR ARTIFACTS IN EVENT LOGS]");
		SetConsoleTextAttribute(conf.hConsole, 7);
		printStep(L" - Extraction of EVENTS: ");

		hresult = events.getData();
		/* La source n'est plus le service EventLog mais les fichiers .evtx
		   extraits par lecture brute : la consignation doit dire lesquels, sans
		   quoi le rapport laisse croire que l'API a encore ete sollicitee. */
		auditRecord(L"Collecte EVENT LOGS (" + std::to_wstring(events.lus)
		            + L" evenement(s) dans " + std::to_wstring(events.fichiers)
		            + L" journal/journaux)",
		            L"\\Windows\\System32\\winevt\\Logs\\*.evtx (copies extraites)",
		            hresult, Footprint::FICHIER_COPIE);
		if (hresult != ERROR_SUCCESS) printError(hresult);
		else {
			hresult = events.toJson();
			if (hresult != ERROR_SUCCESS) printError(hresult);
			else printSuccess();
			events.clear(); // free memory
		}
	}

	/*****************************************
	*   Ruches extraites conservées sur l'USB (preuve) — rien à démonter
	******************************************/


	/************************
	*  JOURNAL D'INVESTIGATION (en dernier : il consigne toute la collecte)
	*************************/
	SetConsoleTextAttribute(conf.hConsole, 14);
	wprintf(L"%ls\n", L"[INVESTIGATION LOG]");
	SetConsoleTextAttribute(conf.hConsole, 7);
	/* L'ECRITURE sur le support de collecte est elle aussi une operation a
	   consigner : c'est la seule ecriture que WAC effectue, et un journal
	   d'audit qui ne la mentionne pas laisse croire que rien n'a ete ecrit.
	   Consignee AVANT auditWrite(), sans quoi elle manquerait au journal. */
	auditRecord(L"Ecriture des resultats de collecte",
	            string_to_wstring(conf._outputDir), ERROR_SUCCESS,
	            Footprint::ECRITURE_USB);

	printStep(L" - Writing investigation.json : ");
	log(3, L"🔈auditWrite");
	hresult = auditWrite();
	if (hresult != ERROR_SUCCESS) printError(hresult);
	else printSuccess();

	end = time(nullptr);

	wprintf(L"%ls%d%ls\n", L"END, Time elapsed : ", end - start , L" s");
	wprintf(L"%ls\n", L"<<< Press any key to quit >>>");
	getchar();
	CloseHandle(conf.hConsole);

	return ERROR_SUCCESS;
}