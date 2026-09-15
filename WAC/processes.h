#pragma once

/*  processes.h — PROCESSUS EN COURS D'EXÉCUTION.
 *
 *  Reste volontairement en collecte LIVE : son objet est l'état instantané de la
 *  machine, qui n'existe nulle part sur disque.
 *
 *  POURQUOI PLUS AUCUN `OpenProcess`. La version d'origine ouvrait un handle par
 *  processus avec `PROCESS_ALL_ACCESS`, puis son jeton avec `TOKEN_ALL_ACCESS`,
 *  alors que seul le SID du propriétaire était lu. Deux conséquences :
 *    - les processus PROTÉGÉS refusaient l'ouverture — sur une VM Windows 11,
 *      16 processus sur 125 (System, Registry, smss, csrss, wininit, services,
 *      lsass, MsMpEng, NisSrv, SecurityHealthService…) sortaient SANS
 *      propriétaire, soit précisément ceux dont l'usurpation compte le plus ;
 *    - demander un accès total en écriture et en injection sur chaque processus
 *      est l'empreinte la plus lourde possible, et le motif que surveillent les
 *      protections en place.
 *
 *  Le SID et la session viennent désormais d'un SEUL appel
 *  `WTSEnumerateProcessesExW`, qui les rend pour TOUS les processus sans ouvrir
 *  aucun handle. Moins d'empreinte, et plus de données.
 *
 *  La liste des modules passe par `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`,
 *  qui n'a jamais eu besoin du handle. Elle est donc collectée même quand le
 *  propriétaire est inconnu : les deux lectures sont indépendantes, et les
 *  enchaîner faisait perdre les modules à chaque échec de jeton.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <map>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include <sddl.h>
#include "tools.h"
#include "quickdigest5.h"



/*! structure représentant un process */
struct Process {
	std::wstring processName = L""; //!< Nom du processus
	DWORD processId = 0; //!< Id du processus
	std::wstring md5 = L""; //!< hash md5 du process exe
	DWORD processParentId = 0;//!< Id du processus Parent
	DWORD processThreadCount = 0;//!< Nombre de threads
	std::wstring processSidName = L"";//!< nom de l'utilisateur propriétaire du processus
	std::wstring processSID = L"";//!< sid de l'utilisateur propriétaire du processus
	DWORD sessionId = 0;              //!< session hébergeant le processus
	bool  sessionConnue = false;      //!< true si la session a pu être relevée
	std::wstring processModulesAccess = L"OK";
	std::vector<std::wstring> processModules; //!< Liste des Dlls chargées par le programme. La première entrée contient le chemin de l’exécutable

	/*! Constructeur
	* @param pe32 pointeur sur l'entrée de l'instantané Toolhelp
	*/
	explicit Process(const PROCESSENTRY32W* pe32);

	/*! Fonction récupérant la liste des modules (Dlls) du processus

	*/
	HRESULT ListProcessModules();

	/*! conversion de l'objet au format json */
	Json toJson() const;

	/* liberation mémoire */
	void clear();
};

/*! structure contenant l'ensemble des objets
*/
struct Processes {
	std::vector<Process> processes; //!< tableau contenant tout les processus


	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};





