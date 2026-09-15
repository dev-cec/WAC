#pragma once

#include <string>
#include <windows.h>
#include "tools.h"
#include "trans_id.h"

/*! Informations système de la machine examinée.
*
*  POURQUOI HORS LIGNE. La version d'origine interrogeait la
*  machine vivante : `GetComputerNameExW`, `RtlGetVersion` et surtout
*  `BrandingFormatString` — qui suppose de CHARGER `winbrand.dll` dans le
*  processus de collecte. Chargement de module et résolution DNS du nom de
*  domaine sont des sollicitations du système examiné, évitables : tout ce qui
*  décrit l'installation est déjà écrit dans les ruches déjà extraites en brut.
*
*  SOURCES REGISTRE
*    - identité   : `SYSTEM\CurrentControlSet\\Control\\ComputerName\\ComputerName`
*                   et `Services\Tcpip\\Parameters` (Hostname, Domain / NV Domain)
*    - OS         : `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`
*    - architecture : `SYSTEM\CurrentControlSet\\Control\Session Manager\Environment`
*    - identifiant machine : `SOFTWARE\\Microsoft\Cryptography\MachineGuid`
*    - fuseau     : déjà relevé par `loadSuspectTimeZone()` (cf. tools.h)
*
*  CE QUI RESTE MESURÉ À CHAUD, ET POURQUOI C'EST LÉGITIME
*  `LocalDateTime` et `LastBootUpTime` ne décrivent pas l'installation mais
*  l'INSTANT de la collecte : aucune ruche ne peut les fournir, et les lire ne
*  laisse aucune trace (`GetSystemTime`, `GetTickCount64`).
*
*  PIÈGE `ProductName` (corrigé ici). Sous Windows 11, `ProductName` vaut
*  toujours « Windows 10 … » : Microsoft ne l'a jamais mis à jour. Le seul
*  discriminant fiable est `CurrentBuild` >= 22000. Sans cette correction, le
*  rapport désignerait un OS faux — c'est-à-dire une erreur de fait dans une
*  pièce d'enquête. `ProductNameRaw` conserve la valeur brute de la ruche pour
*  que la correction reste vérifiable.
*/
struct SystemInfo {
	// --- identité de la machine (ruche SYSTEM) ---
	std::wstring computerName;              //!< nom de l'ordinateur
	std::wstring netbiosName;               //!< nom NetBIOS (Control\\ComputerName)
	std::wstring domainName;                //!< domaine DNS, ou "WORKGROUP" hors domaine
	std::wstring osArchitecture;            //!< architecture de l'OS

	// --- installation (ruche SOFTWARE) ---
	std::wstring osName;                    //!< libellé de l'OS, corrigé pour Windows 11
	std::wstring productNameRaw;            //!< ProductName tel qu'écrit dans la ruche
	std::wstring version;                   //!< "major.minor.build" (+ ".UBR" si connu)
	std::wstring displayVersion;            //!< DisplayVersion / ReleaseId, ex. "23H2"
	std::wstring editionId;                 //!< EditionID, ex. "Professional"
	std::wstring installationType;          //!< "Client" ou "Server"
	std::wstring buildLabEx;                //!< empreinte complète de la build
	std::wstring servicePack;               //!< CSDVersion, si présent
	std::wstring registeredOwner;           //!< propriétaire déclaré à l'installation
	std::wstring registeredOrganization;    //!< organisation déclarée à l'installation
	std::wstring productId;                 //!< identifiant du produit
	std::wstring systemRoot;                //!< chemin d'installation, ex. "C:\\Windows"
	std::wstring machineGuid;               //!< identifiant unique de l'installation
	FILETIME     installDateUtc = { 0, 0 }; //!< date d'installation de l'OS (UTC)

	// --- instant de la collecte (mesuré à chaud) ---
	SYSTEMTIME localDateTime = { 0 };       //!< heure locale au moment de l'exécution
	SYSTEMTIME localDateTimeUtc = { 0 };    //!< heure UTC au moment de l'exécution
	SYSTEMTIME lastBootUpTime = { 0 };      //!< heure locale du dernier démarrage
	SYSTEMTIME lastBootUpTimeUtc = { 0 };   //!< heure UTC du dernier démarrage
	unsigned long long uptimeSeconds = 0;   //!< durée d'activité depuis le démarrage

	/*! Relève les informations système dans les ruches déjà ouvertes.
	* Nécessite `conf.System` ; `conf.Software` et `conf.CurrentControlSet` sont
	* utilisées si disponibles. Un champ sans source reste vide et n'est pas émis.
	*/
	HRESULT getData();

	//! Conversion de l'objet au format JSON
	HRESULT toJson();

	//! Libération mémoire
	void clear();
};
