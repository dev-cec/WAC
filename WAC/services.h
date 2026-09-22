#pragma once

#include "binaires.h"
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include "trans_id.h"
#include "tools.h"
#include "quickdigest5.h"
#include "json.h"

/*! Services et pilotes de la machine examinée.
*
*  POURQUOI LA RUCHE PLUTÔT QUE LE GESTIONNAIRE DE SERVICES.
*  La version d'origine appelait `OpenServiceW` puis `QueryServiceConfigW` pour
*  CHAQUE service, soit plusieurs centaines d'ouvertures de handle sur le SCM.
*  Toute cette configuration est écrite dans
*  `SYSTEM\CurrentControlSet\\Services`, déjà extraite en brut : la lire hors
*  ligne supprime ces appels et apporte, en plus, ce que le SCM ne donne pas.
*
*  CE QUE LA RUCHE AJOUTE
*    - les PILOTES (`SERVICE_KERNEL_DRIVER`, `SERVICE_FILE_SYSTEM_DRIVER`) :
*      l'énumération d'origine filtrait sur `SERVICE_WIN32` et les excluait
*      tous, alors qu'un pilote malveillant est un vecteur de persistance
*      majeur ;
*    - `LastWriteTime` de la clé : l'instant où le service a été créé ou
*      modifié. Aucune API du SCM ne le donne, et c'est souvent la donnée la
*      plus parlante de l'artefact ;
*    - `ServiceDll` (sous `Parameters`) : pour un service hébergé dans
*      svchost.exe, `ImagePath` ne nomme que svchost — le code réellement
*      exécuté est cette DLL ;
*    - `FailureCommand` : commande lancée en cas d'échec du service, détournée
*      comme mécanisme de persistance ;
*    - les services encore inscrits dans la ruche mais absents du SCM.
*
*  CE QUI RESTE MESURÉ À CHAUD, ET POURQUOI
*  `Status` et `ProcessId` n'existent pas sur disque : ils décrivent l'instant
*  de la collecte. Une SEULE énumération (`EnumServicesStatusExW`) les relève
*  pour tous les services à la fois, sans aucun `OpenServiceW` — l'empreinte est
*  donc plus faible qu'avant la bascule, pas plus forte. Les abandonner aurait
*  coûté la corrélation avec processes.json, que rien ne remplace.
*  `LiveStatusAvailable` dit si ce relevé a abouti, pour qu'un service arrêté ne
*  se confonde pas avec un service dont l'état n'a pas pu être lu.
*/
struct ServiceStruct
{
	std::wstring serviceName;               //!< nom interne (nom de la sous-clé)
	std::wstring serviceDisplayName;        //!< nom affiché
	std::wstring serviceDescription;        //!< description (parfois "@dll,-id")
	std::wstring serviceType;               //!< drapeaux de type, décomposés
	std::wstring serviceStartType;          //!< mode de démarrage
	std::wstring serviceErrorControl;       //!< comportement en cas d'échec
	std::wstring serviceOwner;              //!< compte d'exécution (ObjectName)
	std::wstring serviceBinary;             //!< ImagePath, tel qu'écrit dans la ruche
	std::wstring serviceDll;                //!< Parameters\\ServiceDll, si présent
	std::wstring serviceFailureCommand;     //!< commande exécutée en cas d'échec
	std::wstring serviceGroup;              //!< groupe de chargement
	std::vector<std::wstring> dependances;  //!< DependOnService
	EmpreinteBinaire serviceEmpreinte;      //!< empreintes du binaire, si --binary
	EmpreinteBinaire serviceDllEmpreinte;   //!< empreintes de la ServiceDll, si --binary
	FILETIME lastWriteTimeUtc = { 0, 0 };   //!< dernière écriture de la clé (UTC)
	FILETIME lastWriteTime = { 0, 0 };      //!< idem, heure locale du suspect

	// --- état volatil, relevé à chaud ---
	bool         etatReleve = false;        //!< true si le SCM a répondu pour ce service
	std::wstring serviceStatus;             //!< état courant
	DWORD        serviceProcessId = 0;      //!< PID hébergeant le service, 0 si arrêté

	//! Conversion de l'objet au format JSON
	Json toJson() const;

	//! Libération mémoire
	void clear();
};

//! État volatil d'un service, relevé en une seule énumération du SCM.
struct EtatService {
	std::wstring status;
	DWORD processId = 0;
};

struct Services
{
	std::vector<ServiceStruct> services; //!< tableau contenant tous les services

	/*! Relève les services dans `SYSTEM\CurrentControlSet\\Services`, puis
	* complète l'état courant depuis le gestionnaire de services.
	*/
	HRESULT getData();

	//! Conversion de l'objet au format JSON
	HRESULT toJson();

	//! Libération mémoire
	void clear();
};
