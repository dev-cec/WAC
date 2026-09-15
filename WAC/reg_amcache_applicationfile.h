#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include "tools.h"
#include "usb.h"
#include "quickdigest5.h"


struct AmcacheApplicationFile {
public:
	std::wstring name = L""; //!< nom de l’exécutable
	std::wstring publisher = L"";//!< nom de la compagnie
	std::wstring longPath = L""; //!< chemin d'accès  à l’exécutable
	std::wstring md5 = L""; //!< md5 de l’exécutable
	std::wstring version = L"";//!< version de l’exécutable
	std::wstring linkDate = L"";//!< date de création de l'AMCACHE APPLICATION FILE
	std::wstring linkDateUtc = L"";//!< date de création de l'AMCACHE APPLICATION FILE au format UTC
	bool IsOsComponent = false;//!< cet exécutable fait-il parti de l'OS ?

	/*! constructeur
	* @param hKey_amcache représente la clé de registre à parser
	*/
	AmcacheApplicationFile(ORHKEY hKey_amcache);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! *structure contenant l'ensemble des AMCACHE APPLICATION FILES
*/
struct AmcacheApplicationFiles {
public:
	std::vector<AmcacheApplicationFile> amcacheapplicationfiles;//!< tableau contenant tous les AMCACHE APPLICATIONS FILES


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/*liberation mémoire */
	void clear();
};