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



/*! structure représentant un AMCACHE APPLICATION
*/
struct AmcacheApplication {
public:
	std::wstring Name = L""; //!< nom du produit
	std::wstring Publisher = L"";//!< nom de la compagnie
	std::wstring RootDirPath = L"";//!< chemin du repertoire racine
	std::wstring Version = L"";//!< version de l'objet
	std::wstring InstallDate = L"";//!< date d'installation de l'application
	std::wstring InstallDateUtc = L"";//!< date d'installation de l'application au format UTC

	/*! Constructeur
	* @param hKey_amcache contient la clé de registre à parser
	*/
	AmcacheApplication(ORHKEY hKey_amcache);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();
	/*liberation mémoire */
	void clear();
};

/*! *structure contenant l'ensemble des AMCACHE APPLICATION
*/
struct AmcacheApplications {
public:
	std::vector<AmcacheApplication> amcacheapplications; //!< tableau contenant tous les AMCACHE APPLICATIONS
	

	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/*liberation mémoire */
	void clear();
};