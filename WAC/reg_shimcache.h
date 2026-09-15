#pragma once

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include "tools.h"
#include "quickdigest5.h"
#include "usb.h"

/*! structure représentant un artefact ShimCache
*/
struct Shimcache {
public:
	std::wstring path = L""; //!< chemin vers le fichier cible de l'artefact
	std::wstring md5 = L""; //!< hash md5 du fichier cible de l'artefact
	std::wstring lastModification = L""; //!< date de modification
	std::wstring lastModificationUtc = L"";//!< date de modification au format json
	bool executed = false;//!< true si le fichier a été exécuté, non fiable

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();
	void clear();

};

/*! structure contenant l'ensemble des artefacts
*/
struct Shimcaches {
public:
	std::vector<Shimcache> shimcaches;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};
