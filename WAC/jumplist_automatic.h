#pragma once

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include "tools.h"
#include "recent_docs.h"
#include "oleparser.h"

////////////////////////////////////////////////////
// Documentation : https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
// Documentation : https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
// Documentation : https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
///////////////////////////////////////////////////

/*! Représente un objet représentant un objet Automatic Destination
*/
struct AutomaticDestination {
	std::wstring path = L""; //!< chemin du fichier dans le snapshot
	std::wstring pathOriginal = L""; //!< chemin du fichier sur le disque
	std::wstring Sid = L"";//!< SID de l'utilisateur propriétaire du fichier
	std::wstring SidName = L"";//!< nom de l'utilisateur propriétaire du fichier
	std::wstring application = L"";//!< nom de l'application liée

	oleParser ole; //!< Parser ole utilisé pour décompresser l'objet ole
	std::vector<RecentDoc> recentDocs; //!< tableau contenant les objets Shell Entries du fichier
	FILETIME created = { 0 }; //!< date de création du fichier
	FILETIME createdUtc = { 0 }; //!< date de création du fichier au format utc
	FILETIME modified = { 0 };//!< date de modification  du fichier
	FILETIME modifiedUtc = { 0 };//!< date de modification du fichier au format utc
	FILETIME accessed = { 0 };//!< date d'accès du fichier
	FILETIME accessedUtc = { 0 };//!< date d'accès du fichier au format utc

	/*! constructeur
	* @param _path chemin du fichier Automatic Destinations
	* @param _sid SID de l'utilisateur propriétaire du raccourci
	*/
	AutomaticDestination(std::filesystem::path _path, std::wstring _sid);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! Représente un objet représentant un objet Jumplist contenant les Automatic Destinations
*/
struct JumplistAutomatics {
	std::vector<AutomaticDestination> automaticDestinations; //!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};