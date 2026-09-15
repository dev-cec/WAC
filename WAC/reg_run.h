#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include "tools.h"
#include "usb.h"



struct Run {
public:
	std::wstring Sid = L""; //!< Sid de l'utilisateur propriétaire de l'objet
	std::wstring SidName = L""; //!< nom de l'utilisateur propriétaire de l'objet
	std::wstring Key = L""; //!< origine de l'artefact, run ou runonce
	std::wstring Name = L""; //!< nom de la clé
	std::wstring Value = L"";//!< valeur de la clé
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! structure contenant l'ensemble des artefacts
*/
struct Runs {
public:
	std::vector<Run> runs;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};