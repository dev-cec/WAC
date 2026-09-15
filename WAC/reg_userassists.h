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
#include <regex>
#include "tools.h"
#include "trans_id.h"
#include "usb.h"
#include "users.h"



/*! structure représentant un artefact userassist
*/
struct UserAssist {
public:
	std::wstring Sid = L""; //!< SID de l'utilisateur propriétaire de l'objet
	std::wstring SidName = L""; //!< nom de l'utilisateur propriétaire de l'objet
	std::wstring Class = L""; //!< identifiant GUID de classe du UserAssist
	std::wstring Name = L"";//§< nom associé au GUID
	int Count = 0;//!< nombre d’exécutions
	int FocusCount = 0;//! nombre de fois ou le fichier à reçu un focus
	std::wstring DateLocale = L"";//!< date de dernière exécution
	std::wstring DateLocaleUtc = L"";//! date de dernière exécution au format UTC

	/*! Constructeur
	* @param hKey clé de registre contenant l'artefact
	* @param nomValeur nom de la valeur contenant les données
	* @param donnees buffer contenant les données
	* @param _sid proprietaire des données
	*/
	UserAssist(std::wstring hKey, LPWSTR nomValeur, LPBYTE donnees, std::wstring _sid);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! structure contenant l'ensemble des artefacts
*/
struct UserAssists {
public:
	std::vector<UserAssist> userassists;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};