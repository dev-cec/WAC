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

/*! structure représentant l'artefact MUICACHE
*/
struct Muicache {
public:
	std::wstring sid = L""; //!< SID de l'utilisateur propriétaire de l'objet
	std::wstring sidName = L""; //!< nom de l'utilisateur propriétaire de l'objet
	std::wstring name = L""; //!< chemin et nom de l’exécutable
	std::wstring data = L""; //!< nom de l'application

	/*! Constructeur
	* @param hKey clé de registre contenant les valeurs
	* @param nomValeur nom de la valeur portant les informations
	* @param profile profil de l'utilisateur propriétaire de l'artefact
	*/
	Muicache(ORHKEY hKey, std::wstring nomValeur, std::wstring profile);

	/*! conversion de l'objet au format json
   * @return wstring le code json
   */
	Json toJson();
	/* liberation mémoire */
	void clear();
};

/*! structure contenant l'ensemble des artefacts
*/
struct Muicaches {
public:
	std::vector<Muicache> muicaches;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};