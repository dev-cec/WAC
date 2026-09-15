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
	* @param hKey est la cle de registre contenant les valeurs
	* nomValeur est la nom de la valeur de la cle de registre contenant les informations
	* profile est le profile de l'utilisateur proprietaire de l'artefact
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
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};