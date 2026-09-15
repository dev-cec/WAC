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



/*! structure représentant un artefact Usbstor
*/
struct Usbstor {
public:
	std::vector<std::wstring> HardwareId; //!< tableau de chaîne de texte représentant les identifiant hardware du périphérique
	std::wstring FriendlyName = L""; //!< nom du périphérique
	std::wstring CompatibleIds = L"";//!< id compatibles avec le périphérique
	std::wstring ClassGuid = L""; //!< identifiant GUID de la classe
	std::wstring SerialNumber = L"";//!< numéro de série du périphérique
	std::wstring LastInsertion = L"";//!< date de dernière insertion du périphérique
	std::wstring LastInsertionUtc = L"";//!< date de dernière insertion du périphérique au format UTC
	std::wstring FirstInsertion = L"";//!< date de première insertion du périphérique
	std::wstring FirstInsertionUtc = L"";//!< date de première insertion du périphérique au format UTC

	/*! Constructeur
	* @param usb est la cle de registre contenant les information du périphérique
	*/
	Usbstor(ORHKEY hKey_usb);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! structure contenant l'ensemble des artefacts
*/
struct Usbstors {
public:
	std::vector<Usbstor> usbs;//!< tableau contenant les objets


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
