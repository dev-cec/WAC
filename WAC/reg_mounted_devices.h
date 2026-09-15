#pragma once

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <ctype.h>
#include "tools.h"
#include "json.h"
#include "usb.h"



/*! structure représentant un MOUNTED DEVICE
*/
struct MountedDevice {
public:
	std::wstring drive = L""; //!< Lettre du Drive sur laquelle est montée le périphérique
	std::wstring device = L"";//!< identifiant du périphérique monté

	/* constructeur
	* @param hkey représente la clé de registre
	* @param szSubValue représente la valeur de la clé de registre
	*/
	MountedDevice(ORHKEY hKey, PCWSTR szSubValue);

	/*! conversion de l'objet au format json
   * @return wstring le code json
   */
	Json toJson() const;

	/* liberation mémoire */
	void clear();
};

/*! *structure contenant l'ensemble des objets
*/
struct MountedDevices {
public:
	std::vector<MountedDevice> mounteddevices; //!< *structure contenant l'ensemble des objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json */
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};
