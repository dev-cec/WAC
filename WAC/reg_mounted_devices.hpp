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
	MountedDevice(ORHKEY hKey, PCWSTR szSubValue)
	{
		if (wcswcs(szSubValue, L"DosDevices") != NULL) {
			drive = std::wstring(szSubValue);
			drive = replaceAll(drive, L"\\", L"\\\\");
			getRegSzValue(hKey, NULL, szSubValue, &device);
			device = replaceAll(device, L"\\", L"\\\\");
		}
	}

	/*! conversion de l'objet au format json
   * @return wstring le code json
   */
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"Drive\":\"" + drive + L"\", \n"
			L"\t\t\"Device\":\"" + device + L"\"\n"
			L"\t}";
	}
};

/*! *structure contenant l'ensemble des objets
*/
struct MountedDevices {
public:
	std::vector<MountedDevice> mounteddevices; //!< *structure contenant l'ensemble des objets
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param conf contient la paramètres de l'application issues de la ligne de commande
	* @param system contient la ruche SYSTEM
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		//variables
		HRESULT hresult;
		ORHKEY hKey;
		DWORD nSubkeys;
		DWORD nValues;

		hresult = OROpenKey(_conf.System, L"MountedDevices", &hKey);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			errors.push_back({ L"Unable to open key : MountedDevices", hresult });
			return hresult;
		};
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			errors.push_back({ L"Unable to get info key : MountedDevices", hresult });
			return hresult;
		};

		for (int i = 0; i < (int)nValues; i++) {
			DWORD nSize = MAX_VALUE_NAME;
			DWORD cData = MAX_DATA;
			WCHAR  szSubValue[MAX_VALUE_NAME];
			hresult = OREnumValue(hKey, i, szSubValue, &nSize, NULL, NULL, &cData);
			MountedDevice mounteddevice(hKey, szSubValue);
			//save
			if (mounteddevice.device != L"")
				mounteddevices.push_back(mounteddevice);
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
   */
	HRESULT to_json()
	{
		std::wstring result = L"[ \n";
		std::vector<MountedDevice>::iterator it;
		for (it = mounteddevices.begin(); it != mounteddevices.end(); it++) {
			result += it->to_json();
			if (it != mounteddevices.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/mounted_device.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/mounted_device_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}
};
