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
		log(3, L"🔈getRegSzValue device");
		HRESULT hr = getRegSzValue(hKey, NULL, szSubValue, &device);
		if (hr == ERROR_SUCCESS) {
			log(3, L"🔈replaceAll device");
			device = replaceAll(device, L"\\", L"\\\\");
			log(2, L"❇️MountedDEvice device : " + device);
		}
		else {
			log(2, L"🔥getRegSzValue", hr);
		}

		drive = std::wstring(szSubValue);
		log(3, L"🔈replaceAll drive");
		drive = replaceAll(drive, L"\\", L"\\\\");
		log(1, L"➕Drive " + drive);
	}

	/*! conversion de l'objet au format json
   * @return wstring le code json
   */
	std::wstring to_json() {
		log(3, L"🔈MountedDevice to_json");
		std::wstring result = L"\t{ \n";
		result += L"\t\t\"Drive\":\"" + drive + L"\", \n";
		result += L"\t\t\"Device\":\"" + device + L"\" \n";
		result += L"\t}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈MountedDevice clear");
	}
};

/*! *structure contenant l'ensemble des objets
*/
struct MountedDevices {
public:
	std::vector<MountedDevice> mounteddevices; //!< *structure contenant l'ensemble des objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		//variables
		HRESULT hresult;
		ORHKEY hKey;
		DWORD nSubkeys;
		DWORD nValues;
		FILETIME lastWriteTimeUtc = { 0 };

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Mounted devices :");
		log(0, L"*******************************************************************************************************************");

		log(3, L"🔈OROpenKey System\\MountedDevices");
		hresult = OROpenKey(conf.System, L"MountedDevices", &hKey);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥OROpenKey System\\MountedDevices", hresult);
			return hresult;
		};

		log(3, L"🔈ORQueryInfoKey System\\MountedDevices");
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥ORQueryInfoKey System\\MountedDevices", hresult);
			return hresult;
		};

		for (int i = 0; i < (int)nValues; i++) {
			DWORD nSize = MAX_VALUE_NAME;
			DWORD cData = MAX_DATA;
			WCHAR  szSubValue[MAX_VALUE_NAME];
			log(3, L"🔈OREnumValue System\\MountedDevices Value " + std::to_wstring(i));
			hresult = OREnumValue(hKey, i, szSubValue, &nSize, NULL, NULL, &cData);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OREnumValue System\\MountedDevices Value " + std::to_wstring(i), hresult);
				continue;
			}
			//save
			log(1, L"➕MountedDevice");
			mounteddevices.push_back(MountedDevice(hKey, szSubValue));

		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json */
	HRESULT to_json()
	{
		log(3, L"🔈MountedDevices to_json");
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
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/mounted_device.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈MountedDevices clear");
		for (MountedDevice temp : mounteddevices)
			temp.clear();
	}
};
