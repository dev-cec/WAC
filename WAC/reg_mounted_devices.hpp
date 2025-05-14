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


/*! structure repr�sentant un MOUNTED DEVICE
*/
struct MountedDevice {
public:
	std::wstring drive = L""; //!< Lettre du Drive sur laquelle est mont�e le p�riph�rique
	std::wstring device = L"";//!< identifiant du p�riph�rique mont�

	/* constructeur
	* @param hkey repr�sente la cl� de registre
	* @param szSubValue repr�sente la valeur de la cl� de registre
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
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remont�es lors du traitement des objets
	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json

	/*! Fonction permettant de parser les objets
	* @param system contient la ruche SYSTEM
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	*/
	HRESULT getData(ORHKEY System, bool pdebug) {
		_debug = pdebug;
		//variables
		HRESULT hresult;
		ORHKEY hKey;
		DWORD nSubkeys;
		DWORD nValues;

		hresult = OROpenKey(System, L"MountedDevices", &hKey);
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
		std::filesystem::create_directory("output"); //cr�e le repertoire, pas d'erreur s'il existe d�j�
		std::wofstream myfile;
		myfile.open("output/mounted_device.json");
		myfile << result;
		myfile.close();

		if (_debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory("errors"); //cr�e le repertoire, pas d'erreur s'il existe d�j�
			myfile.open("errors/mounted_device_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}
};
