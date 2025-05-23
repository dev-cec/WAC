#pragma once

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include "tools.h"
#include "usb.h"



/*! structure repr�sentant un artefact ShimCache
*/
struct Shimcache {
public:
	std::wstring path = L""; //!< chemin vers le fichier cible de l'artefact
	std::wstring lastModification = L""; //!< date de modification
	std::wstring lastModificationUtc = L"";//!< date de modification au format json
	bool executed = false;//!< true si le fichier a �t� ex�cut�, non fiable

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"Path\":\"" + path + L"\", \n"
			L"\t\t\"LastModification\":\"" + lastModification + L"\", \n"
			L"\t\t\"LastModificationUtc\":\"" + lastModificationUtc + L"\", \n"
			L"\t\t\"Executes\":" + bool_to_wstring(executed) + L" \n"
			L"\t}";
	}
	/* liberation m�moire */
	void clear() {}

};

/*! structure contenant l'ensemble des artefacts
*/
struct Shimcaches {
public:
	std::vector<Shimcache> shimcaches;//!< tableau contenant les objets
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs de traitement des objets


	/*! Fonction permettant de parser les objets
	* @param conf contient les param�tres de l'application issue des param�tres de la ligne de commande
	*/
	HRESULT getData() {
		
		//variables
		HRESULT hresult=0;
		ORHKEY hKey=NULL;
		DWORD nSubkeys=0;
		DWORD nValues=0;

		hresult = OROpenKey(conf.CurrentControlSet, L"Control\\Session Manager\\AppCompatCache", &hKey);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", hresult });
			return hresult;
		}

		DWORD dwSize=0;
		hresult = ORGetValue(hKey, NULL, L"AppCompatCache", NULL, nullptr, &dwSize); //taille des donnes � lire
		LPBYTE pData = new BYTE[dwSize]; // Buffer de donn�es
		hresult = getRegBinaryValue(hKey, NULL, L"AppCompatCache", pData);
		if (hresult != ERROR_SUCCESS) {
			errors.push_back({ L"Unable to get value : HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\\AppCompatCache", hresult });
			return hresult;
		}
		int offset = bytes_to_int(pData);


		while (offset < dwSize) {
			Shimcache shimcache;
			std::wstring signature = std::wstring(pData + offset, pData + offset + 4);
			if (signature == L"10ts") {
				offset += 12;//unused
				short int name_length = bytes_to_short(pData + offset);
				offset += 2;
				shimcache.path = std::wstring((LPWSTR)(pData + offset), (LPWSTR)(pData + offset) + name_length / sizeof(wchar_t));
				shimcache.path = replaceAll(shimcache.path, L"\\", L"\\\\");
				shimcache.path = replaceAll(shimcache.path, L"\t", L" "); // replace tab by space. seen in values
				offset += name_length;
				FILETIME filetime = bytes_to_filetime(pData + offset);
				shimcache.lastModification = time_to_wstring(filetime);
				shimcache.lastModificationUtc = time_to_wstring(filetime, true);
				offset += 8;
				int data_length = bytes_to_int(pData + offset);
				offset += data_length;
				short int executed = bytes_to_short(pData + offset);
				shimcache.executed = executed;
				offset += 4; // 2 unused

				//save 
				shimcaches.push_back(shimcache);
			}
		}

		delete [] pData;
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		std::wstring result = L"[ \n";
		std::vector<Shimcache>::iterator it;
		for (it = shimcaches.begin(); it != shimcaches.end(); it++) {
			result += it->to_json();
			if (it != shimcaches.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/shimcache.json");
		myfile << result;
		myfile.close();

		if (conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(conf._errorOutputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
			myfile.open(conf._errorOutputDir + "/shimcache_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}

	/* liberation m�moire */
	void clear() {
		for (Shimcache temp : shimcaches)
			temp.clear();
	}
};
