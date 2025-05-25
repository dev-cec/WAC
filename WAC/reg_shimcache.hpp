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

/*! structure représentant un artefact ShimCache
*/
struct Shimcache {
public:
	std::wstring path = L""; //!< chemin vers le fichier cible de l'artefact
	std::wstring lastModification = L""; //!< date de modification
	std::wstring lastModificationUtc = L"";//!< date de modification au format json
	bool executed = false;//!< true si le fichier a été exécuté, non fiable

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈Shimcache to_json");
		std::wstring result = L"\t{ \n";
		result += L"\t\t\"Path\":\"" + path + L"\", \n";
		result += L"\t\t\"LastModification\":\"" + lastModification + L"\", \n";
		result += L"\t\t\"LastModificationUtc\":\"" + lastModificationUtc + L"\", \n";
		log(3, L"🔈bool_to_wstring Executes");
		result += L"\t\t\"Executes\":" + bool_to_wstring(executed) + L" \n";
		result += L"\t}";
		return result;
	}
	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Shimcache clear");
	}

};

/*! structure contenant l'ensemble des artefacts
*/
struct Shimcaches {
public:
	std::vector<Shimcache> shimcaches;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Shimcaches :");
		log(0, L"*******************************************************************************************************************");

		//variables
		HRESULT hresult=0;
		ORHKEY hKey=NULL;
		DWORD nSubkeys=0;
		DWORD nValues=0;
		LPBYTE pData = NULL;

		log(3, L"🔈OROpenKey CurrentControlSet\\Control\\Session Manager\\AppCompatCache");
		hresult = OROpenKey(conf.CurrentControlSet, L"Control\\Session Manager\\AppCompatCache", &hKey);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥OROpenKey CurrentControlSet\\Control\\Session Manager\\AppCompatCache", hresult );
			return hresult;
		}

		DWORD dwSize=0;
		log(3, L"🔈getRegBinaryValue AppCompatCache");
		hresult = getRegBinaryValue(hKey, nullptr, L"AppCompatCache", &pData, &dwSize);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue AppCompatCache", hresult );
			return hresult;
		}
		int offset = *reinterpret_cast<int*>(pData);
		while (offset < dwSize) {
			Shimcache shimcache;
			std::wstring signature = std::wstring(pData + offset, pData + offset + 4);
			if (signature == L"10ts") {
				offset += 12;//unused
				short int name_length = *reinterpret_cast<short int*>(pData + offset);
				offset += 2;
				shimcache.path = std::wstring((LPWSTR)(pData + offset));
				log(3, L"🔈replaceAll path");
				shimcache.path = replaceAll(shimcache.path, L"\\", L"\\\\");
				shimcache.path = replaceAll(shimcache.path, L"\t", L" "); // replace tab by space. seen in values
				offset += name_length;
				FILETIME filetime = *reinterpret_cast<FILETIME*>(pData + offset);
				log(3, L"🔈time_to_wstring lastModification");
				shimcache.lastModification = time_to_wstring(filetime);
				log(3, L"🔈time_to_wstring lastModificationUtc");
				shimcache.lastModificationUtc = time_to_wstring(filetime, true);
				offset += 8;
				int data_length = *reinterpret_cast<int*>(pData + offset);
				offset += data_length;
				short int executed = *reinterpret_cast<short int*>(pData + offset);
				shimcache.executed = executed;
				offset += 4; // 2 unused

				//save 
				log(1, L"➕Shimecache ");
				log(2, L"❇️Shimecache Path : " + shimcache.path);
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
		log(3, L"🔈Shimcaches to_json");
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
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/shimcache.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Shimcaches clear");
		for (Shimcache temp : shimcaches)
			temp.clear();
	}
};
