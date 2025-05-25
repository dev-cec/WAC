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
#include "users.hpp"



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
	* @param szValue nom de la valeur contenant les données
	* @param pData buffer contenant les données
	* @param _sid proprietaire des données
	*/
	UserAssist(std::wstring hKey, LPWSTR szValue, LPBYTE pData, std::wstring _sid) {
		// Codage ANSI mais on veut de l'utf8
		log(3, L"🔈ROT13 Name");
		Name = ROT13(szValue); // Rot13 du nom de la Value pour récupérer le nom de l’exécutable
		log(2, L"❇️UserAssist Name : " + Name);
		Sid = _sid;
		log(3, L"🔈getNameFromSid SidName");
		SidName = getNameFromSid(Sid);
		Class = hKey;
		//conversion des GUID Directory
		std::wsmatch pieces_match;
		std::wregex key(L"[\\{][a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}[\\}]");
		log(3, L"🔈regex_search Name");
		if (std::regex_search(Name, pieces_match, key)) {
			for (std::wstring s : pieces_match) {
				std::wstring n = trans_guid_to_wstring(s);
				log(3, L"🔈replaceAll Regex Name");
				Name = replaceAll(Name, s, n);
			}
		}
		log(3, L"🔈replaceAll Name");
		Name = replaceAll(Name, L"\\", L"\\\\"); // escape \ in std::string
		Count = *reinterpret_cast<int*>(pData + 4); // conversion en integer du nombre d'exécutions à partir du little endian
		FocusCount = *reinterpret_cast<int*>(pData + 8); // conversion en integer du nombre d'exécutions à partir du little endian
		FILETIME filetime = *reinterpret_cast<FILETIME*>(pData + 60);
		log(3, L"🔈time_to_wstring DateLocale");
		DateLocale = time_to_wstring(filetime); // récupération de la date de dernière exécution sous forme de tableau de bytes
		if (DateLocale != L"") { // si la date est vide
			// sinon on la convertie en UTC
			log(3, L"🔈time_to_wstring DateLocaleUtc");
			DateLocaleUtc = time_to_wstring(filetime, true); // récupération de la date de dernière exécution sous forme de tableau de bytes
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈UserAssist to_json");
		std::wstring result = L"\t{ \n";
		result += L"\t\t\"SID\":\"" + Sid + L"\", \n";
		result += L"\t\t\"SIDName\":\"" + SidName + L"\", \n";
		result += L"\t\t\"Class\":\"" + Class + L"\", \n";
		result += L"\t\t\"Name\":\"" + Name + L"\", \n";
		result += L"\t\t\"Count\":" + std::to_wstring(Count) + L", \n";
		result += L"\t\t\"FocusCount\":" + std::to_wstring(FocusCount) + L", \n";
		result += L"\t\t\"DateLocale\":\"" + DateLocale + L"\", \n";
		result += L"\t\t\"DateLocaleUtc\":\"" + DateLocaleUtc + L"\"\n";
		result += L"\t}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈UserAssist clear");
	}
};

/*! structure contenant l'ensemble des artefacts
*/
struct UserAssists {
public:
	std::vector<UserAssist> userassists;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️User assists :");
		log(0, L"*******************************************************************************************************************");

		HRESULT hresult = 0;
		ORHKEY hKey = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0;
		DWORD dType = 0;
		WCHAR szValue[MAX_VALUE_NAME] = L"";
		WCHAR szSubKey[MAX_VALUE_NAME] = L"";
		DWORD nSize = 0;
		ORHKEY Offhive = NULL;
		std::wstring ruche = L"";
		std::wstring userassitsKey[2] = { L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" }; // les GUID à lire pour les userassists
		for (std::wstring key : userassitsKey) {
			for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
				//ouverture de la ruche user
				log(3, L"🔈replaceAll profile");
				ruche = conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\\\ntuser.dat";
				log(3, L"🔈OROpenHive " + get<1>(profile) + L"\\ntuser.dat");
				hresult = OROpenHive(ruche.c_str(), &Offhive);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenHive " + get<1>(profile) + L"\\ntuser.dat", hresult);
					continue;
				}

				std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\" + key + L"\\count\\";
				log(3, L"🔈OROpenKey " + subkey);
				hresult = OROpenKey(Offhive, subkey.c_str(), &hKey);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey " + subkey);
					continue;
				}

				log(3, L"🔈ORQueryInfoKey " + subkey);
				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥ORQueryInfoKey " + subkey);
					continue;
				}
				for (DWORD i = 0; i < nValues; i++) {
					DWORD dataSize = 0;
					LPBYTE pData = NULL;
					do {
						if (pData != NULL)
							delete[] pData;
						pData = new BYTE[dataSize];
						log(3, L"🔈OREnumValue " + subkey + L" " + std::to_wstring(i));
						hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, pData, &dataSize);
					} while (hresult == ERROR_MORE_DATA);
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥OREnumValue " + subkey + L" " + std::to_wstring(i), hresult);
						continue;
					}
					//save
					log(1, L"➕UserAssist ");
					userassists.push_back(UserAssist(key, szValue, pData, get<0>(profile)));

					delete[] pData;
				}
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		log(3, L"🔈UserAssists to_json");
		std::vector<UserAssist>::iterator usersassist;
		std::wstring result = L"[ \n";
		for (usersassist = userassists.begin(); usersassist != userassists.end(); usersassist++) {
			result += usersassist->to_json();
			if (usersassist != userassists.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/userassists.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈UserAssists clear");
		for (UserAssist temp : userassists)
			temp.clear();
	}
};