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

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"SID\":\"" + Sid + L"\", \n"
			L"\t\t\"SIDName\":\"" + SidName + L"\", \n"
			L"\t\t\"Class\":\"" + Class + L"\", \n"
			L"\t\t\"Name\":\"" + Name + L"\", \n"
			L"\t\t\"Count\":" + std::to_wstring(Count) + L", \n"
			L"\t\t\"FocusCount\":" + std::to_wstring(FocusCount) + L", \n"
			L"\t\t\"DateLocale\":\"" + DateLocale + L"\", \n"
			L"\t\t\"DateLocaleUtc\":\"" + DateLocaleUtc + L"\"\n"
			L"\t}";
	}
};

/*! structure contenant l'ensemble des artefacts
*/
struct UserAssists {
public:
	std::vector<UserAssist> userassists;//!< tableau contenant les objets
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs de traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		HRESULT hresult;
		ORHKEY hKey;
		DWORD nSubkeys;
		DWORD nValues, dType;
		WCHAR szValue[MAX_VALUE_NAME];
		WCHAR szSubKey[MAX_VALUE_NAME];
		DWORD nSize = 0;
		ORHKEY Offhive;
		std::wstring ruche = L"";
		std::wstring userassitsKey[2] = { L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" }; // les GUID à lire pour les userassists
		for (std::wstring key : userassitsKey) {
			for (std::tuple<std::wstring, std::wstring> profile: _conf.profiles) {
				//ouverture de la ruche user
				ruche = _conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\\\ntuser.dat";
				hresult = OROpenHive(ruche.c_str(), &Offhive);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to open hive : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat" , hresult });
					continue;
				}
				std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\" + key + L"\\count\\";
				hresult = OROpenKey(Offhive, subkey.c_str(), &hKey);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to open key : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat / SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\UserAssist\\\\" + key + L"\\count\\" , hresult });
					continue;
				}
				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to open key : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat / SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\UserAssist\\\\" + key + L"\\\\count\\\\" , hresult });
					continue;
				}

				for (int i = 0; i < (int)nValues; i++) {
					UserAssist userassist;
					nSize = MAX_VALUE_NAME;
					DWORD cData = MAX_DATA;
					hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
					// allocate memory to store the name
					LPBYTE pData = new BYTE[cData];
					getRegBinaryValue(hKey, nullptr, szValue, pData);
					userassist.Sid = get<0>(profile);
					userassist.SidName = getNameFromSid(userassist.Sid);
					userassist.Class = key;

					// Codage ANSI mais on veut de l'utf8
					userassist.Name = ansi_to_utf8(ROT13(szValue)); // Rot13 du nom de la Value pour récupérer le nom de l’exécutable

					//conversion des GUID Directory
					std::wsmatch pieces_match;
					std::wregex key(L"[\{][a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}[\}]");
					if (std::regex_search(userassist.Name, pieces_match, key)) {
						for (std::wstring s : pieces_match) {
							std::wstring n = trans_guid_to_wstring(s);
							userassist.Name = replaceAll(userassist.Name, s, n);
						}
					}
					userassist.Name = replaceAll(userassist.Name, L"\\", L"\\\\"); // escape \ in std::string

					userassist.Count = bytes_to_int(&pData[4]); // conversion en integer du nombre d'exécutions à partir du little endian
					userassist.FocusCount = bytes_to_int(&pData[8]); // conversion en integer du nombre d'exécutions à partir du little endian
					FILETIME filetime = bytes_to_filetime(&pData[60]);
					userassist.DateLocale = time_to_wstring(filetime); // récupération de la date de dernière exécution sous forme de tableau de bytes
					if (userassist.DateLocale != L"") { // si la date est vide
						// sinon on la convertie en UTC
						userassist.DateLocaleUtc = time_to_wstring(filetime, true); // récupération de la date de dernière exécution sous forme de tableau de bytes
					}
					//save
					userassists.push_back(userassist);
				}
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
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
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/userassists.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/userassists_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}
};