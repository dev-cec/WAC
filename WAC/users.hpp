#pragma once

#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include <lmaccess.h>
#include <sddl.h>
#include <LM.h>
#include "tools.h"
#include "trans_id.h"



#pragma comment(lib, "netapi32.lib")

/*! structure contenant les informations d'un utilisateur*/
struct User {
	std::wstring name = L"";
	std::wstring fullName = L"";
	std::wstring SID = L"";

	bool disabled = false;
	std::wstring profile = L"";
	DWORD flags = 0;

	/*! Constructeur */
	User() {};

	/*! Constructeur
	@param profilName contient le nom du profil
	*/
	User(LPWSTR profilName) {
		HRESULT hresult;
		HKEY hKey;
		DWORD dataSize = 0;
		LPWSTR data = NULL;
		LPUSER_INFO_4 info4 = NULL;
		LPWSTR temp = NULL;

		log(1, L"➕User");
		log(2, L"❇️User name : " + std::wstring(profilName));
		log(3, L"🔈NetUserGetInfo");
		int r = NetUserGetInfo(NULL, profilName, 4, (LPBYTE*)&info4);
		if (r == NERR_Success) {
			name = std::wstring(info4->usri4_name);
			fullName = std::wstring(info4->usri4_full_name);
			flags = info4->usri4_flags;
			//sid to wstring
			log(3, L"🔈ConvertSidToStringSidW");
			if (ConvertSidToStringSidW(info4->usri4_user_sid, &temp)) {
				SID = std::wstring(temp);
			}
			else {
				log(2, L"🔥ConvertSidToStringSidW", GetLastError());
			}
			NetApiBufferFree(info4);

			//profile path présent uniquement en base de registre
			std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + SID;
			log(3, L"🔈RegOpenKeyExW");
			hresult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey);
			if (hresult == ERROR_SUCCESS) {
				log(3, L"🔈RegQueryValueExW");
				hresult = RegQueryValueExW(hKey, L"ProfileImagePath", NULL, NULL, NULL, &dataSize); // get dataSize;
				data = (LPWSTR)malloc(dataSize);
				hresult = RegQueryValueExW(hKey, L"ProfileImagePath", NULL, NULL, (LPBYTE)data, &dataSize);
				if (hresult == ERROR_SUCCESS) {
					profile = std::wstring(data);
				}
				else {
					profile = L"";
					log(2, L"🔥ᬈᬈᬈᬈᬈᬈᬈᬈᬈᬈᬈᬈᬈᬈRegOpenKeyExW " + key + L"/ProfileImagePath", hresult);
				}
				free(data);
			}
			else {
				profile = L"";
				log(2, L"🔥RegOpenKeyExW " + key, hresult);
			}
		}
		else
			log(2, L"🔥NetUserGetInfo", r);
	}

	/*! conversion de l'objet au format json
	*/
	std::wstring to_json() {
		log(3, L"🔈user to_json");
		std::wstring result = tab(1) + L"{ \n";
			result+= tab(2) + L"\"Name\":\"" + name + L"\", \n";
			result+= tab(2) + L"\"FullName\":\"" + fullName + L"\", \n";
			result+= tab(2) + L"\"SID\":\"" + SID + L"\", \n";
			log(3, L"🔈bool_to_wstring flags");
			result+= tab(2) + L"\"Disabled\":\"" + bool_to_wstring((flags & UF_ACCOUNTDISABLE) ? true : false) + L"\", \n";
			log(3, L"🔈replaceAll profile");
			result+= tab(2) + L"\"Profile\":\"" + replaceAll(profile, L"\\", L"\\\\") +L"\" \n";
			result += tab(1) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈user clear");
	}

};

/*! structure contenant la liste des objets */
struct Users {
	std::vector<User> users;//!< tableau contenant tous les utilisateurs


	/*! Fonction permettant de parser les objets
	* @param conf contient un pointeur sur les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		LPUSER_INFO_3 usersBuf = NULL;
		DWORD nbUsers = 0, nbTotal = 0;

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Users :");
		log(0, L"*******************************************************************************************************************");

		log(3, L"🔈NetUserEnum");
		int r = NetUserEnum(NULL, 3, 0, (LPBYTE*)&usersBuf, MAX_PREFERRED_LENGTH, &nbUsers, &nbTotal, NULL);
		if (r!= NERR_Success) {
			log(2, L"🔥No user found",r);
			return ERROR_EMPTY;
		}
		else {
			for (DWORD i = 0; i < nbUsers; i++) {
				User temp = User(usersBuf[i].usri3_name);
				users.push_back(temp);
				if (temp.profile != L"")
					conf.profiles.push_back({ temp.SID,temp.profile });
			}
			return ERROR_SUCCESS;
		}
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		std::vector<User>::iterator it;
		HRESULT hresult = 0;
		std::wstring result = L"[ \n";

		log(3, L"🔈users to_json");
		for (it = users.begin(); it != users.end(); it++) {
			result += it->to_json();
			if (it != users.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";
		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/users.json");
		log(3, L"🔈ansi_to_utf8 result");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈users clear");
		for (User temp : users)
			temp.clear();
	}
};