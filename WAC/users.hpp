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

		NetUserGetInfo(NULL, profilName, 4, (LPBYTE*)&info4);
		name = ansi_to_utf8(std::wstring(info4->usri4_name));
		fullName = ansi_to_utf8(std::wstring(info4->usri4_full_name));
		flags = info4->usri4_flags;
		//sid to wstring
		ConvertSidToStringSidW(info4->usri4_user_sid, &temp);
		SID = std::wstring(temp);

		NetApiBufferFree(info4);

		//profile path présent uniquement en base de registre
		std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + SID;
		hresult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey);
		if (hresult == ERROR_SUCCESS) {
			hresult = RegQueryValueExW(hKey, L"ProfileImagePath", NULL, NULL, NULL, &dataSize); // get dataSize;
			data = (LPWSTR)malloc(dataSize);
			hresult = RegQueryValueExW(hKey, L"ProfileImagePath", NULL, NULL, (LPBYTE)data, &dataSize);
			profile = ansi_to_utf8(std::wstring(data));
			free(data);
		}
		else
			profile = L"";
	}

	/*! conversion de l'objet au format json
	*/
	std::wstring to_json() {
		std::wstring result = tab(1) + L"{ \n"
			+ tab(2) + L"\"Name\":\"" + name + L"\", \n"
			+ tab(2) + L"\"FullName\":\"" + fullName + L"\", \n"
			+ tab(2) + L"\"SID\":\"" + SID + L"\", \n"
			+ tab(2) + L"\"Disabled\":\"" + bool_to_wstring((flags & UF_ACCOUNTDISABLE) ? true : false) + L"\", \n"
			+ tab(2) + L"\"Profile\":\"" + replaceAll(profile, L"\\", L"\\\\"); +L"\" \n"
			+ tab(1) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {}

};

/*! structure contenant la liste des objets */
struct Users {
	std::vector<User> users;//!< tableau contenant tous les utilisateurs
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets


	/*! Fonction permettant de parser les objets
	* @param conf contient un pointeur sur les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		LPUSER_INFO_3 usersBuf = NULL;

		DWORD nbUsers, nbTotal;

		NetUserEnum(NULL, 3, 0, (LPBYTE*)&usersBuf, MAX_PREFERRED_LENGTH, &nbUsers, &nbTotal, NULL);
		for (int i = 0; i < nbUsers; i++) {
			User temp = User(usersBuf[i].usri3_name);
			users.push_back(temp);
			if(temp.profile!=L"")
				conf.profiles.push_back({ temp.SID,temp.profile });
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		std::vector<User>::iterator it;
		HRESULT hresult;
		std::wstring result = L"[ \n";

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
		myfile << result;
		myfile.close();

		if (conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(conf._errorOutputDir + "/users_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		for (User temp : users)
			temp.clear();
	}
};