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
#include "idList.h"

/* structure représentant l'artefact Most REcently Used
*/
struct Mru {
public:
	unsigned int id = 0; //!< identifiant de l'objet
	unsigned int niveau = 0;//!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie
	std::wstring extension = L""; //!< extension du fichier
	std::wstring sid = L""; //!<SID de l'utilisateur ayant ouvert le fichier
	std::wstring sidName = L""; //!<nom de l'utilisateur ayant ouvert le fichier
	std::wstring source = L"";//!< provient de "OpenSavePidlMRU " ou "OpenSaveMRU"
	std::vector<IdList*> shellitems; //!< tableau contenant les Idlist
	bool _debug = false;//!< paramètre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false;//!< paramètre de la ligne de commande, si true alors on sauvegarde contenu du buffer au format hexadecimal dans un fichier json

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		std::wstring result = tab(niveau) + L"{ \n"
			+ tab(niveau + 1) + L"\"ID\":" + std::to_wstring(id) + L", \n"
			+ tab(niveau + 1) + L"\"Extension\":\"" + extension + L"\", \n"
			+ tab(niveau + 1) + L"\"SID\":\"" + sid + L"\", \n"
			+ tab(niveau + 1) + L"\"SIDName\":\"" + sidName + L"\", \n"
			+ tab(niveau + 1) + L"\"Source\":\"" + source + L"\", \n"
			+ tab(niveau + 1) + L"\"ShellItems\" : [\n";
		std::vector<IdList*>::iterator it;
		for (it = shellitems.begin(); it != shellitems.end(); it++) {
			IdList* temp = *it;
			result += temp->to_json();
			if (it != shellitems.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(niveau + 1) + L"]\n"
			+ tab(niveau) + L"}";
		return result;
	}
};

/* Structure contenant l'ensemble des artefacts
*/
struct Mrus {
public:
	std::vector<Mru> Mrus; //!< contient l'ensemble des objets
	unsigned int niveau = 0; //!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	* param _niveau est utilisé pour la mie en forme de la hiérarchie des objet dans le json de sortie
	*/
	HRESULT getData(AppliConf conf, int _niveau = 0) {
		_conf = conf;
		HRESULT hresult = NULL;
		ORHKEY hKey;
		ORHKEY hSubKey;
		DWORD nSubkeys;
		DWORD nValues, dType;
		WCHAR szValue[MAX_VALUE_NAME];
		WCHAR szSubKey[MAX_VALUE_NAME];
		DWORD nSize = 0;
		ORHKEY Offhive;
		std::wstring ruche = L"";
		niveau = _niveau;
		//HKEY_USERS
		for (std::tuple<std::wstring, std::wstring> profile : _conf.profiles) {
			std::wstring keynames[2] = { L"OpenSavePidlMRU",L"OpenSaveMRU" };
			for (std::wstring keyname : keynames) {
				//ouverture de la ruche user
				ruche = _conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\\\ntuser.dat";
				hresult = OROpenHive(ruche.c_str(), &Offhive);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"unable to open hive : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\")+ L"\\\\ntuser.dat" , hresult });
					continue;
				}

				hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname).c_str(), &hKey);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"unable to open key " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat / Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ComDlg32\\\\" + keyname, hresult });
					continue;
				}

				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"unable to get info key " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat / Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ComDlg32\\\\" + keyname, hresult });
					continue;
				}

				for (int i = 1; i < (int)nSubkeys; i++) {//i=0 = *, on passe
					nSize = MAX_KEY_NAME;
					DWORD cData = 0;
					hresult = OREnumKey(hKey, i, szValue, &nSize, NULL, NULL, NULL);
					hresult = OROpenKey(hKey, szValue, &hSubKey);
					if (hresult != ERROR_SUCCESS) {
						errors.push_back({ L"unable to open key Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ComDlg32\\\\" + keyname + L"\\" + szValue, hresult});
						continue;
					}
					hresult = parse(hSubKey, get<0>(profile), keyname, &Mrus, 1, false, szValue);
					if (hresult != ERROR_SUCCESS) {
						errors.push_back({ L"unable to get info key Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\ComDlg32\\\\" + keyname + L"\\" + szValue, hresult });
						continue;
					}
				}
			}
		}
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parser une clé MRUListEx
	* @param hKey contient le clé de la base de registre à parser
	* @param sid contient le sid de l'utilisateur
	* @param source contient l'origine de l’artefact (provient de "OpenSavePidlMRU " ou "OpenSaveMRU")
	* @param Mrus est un tableau contenant les MRUS parsés
	* @param niveau est utilisé par la mise en forme du json de sortie
	* @param _Parentiszip indique le Parent est un fichier zip
	* @param extension contient l'extension de fichier
	*/
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Mru>* Mrus, unsigned int niveau, bool _Parentiszip, std::wstring extension) {
		HRESULT hresult = NULL;
		ORHKEY hKeyChilds;
		std::vector<unsigned int> ids;
		LPBYTE pData = new BYTE[MAX_DATA];
		unsigned int pos = 0;


		getRegBinaryValue(hKey, L"", L"MRUListEx", pData);
		while (true) {
			int id = bytes_to_int(pData + pos);
			if (id == 0xffffffff) break;
			ids.push_back(id);
			pos += 4;
		}
		for (int id : ids) {
			bool Parentiszip = false | _Parentiszip;
			Mru Mru;
			Mru.id = id;
			Mru.extension = extension;
			Mru.niveau = niveau;
			Mru.sid = sid;
			Mru.sidName = getNameFromSid(sid);
			Mru.source = source;
			Mru._debug = _conf._debug;
			Mru._dump = _conf._dump;
			getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), pData);
			unsigned int offset = 0;
			while (true) {

				unsigned short int size = bytes_to_unsigned_short(pData + offset);
				if (size == 0) break;
				else {

					IdList* shellitem = new IdList(pData + offset, niveau + 2, _conf._debug, _conf._dump, &errors, Parentiszip);
					if (shellitem->shellItem->is_zip == true)
						Parentiszip = true;
					offset += size;
					Mru.shellitems.push_back(shellitem);
				}
			}

			//save
			Mrus->push_back(Mru);
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/

	virtual HRESULT to_json() {
		std::wstring result = L"[ \n";
		std::vector<Mru>::iterator it;
		for (it = Mrus.begin(); it != Mrus.end(); it++) {
			result += it->to_json();
			if (it != Mrus.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir +"/mrus.json");
		myfile << result;
		myfile.close();

		if(_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir +"/mrus_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}
};