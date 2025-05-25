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
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC
	std::vector<IdList*> shellitems; //!< tableau contenant les Idlist

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈Mru to_json");
		std::wstring result = tab(niveau) + L"{ \n";
		result += tab(niveau + 1) + L"\"ID\":" + std::to_wstring(id) + L", \n";
		result += tab(niveau + 1) + L"\"Extension\":\"" + extension + L"\", \n";
		result += tab(niveau + 1) + L"\"SID\":\"" + sid + L"\", \n";
		result += tab(niveau + 1) + L"\"SIDName\":\"" + sidName + L"\", \n";
		result += tab(niveau + 1) + L"\"Source\":\"" + source + L"\", \n";
		log(3, L"🔈time_to_wstring lastWriteTime");
		result += L"\t\t\"LastWriteTime\":\"" + time_to_wstring(lastWriteTime) + L"\", \n";
		log(3, L"🔈time_to_wstring lastWriteTimeUtc");
		result += L"\t\t\"LastWriteTimeUtc\":\"" + time_to_wstring(lastWriteTimeUtc) + L"\", \n";
		result += tab(niveau + 1) + L"\"ShellItems\" : [\n";
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

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Mru clear");
		for (IdList* temp : shellitems)
			temp->clear();
	}
};

/* Structure contenant l'ensemble des artefacts
*/
struct Mrus {
public:
	std::vector<Mru> Mrus; //!< contient l'ensemble des objets
	unsigned int niveau = 0; //!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	* param _niveau est utilisé pour la mie en forme de la hiérarchie des objet dans le json de sortie
	*/
	HRESULT getData(int _niveau = 0) {

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Mrus : ");
		log(0, L"*******************************************************************************************************************");

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
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			std::wstring keynames[2] = { L"OpenSavePidlMRU",L"OpenSaveMRU" };
			for (std::wstring keyname : keynames) {
				//ouverture de la ruche user
				log(3, L"🔈replaceAll profile");
				ruche = conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\\\ntuser.dat";
				log(3, L"🔈OROpenHive " + get<1>(profile) + L"\\ntuser.dat");
				hresult = OROpenHive(ruche.c_str(), &Offhive);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenHive " + get<1>(profile) + L"\\ntuser.dat", hresult);
					continue;
				}
				log(3, L"🔈OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname);
				hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname).c_str(), &hKey);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname, hresult);
					continue;
				}

				log(3, L"🔈ORQueryInfoKey hKey");
				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥ORQueryInfoKey hKey", hresult);
					continue;
				}

				for (int i = 1; i < (int)nSubkeys; i++) {//i=0 = *, on passe
					nSize = MAX_KEY_NAME;
					DWORD cData = 0;
					log(3, L"🔈OREnumKey hKey");
					hresult = OREnumKey(hKey, i, szValue, &nSize, NULL, NULL, NULL);
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥OREnumKey hkey", hresult);
						continue;
					}
					log(3, L"🔈OROpenKey hkey\\" + std::wstring(szValue));
					hresult = OROpenKey(hKey, szValue, &hSubKey);
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥OROpenKey hkey\\" + std::wstring(szValue), hresult);
						continue;
					}
					hresult = parse(hSubKey, get<0>(profile), keyname, &Mrus, 1, false, szValue);
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥parse", hresult);
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
		LPBYTE pData = NULL;
		FILETIME lastWriteTimeUtc = { 0 };
		DWORD nSubkeys = 0, nValues = 0;

		unsigned int pos = 0;
		DWORD dwSize = 0;

		log(3, L"🔈ORQueryInfoKey hKey");
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥ORQueryInfoKey hKey", hresult);
			return hresult;
		}

		log(3, L"🔈getRegBinaryValue hkey\\MRUListEx");
		hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &pData, &dwSize);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue hkey\\MRUListEx", hresult);
			return hresult;
		}
		while (pos < dwSize) {
			int id = *reinterpret_cast<int*>(pData + pos);
			if (id == 0xffffffff) break;
			ids.push_back(id);
			pos += 4;
		}

		delete[] pData;
		pData = NULL;
		for (int id : ids) {
			bool Parentiszip = false | _Parentiszip;
			log(1, L"➕Mru");
			Mru mru;
			mru.id = id;
			log(2, L"❇️Mru id" + id);
			mru.lastWriteTimeUtc = lastWriteTimeUtc;
			log(3, L"🔈FileTimeToLocalFileTime lastWriteTime");
			FileTimeToLocalFileTime(&lastWriteTimeUtc, &mru.lastWriteTime);
			mru.extension = extension;
			mru.niveau = niveau;
			mru.sid = sid;
			log(3, L"🔈getNameFromSid sidName");
			mru.sidName = getNameFromSid(sid);
			mru.source = source;
			log(3, L"🔈getRegBinaryValue hkey\\" + std::to_wstring(id));
			hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &pData, &dwSize);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥getRegBinaryValue hkey\\" + std::to_wstring(id), hresult);
				continue;
			}
			unsigned int offset = 0;
			while (offset < dwSize) {
				unsigned short int size = *reinterpret_cast<unsigned short int*>(pData + offset);
				if (size == 0) break;
				else {
					log(3, L"🔈IdList");
					IdList* shellitem = new IdList(pData + offset, niveau + 2, Parentiszip);
					if (shellitem->shellItem->is_zip == true)
						Parentiszip = true;
					offset += size;
					mru.shellitems.push_back(shellitem);
				}
			}
			delete[] pData;
			pData = NULL;

			//save
			Mrus->push_back(mru);

		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/

	virtual HRESULT to_json() {
		log(3, L"🔈Mrus to_json");
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
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/mrus.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Mrus clear");
		for (Mru temp : Mrus)
			temp.clear();
	}
};