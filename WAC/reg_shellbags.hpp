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

/*! structure représentant un artefact Shellbag
*/
struct Shellbag {
public:
	unsigned int id = 0; //!< identifiant de l'objet
	unsigned int Parent = 0;//!< identifiant du Parent
	unsigned int niveau = 0;//! niveau de profondeur de l'arborescence utilisé pour la mise en forme du json
	std::wstring sid = L""; //!< Sid de l'utilisateur propriétaire de l'objet
	std::wstring sidName = L""; //!< nom de l'utilisateur propriétaire de l'objet
	std::wstring source = L""; //!< origine de l'artefact
	std::vector<IdList*> shellitems; //!< tableau de IdList
	std::vector<Shellbag> childs; //!< tableau contenant les shellbags enfant
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈Shellbag to_json");
		std::wstring result = tab(niveau) + L"{ \n";
		result += tab(niveau + 1) + L"\"ID\":" + std::to_wstring(id) + L", \n";
		result += tab(niveau + 1) + L"\"Parent\":" + std::to_wstring(Parent) + L", \n";
		result += tab(niveau + 1) + L"\"SID\":\"" + sid + L"\", \n";
		result += tab(niveau + 1) + L"\"SIDName\":\"" + sidName + L"\", \n";
		result += tab(niveau + 1) + L"\"Source\":\"" + source + L"\", \n";
		log(3, L"🔈time_to_wstring lastWriteTime");
		result += tab(niveau + 1) + L"\"LastWriteTime\":\"" + time_to_wstring(lastWriteTime) + L"\", \n";
		log(3, L"🔈time_to_wstring lastWriteTimeUtc");
		result += tab(niveau + 1) + L"\"LastWriteTimeUtc\":\"" + time_to_wstring(lastWriteTimeUtc) + L"\", \n";
		result += tab(niveau + 1) + L"\"ShellItems\" : [\n";

		std::vector<IdList*>::iterator it;
		for (it = shellitems.begin(); it != shellitems.end(); it++) {
			IdList* temp = *it;
			result += temp->to_json();
			if (it != shellitems.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(niveau + 1) + L"],\n"
			+ tab(niveau + 1) + L"\"Childs\" : [\n";
		std::vector<Shellbag>::iterator it2;
		for (it2 = childs.begin(); it2 != childs.end(); it2++) {
			result += it2->to_json();
			if (it2 != childs.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(niveau + 1) + L"]\n"
			+ tab(niveau) + L"}";
		return result;
	}

	/* libération mémoire */
	void clear() {
		log(3, L"🔈Shellbag clear");
	}

};

/*! structure contenant l'ensemble des artefacts
*/
struct Shellbags {
public:
	std::vector<Shellbag> shellbags;//!< tableau contenant les objets
	unsigned int niveau = 0;//!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	* param _niveau est utilisé pour la mie en forme de la hiérarchie des objet dans le json de sortie
	*/
	HRESULT getData(int _niveau = 0) {

		HRESULT hresult = NULL;
		ORHKEY hKey = NULL;
		ORHKEY hSubKey = NULL;
		ORHKEY Offhive = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0;
		DWORD nSize = 0;
		WCHAR szValue[MAX_VALUE_NAME] = L"";
		WCHAR szSubKey[MAX_VALUE_NAME] = L"";
		FILETIME lastWriteTimeUtc = { 0 };
		std::wstring ruche = L"";
		niveau = _niveau;
		//HKEY_USERS
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			//ouverture de la ruche user
			log(3, L"🔈replaceAll profile");
			ruche = conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat";
			log(3, L"🔈OROpenHive " + get<1>(profile) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
			hresult = OROpenHive(ruche.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + get<1>(profile) + +L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat", hresult);
				continue;
			}

			log(3, L"🔈OROpenKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
			hresult = OROpenKey(Offhive, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive OROpenKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", hresult);
				continue;
			}

			log(3, L"🔈parse hKey");
			hresult = parse(hKey, get<0>(profile), L"BagMRU", &shellbags, 1, false);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥parse hKey", hresult);
				continue;
			}
		}
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parser une clé de la base de registre
	* @param hKey contient la clé à parser
	* @param sid contient le sid de l'utilisateur propriétaire de la clé
	* @param source contient l'origine de l'artefact
	* @param shellbags contient l'ensemble des mru parsés pour stocker le résultat
	* @param niveau, profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie
	* @param _Parentiszip sit le père de l'artefact est un fichier zip
	* @param Parent est le shellbag Parent si present
	*/
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Shellbag>* shellbags, unsigned int niveau, bool _Parentiszip, unsigned int Parent = NULL) {
		HRESULT hresult = NULL;
		ORHKEY hKeyChilds;
		std::vector<unsigned int> ids;
		LPBYTE pData = new BYTE[MAX_DATA];
		unsigned int pos = 0;
		DWORD dwSize = 0;
		DWORD nSubkeys = 0, nValues = 0;;
		FILETIME lastWriteTimeUtc = { 0 };

		log(3, L"🔈ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", hresult);
		}

		log(3, L"🔈getRegBinaryValue hKey\\MRUListEx");
		hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &pData, &dwSize);
		if (hresult == ERROR_SUCCESS) {
			while (pos < dwSize) {
				int id = *reinterpret_cast<int*>(pData + pos);
				if (id == 0xffffffff) break;
				ids.push_back(id);
				pos += 4;
			}
		}
		else {
			log(2, L"🔥getRegBinaryValue hKey\\MRUListEx", hresult);
		}

		delete[] pData;
		pData = NULL;

		for (int id : ids) {
			bool Parentiszip = false | _Parentiszip;
			DWORD dwSize = 0;
			log(1, L"➕Shellbag");
			Shellbag shellbag;
			shellbag.id = id;
			log(2, L"❇️Shellbag id : " + id);
			shellbag.lastWriteTimeUtc = lastWriteTimeUtc;
			log(3, L"🔈FileTimeToLocalFileTime lastWriteTime");
			FileTimeToLocalFileTime(&lastWriteTimeUtc, &shellbag.lastWriteTime);
			shellbag.Parent = Parent;
			shellbag.niveau = niveau;
			shellbag.sid = sid;
			log(3, L"🔈getNameFromSid sidName");
			shellbag.sidName = getNameFromSid(sid);
			shellbag.source = source;
			log(3, L"🔈getRegBinaryValue hKey\\" + std::to_wstring(id));
			hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &pData, &dwSize);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥getRegBinaryValue hKey\\" + std::to_wstring(id));
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
					shellbag.shellitems.push_back(shellitem);
				}
			}
			delete[] pData;
			pData = NULL;

			//Childs
			log(3, L"🔈OROpenKey hKey\\" + std::to_wstring(id));
			hresult = OROpenKey(hKey, std::to_wstring(id).c_str(), &hKeyChilds);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey hKey\\" + std::to_wstring(id), hresult);
				continue;
			}
			log(3, L"🔈parse");
			hresult = parse(hKeyChilds, sid, source, &shellbag.childs, niveau + 3, Parentiszip, id);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥parse", hresult);
				continue;
			}
			//save
			shellbags->push_back(shellbag);
		}

		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	virtual HRESULT to_json() {
		log(3, L"🔈Shellbags to_json");
		std::wstring result = L"[ \n";
		std::vector<Shellbag>::iterator it;
		for (it = shellbags.begin(); it != shellbags.end(); it++) {
			result += it->to_json();
			if (it != shellbags.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/shellbags.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Shellbags clear");
		for (Shellbag temp : shellbags)
			temp.clear();
	}
};