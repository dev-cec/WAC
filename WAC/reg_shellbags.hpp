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



/*! structure repr�sentant un artefact Shellbag
*/
struct Shellbag {
public:
	unsigned int id = 0; //!< identifiant de l'objet
	unsigned int Parent = 0;//!< identifiant du Parent
	unsigned int niveau = 0;//! niveau de profondeur de l'arborescence utilis� pour la mise en forme du json
	std::wstring sid = L""; //!< Sid de l'utilisateur propri�taire de l'objet
	std::wstring sidName = L""; //!< nom de l'utilisateur propri�taire de l'objet
	std::wstring source = L""; //!< origine de l'artefact
	std::vector<IdList*> shellitems; //!< tableau de IdList
	std::vector<Shellbag> childs; //!< tableau contenant les shellbags enfant
	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde contenu du buffer au format hexadecimal dans un fichier json

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		std::wstring result = tab(niveau) + L"{ \n"
			+ tab(niveau + 1) + L"\"ID\":" + std::to_wstring(id) + L", \n"
			+ tab(niveau + 1) + L"\"Parent\":" + std::to_wstring(Parent) + L", \n"
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

	/* lib�ration m�moire */
	void clear(){}

};

/*! structure contenant l'ensemble des artefacts
*/
struct Shellbags {
public:
	std::vector<Shellbag> shellbags;//!< tableau contenant les objets
	unsigned int niveau = 0;//!< profondeur dans l'arborescence utilis� pour la mise en forme du fichier json de sortie
	std::vector<std::tuple<std::wstring,HRESULT>> errors;//!< tableau contenant les erreurs de traitement des objets


	/*! Fonction permettant de parser les objets
	* @param conf contient les param�tres de l'application issue des param�tres de la ligne de commande
	* param _niveau est utilis� pour la mie en forme de la hi�rarchie des objet dans le json de sortie
	*/
	HRESULT getData( int _niveau = 0) {
		
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
			//ouverture de la ruche user
			ruche = conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat";
			hresult = OROpenHive(ruche.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"unable to open hive " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\usrClass.dat", hresult });
				continue;
			}

			hresult = OROpenKey(Offhive, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", &hKey);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"unable to open key " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\usrClass.dat / Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\BagMRU de la ruche " + ruche, hresult });
				continue;
			}

			hresult = parse(hKey, get<0>(profile), L"BagMRU", &shellbags, 1, false);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"unable to parse key " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\usrClass.dat / Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\BagMRU de la ruche " + ruche, hresult });
				continue;
			}
		}
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parser une cl� de la base de registre
	* @param hKey contient la cl� � parser
	* @param sid contient le sid de l'utilisateur propri�taire de la cl�
	* @param source contient l'origine de l'artefact
	* @param shellbags contient l'ensemble des mru pars�s pour stocker le r�sultat
	* @param niveau, profondeur dans l'arborescence utilis� pour la mise en forme du fichier json de sortie
	* @param _Parentiszip sit le p�re de l'artefact est un fichier zip
	* @param Parent est le shellbag Parent si present
	*/
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Shellbag>* shellbags, unsigned int niveau, bool _Parentiszip, unsigned int Parent = NULL) {
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
			Shellbag shellbag;
			shellbag.id = id;
			shellbag.Parent = Parent;
			shellbag.niveau = niveau;
			shellbag.sid = sid;
			shellbag.sidName = getNameFromSid(sid);
			shellbag.source = source;
			shellbag._debug = conf._debug;
			shellbag._dump = conf._dump;
			getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), pData);
			unsigned int offset = 0;
			while (true) {

				unsigned short int size = bytes_to_unsigned_short(pData + offset);
				if (size == 0) break;
				else {

					IdList* shellitem = new IdList(pData + offset, niveau + 2,  &errors, Parentiszip);
					if (shellitem->shellItem->is_zip == true)
						Parentiszip = true;
					offset += size;
					shellbag.shellitems.push_back(shellitem);
				}
			}
			//Childs
			hresult = OROpenKey(hKey, std::to_wstring(id).c_str(), &hKeyChilds);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"unable to open key " + std::to_wstring(id), hresult });
				continue;
			}
			hresult = parse(hKeyChilds, sid, source, &shellbag.childs, niveau + 3, Parentiszip, id);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"unable to parse key " + std::to_wstring(id), hresult });
				continue;
			}
			//save
			shellbags->push_back(shellbag);
		}
		delete [] pData;
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	virtual HRESULT to_json() {
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
		std::filesystem::create_directory(conf._outputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
		std::wofstream myfile;
		myfile.open(conf._outputDir +"/shellbags.json");
		myfile << result;
		myfile.close();

		if(conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(conf._errorOutputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
			myfile.open(conf._errorOutputDir +"/shellbags_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}

	/* liberation m�moire */
	void clear() {
		for (Shellbag temp : shellbags)
			temp.clear();
	}
};