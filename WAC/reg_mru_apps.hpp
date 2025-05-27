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



/*! structure représentant l'artefact MRU Application
*/
struct MruApp {
public:
	unsigned int id = 0; //!< identifiant de l'objet
	unsigned int niveau = 0;//!< profondeur de l’arborescence, utilisé pour la mise en forme de json de sortie
	std::wstring name = L"";//!w nom de l'application
	std::wstring sid = L"";//!< sid de l'utilisateur propriétaire de l'objet
	std::wstring sidName = L"";//!< nom de l'utilisateur propriétaire de l'objet
	std::wstring source = L"";//!< origine de l'artefact
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC
	std::vector<IdList*> shellitems;//!< tableau de IdList

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈Mru to_json");
		std::wstring result = tab(niveau) + L"{ \n";
		result += tab(niveau + 1) + L"\"ID\":" + std::to_wstring(id) + L", \n";
		result += tab(niveau + 1) + L"\"Name\":\"" + name + L"\", \n";
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
struct MruApps {
public:
	std::vector<MruApp> MruApps;//!< contient l'ensemble des objets
	unsigned int niveau = 0;//!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	* param _niveau est utilisé pour la mie en forme de la hiérarchie des objet dans le json de sortie
	*/
	HRESULT getData(int _niveau = 0) {

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Mru Apps : ");
		log(0, L"*******************************************************************************************************************");

		HRESULT hresult = NULL;
		ORHKEY hKey = NULL;
		ORHKEY hSubKey = NULL;
		ORHKEY Offhive = NULL;
		DWORD nSubkeys = NULL;
		DWORD nValues = 0;
		DWORD nSize = 0;
		WCHAR szValue[MAX_VALUE_NAME] = L"";
		WCHAR szSubKey[MAX_VALUE_NAME] = L"";
		std::wstring ruche = L"";
		niveau = _niveau;

		//HKEY_USERS
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			std::wstring keynames[3] = { L"LastVisitedMRU",L"LastVisitedPidlMRU",L"LastVisitedPidlMRULegacy" };
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
				log(3, L"🔈OROpenHive Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname);
				hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname).c_str(), &hKey);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenHive Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname, hresult);
					continue;
				}

				log(3, L"🔈parse");
				hresult = parse(hKey, get<0>(profile), keyname, &MruApps, 1, false);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥parse", hresult);
					continue;
				};
			}
		}
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parser une clé de la base de registre
	* @param hKey contient la clé à parser
	* @param sid contient le sid de l'utilisateur propriétaire de la clé
	* @param source contient l'origine de l'artefact
	* @param MruApps contient l'ensemble des mru parsés pour stocker le résultat
	* @param _niveau, profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie
	* @param _Parentiszip sit le père de l'artefact est un fichier zip
	*/
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<MruApp>* MruApps, unsigned int niveau, bool _Parentiszip) {
		HRESULT hresult = NULL;
		ORHKEY hKeyChilds = NULL;
		std::vector<unsigned int> ids;
		LPBYTE pData = new BYTE[MAX_DATA];
		unsigned int pos = 0;
		DWORD dwSize = 0;
		FILETIME lastWriteTimeUtc = { 0 };
		DWORD nSubkeys = 0, nValues = 0;

		log(3, L"🔈ORQueryInfoKey hKey");
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥ORQueryInfoKey hKey", hresult);
			return hresult;
		}

		log(3, L"🔈getRegBinaryValue hKey\\MRUListEx");
		hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &pData, &dwSize);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥parse", hresult);
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
			log(1, L"➕MruApp");
			MruApp mruApp;
			mruApp.id = id;
			log(2, L"❇️MruApp id" + id);
			mruApp.lastWriteTimeUtc = lastWriteTimeUtc;
			log(3, L"🔈FileTimeToLocalFileTime lastWriteTime");
			FileTimeToLocalFileTime(&lastWriteTimeUtc, &mruApp.lastWriteTime);
			mruApp.niveau = niveau;
			mruApp.sid = sid;
			log(3, L"🔈getNameFromSid sidName");
			mruApp.sidName = getNameFromSid(sid);
			mruApp.source = source;
			log(3, L"🔈getRegBinaryValue hKey\\" + std::to_wstring(id));
			hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &pData, &dwSize);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥getRegBinaryValue hKey\\" + std::to_wstring(id), hresult);
				continue;
			}
			size_t offset = 0;
			mruApp.name = std::wstring((wchar_t*)(pData)).data();
			offset += mruApp.name.size() * 2 + 2;
			while (offset < dwSize) {
				unsigned short int size = *reinterpret_cast<unsigned short int*>(pData + offset);
				if (size == 0) break;
				else {
					log(3, L"🔈IdList");
					IdList* shellitem = new IdList(pData + offset, niveau + 2, Parentiszip);
					if (shellitem->shellItem->is_zip == true)
						Parentiszip = true;
					offset += size;
					mruApp.shellitems.push_back(shellitem);
				}
			}
			delete[] pData;
			pData = NULL;

			//save
			MruApps->push_back(mruApp);
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	virtual HRESULT to_json() {
		log(3, L"🔈MruApps to_json");
		std::wstring result = L"[ \n";
		std::vector<MruApp>::iterator it;
		for (it = MruApps.begin(); it != MruApps.end(); it++) {
			result += it->to_json();
			if (it != MruApps.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";
		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/mruApps.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈MruApps clear");
		for (MruApp temp : MruApps)
			temp.clear();
	}
};