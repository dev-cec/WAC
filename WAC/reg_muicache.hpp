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



/*! structure représentant l'artefact MUICACHE
*/
struct Muicache {
public:
	std::wstring sid = L""; //!< SID de l'utilisateur propriétaire de l'objet
	std::wstring sidName = L""; //!< nom de l'utilisateur propriétaire de l'objet
	std::wstring name = L""; //!< chemin et nom de l’exécutable
	std::wstring data = L""; //!< nom de l'application

	/*! conversion de l'objet au format json
   * @return wstring le code json
   */
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"SID\":\"" + sid + L"\", \n"
			L"\t\t\"SIDName\":\"" + sidName + L"\", \n"
			L"\t\t\"Name\":\"" + name + L"\", \n"
			L"\t\t\"Data\":\"" + data + L"\" \n"
			L"\t}";
	}

	/* liberation mémoire */
	void clear() {}
};

/*! structure contenant l'ensemble des artefacts
*/
struct Muicaches {
public:
	std::vector<Muicache> muicaches;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		HRESULT hresult;
		ORHKEY hKey;
		DWORD nSubkeys;
		DWORD nValues, dType;
		WCHAR szValue[MAX_VALUE_NAME];
		WCHAR szSubKey[MAX_VALUE_NAME];
		DWORD nSize = 0;
		ORHKEY Offhive;
		std::wstring ruche = L"";
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			//ouverture de la ruche user
			ruche = conf.mountpoint + replaceAll(get<0>(profile), L"C:", L"") + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat";
			hresult = OROpenHive(ruche.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				log(1,  L"Unable to open hive : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\usrClass.dat", hresult );
				continue;
			};

			hresult = OROpenKey(Offhive, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(1,  L"Unable to open key : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\usrClass.dat / " + L"Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\MuiCache", hresult );
				continue;
			};

			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS) {
				log(1,  L"Unable to get info key : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\usrClass.dat / " + L"Local Settings\\\\Software\\\\Microsoft\\\\Windows\\Shell\\\\MuiCache", hresult );
				continue;
			};

			for (int i = 0; i < (int)nValues; i++) {
				Muicache muicache;
				nSize = MAX_VALUE_NAME;
				DWORD cData = MAX_DATA;
				hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
				if (hresult != ERROR_SUCCESS) {
					log(1,  L"Unable to open key : " + get<0>(profile) + L"/ USERCLASS.dat / " + L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache\\" + szValue, hresult );
					continue;
				};
				if (dType != REG_SZ) continue;
				getRegSzValue(hKey, nullptr, szValue, &muicache.data);
				muicache.data = replaceAll(muicache.data, L"\"", L"\\\"");//escape " in std::string


				muicache.sid = get<0>(profile);
				muicache.sidName = getNameFromSid(muicache.sid);
				muicache.name = szValue;
				muicache.name = replaceAll(muicache.name, L"\\", L"\\\\");//escape \ in std::string
				//save
				muicaches.push_back(muicache);
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		std::wstring result = L"[ \n";
		std::vector<Muicache>::iterator it;
		for (it = muicaches.begin(); it != muicaches.end(); it++) {
			result += it->to_json();
			if (it != muicaches.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/muicache.json");
		myfile << result;
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		for (Muicache temp : muicaches)
			temp.clear();
	}
};