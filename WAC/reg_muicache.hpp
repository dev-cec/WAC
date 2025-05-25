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

	/*! Constructeur
	* @param hKey est la cle de registre contenant les valeurs
	* szValue est la nom de la valeur de la cle de registre contenant les informations
	* profile est le profile de l'utilisateur proprietaire de l'artefact
	*/
	Muicache(ORHKEY hKey, std::wstring szValue, std::wstring profile) {
		
		DWORD dType = 0;
		HRESULT hresult = 0;

		name = szValue;
		log(3, L"🔈replaceAll name");
		name = replaceAll(name, L"\\", L"\\\\");//escape \ in std::string
		log(2, L"❇️muicache Name : " + name);
		sid = profile;
		log(3, L"🔈getNameFromSid sidName");
		sidName = getNameFromSid(sid);

		log(3, L"🔈getRegSzValue szValue");
		hresult = getRegSzValue(hKey, nullptr, szValue.c_str(), &data);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegSzValue Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache\\" + std::wstring(szValue), hresult);
		}
		else {
			log(3, L"🔈replaceAll data");
			data = replaceAll(data, L"\"", L"\\\"");//escape " in std::string
		}
	}

	/*! conversion de l'objet au format json
   * @return wstring le code json
   */
	std::wstring to_json() {
		log(3, L"🔈Muicache to_json");
		return L"\t{ \n"
			L"\t\t\"SID\":\"" + sid + L"\", \n"
			L"\t\t\"SIDName\":\"" + sidName + L"\", \n"
			L"\t\t\"Name\":\"" + name + L"\", \n"
			L"\t\t\"Data\":\"" + data + L"\" \n"
			L"\t}";
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Muicache clear");
	}
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
		
		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Muicache : ");
		log(0, L"*******************************************************************************************************************");


		HRESULT hresult=0;
		ORHKEY hKey=NULL;
		ORHKEY Offhive=NULL;
		DWORD nSubkeys = 0;
		DWORD nValues=0;
		DWORD nSize = 0;
		DWORD dType = 0;
		WCHAR szValue[MAX_VALUE_NAME]=L"";
		WCHAR szSubKey[MAX_VALUE_NAME]=L"";

		std::wstring ruche = L"";
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			//ouverture de la ruche user
			log(3, L"🔈replaceAll profile");
			ruche = conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat";
			log(3, L"🔈OROpenHive " + get<1>(profile) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
			hresult = OROpenHive(ruche.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + get<1>(profile) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat", GetLastError());
				continue;
			};

			log(3, L"🔈OROpenKey Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\MuiCache");
			hresult = OROpenKey(Offhive, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\MuiCache", hresult );
				continue;
			};

			log(3, L"🔈ORQueryInfoKey MuiCache");
			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥ORQueryInfoKey MuiCache", hresult );
				continue;
			};

			for (int i = 0; i < (int)nValues; i++) {
				DWORD nSize = MAX_VALUE_NAME;
				DWORD cData = MAX_DATA;
				log(3, L"🔈OREnumValue " + std::to_wstring(i));
				hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OREnumValue " + std::to_wstring(i), hresult);
					continue;
				};
				if (dType != REG_SZ) {
					log(2, L"🔥OREnumValue " + std::wstring(szValue) + L" not REG_SZ type");
					continue;
				}
				//save
				log(1, L"➕Muicache");
				muicaches.push_back(Muicache(hKey, szValue, get<0>(profile)));
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		log(3, L"🔈Muicaches to_json");
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
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Muicaches clear");
		for (Muicache temp : muicaches)
			temp.clear();
	}
};