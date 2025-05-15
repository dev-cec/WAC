#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include "tools.h"
#include "usb.h"



/*! structure représentant un AMCACHE APPLICATION
*/
struct AmcacheApplication {
public:
	std::wstring Name = L""; //!< nom du produit
	std::wstring Publisher = L"";//!< nom de la compagnie
	std::wstring RootDirPath = L"";//!< chemin du repertoire racine
	std::wstring Version = L"";//!< version de l'objet
	std::wstring InstallDate = L"";//!< date d'installation de l'application
	std::wstring InstallDateUtc = L"";//!< date d'installation de l'application au format UTC

	/*! Constructeur
	* @param hKey_amcache contient la clé de registre à parser
	*/
	AmcacheApplication(ORHKEY hKey_amcache)
	{
		getRegSzValue(hKey_amcache, nullptr, L"Name", &Name);
		getRegSzValue(hKey_amcache, nullptr, L"Publisher", &Publisher);
		Publisher = replaceAll(Publisher, L"\\", L"\\\\");
		getRegSzValue(hKey_amcache, nullptr, L"RootDirPath", &RootDirPath);
		RootDirPath = replaceAll(RootDirPath, L"\\", L"\\\\");
		getRegSzValue(hKey_amcache, nullptr, L"Version", &Version);
		//la date est stockée en REG_SZ, donc il faut la reconvertir en FILETIME pour avoir le bon format et la bonne timezone
		std::wstring temp;
		getRegSzValue(hKey_amcache, nullptr, L"InstallDate", &temp);
		if (!temp.empty()) {
			FILETIME filetime = { 0 };
			filetime = wstring_to_filetime(temp);
			InstallDate = time_to_wstring(filetime, false);
			InstallDateUtc = time_to_wstring(filetime, true);
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"Name\":\"" + Name + L"\", \n"
			L"\t\t\"Publisher\":\"" + Publisher + L"\", \n"
			L"\t\t\"RootDirPath\":\"" + RootDirPath + L"\", \n"
			L"\t\t\"Version\":\"" + Version + L"\", \n"
			L"\t\t\"InstallDate\":\"" + InstallDate + L"\", \n"
			L"\t\t\"InstallDateUtc\":\"" + InstallDateUtc + L"\"\n"
			L"\t}";
	}
};

/*! *structure contenant l'ensemble des AMCACHE APPLICATION
*/
struct AmcacheApplications {
public:
	std::vector<AmcacheApplication> amcacheapplications; //!< tableau contenant tous les AMCACHE APPLICATIONS
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param mountpoint contient le point de montage du snapshot du disque
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		HRESULT hresult = NULL;
		ORHKEY hKey = NULL;
		ORHKEY hKey_amcache = NULL;
		ORHKEY Offhive = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0, dTyp0;
		DWORD nSize = 0;
		WCHAR szValue[MAX_VALUE_NAME];
		WCHAR szSubKey[MAX_VALUE_NAME];
		std::wstring ruche = _conf.mountpoint + L"\\Windows\\AppCompat\\Programs\\Amcache.hve";

		hresult = OROpenHive(ruche.c_str(), &Offhive);
		if (hresult != ERROR_SUCCESS) {
			errors.push_back({ L"Unable to open hive : C:\\Windows\\AppCompat\\Programs\\Amcache.hve", hresult });
			return hresult;
		}

		hresult = OROpenKey(Offhive, L"Root\\InventoryApplication", &hKey);
		if (hresult != ERROR_SUCCESS) {
			errors.push_back({ L"Unable to open key :C:\\Windows\\AppCompat\\Programs\\Amcache.hve / Root\\InventoryApplication", hresult });
			return hresult;
		}

		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS) {
			errors.push_back({ L"Unable to get info key : C:\\Windows\\AppCompat\\Programs\\Amcache.hve / Root\\InventoryApplication" , hresult });
			return hresult;
		};

		for (int i = 0; i < (int)nSubkeys; i++) {
			nSize = MAX_VALUE_NAME;
			hresult = OREnumKey(hKey, i, szSubKey, &nSize, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				errors.push_back({ L"Unable to open key : " + ruche + L"Root\\InventoryApplication\\" + szSubKey, hresult });
				continue;
			}
			hresult = OROpenKey(hKey, szSubKey, &hKey_amcache);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"Unable to open key : " + ruche + L"Root\\InventoryApplication\\" + szSubKey, hresult });
				continue;
			}
			AmcacheApplication amcacheapplication(hKey_amcache);
			//save
			amcacheapplications.push_back(amcacheapplication);
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		std::wstring result = L"[ \n";
		std::vector<AmcacheApplication>::iterator it;
		for (it = amcacheapplications.begin(); it != amcacheapplications.end(); it++) {
			result += it->to_json();
			if (it != amcacheapplications.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/amcache_applications.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/amcache_applications_errors.txt");
			myfile << result;
			myfile.close();
		}
		return ERROR_SUCCESS;
	}
};