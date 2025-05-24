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
		log(3, L"🔈getRegSzValue Name");
		getRegSzValue(hKey_amcache, nullptr, L"Name", &Name);
		log(2, L"❇️AmcacheApplication Name : " + Name);
		log(3, L"🔈getRegSzValue Publisher");
		getRegSzValue(hKey_amcache, nullptr, L"Publisher", &Publisher);
		log(3, L"🔈replaceAll Publisher");
		Publisher = replaceAll(Publisher, L"\\", L"\\\\");
		log(3, L"🔈getRegSzValue RootDirPath");
		getRegSzValue(hKey_amcache, nullptr, L"RootDirPath", &RootDirPath);
		log(3, L"🔈replaceAll RootDirPath");
		RootDirPath = replaceAll(RootDirPath, L"\\", L"\\\\");
		log(3, L"🔈getRegSzValue Version");
		getRegSzValue(hKey_amcache, nullptr, L"Version", &Version);
		//la date est stockée en REG_SZ, donc il faut la reconvertir en FILETIME pour avoir le bon format et la bonne timezone
		std::wstring temp;
		log(3, L"🔈getRegSzValue InstallDate");
		getRegSzValue(hKey_amcache, nullptr, L"InstallDate", &temp);
		if (!temp.empty()) {
			FILETIME filetime = { 0 };
			log(3, L"🔈wstring_to_filetime InstallDate");
			filetime = wstring_to_filetime(temp);
			log(3, L"🔈time_to_wstring InstallDate");
			InstallDate = time_to_wstring(filetime, false);
			log(3, L"🔈time_to_wstring InstallDateUtc");
			InstallDateUtc = time_to_wstring(filetime, true);
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈AmcacheApplication to_json");
		return L"\t{ \n"
			L"\t\t\"Name\":\"" + Name + L"\", \n"
			L"\t\t\"Publisher\":\"" + Publisher + L"\", \n"
			L"\t\t\"RootDirPath\":\"" + RootDirPath + L"\", \n"
			L"\t\t\"Version\":\"" + Version + L"\", \n"
			L"\t\t\"InstallDate\":\"" + InstallDate + L"\", \n"
			L"\t\t\"InstallDateUtc\":\"" + InstallDateUtc + L"\"\n"
			L"\t}";
	}

	/*liberation mémoire */
	void clear() {
		log(3, L"🔈AmcacheApplication clear");
	}
};

/*! *structure contenant l'ensemble des AMCACHE APPLICATION
*/
struct AmcacheApplications {
public:
	std::vector<AmcacheApplication> amcacheapplications; //!< tableau contenant tous les AMCACHE APPLICATIONS
	

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Amcache Applications :");
		log(0, L"*******************************************************************************************************************");

		HRESULT hresult = NULL;
		ORHKEY hKey = NULL;
		ORHKEY hKey_amcache = NULL;
		ORHKEY Offhive = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0;
		DWORD nSize = 0;
		WCHAR szValue[MAX_VALUE_NAME]=L"";
		WCHAR szSubKey[MAX_VALUE_NAME]=L"";
		std::wstring ruche = conf.mountpoint + L"\\Windows\\AppCompat\\Programs\\Amcache.hve";

		log(3, L"🔈OROpenHive C:\\Windows\\AppCompat\\Programs\\Amcache.hve");
		hresult = OROpenHive(ruche.c_str(), &Offhive);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive C:\\Windows\\AppCompat\\Programs\\Amcache.hve", hresult);
			return hresult;
		}
		log(3, L"🔈OROpenHive Root\\InventoryApplication");
		hresult = OROpenKey(Offhive, L"Root\\InventoryApplication", &hKey);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive Root\\InventoryApplication", hresult);
			return hresult;
		}
		log(3, L"🔈ORQueryInfoKey Root\\InventoryApplication");
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥ORQueryInfoKey Root\\InventoryApplication" , hresult );
			return hresult;
		};

		for (int i = 0; i < (int)nSubkeys; i++) {
			nSize = MAX_VALUE_NAME;
			log(3, L"🔈OREnumKey Root\\InventoryApplication " + std::to_wstring(1));
			hresult = OREnumKey(hKey, i, szSubKey, &nSize, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				log(2, L"🔥OREnumKey Root\\InventoryApplication " + std::to_wstring(1), hresult );
				continue;
			}
			log(3, L"🔈OROpenKey Root\\InventoryApplication\\" + std::wstring(szSubKey));
			hresult = OROpenKey(hKey, szSubKey, &hKey_amcache);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey Root\\InventoryApplication\\" + std::wstring(szSubKey), hresult);
				continue;
			}
			
			log(1, L"➕AmcacheApplication ");
			//save
			amcacheapplications.push_back(AmcacheApplication(hKey_amcache));
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		log(3, L"🔈AmcacheApplications to_json");
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
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/amcache_applications.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/*liberation mémoire */
	void clear() {
		log(3, L"🔈AmcacheApplications clear");
		for (AmcacheApplication temp : amcacheapplications)
			temp.clear();
	}
};