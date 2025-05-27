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
#include "quickdigest5.hpp"


struct AmcacheApplicationFile {
public:
	std::wstring name = L""; //!< nom de l’exécutable
	std::wstring publisher = L"";//!< nom de la compagnie
	std::wstring longPath = L""; //!< chemin d'accès  à l’exécutable
	std::wstring md5 = L""; //!< md5 de l’exécutable
	std::wstring version = L"";//!< version de l’exécutable
	std::wstring linkDate = L"";//!< date de création de l'AMCACHE APPLICATION FILE
	std::wstring linkDateUtc = L"";//!< date de création de l'AMCACHE APPLICATION FILE au format UTC
	bool IsOsComponent = false;//!< cet exécutable fait-il parti de l'OS ?

	/*! constructeur
	* @param hKey_amcache représente la clé de registre à parser
	*/
	AmcacheApplicationFile(ORHKEY hKey_amcache)
	{
		log(3, L"🔈getRegSzValue Name");
		getRegSzValue(hKey_amcache, nullptr, L"Name", &name);
		log(2, L"❇️AmcacheApplicationFile Name : " + name);
		log(3, L"🔈getRegSzValue Publisher");
		getRegSzValue(hKey_amcache, nullptr, L"Publisher", &publisher);
		log(3, L"🔈replaceAll Publisher");
		publisher = replaceAll(publisher, L"\"", L"\\\""); // escape " in std::string
		log(3, L"🔈getRegSzValue LongPath");
		getRegSzValue(hKey_amcache, nullptr, L"LowerCaseLongPath", &longPath);

		//calcul hash avant escape
		char appdata[MAX_PATH];
		log(3, L"🔈replaceAll temp");
		std::wstring wp(replaceAll(longPath, L"\"", L""));
		log(3, L"🔈wstring_to_string p");
		std::string p = wstring_to_string(wp); // remove " in path

		log(3, L"🔈fileToHash " + longPath);
		md5 = QuickDigest5::fileToHash(p); // calcul hash


		log(3, L"🔈replaceAll LongPath");
		longPath = replaceAll(longPath, L"\\", L"\\\\"); // escape \ in std::string
		log(3, L"🔈getRegSzValue Version");
		getRegSzValue(hKey_amcache, nullptr, L"Version", &version);
		log(3, L"🔈replaceAll Version");
		version = replaceAll(version, L"\t", L"\\t"); // replace tab in std::string by \t, tab not supported by json in strings
		log(3, L"🔈getRegboolValue IsOsComponent");
		getRegboolValue(hKey_amcache, nullptr, L"IsOsComponent", &IsOsComponent);
		//la date est stockée en REG_SZ, donc il faut la reconvertir en FILETIME pour avoir le bon format et la bonne timezone
		std::wstring temp;
		log(3, L"🔈getRegSzValue LinkDate");
		getRegSzValue(hKey_amcache, nullptr, L"LinkDate", &temp);
		if (!temp.empty()) {
			FILETIME filetime = { 0 };
			log(3, L"🔈wstring_to_filetime LinkDate");
			filetime = wstring_to_filetime(temp);
			log(3, L"🔈time_to_wstring LinkDate");
			linkDate = time_to_wstring(filetime, false);
			log(3, L"🔈time_to_wstring LinkDateUtc");
			linkDateUtc = time_to_wstring(filetime, true);
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈AmcacheApplicationFile to_json");
		std::wstring result = L"\t{ \n";
			result += L"\t\t\"Name\":\"" + name + L"\", \n";
			result += L"\t\t\"Publisher\":\"" + publisher + L"\", \n";
			result += L"\t\t\"LongPath\":\"" + longPath + L"\", \n";
			result += L"\t\t\"MD5\":\"" + md5 + L"\", \n";
			result += L"\t\t\"Version\":\"" + version + L"\", \n";
			result += L"\t\t\"LinkDate\":\"" + linkDate + L"\", \n";
			result += L"\t\t\"LinkDateUtc\":\"" + linkDateUtc + L"\", \n";
			log(3, L"🔈bool_to_wstring IsOsComponent");
			result += L"\t\t\"IsOsComponent\":" + bool_to_wstring(IsOsComponent) + L"\n";
			result += L"\t}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈AmcacheApplicationFile to_json");
	}
};

/*! *structure contenant l'ensemble des AMCACHE APPLICATION FILES
*/
struct AmcacheApplicationFiles {
public:
	std::vector<AmcacheApplicationFile> amcacheapplicationfiles;//!< tableau contenant tous les AMCACHE APPLICATIONS FILES


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Amcache Application Files :");
		log(0, L"*******************************************************************************************************************");


		HRESULT hresult = 0;
		ORHKEY hKey = NULL, hKey_amcache = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0;
		WCHAR szValue[MAX_VALUE_NAME] = L"";
		WCHAR szSubKey[MAX_VALUE_NAME] = L"";
		DWORD nSize = 0;
		ORHKEY Offhive = NULL;
		std::wstring ruche = conf.mountpoint + L"\\Windows\\AppCompat\\Programs\\Amcache.hve";

		log(3, L"🔈OROpenHive C:\\Windows\\AppCompat\\Programs\\Amcache.hve");
		hresult = OROpenHive(ruche.c_str(), &Offhive);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive : C:\\Windows\\AppCompat\\Programs\\Amcache.hve", hresult);
			return hresult;
		}

		log(3, L"🔈OROpenKey Root\\InventoryApplicationFile");
		hresult = OROpenKey(Offhive, L"Root\\InventoryApplicationFile", &hKey);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive : Root\\InventoryApplicationFile", hresult);
			return hresult;
		}

		log(3, L"🔈ORQueryInfoKey Root\\InventoryApplicationFile");
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥ORQueryInfoKey : Root\\InventoryApplicationFile", hresult);
			return hresult;
		}
		for (DWORD i = 0; i < nSubkeys; i++) {
			nSize = MAX_VALUE_NAME;
			log(3, L"🔈OREnumKey Root\\InventoryApplicationFile " + std::to_wstring(i));
			hresult = OREnumKey(hKey, i, szSubKey, &nSize, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				log(2, L"🔥OREnumKey Root\\InventoryApplicationFile " + std::to_wstring(i), hresult);
				continue;
			}
			log(3, L"🔈OROpenKey  subkey " + std::wstring(szSubKey));
			hresult = OROpenKey(hKey, szSubKey, &hKey_amcache);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey  subkey " + std::wstring(szSubKey), hresult);
				continue;
			}
			log(1, L"➕AmcacheApplicationFile ");
			//save
			amcacheapplicationfiles.push_back(AmcacheApplicationFile(hKey_amcache));
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈AmcacheApplicationFiles to_json");
		std::wstring result = L"[ \n";
		std::vector<AmcacheApplicationFile>::iterator it;
		for (it = amcacheapplicationfiles.begin(); it != amcacheapplicationfiles.end(); it++) {
			result += it->to_json();
			if (it != amcacheapplicationfiles.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/amcache_application_files.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/*liberation mémoire */
	void clear() {
		log(3, L"🔈AmcacheApplicationFiles clear");
		for (AmcacheApplicationFile temp : amcacheapplicationfiles)
			temp.clear();
	}
};