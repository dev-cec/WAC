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



struct AmcacheApplicationFile {
public:
	std::wstring Name = L""; //!< nom de l�ex�cutable
	std::wstring Publisher = L"";//!< nom de la compagnie
	std::wstring LongPath = L""; //!< chemin d'acc�s  � l�ex�cutable
	std::wstring Version = L"";//!< version de l�ex�cutable
	std::wstring LinkDate = L"";//!< date de cr�ation de l'AMCACHE APPLICATION FILE
	std::wstring LinkDateUtc = L"";//!< date de cr�ation de l'AMCACHE APPLICATION FILE au format UTC
	bool IsOsComponent = false;//!< cet ex�cutable fait-il parti de l'OS ?

	/*! constructeur
	* @param hKey_amcache repr�sente la cl� de registre � parser
	*/
	AmcacheApplicationFile(ORHKEY hKey_amcache)
	{
		getRegSzValue(hKey_amcache, nullptr, L"Name", &Name);
		getRegSzValue(hKey_amcache, nullptr, L"Publisher", &Publisher);
		Publisher = replaceAll(Publisher, L"\"", L"\\\""); // escape " in std::string
		getRegSzValue(hKey_amcache, nullptr, L"LowerCaseLongPath", &LongPath);
		LongPath = replaceAll(LongPath, L"\\", L"\\\\"); // escape \ in std::string
		getRegSzValue(hKey_amcache, nullptr, L"Version", &Version);
		Version = replaceAll(Version, L"\t", L"\\t"); // replace tab in std::string by \t, tab not supported by json in strings
		getRegboolValue(hKey_amcache, nullptr, L"IsOsComponent", &IsOsComponent);
		//la date est stock�e en REG_SZ, donc il faut la reconvertir en FILETIME pour avoir le bon format et la bonne timezone
		std::wstring temp;
		getRegSzValue(hKey_amcache, nullptr, L"LinkDate", &temp);
		if (!temp.empty()) {
			FILETIME filetime = { 0 };
			filetime = wstring_to_filetime(temp);
			LinkDate = time_to_wstring(filetime, false);
			LinkDateUtc = time_to_wstring(filetime, true);
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"Name\":\"" + Name + L"\", \n"
			L"\t\t\"Publisher\":\"" + Publisher + L"\", \n"
			L"\t\t\"LongPath\":\"" + LongPath + L"\", \n"
			L"\t\t\"Version\":\"" + Version + L"\", \n"
			L"\t\t\"LinkDate\":\"" + LinkDate + L"\", \n"
			L"\t\t\"LinkDateUtc\":\"" + LinkDateUtc + L"\", \n"
			L"\t\t\"IsOsComponent\":" + bool_to_wstring(IsOsComponent) + L"\n"
			L"\t}";
	}

	/* liberation m�moire */
	void clear() {}
};

/*! *structure contenant l'ensemble des AMCACHE APPLICATION FILES
*/
struct AmcacheApplicationFiles {
public:
	std::vector<AmcacheApplicationFile> amcacheapplicationfiles;//!< tableau contenant tous les AMCACHE APPLICATIONS FILES
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remont�es lors du traitement des objets


	/*! Fonction permettant de parser les objets
	* @param conf contient les param�tres de l'application issue des param�tres de la ligne de commande
	*/
	HRESULT getData() {
		
		HRESULT hresult=0;
		ORHKEY hKey=NULL, hKey_amcache=NULL;
		DWORD nSubkeys=0;
		DWORD nValues=0;
		WCHAR szValue[MAX_VALUE_NAME]=L"";
		WCHAR szSubKey[MAX_VALUE_NAME]=L"";
		DWORD nSize = 0;
		ORHKEY Offhive=NULL;
		std::wstring ruche = conf.mountpoint + L"\\Windows\\AppCompat\\Programs\\Amcache.hve";

		hresult = OROpenHive(ruche.c_str(), &Offhive);
		if (hresult != ERROR_SUCCESS) {
			errors.push_back({ L"Unable to open hive : C:\\Windows\\AppCompat\\Programs\\Amcache.hve" , hresult });
			return hresult;
		};

		hresult = OROpenKey(Offhive, L"Root\\InventoryApplicationFile", &hKey);
		if (hresult != ERROR_SUCCESS) {
			errors.push_back({ L"Unable to open key : C:\\Windows\\AppCompat\\Programs\\Amcache.hve / Root\\InventoryApplicationFile" , hresult });
			return hresult;
		};

		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS) {
			errors.push_back({ L"Unable to get info key : C:\\Windows\\AppCompat\\Programs\\Amcache.hve / Root\\InventoryApplicationFile" , hresult });
			return hresult;
		};
		for (DWORD i = 0; i < nSubkeys; i++) {
			nSize = MAX_VALUE_NAME;
			hresult = OREnumKey(hKey, i, szSubKey, &nSize, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				errors.push_back({ L"Unable to open key : " + std::wstring(szSubKey), hresult });
				continue;
			};
			hresult = OROpenKey(hKey, szSubKey, &hKey_amcache);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"Unable to open key : " + std::wstring(szSubKey), hresult });
				continue;
			};
			AmcacheApplicationFile amcacheapplicationfile(hKey_amcache);

			//save
			amcacheapplicationfiles.push_back(amcacheapplicationfile);
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
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
		std::filesystem::create_directory(conf._outputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/amcache_application_files.json");
		myfile << result;
		myfile.close();

		if (conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(conf._errorOutputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
			myfile.open(conf._errorOutputDir + "/amcache_application_files_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}

	/*liberation m�moire */
	void clear() {
		for (AmcacheApplicationFile temp : amcacheapplicationfiles)
			temp.clear();
	}
};