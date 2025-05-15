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
#include "users.hpp"

/*!structure représentant un artefact Background Activity Monitor (BAM)
*/
struct Bam {
public:
	std::wstring sid = L""; //!< SID de l'utilisateur
	std::wstring sidName = L""; //!< nom de l'utilisateur
	std::wstring name = L"";//!< nom de l'objet
	std::wstring datetime = L"";//!< date de création de l'objet
	std::wstring datetimeUtc = L"";//!< date de création de l'objet au format UTC

	/*! Constructeur
	* @param pData contient timestamps à transformer en datetime
	* @param szValue contient le nom de la clé de registre contenant le BAM
	* @param psid contient le SID de l'utilisateur
	*/
	Bam(LPBYTE pData, std::wstring szValue, std::wstring psid) {
		FILETIME temp = bytes_to_filetime(pData);
		datetime = time_to_wstring(temp);
		datetimeUtc = time_to_wstring(temp, true);
		sid = psid;
		sidName = getNameFromSid(psid);
		name = szValue;
		name = replaceAll(name, L"\\", L"\\\\"); //escape _ in strings
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"SID\":\"" + sid + L"\", \n"
			L"\t\t\"SIDName\":\"" + sidName + L"\", \n"
			L"\t\t\"Name\":\"" + name + L"\", \n"
			L"\t\t\"Datetime\":\"" + datetime + L"\", \n"
			L"\t\t\"DatetimeUtc\":\"" + datetimeUtc + L"\"\n"
			L"\t}";
	}
};

/*! *structure contenant l'ensemble des BAM
*/
struct Bams {
public:
	std::vector<Bam> bams;//!< tableau contenant tous les objets
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param CurrentControlSet contient la ruche CURRENT CONTROL SET
	* @param userprofiles contient les profils utilisateur de la machine
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		//variables
		HRESULT hresult = NULL;
		ORHKEY hKey = NULL;
		ORHKEY hKey2 = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0;
		DWORD dType = 0;
		DWORD nSize = 0;
		WCHAR szSubKey[MAX_KEY_NAME];
		WCHAR szValue[MAX_VALUE_NAME];
		std::wstring bam_keys[2] = { L"bam",L"bam\\state" };
		for (std::wstring key : bam_keys) {
			for (std::tuple<std::wstring, std::wstring> profile : _conf.profiles) {
				std::wstring temp = L"Services\\" + key + L"\\UserSettings\\" + get<0>(profile);
				CONST wchar_t* regkey = temp.c_str();
				hresult = OROpenKey(_conf.CurrentControlSet, regkey, &hKey);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to open key : SYSTEM\\\\CurrentControlSet\\\\" + replaceAll(std::wstring(regkey),L"\\",L"\\\\"), hresult});
					continue;
				};

				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to get info key : SYSTEM\\\\CurrentControlSet\\\\" + replaceAll(std::wstring(regkey),L"\\",L"\\\\"), hresult });
					continue;
				};

				for (int i = 0; i < (int)nValues; i++) {
					nSize = MAX_KEY_NAME;
					DWORD cData = 0;
					hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
					if (dType != REG_BINARY) continue;
					// allocate memory to store the name
					LPBYTE pData = new BYTE[cData + 2];

					memset(pData, 0, cData + 2);
					// get the name, type, and data 
					OREnumValue(hKey, i, szValue, &nSize, NULL, pData, &cData);
					Bam bam(pData, std::wstring(szValue), std::wstring(get<0>(profile)));

					//save
					bams.push_back(bam);
				}
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		std::wstring result = L"[ \n";
		std::vector<Bam>::iterator it;
		for (it = bams.begin(); it != bams.end(); it++) {
			result += it->to_json();
			if (it != bams.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/bams.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/bams_errors.txt");
			myfile << result;
			myfile.close();
		}
		return ERROR_SUCCESS;
	}
};