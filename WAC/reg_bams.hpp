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
		name = szValue;
		log(3, L"🔈replaceAll name");
		name = replaceAll(name, L"\\", L"\\\\"); //escape _ in strings
		log(2, L"❇️Bam Name : " + name);
		FILETIME temp = *reinterpret_cast<FILETIME*>(pData);
		log(3, L"🔈time_to_wstring datetime");
		datetime = time_to_wstring(temp);
		log(3, L"🔈time_to_wstring datetimeUtc");
		datetimeUtc = time_to_wstring(temp, true);
		sid = psid;
		log(3, L"🔈getNameFromSid sidName");
		sidName = getNameFromSid(sid);
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈Bam to_json");
		return L"\t{ \n"
			L"\t\t\"SID\":\"" + sid + L"\", \n"
			L"\t\t\"SIDName\":\"" + sidName + L"\", \n"
			L"\t\t\"Name\":\"" + name + L"\", \n"
			L"\t\t\"Datetime\":\"" + datetime + L"\", \n"
			L"\t\t\"DatetimeUtc\":\"" + datetimeUtc + L"\"\n"
			L"\t}";
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Bam clear");
	}
};

/*! *structure contenant l'ensemble des BAM
*/
struct Bams {
public:
	std::vector<Bam> bams;//!< tableau contenant tous les objets
	
	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Bams : ");
		log(0, L"*******************************************************************************************************************");

		//variables
		HRESULT hresult = NULL;
		ORHKEY hKey = NULL;
		ORHKEY hKey2 = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0;
		DWORD dType = 0;
		DWORD nSize = 0;
		WCHAR szSubKey[MAX_KEY_NAME]=L"";
		WCHAR szValue[MAX_VALUE_NAME]=L"";
		std::wstring bam_keys[2] = { L"bam",L"bam\\state" };
		for (std::wstring key : bam_keys) {
			for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
				std::wstring temp = L"Services\\" + key + L"\\UserSettings\\" + get<0>(profile);
				CONST wchar_t* regkey = temp.c_str();
				log(3, L"🔈OROpenKey CurrentControlSet\\" + std::wstring(regkey));
				hresult = OROpenKey(conf.CurrentControlSet, regkey, &hKey);
				if (hresult != ERROR_SUCCESS) {
					log(2,  L"🔥OROpenKey CurrentControlSet\\" + std::wstring(regkey), hresult);
					continue;
				};

				log(3, L"🔈ORQueryInfoKey CurrentControlSet\\" + std::wstring(regkey));
				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥ORQueryInfoKey CurrentControlSet\\" + std::wstring(regkey), hresult);
					continue;
				};

				for (int i = 0; i < (int)nValues; i++) {
					nSize = MAX_KEY_NAME;
					DWORD cData = 0;
					LPBYTE pData = NULL;

					do {
						if (pData != NULL)
							delete[] pData;
						pData = new BYTE[cData];
						log(3, L"🔈OREnumValue CurrentControlSet\\" + std::wstring(regkey));
						hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, (LPBYTE)pData, &cData);
					} while (hresult == ERROR_MORE_DATA);
					if (dType != REG_BINARY) {
						log(2, L"🔥OREnumValue "+ std::wstring(szValue) + L" not a REG_BINARY value");
					}
					else {
						if (hresult != ERROR_SUCCESS) {
							log(2, L"🔥OREnumValue OREnumValue CurrentControlSet\\" + std::wstring(regkey), hresult);
						}
						else {
							log(1, L"➕Bam");
							Bam bam(pData, std::wstring(szValue), std::wstring(get<0>(profile)));
							//save
							bams.push_back(bam);
						}
					}
					delete[] pData;
				}
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		log(3, L"🔈Bams to_json");
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
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/bams.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Bams clear");
		for (Bam temp : bams)
			temp.clear();
	}
};