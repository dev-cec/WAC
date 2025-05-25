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



struct Run {
public:
	std::wstring Sid = L""; //!< Sid de l'utilisateur propriétaire de l'objet
	std::wstring SidName = L""; //!< nom de l'utilisateur propriétaire de l'objet
	std::wstring Key = L""; //!< origine de l'artefact, run ou runonce
	std::wstring Name = L""; //!< nom de la clé
	std::wstring Value = L"";//!< valeur de la clé
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈Run to_jon");
		std::wstring result = L"\t{ \n";
		result += L"\t\t\"SID\":\"" + Sid + L"\", \n";
		result += L"\t\t\"SIDName\":\"" + SidName + L"\", \n";
		result += L"\t\t\"Key\":\"" + Key + L"\", \n";
		result += L"\t\t\"Name\":\"" + Name + L"\", \n";
		result += L"\t\t\"Value\":\"" + Value + L"\", \n";
		log(3, L"🔈time_to_wstring lastWriteTime");
		result += L"\t\t\"LastWriteTime\":\"" + time_to_wstring(lastWriteTime) + L"\", \n";
		log(3, L"🔈time_to_wstring lastWriteTimeUtc");
		result += L"\t\t\"LastWriteTimeUtc\":\"" + time_to_wstring(lastWriteTimeUtc) + L"\"\n";
		result += L"\t}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Run clear");
	}
};

/*! structure contenant l'ensemble des artefacts
*/
struct Runs {
public:
	std::vector<Run> runs;//!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Runs :");
		log(0, L"*******************************************************************************************************************");

		HRESULT hresult = 0;
		ORHKEY hKey = NULL;
		ORHKEY Offhive = NULL;
		DWORD nSubkeys = 0;
		DWORD nValues = 0;
		DWORD nSize = 0;
		DWORD dType = 0;
		WCHAR szValue[MAX_VALUE_NAME] = L"";
		WCHAR szSubKey[MAX_VALUE_NAME] = L"";
		FILETIME lastWriteTimeUtc = { 0 };
		std::wstring ruche = L"";
		std::wstring runKeys[2] = { L"Run",L"RunOnce" };
		for (std::wstring runKey : runKeys) {
			log(3, L"🔈OROpenKey HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
			hresult = OROpenKey(conf.Software, (L"Microsoft\\Windows\\CurrentVersion\\" + runKey).c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey, hresult);
				continue;
			}

			log(3, L"🔈ORQueryInfoKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥ORQueryInfoKey HKLM\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey, hresult);
				continue;
			}
			for (int i = 0; i < (int)nValues; i++) {
				log(1, L"➕Run ");
				Run run;
				nSize = MAX_VALUE_NAME;
				run.lastWriteTimeUtc = lastWriteTimeUtc;
				log(3, L"🔈FileTimeToLocalFileTime lastWriteTime");
				FileTimeToLocalFileTime(&lastWriteTimeUtc, &run.lastWriteTime);
				DWORD cData = MAX_DATA;
				log(3, L"🔈OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i));
				hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i), hresult);
				}
				if (dType != REG_SZ) {
					log(2, L"🔥OREnumValue " + std::wstring(szValue) + L" not REG_SZ type");
					continue;
				}
				run.Name = szValue;
				log(2, L"❇️Run Name : " + run.Name);
				run.Sid = L"";
				run.SidName = L"HKLM";
				run.Key = runKey;
				log(3, L"🔈getRegSzValue " + std::wstring(szValue));
				hresult = getRegSzValue(hKey, nullptr, szValue, &run.Value);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥getRegSzValue " + std::wstring(szValue), hresult);
				}
				log(3, L"🔈replaceAll Value");
				run.Value = replaceAll(run.Value, L"\\", L"\\\\");// escape \ in std::string
				run.Value = replaceAll(run.Value, L"\"", L"\\\""); // remplace les " dans les lignes de commande par \"
				//save
				runs.push_back(run);
			}
			for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
				//ouverture de la ruche user
				log(3, L"🔈replaceAll Profile");
				ruche = conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\\\ntuser.dat";
				log(3, L"🔈OROpenHive " + get<1>(profile) + L"\\ntuser.dat");
				hresult = OROpenHive(ruche.c_str(), &Offhive);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenHive " + get<1>(profile) + L"\\ntuser.dat", hresult);
					continue;
				}

				log(3, L"🔈OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
				hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey).c_str(), &hKey);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey, hresult);
					continue;
				}

				log(3, L"🔈ORQueryInfoKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥ORQueryInfoKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey, hresult);
					continue;
				}

				for (int i = 0; i < (int)nValues; i++) {
					log(1, L"➕Run ");
					Run run;
					nSize = MAX_VALUE_NAME;
					DWORD cData = MAX_DATA;
					run.lastWriteTimeUtc = lastWriteTimeUtc;
					log(3, L"🔈FileTimeToLocalFileTime lastWriteTime");
					FileTimeToLocalFileTime(&lastWriteTimeUtc, &run.lastWriteTime);
					log(3, L"🔈OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i));
					hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i), hresult);
					}
					if (dType != REG_SZ) {
						log(2, L"🔥OREnumValue " + std::wstring(szValue) + L" not REG_SZ type");
						continue;
					}
					run.Name = szValue;
					log(2, L"❇️Run Name : " + run.Name);
					run.Sid = get<0>(profile);
					log(3, L"🔈getNameFromSid Sid");
					run.SidName = getNameFromSid(run.Sid);
					run.Key = runKey;
					log(3, L"🔈getRegSzValue " + std::wstring(szValue));
					hresult = getRegSzValue(hKey, nullptr, szValue, &run.Value);
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥getRegSzValue " + std::wstring(szValue), hresult);
					}
					log(3, L"🔈replaceAll Value");
					run.Value = replaceAll(run.Value, L"\\", L"\\\\");// escape \ in std::string
					run.Value = replaceAll(run.Value, L"\"", L"\\\""); // remplace les " dans les lignes de commande par \"
					//save
					runs.push_back(run);
				}
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		log(3, L"🔈Runs to_jon");
		std::wstring result = L"[ \n";
		std::vector<Run>::iterator it;
		for (it = runs.begin(); it != runs.end(); it++) {
			result += it->to_json();
			if (it != runs.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/run.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Runs clear");
		for (Run temp : runs)
			temp.clear();
	}
};