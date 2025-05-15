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

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		return L"\t{ \n"
			L"\t\t\"SID\":\"" + Sid + L"\", \n"
			L"\t\t\"SIDName\":\"" + SidName + L"\", \n"
			L"\t\t\"Key\":\"" + Key + L"\", \n"
			L"\t\t\"Name\":\"" + Name + L"\", \n"
			L"\t\t\"Value\":\"" + Value + L"\"\n"
			L"\t}";
	}
};

/*! structure contenant l'ensemble des artefacts
*/
struct Runs {
public:
	std::vector<Run> runs;//!< tableau contenant les objets
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs de traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param mountpoint est le point de montage du snapshot du système
	* @param userprofiles contient les profils des utilisateurs de la machine
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		HRESULT hresult;
		ORHKEY hKey;
		DWORD nSubkeys;
		DWORD nValues, dType;
		WCHAR szValue[MAX_VALUE_NAME];
		WCHAR szSubKey[MAX_VALUE_NAME];
		DWORD nSize = 0;
		ORHKEY Offhive;
		std::wstring ruche = L"";
		std::wstring runKeys[2] = { L"Run",L"RunOnce" };

		for (std::wstring runKey : runKeys) {
			hresult = OROpenKey(_conf.Software, (L"Microsoft\\Windows\\CurrentVersion\\" + runKey).c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"Unable to open key : HKLM\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey, hresult });
				continue;
			}
			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"Unable to get info key : HKLM\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey, hresult });
				continue;
			}
			for (int i = 0; i < (int)nValues; i++) {
				Run run;
				nSize = MAX_VALUE_NAME;
				DWORD cData = MAX_DATA;
				hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
				if (dType != REG_SZ) continue;
				run.Sid = L"";
				run.SidName = L"HKLM";
				run.Key = runKey;
				run.Name = szValue;
				hresult = getRegSzValue(hKey, nullptr, szValue, &run.Value);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to get value : HKLM\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey + L"\\" + szValue, hresult });
					continue;
				}
				run.Value = replaceAll(run.Value, L"\"", L"\\\""); // remplace les " dans les lignes de commande par \"
				run.Value = replaceAll(run.Value, L"\\", L"\\\\");// escape \ in std::string
				run.Value = replaceAll(run.Value, L"\\\\\"", L"\\\""); // corrige \\" to \"
				if (hresult != ERROR_SUCCESS) continue;

				//save
				runs.push_back(run);
			}
			for (std::tuple<std::wstring, std::wstring> profile : _conf.profiles) {
				//ouverture de la ruche user
				ruche = _conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"") + L"\\\\ntuser.dat";
				hresult = OROpenHive(ruche.c_str(), &Offhive);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L" Unable to open hive : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat", hresult});
					continue;
				}

				hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey).c_str(), &hKey);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to open key : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat / Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey, hresult});
					continue;
				}

				hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to get info key : " + get<0>(profile) + L" / " + replaceAll(get<1>(profile),L"\\",L"\\\\") + L"\\\\ntuser.dat / Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey, hresult});
					continue;
				}

				for (int i = 0; i < (int)nValues; i++) {
					Run run;
					nSize = MAX_VALUE_NAME;
					DWORD cData = MAX_DATA;
					hresult = OREnumValue(hKey, i, szValue, &nSize, &dType, NULL, &cData);
					if (dType != REG_SZ) continue;
					if (hresult != ERROR_SUCCESS) {
						errors.push_back({ L"Unable to open key : " + get<0>(profile) + L"/ NTUSER.dat / Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey + L"\\" + szValue, hresult});
						continue;
					}
					run.Sid = get<0>(profile);
					run.SidName = getNameFromSid(run.Sid);
					run.Key = runKey;
					run.Name = szValue;
					run.Name = replaceAll(run.Name, L"\\", L"\\\\");// escape \ in std::string
					
					getRegSzValue(hKey, nullptr, szValue, &run.Value);
					run.Value = replaceAll(run.Value, L"\"", L"\\\""); // remplace les " dans les lignes de commande par \"
					run.Value = replaceAll(run.Value, L"\\", L"\\\\");// escape \ in std::string
					run.Value = replaceAll(run.Value, L"\\\\\"", L"\\\""); // corrige \\" to \"

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
		std::vector<Run>::iterator run;
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
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/run.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir +"/run_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}
};