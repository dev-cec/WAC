#pragma once
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



/*! structure représentant un artefact Usbstor
*/
struct Usbstor {
public:
	std::vector<std::wstring> HardwareId; //!< tableau de chaîne de texte représentant les identifiant hardware du périphérique
	std::wstring FriendlyName = L""; //!< nom du périphérique
	std::wstring CompatibleIds = L"";//!< id compatibles avec le périphérique
	std::wstring ClassGuid = L""; //!< identifiant GUID de la classe
	std::wstring SerialNumber = L"";//!< numéro de série du périphérique
	std::wstring LastInsertion = L"";//!< date de dernière insertion du périphérique
	std::wstring LastInsertionUtc = L"";//!< date de dernière insertion du périphérique au format UTC
	std::wstring FirstInsertion = L"";//!< date de première insertion du périphérique
	std::wstring FirstInsertionUtc = L"";//!< date de première insertion du périphérique au format UTC

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		return tab(1) + L"{ \n"
			+ tab(2) + L"\"HardwareId\":" + multiSz_to_json(HardwareId, 2) + L", \n"
			+ tab(2) + L"\"FriendlyName\":\"" + FriendlyName + L"\", \n"
			+ tab(2) + L"\"CompatibleIds\":\"" + CompatibleIds + L"\", \n"
			+ tab(2) + L"\"ClassGuid\":\"" + ClassGuid + L"\", \n"
			+ tab(2) + L"\"SerialNumber\":\"" + SerialNumber + L"\", \n"
			+ tab(2) + L"\"LastInsertion\":\"" + LastInsertion + L"\", \n"
			+ tab(2) + L"\"LastInsertionUtc\":\"" + LastInsertionUtc + L"\", \n"
			+ tab(2) + L"\"FirstInsertion\":\"" + FirstInsertion + L"\", \n"
			+ tab(2) + L"\"FirstInsertionUtc\":\"" + FirstInsertionUtc + L"\" \n"
			+ tab(1) + L"}";
	}

	/* liberation mémoire */
	void clear() {}
};

/*! structure contenant l'ensemble des artefacts
*/
struct Usbstors {
public:
	std::vector<Usbstor> usbs;//!< tableau contenant les objets
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs de traitement des objets


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		//variables
		HRESULT hresult;
		ORHKEY hkey, hKey_fabricant, hKey_usb, hkey_time;
		DWORD nSubkeys_usbstor;
		DWORD nSubkeys_fabricant;
		DWORD nValues;
		WCHAR szSubKey_usbstor[MAX_KEY_NAME];
		WCHAR szSubKey_fabricant[MAX_KEY_NAME];
		DWORD nSize = MAX_VALUE_NAME;

		hresult = OROpenKey(conf.CurrentControlSet, L"Enum\\USBSTOR\\", &hkey);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\", hresult });
			return hresult;
		}

		hresult = ORQueryInfoKey(hkey, NULL, NULL, &nSubkeys_usbstor, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\", hresult });
			return hresult;
		};

		for (int i = 0; i < (int)nSubkeys_usbstor; i++) {
			memset(szSubKey_usbstor, 0, sizeof(szSubKey_usbstor));
			nSize = MAX_KEY_NAME;
			hresult = OREnumKey(hkey, i, szSubKey_usbstor, &nSize, NULL, NULL, NULL);

			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor), hresult });
				continue;
			}

			hresult = OROpenKey(hkey, szSubKey_usbstor, &hKey_fabricant); // on ouvre la clé du fabricant
			if (hresult != ERROR_SUCCESS) {
				errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor), hresult });
				continue;
			}

			hresult = ORQueryInfoKey(hKey_fabricant, NULL, NULL, &nSubkeys_fabricant, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor), hresult });
				continue;
			}

			for (int j = 0; j < (int)nSubkeys_fabricant; j++) {
				memset(szSubKey_fabricant, 0, sizeof(szSubKey_fabricant));
				nSize = MAX_KEY_NAME;
				hresult = OREnumKey(hKey_fabricant, j, szSubKey_fabricant, &nSize, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
					errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L"\\" + std::wstring(szSubKey_fabricant), hresult });
					continue;
				}

				hresult = OROpenKey(hKey_fabricant, szSubKey_fabricant, &hKey_usb);
				if (hresult != ERROR_SUCCESS) {
					errors.push_back({ L"Unable to open key : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L"\\" + std::wstring(szSubKey_fabricant), hresult });
					continue;
				}

				Usbstor usb;
				hresult = getRegMultiSzValue(hKey_usb, NULL, L"HardwareId", &usb.HardwareId);
				hresult = getRegSzValue(hKey_usb, nullptr, L"FriendlyName", &usb.FriendlyName);
				hresult = getRegSzValue(hKey_usb, nullptr, L"CompatibleIds", &usb.CompatibleIds);
				usb.CompatibleIds = replaceAll(usb.CompatibleIds, L"\\", L"\\\\"); // replace\ by \\ in std::string
				hresult = getRegSzValue(hKey_usb, nullptr, L"ClassGuid", &usb.ClassGuid);
				hresult = getRegSzValue(hKey_usb, nullptr, L"SerialNumber", &usb.SerialNumber);
				FILETIME tempFiletime = { 0 };
				hresult = OROpenKey(hKey_usb, L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066", &hkey_time);
				if (hresult == ERROR_SUCCESS) {
					hresult = getRegFiletimeValue(hkey_time, nullptr, L"", &tempFiletime);
					
					if (hresult != ERROR_SUCCESS) {
						errors.push_back({ L"Unable to get Filetime Value : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L"\\" + std::wstring(szSubKey_fabricant) + L"\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066" , hresult });
						continue;
					}
					usb.LastInsertion = time_to_wstring(tempFiletime);
					usb.LastInsertionUtc = time_to_wstring(tempFiletime, true);
				}
				hresult = OROpenKey(hKey_usb, L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064", &hkey_time);
				if (hresult == ERROR_SUCCESS) {
					tempFiletime = { 0 };
					hresult = getRegFiletimeValue(hkey_time, nullptr, L"", &tempFiletime);
					
					if (hresult != ERROR_SUCCESS) {
						errors.push_back({ L"Unable to gt Filetime Value : HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L"\\" + std::wstring(szSubKey_fabricant) + L"\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064" , hresult });
						continue;
					}
					usb.FirstInsertion = time_to_wstring(tempFiletime);
					usb.FirstInsertionUtc = time_to_wstring(tempFiletime, true);
				}

				//save
				usbs.push_back(usb);
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		std::vector<Usbstor>::iterator usb;
		std::wstring result = L"[ \n";
		std::vector<Usbstor>::iterator it;
		for (it = usbs.begin(); it != usbs.end(); it++) {
			result += it->to_json();
			if (it != usbs.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/Usbstor.json");
		myfile << result;
		myfile.close();

		if (conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(conf._errorOutputDir + "/usbstor_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		for (Usbstor temp : usbs)
			temp.clear();
	}
};
