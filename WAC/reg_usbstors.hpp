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
		log(3, L"🔈usbstor to_json");
		std::wstring result = tab(1) + L"{ \n";
		log(3, L"🔈multiSz_to_json HardwareId");
		result += tab(2) + L"\"HardwareId\":" + multiSz_to_json(HardwareId, 2) + L", \n";
		result += tab(2) + L"\"FriendlyName\":\"" + FriendlyName + L"\", \n";
		result += tab(2) + L"\"CompatibleIds\":\"" + CompatibleIds + L"\", \n";
		result += tab(2) + L"\"ClassGuid\":\"" + ClassGuid + L"\", \n";
		result += tab(2) + L"\"SerialNumber\":\"" + SerialNumber + L"\", \n";
		result += tab(2) + L"\"LastInsertion\":\"" + LastInsertion + L"\", \n";
		result += tab(2) + L"\"LastInsertionUtc\":\"" + LastInsertionUtc + L"\", \n";
		result += tab(2) + L"\"FirstInsertion\":\"" + FirstInsertion + L"\", \n";
		result += tab(2) + L"\"FirstInsertionUtc\":\"" + FirstInsertionUtc + L"\" \n";
		result += tab(1) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈usbstor clear");
	}
};

/*! structure contenant l'ensemble des artefacts
*/
struct Usbstors {
public:
	std::vector<Usbstor> usbs;//!< tableau contenant les objets


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		//variables
		HRESULT hresult = 0;
		ORHKEY hkey = NULL, hKey_fabricant = NULL, hKey_usb = NULL, hkey_time = NULL;
		DWORD nSubkeys_usbstor = 0;
		DWORD nSubkeys_fabricant = 0;
		DWORD nValues = 0;
		WCHAR szSubKey_usbstor[MAX_KEY_NAME] = L"";
		WCHAR szSubKey_fabricant[MAX_KEY_NAME] = L"";
		DWORD nSize = MAX_VALUE_NAME;

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️USBSTOR :");
		log(0, L"*******************************************************************************************************************");

		log(3, L"🔈OROpenKey hkey");
		hresult = OROpenKey(conf.CurrentControlSet, L"Enum\\USBSTOR\\", &hkey);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥OROpenKey hkey", hresult);
			return hresult;
		}
		log(3, L"🔈ORQueryInfoKey hkey");
		hresult = ORQueryInfoKey(hkey, NULL, NULL, &nSubkeys_usbstor, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥ORQueryInfoKey hkey", hresult);
			return hresult;
		};

		for (int i = 0; i < (int)nSubkeys_usbstor; i++) {
			memset(szSubKey_usbstor, 0, sizeof(szSubKey_usbstor));
			nSize = MAX_KEY_NAME;
			log(3, L"🔈OREnumKey hkey");
			hresult = OREnumKey(hkey, i, szSubKey_usbstor, &nSize, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				log(2, L"🔥OREnumKey hkey", hresult);
				continue;
			}
			log(3, L"🔈OROpenKey hKey_fabricant");
			hresult = OROpenKey(hkey, szSubKey_usbstor, &hKey_fabricant); // on ouvre la clé du fabricant
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey hKey_fabricant", hresult);
				continue;
			}
			log(3, L"🔈ORQueryInfoKey hKey_fabricant");
			hresult = ORQueryInfoKey(hKey_fabricant, NULL, NULL, &nSubkeys_fabricant, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				log(2, L"🔥ORQueryInfoKey hKey_fabricant", hresult);
				continue;
			}

			for (int j = 0; j < (int)nSubkeys_fabricant; j++) {
				memset(szSubKey_fabricant, 0, sizeof(szSubKey_fabricant));
				nSize = MAX_KEY_NAME;
				log(3, L"🔈OREnumKey szSubKey_fabricant");
				hresult = OREnumKey(hKey_fabricant, j, szSubKey_fabricant, &nSize, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
					log(2, L"🔥OREnumKey szSubKey_fabricant", hresult);
					continue;
				}

				log(3, L"🔈OROpenKey hKey_usb");
				hresult = OROpenKey(hKey_fabricant, szSubKey_fabricant, &hKey_usb);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey hKey_usb", hresult);
					continue;
				}
				log(1, L"➕USB ");
				Usbstor usb;
				log(3, L"🔈getRegMultiSzValue HardwareId");
				hresult = getRegMultiSzValue(hKey_usb, NULL, L"HardwareId", &usb.HardwareId);
				log(3, L"🔈getRegSzValue FriendlyName");
				hresult = getRegSzValue(hKey_usb, nullptr, L"FriendlyName", &usb.FriendlyName);
				log(2, L"❇️USB Friendlyname : " + usb.FriendlyName);
				log(3, L"🔈getRegSzValue CompatibleIds");
				hresult = getRegSzValue(hKey_usb, nullptr, L"CompatibleIds", &usb.CompatibleIds);
				log(3, L"🔈replaceAll CompatibleIds");
				usb.CompatibleIds = replaceAll(usb.CompatibleIds, L"\\", L"\\\\"); // replace\ by \\ in std::string
				log(3, L"🔈getRegSzValue ClassGuid");
				hresult = getRegSzValue(hKey_usb, nullptr, L"ClassGuid", &usb.ClassGuid);
				log(3, L"🔈getRegSzValue SerialNumber");
				hresult = getRegSzValue(hKey_usb, nullptr, L"SerialNumber", &usb.SerialNumber);
				FILETIME tempFiletime = { 0 };
				log(3, L"🔈OROpenKey hkey_time 0066");
				hresult = OROpenKey(hKey_usb, L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066", &hkey_time);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey hkey_time 0066", hresult);
					continue;
				}
				else {
					log(3, L"🔈getRegFiletimeValue tempFiletime 0066");
					hresult = getRegFiletimeValue(hkey_time, nullptr, L"", &tempFiletime);
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥getRegFiletimeValue tempFiletime", hresult);
						continue;
					}
					else {
						log(3, L"🔈time_to_wstring tempFiletime");
						usb.LastInsertion = time_to_wstring(tempFiletime);
						log(3, L"🔈time_to_wstring LastInsertionUtc");
						usb.LastInsertionUtc = time_to_wstring(tempFiletime, true);
					}
				}
				log(3, L"🔈OROpenKey hkey_time 0064");
				hresult = OROpenKey(hKey_usb, L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064", &hkey_time);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey hkey_time 0064", hresult);
					continue;
				}
				else {
					tempFiletime = { 0 };
					log(3, L"🔈getRegFiletimeValue tempFiletime 0064");
					hresult = getRegFiletimeValue(hkey_time, nullptr, L"", &tempFiletime);

					if (hresult != ERROR_SUCCESS) {
						log(2, L"getRegFiletimeValue  tempFiletime 0064", hresult);
						continue;
					}
					else {
						log(3, L"🔈time_to_wstring FirstInsertion");
						usb.FirstInsertion = time_to_wstring(tempFiletime);
						log(3, L"🔈time_to_wstring FirstInsertionUtc");
						usb.FirstInsertionUtc = time_to_wstring(tempFiletime, true);
					}
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
		log(3, L"🔈usbstors to_json");
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
		log(3, L"🔈ansi_to_utf8 result");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈usbstors clear");
		for (Usbstor temp : usbs)
			temp.clear();
	}
};
