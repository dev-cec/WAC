#pragma once

#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include "tools.h"
#include "trans_id.h"



/*! structure contenant les information du système
* Documentation : https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
* Documentation : https://learn.microsoft.com/fr-fr/windows/win32/api/timezoneapi/nf-timezoneapi-getdynamictimezoneinformation
* Documentation : https://learn.microsoft.com/fr-fr/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw
*/
struct SystemInfo {
	std::wstring osArchitecture = L"";//!< architecture de l'OS
	std::wstring computerName = L""; //!< nom de l'ordinateur
	std::wstring domainName = L"";//!< nom du domain de l'ordinateur
	std::wstring currentTimeZoneCaption = L"";//!< nom de la timezone
	std::wstring currentTimeZone = L""; //!< identifiant de la timezone
	std::wstring osName = L""; //!< version de l'OS
	std::wstring version = L""; //!< version de l'OS
	std::wstring servicePack = L""; //!< version du service pack installé si non null
	SYSTEMTIME localDateTime = { 0 }; //!< heure du système au moment de l’exécution du programme
	SYSTEMTIME localDateTimeUtc = { 0 };//!< heure du système au moment de l’exécution du programme au format UTC
	SYSTEMTIME lastBootUpTime = { 0 }; //!< heure du dernier démarrage du system
	SYSTEMTIME lastBootUpTimeUtc = { 0 };//!< heure du dernier démarrage du system au format UTC
	int currentBias = 0; //!< décalage horaire actuel
	bool daylightInEffect = false; //!< Heure d'été active si true
	AppliConf conf = { 0 };//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		DWORD nSize = 0;
		LPWSTR buffer = NULL;
		SYSTEM_INFO systemInfos = { 0 };

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Operating System :");
		log(0, L"*******************************************************************************************************************");
		log(1, L"➕System");
		log(3, L"🔈GetSystemInfo");
		GetSystemInfo(&systemInfos);

		//architecture su système
		log(3, L"🔈os_architecture");
		osArchitecture = os_architecture(systemInfos.wProcessorArchitecture);
		// nom de l'ordinateur
		do {
			buffer = (LPWSTR)malloc(nSize * sizeof(wchar_t));
			log(3, L"🔈GetComputerNameExW ComputerNameDnsHostname");
			bool r = GetComputerNameExW(ComputerNameDnsHostname, buffer, &nSize);
			if (GetLastError() != ERROR_MORE_DATA && !r) {
				log(2, L"🔥GetComputerNameExW ComputerNameDnsHostname", GetLastError());
				computerName = L"";
			}
			else
				computerName = std::wstring(buffer).data();
			free(buffer);
		} while (GetLastError() == ERROR_MORE_DATA);
		log(2, L"❇️Computer name : " + computerName);

		// nom de domaine
		nSize = 0;
		do {
			buffer = (LPWSTR)malloc(nSize * sizeof(wchar_t));
			log(3, L"🔈GetComputerNameExW ComputerNameDnsDomain");
			bool r = GetComputerNameExW(ComputerNameDnsDomain, buffer, &nSize);
			if (GetLastError() != ERROR_MORE_DATA && !r) {
				log(2, L"🔥GetComputerNameExW ComputerNameDnsHostname", GetLastError());
				domainName = L"";
			}
			else
				domainName = std::wstring(buffer).data();
			free(buffer);
		} while (GetLastError() == ERROR_MORE_DATA);

		if (domainName.length() == 0)
			domainName = L"WORKGROUP";

		// timezone


		DYNAMIC_TIME_ZONE_INFORMATION timezoneInformations;
		TIME_ZONE_INFORMATION timezone;
		log(3, L"🔈GetDynamicTimeZoneInformation");
		int r = GetDynamicTimeZoneInformation(&timezoneInformations);
		if (r != 0) {
			if (r != 0) {
				currentTimeZoneCaption = std::wstring(timezoneInformations.StandardName).data();
				currentTimeZone = std::wstring(timezoneInformations.TimeZoneKeyName).data();
				if (r==2) {//si heure d'été actif
					daylightInEffect = true;
					currentBias = timezoneInformations.Bias + timezoneInformations.DaylightBias;
				}
				else {
					daylightInEffect = false;
					currentBias = timezoneInformations.Bias + +timezoneInformations.StandardBias;
				}
			}
		}
		//heure système
		log(3, L"🔈GetSystemTime");
		GetSystemTime(&localDateTimeUtc);
		log(3, L"🔈GetTimeZoneInformation");
		r = GetTimeZoneInformation(&timezone);
		if (r != 0) {
			log(3, L"🔈SystemTimeToTzSpecificLocalTime");
			SystemTimeToTzSpecificLocalTime(&timezone, &localDateTimeUtc, &localDateTime);
		}
		else
			log(2, L"🔥GetTimeZoneInformation", TIME_ZONE_ID_UNKNOWN);
		//Version
		log(3, L"🔈LoadLibrary(TEXT(\"ntdll.dll\")");
		HMODULE hDll = LoadLibrary(TEXT("ntdll.dll"));
		if (hDll) {
			log(3, L"🔈Chargement de RTLGETVERSION");
			typedef NTSTATUS(CALLBACK* RTLGETVERSION) (PRTL_OSVERSIONINFOW lpVersionInformation);
			RTLGETVERSION pRtlGetVersion;
			pRtlGetVersion = (RTLGETVERSION)GetProcAddress(hDll, "RtlGetVersion");
			if (pRtlGetVersion)
			{
				RTL_OSVERSIONINFOW ovi = { 0 };
				ovi.dwOSVersionInfoSize = sizeof(ovi);
				log(3, L"🔈Appel de RTLGETVERSION");
				NTSTATUS ntStatus = pRtlGetVersion(&ovi);
				if (ntStatus == 0)//STATUS_SUCCESS
				{
					version = std::to_wstring(ovi.dwMajorVersion) + L"." + std::to_wstring(ovi.dwMinorVersion) + L"." + std::to_wstring(ovi.dwBuildNumber);
					servicePack = std::wstring(ovi.szCSDVersion).data();
				}
			}
			else
				log(2, L"🔥Chargement de RTLGETVERSION", GetLastError());
			FreeLibrary(hDll);
		}
		else 
			log(2, L"🔥LoadLibrary(TEXT(\"ntdll.dll\")", GetLastError());
		

		// OS NAME
		log(3, L"🔈LoadLibrary(TEXT(\"winbrand.dll\")");
		HMODULE hMod = LoadLibraryEx(L"winbrand.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (hMod)
		{
			log(3, L"🔈Chargement de BrandingFormatString");
			PWSTR(WINAPI * pfnBrandingFormatString)(PCWSTR pstrFormat);
			log(3, L"🔈Appel de GetProcAddress");
			(FARPROC&)pfnBrandingFormatString = GetProcAddress(hMod, "BrandingFormatString");
			if (pfnBrandingFormatString)
				osName = std::wstring(pfnBrandingFormatString(L"%WINDOWS_LONG%")).data();
			else
				log(2, L"🔥Chargement de BrandingFormatString", GetLastError());
			FreeLibrary(hMod);
		}
		else
			log(2, L"🔥LoadLibrary(TEXT(\"winbrand.dll\")", GetLastError());

		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈system to_json");
		std::wstring result = L"{ \n";
			result+=L"\t\"OsArchitecture\":\"" + osArchitecture + L"\", \n";
			result+=L"\t\"OsName\":\"" + osName + L"\", \n";
			result+=L"\t\"ComputerName\":\"" + computerName + L"\", \n";
			result+=L"\t\"DomainName\":\"" + domainName + L"\", \n";
			log(3, L"🔈time_to_wstring localDateTime ");
			result+=L"\t\"LocalDateTime\":\"" + time_to_wstring(localDateTime) + L"\", \n";
			log(3, L"🔈time_to_wstring localDateTimeUtc ");
			result+=L"\t\"LocalDateTimeUtc\":\"" + time_to_wstring(localDateTimeUtc) + L"\", \n";
			result+=L"\t\"CurrentTimeZoneId\":\"" + currentTimeZone + L"\", \n";
			result+=L"\t\"CurrentTimeZoneCaption\":\"" + currentTimeZoneCaption + L"\", \n";
			result+=L"\t\"CurrentBias\":\"" + std::to_wstring(currentBias) + L"\", \n";
			log(3, L"🔈bool_to_wstring daylightInEffect ");
			result+=L"\t\"DaylightInEffect\":\"" + bool_to_wstring(daylightInEffect) + L"\", \n";
			result+=L"\t\"Version\":\"" + version + L"\", \n";
			result+=L"\t\"ServicePack\":\"" + servicePack + L"\" \n";
			result += L"}";


		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/OperatingSystem.json");
		log(3, L"🔈ansi_to_utf8 result");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* libération mémoire */
	void clear() {
		log(3, L"🔈system clear");
	}
};