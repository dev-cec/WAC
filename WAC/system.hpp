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
	bool daylightInEffect=false; //!< Heure d'été active si true
	AppliConf _conf = { 0 };//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		DWORD nSize = 0;
		LPWSTR buffer = NULL;
		//architecture su système
		SYSTEM_INFO systemInfos = { 0 };
		GetSystemInfo(&systemInfos);
		osArchitecture = os_architecture(systemInfos.wProcessorArchitecture);
		//// nom de l'ordinateur
		do {
			buffer = (LPWSTR)malloc(nSize*sizeof(wchar_t));
			GetComputerNameExW(ComputerNameDnsHostname, buffer, &nSize);
			computerName = std::wstring(buffer);
		} while (GetLastError() == ERROR_MORE_DATA);
		
		free(buffer);
		
		// nom de domaine
		nSize = 0;
		do {
			buffer = (LPWSTR)malloc(nSize*sizeof(wchar_t));
			GetComputerNameExW(ComputerNameDnsDomain, buffer, &nSize);
			domainName = std::wstring(buffer);
		} while (GetLastError() == ERROR_MORE_DATA);
		
		if (domainName.length() == 0)
			domainName = L"WORKGROUP";
		
		free(buffer);
		
		// timezone
		
		
		DYNAMIC_TIME_ZONE_INFORMATION timezoneInformations;
		TIME_ZONE_INFORMATION timezone;
		GetDynamicTimeZoneInformation(&timezoneInformations);
		GetTimeZoneInformation(&timezone);
		currentTimeZoneCaption = std::wstring(timezoneInformations.StandardName);
		currentTimeZone = std::wstring(timezoneInformations.TimeZoneKeyName);
		time_t rawtime = time(nullptr); // heure actuelle 
		struct tm* timeinfo = localtime(&rawtime);//localtime pour savoir si heure d'été active ou non
		if (timeinfo->tm_isdst) {//si heure d'été actif
			daylightInEffect = true;
			currentBias = timezoneInformations.Bias + timezoneInformations.DaylightBias;
		}
		else {
			daylightInEffect = false;
			currentBias = timezoneInformations.Bias + +timezoneInformations.StandardBias;
		}
		
		//heure système
		GetSystemTime(&localDateTimeUtc);
		SystemTimeToTzSpecificLocalTime(&timezone, &localDateTimeUtc, &localDateTime);
		
		//Version
		HMODULE hDll = LoadLibrary(TEXT("ntdll.dll"));
		typedef NTSTATUS(CALLBACK* RTLGETVERSION) (PRTL_OSVERSIONINFOW lpVersionInformation);
		RTLGETVERSION pRtlGetVersion;
		pRtlGetVersion = (RTLGETVERSION)GetProcAddress(hDll, "RtlGetVersion");
		if (pRtlGetVersion)
		{
			RTL_OSVERSIONINFOW ovi = { 0 };
			ovi.dwOSVersionInfoSize = sizeof(ovi);
			NTSTATUS ntStatus = pRtlGetVersion(&ovi);
			if (ntStatus == 0)
			{
				version = std::to_wstring(ovi.dwMajorVersion) + L"." + std::to_wstring(ovi.dwMinorVersion) + L"." + std::to_wstring(ovi.dwBuildNumber);
				servicePack = std::wstring(ovi.szCSDVersion);
			}
		}
		FreeLibrary(hDll);
		
		HMODULE hMod = LoadLibraryEx(L"winbrand.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (hMod)
		{
			PWSTR(WINAPI * pfnBrandingFormatString)(PCWSTR pstrFormat);
			(FARPROC&)pfnBrandingFormatString = GetProcAddress(hMod, "BrandingFormatString");
			if (pfnBrandingFormatString)
				osName = std::wstring(pfnBrandingFormatString(L"%WINDOWS_LONG%"));
			FreeLibrary(hMod);
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		std::wstring result = L"{ \n"
			L"\t\"OsArchitecture\":\"" + osArchitecture + L"\", \n"
			L"\t\"OsName\":\"" + osName + L"\", \n"
			L"\t\"ComputerName\":\"" + computerName + L"\", \n"
			L"\t\"DomainName\":\"" + domainName + L"\", \n"
			L"\t\"LocalDateTime\":\"" + time_to_wstring(localDateTime) + L"\", \n"
			L"\t\"LocalDateTimeUtc\":\"" + time_to_wstring(localDateTimeUtc) + L"\", \n"
			L"\t\"CurrentTimeZoneId\":\"" + currentTimeZone + L"\", \n"
			L"\t\"CurrentTimeZoneCaption\":\"" + currentTimeZoneCaption + L"\", \n"
			L"\t\"CurrentBias\":\"" + std::to_wstring(currentBias) + L"\", \n"
			L"\t\"DaylightInEffect\":\"" + bool_to_wstring(daylightInEffect) + L"\", \n"
			L"\t\"Version\":\"" + version + L"\", \n"
			L"\t\"ServicePack\":\"" + servicePack + L"\", \n"
			L"}";


		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/OperatingSystem.json");
		myfile << result;
		myfile.close();

		return ERROR_SUCCESS;
	}
};