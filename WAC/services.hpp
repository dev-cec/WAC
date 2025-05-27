#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include "trans_id.h"
#include "tools.h"



struct ServiceStruct
{
	std::wstring serviceName = L"";
	std::wstring serviceDisplayName = L"";
	std::wstring serviceType = L"";
	std::wstring serviceStatus = L"";
	std::wstring serviceProcessId = L"";
	std::wstring serviceStartType = L"";
	std::wstring serviceOwner = L"";
	std::wstring serviceBinary = L"";
	std::wstring serviceMd5 = L"";
	std::wstring serviceAccessMessage = L"OK";

	/*! Constructeur
	* @param hSCM contient le pointeur sur le manager de contrôle de service
	* @param service contient les données du service
	*/
	ServiceStruct(SC_HANDLE hSCM, ENUM_SERVICE_STATUS_PROCESS service) {
		DWORD bufSize = 0;
		DWORD moreBytesNeeded;

		serviceName = std::wstring(service.lpServiceName).data();
		serviceDisplayName = std::wstring(service.lpDisplayName).data();
		log(1, L"➕Service");
		log(2, L"❇️Service name : " + serviceDisplayName);
		log(3, L"🔈serviceType_to_wstring");
		serviceType = serviceType_to_wstring(service.ServiceStatusProcess.dwServiceType);
		log(3, L"🔈serviceState_to_wstring");
		serviceStatus = serviceState_to_wstring(service.ServiceStatusProcess.dwCurrentState);
		serviceProcessId = std::to_wstring(service.ServiceStatusProcess.dwProcessId);

		log(3, L"🔈OpenServiceW");
		SC_HANDLE hService = OpenServiceW(hSCM, service.lpServiceName, SC_MANAGER_ALL_ACCESS);
		if (hService) {
			log(3, L"🔈QueryServiceConfigW");
			QueryServiceConfigW(hService, NULL, 0, &moreBytesNeeded); //get size of buffer
			LPQUERY_SERVICE_CONFIG sData = (LPQUERY_SERVICE_CONFIG)malloc(moreBytesNeeded);
			bufSize = moreBytesNeeded;
			if (QueryServiceConfigW(hService, sData, bufSize, &moreBytesNeeded)) { //get service info
				log(3, L"🔈serviceStart_to_wstring");
				serviceStartType = serviceStart_to_wstring(sData->dwStartType);
				serviceOwner = std::wstring(sData->lpServiceStartName).data();
				log(3, L"🔈replaceAll lpServiceStartName");
				serviceOwner = replaceAll(serviceOwner, L"\\", L"\\\\");
				serviceBinary = std::wstring(sData->lpBinaryPathName).data();

				//calcul hash avant escape
				char appdata[MAX_PATH];
				log(3, L"🔈replaceAll temp");
				std::wstring wp(replaceAll(serviceBinary, L"\"", L""));
				log(3, L"🔈wstring_to_string p");
				std::string p = wstring_to_string(wp); // remove " in path
				//retrait des options dans la ligne de commande
				size_t pos = p.find(" -");
				p=p.substr(0, pos);
				pos = p.find(" /");
				p = p.substr(0, pos);

				log(3, L"🔈ExpandEnvironmentStringsA command");
				ExpandEnvironmentStringsA(p.c_str(), appdata, MAX_PATH); // replace env variable by their value in path

				log(3, L"🔈fileToHash " + serviceBinary);
				serviceMd5 = QuickDigest5::fileToHash(appdata); // calcul hash

				log(3, L"🔈replaceAll serviceBinary");
				serviceBinary = replaceAll(serviceBinary, L"\\", L"\\\\");
				serviceBinary = replaceAll(serviceBinary, L"\"", L"\\\"");
			}
			else {
				log(3, L"🔈getErrorMessage");
				serviceAccessMessage = getErrorMessage(GetLastError());
				log(2, L"🔥QueryServiceConfigW", GetLastError());
			}
			free(sData);
			CloseServiceHandle(hService);
		}
		else {
			log(3, L"🔈getErrorMessage");
			serviceAccessMessage = getErrorMessage(GetLastError());
			log(2, L"🔥OpenServiceW", GetLastError());
		}
	}

	/*! conversion de l'objet au format json
   */
	std::wstring to_json() {
		std::wstring result = L"";

		log(3, L"🔈service to_json");
		result += tab(1) + L"{ \n";
		result += tab(2) + L"\"Name\":\"" + serviceName + L"\", \n";
		result += tab(2) + L"\"DislayName\":\"" + serviceDisplayName + L"\", \n";
		result += tab(2) + L"\"Status\":\"" + serviceStatus + L"\", \n";
		result += tab(2) + L"\"ProcessId\":\"" + serviceProcessId + L"\", \n";
		result += tab(2) + L"\"AccessMessage\":\"" + serviceAccessMessage + L"\", \n";
		result += tab(2) + L"\"StartType\":\"" + serviceStartType + L"\", \n";
		result += tab(2) + L"\"Owner\":\"" + serviceOwner + L"\", \n";
		result += tab(2) + L"\"Binary\":\"" + serviceBinary + L"\", \n";
		result += tab(2) + L"\"MD5\":\"" + serviceMd5 + L"\" \n";
		result += tab(1) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈service clear");
	}
};

struct Services
{
	std::vector<ServiceStruct> services; //!< tableau contenant tout les processus

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData()
	{
		SC_HANDLE hSCM = NULL;
		PUCHAR  pBuf = NULL;
		ULONG  dwBufSize = 0x00;
		ULONG  dwBufNeed = 0x00;
		ULONG  dwNumberOfService = 0x00;
		LPENUM_SERVICE_STATUS_PROCESS servicesBuf = NULL;
		DWORD bufSize = 0;
		DWORD moreBytesNeeded, serviceCount;

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Services :");
		log(0, L"*******************************************************************************************************************");

		log(3, L"🔈OpenSCManager");
		hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
		if (hSCM == NULL)
		{
			HRESULT error = GetLastError();
			log(1, L"Could not open Service Control Manager", error);
			return error;
		}

		// et buffer size needed
		log(3, L"🔈EnumServicesStatusExW");
		EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &moreBytesNeeded, &serviceCount, 0, NULL);
		servicesBuf = (LPENUM_SERVICE_STATUS_PROCESS)malloc(moreBytesNeeded);
		bufSize = moreBytesNeeded;
		if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)servicesBuf, bufSize, &moreBytesNeeded, &serviceCount, 0, NULL)) {
			for (DWORD i = 0; i < serviceCount; ++i) {
				services.push_back(ServiceStruct(hSCM, (ENUM_SERVICE_STATUS_PROCESS)servicesBuf[i]));
			}
			return ERROR_SUCCESS;
		}
		else {
			int err = GetLastError();
			log(2, L"🔥EnumServicesStatusExW", err);
			return err;
		}
		free(servicesBuf);
		CloseServiceHandle(hSCM);
		return 0;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈services to_json");

		std::wstring result = L"[ \n";
		std::vector<ServiceStruct>::iterator it;

		for (it = services.begin(); it != services.end(); it++) {
			result += it->to_json();
			if (it != services.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/services.json");
		log(3, L"🔈ansi_to_utf8 result");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈services clear");
		for (ServiceStruct temp : services)
			temp.clear();
	}
};