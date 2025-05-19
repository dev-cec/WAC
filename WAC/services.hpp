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
	std::wstring serviceAccessMessage = L"OK";

	/*! Constructeur
	* @param hSCM contient le pointeur sur le manager de contrôle de service
	* @param service contient les données du service
	*/
	ServiceStruct(SC_HANDLE hSCM, ENUM_SERVICE_STATUS_PROCESS service) {
		DWORD bufSize = 0;
		DWORD moreBytesNeeded;

		serviceName = std::wstring(service.lpServiceName);
		serviceDisplayName = ansi_to_utf8(std::wstring(service.lpDisplayName));
		serviceType = serviceType_to_wstring(service.ServiceStatusProcess.dwServiceType);
		serviceStatus = serviceState_to_wstring(service.ServiceStatusProcess.dwCurrentState);
		serviceProcessId = std::to_wstring(service.ServiceStatusProcess.dwProcessId);

		SC_HANDLE hService = OpenServiceW(hSCM, service.lpServiceName, SC_MANAGER_ALL_ACCESS);
		QueryServiceConfigW(hService, NULL, 0, &moreBytesNeeded); //get size of buffer
		LPQUERY_SERVICE_CONFIG sData = (LPQUERY_SERVICE_CONFIG)malloc(moreBytesNeeded);
		bufSize = moreBytesNeeded;
		if (QueryServiceConfigW(hService, sData, bufSize, &moreBytesNeeded)) { //get service info
			serviceStartType = serviceStart_to_wstring(sData->dwStartType);
			serviceOwner = std::wstring(sData->lpServiceStartName);
			serviceOwner = replaceAll(serviceOwner, L"\\", L"\\\\");
			serviceBinary = std::wstring(sData->lpBinaryPathName);
			serviceBinary = replaceAll(serviceBinary, L"\\", L"\\\\");
			serviceBinary = replaceAll(serviceBinary, L"\"", L"\\\"");
		}

		else {
			serviceAccessMessage = ansi_to_utf8(getErrorWstring(GetLastError()));
		}
		free(sData);
		CloseServiceHandle(hService);
	}

	/*! conversion de l'objet au format json
   */
	std::wstring to_json() {
		std::wstring result = L"";

		result += tab(1) + L"{ \n"
			+ tab(2) + L"\"Name\":\"" + serviceName + L"\", \n"
			+ tab(2) + L"\"DislayName\":\"" + serviceDisplayName + L"\", \n"
			+ tab(2) + L"\"Status\":\"" + serviceStatus + L"\", \n"
			+ tab(2) + L"\"AccessMessage\":\"" + serviceAccessMessage + L"\", \n"
			+ tab(2) + L"\"ProcessId\":\"" + serviceProcessId + L"\", \n"
			+ tab(2) + L"\"StartType\":\"" + serviceStartType + L"\", \n"
			+ tab(2) + L"\"Owner\":\"" + serviceOwner + L"\", \n"
			+ tab(2) + L"\"Binary\":\"" + serviceBinary + L"\" \n"
			+ tab(1) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {}
};

struct Services
{
	std::vector<ServiceStruct> services; //!< tableau contenant tout les processus
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = { 0 };//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData(AppliConf conf)
	{
		SC_HANDLE hSCM = NULL;
		PUCHAR  pBuf = NULL;
		ULONG  dwBufSize = 0x00;
		ULONG  dwBufNeed = 0x00;
		ULONG  dwNumberOfService = 0x00;
		LPENUM_SERVICE_STATUS_PROCESS servicesBuf = NULL;
		DWORD bufSize = 0;
		DWORD moreBytesNeeded, serviceCount;

		_conf = conf;

		hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
		if (hSCM == NULL)
		{
			HRESULT error = GetLastError();
			errors.push_back({ L"Could not open Service Control Manager",error });
			return error;
		}

		// et buffer size needed
		EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &moreBytesNeeded, &serviceCount, 0, NULL);
		servicesBuf = (LPENUM_SERVICE_STATUS_PROCESS)malloc(moreBytesNeeded);
		bufSize = moreBytesNeeded;
		if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)servicesBuf, bufSize, &moreBytesNeeded, &serviceCount, 0, NULL)) {
			for (DWORD i = 0; i < serviceCount; ++i) {
				services.push_back(ServiceStruct(hSCM, (ENUM_SERVICE_STATUS_PROCESS)servicesBuf[i]));
			}
			return ERROR_SUCCESS;
		}
		int err = GetLastError();
		if (ERROR_MORE_DATA != err) {
			return err;
		}
		free(servicesBuf);
		CloseServiceHandle(hSCM);
		return 0;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
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
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/services.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/services_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		for (ServiceStruct temp : services)
			temp.clear();
	}
};