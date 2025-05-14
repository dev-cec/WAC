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
	std::wstring serviceName=L"";
	std::wstring serviceDisplayName=L"";
	std::wstring serviceType=L"";
	std::wstring serviceStatus=L"";
	std::wstring serviceProcessId=L"";
	std::wstring serviceStartType=L"";
	std::wstring serviceOwner=L"";
	std::wstring serviceBinary=L"";
	std::wstring serviceAccessMessage=L"OK";

	/*! Constructeur 
	* @param hSCM contient le pointeur sur le manager de contrôle de service
	* @param service contient les données du service
	*/
	ServiceStruct(SC_HANDLE hSCM, ENUM_SERVICE_STATUS_PROCESS service) {
		DWORD bufSize = 0;
		DWORD moreBytesNeeded;

		serviceName =  std::wstring(service.lpServiceName);
		serviceDisplayName= ansi_to_utf8(std::wstring(service.lpDisplayName)) ;
		serviceType= serviceType_to_wstring(service.ServiceStatusProcess.dwServiceType) ;
		serviceStatus= serviceState_to_wstring(service.ServiceStatusProcess.dwCurrentState) ;
		serviceProcessId = std::to_wstring(service.ServiceStatusProcess.dwProcessId);

		SC_HANDLE hService = OpenServiceW(hSCM, service.lpServiceName, SC_MANAGER_ALL_ACCESS);
		QueryServiceConfigW(hService, NULL, 0, &moreBytesNeeded); //get size of buffer
		LPQUERY_SERVICE_CONFIG sData = (LPQUERY_SERVICE_CONFIG)malloc(moreBytesNeeded);
		bufSize = moreBytesNeeded;
		if (QueryServiceConfigW(hService, sData, bufSize, &moreBytesNeeded)) { //get service info
			serviceStartType = serviceStart_to_wstring(sData->dwStartType) ;
			serviceOwner = std::wstring(sData->lpServiceStartName) ;
			serviceOwner = replaceAll(serviceOwner, L"\\", L"\\\\");
			serviceBinary = std::wstring(sData->lpBinaryPathName);
			serviceBinary = replaceAll(serviceBinary, L"\\", L"\\\\");
			serviceBinary = replaceAll(serviceBinary, L"\"", L"\\\"");
		}

		else {
			serviceAccessMessage = ansi_to_utf8(getErrorWstring(GetLastError()));
		}
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
};

struct Services
{
	std::vector<ServiceStruct> services; //!< tableau contenant tout les processus
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	bool _debug = false;//!< paramètre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json

	/*! Fonction permettant de parser les objets
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(bool pdebug)
	{
		SC_HANDLE hSCM = NULL;
		PUCHAR  pBuf = NULL;
		ULONG  dwBufSize = 0x00;
		ULONG  dwBufNeed = 0x00;
		ULONG  dwNumberOfService = 0x00;
		LPENUM_SERVICE_STATUS_PROCESS servicesBuf = NULL;
		DWORD bufSize = 0;
		DWORD moreBytesNeeded, serviceCount;

		_debug = pdebug;

		hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
		if (hSCM == NULL)
		{
			errors.push_back({L"Could not open Service Control Manager",ERROR_UNIDENTIFIED_ERROR });
			return ERROR_UNIDENTIFIED_ERROR;
		}

		// et buffer size needed
		EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, bufSize, &moreBytesNeeded, &serviceCount, 0, NULL);
		servicesBuf = (LPENUM_SERVICE_STATUS_PROCESS)malloc(moreBytesNeeded);
		bufSize = moreBytesNeeded;
		if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)servicesBuf, bufSize, &moreBytesNeeded, &serviceCount, 0, NULL)) {
			for (DWORD i = 0; i < serviceCount; ++i) {

				services.push_back(ServiceStruct(hSCM, (ENUM_SERVICE_STATUS_PROCESS)servicesBuf[i]));
			}
			free(servicesBuf);
			return 0;
		}
		int err = GetLastError();
		if (ERROR_MORE_DATA != err) {
			free(servicesBuf);
			return err;
		}
		free(servicesBuf);

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
		std::filesystem::create_directory("output"); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open("output/services.json");
		myfile << result;
		myfile.close();

		if (_debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory("errors"); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open("errors/services_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}
};