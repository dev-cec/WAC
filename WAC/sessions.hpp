#pragma once

#include <iostream>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include <Sddl.h>
#include <wtsapi32.h>
#include <winternl.h>
#define _NTDEF_ //pour éviter les conflits de type avec winternl.h
#include <ntsecapi.h>
#include "tools.h"
#include "trans_id.h"

/*! structure contenant les informations d'une session
*/
struct Session {

	FILETIME startTime = { 0 };
	FILETIME startTimeUtc = { 0 };
	std::wstring authenticationPackage = L"";
	std::wstring logonName = L"";
	std::wstring logonDomainName = L"";
	std::wstring logonTypeName = L"";
	ULONG logonType = 0;
	PSID sid = { 0 };
	LONG sessionId = 0;
	/*! Constructeur
	* @param id est l'id de session
	*/
	Session(LUID* id) {
		PSECURITY_LOGON_SESSION_DATA data = new SECURITY_LOGON_SESSION_DATA();
		_LARGE_INTEGER temp = { 0 };

		if (LsaGetLogonSessionData(id, &data) == ERROR_SUCCESS) {
			temp = data->LogonTime;
			memcpy(&startTime, &temp, sizeof(startTime));
			LocalFileTimeToFileTime(&startTime, &startTimeUtc);
			logonName = std::wstring(data->UserName.Buffer);
			logonDomainName = std::wstring(data->LogonDomain.Buffer);
			logonType = data->LogonType;
			logonTypeName = logon_type(logonType);
			authenticationPackage = std::wstring(data->AuthenticationPackage.Buffer);
			sid = data->Sid;
			sessionId = (data->LogonId.HighPart << 32) + data->LogonId.LowPart;
		}
	}

	/*! conversion de l'objet au format json
	*/
	std::wstring to_json() {
		LPWSTR lpsid_wstring = NULL;
		std::wstring sid_wstring = L"";
		if (ConvertSidToStringSid(sid, &lpsid_wstring) != 0)
			sid_wstring = std::wstring(lpsid_wstring);

		std::wstring result = tab(1) + L"{ \n"
			+ tab(2) + L"\"SessionId\":\"" + std::to_wstring(sessionId) + L"\", \n"
			+ tab(2) + L"\"SID\":\"" + sid_wstring + L"\", \n"
			+ tab(2) + L"\"LogonName\":\"" + logonName + L"\", \n"
			+ tab(2) + L"\"LogonDomainName\":\"" + logonDomainName + L"\", \n"
			+ tab(2) + L"\"LogonType\":\"" + std::to_wstring(logonType) + L"\", \n"
			+ tab(2) + L"\"LogonTypeName\":\"" + logonTypeName + L"\", \n"
			+ tab(2) + L"\"AuthenticationPackage\":\"" + authenticationPackage + L"\", \n"
			+ tab(2) + L"\"StartTime\":\"" + time_to_wstring(startTime) + L"\", \n"
			+ tab(2) + L"\"StartTimeUtc\":\"" + time_to_wstring(startTimeUtc) + L"\", \n"
			+ tab(1) + L"}";
		return result;
	}
};

/*! structure contenant les artefacts
*/
struct Sessions {
	std::vector<Session> sessions; //!< tableau contenant tout les Session
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		PLUID pointer;
		ULONG nbSessions;
		NTSTATUS hr;
		hr = LsaEnumerateLogonSessions(&nbSessions, &pointer);
		if (hr != ERROR_SUCCESS)
			return hr;
		for (int i = 0; i < nbSessions; i++) {
			sessions.push_back(Session(&pointer[i]));
		}

		return ERROR_SUCCESS;
	}
	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		std::wofstream myfile;
		std::wstring result = L"[\n";
		std::vector<Session>::iterator it;
		for (it = sessions.begin(); it != sessions.end(); it++) {

			result += it->to_json();
			if (it != sessions.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"]";
		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(_conf._outputDir + "/Sessions.json");
		myfile << result;
		myfile.close();
		return ERROR_SUCCESS;
	}
};