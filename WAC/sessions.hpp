#pragma once

#include <iostream>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include <Sddl.h>
#include <wtsapi32.h>
#include <winternl.h>
#define _NTDEF_ //pour éviter les conflits de type entre ntsecapi.h et winternl.h
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
	LONGLONG sessionId = 0;
	/*! Constructeur
	* @param id est l'id de session
	*/
	Session(LUID* id) {
		PSECURITY_LOGON_SESSION_DATA data = new SECURITY_LOGON_SESSION_DATA();
		_LARGE_INTEGER temp = { 0 };
		HRESULT hresult = 0;

		sessionId = ((LONGLONG)(id->HighPart) << 32) + id->LowPart;
		log(1, L"➕Session : ");
		log(2, L"❇️Session Id : " + std::to_wstring(sessionId));
		log(3, L"🔈LsaGetLogonSessionData");
		hresult = LsaGetLogonSessionData(id, &data);
		if (hresult  == ERROR_SUCCESS) {
			temp = data->LogonTime;
			memcpy(&startTime, &temp, sizeof(startTime));
			log(3, L"🔈LocalFileTimeToFileTime");
			LocalFileTimeToFileTime(&startTime, &startTimeUtc);
			logonName = std::wstring(data->UserName.Buffer);
			logonDomainName = std::wstring(data->LogonDomain.Buffer);
			logonType = data->LogonType;
			logonTypeName = logon_type(logonType);
			authenticationPackage = std::wstring(data->AuthenticationPackage.Buffer);
			sid = data->Sid;
		}
		else {
			log(2, L"🔥LsaGetLogonSessionData", hresult);
		}
		LsaFreeReturnBuffer(data);
	}

	/*! conversion de l'objet au format json
	*/
	std::wstring to_json() {
		LPWSTR lpsid_wstring = NULL;
		std::wstring sid_wstring = L"";

		log(3, L"🔈session to_json");
		log(3, L"🔈ConvertSidToStringSid");
		if (ConvertSidToStringSid(sid, &lpsid_wstring) != 0) {
			sid_wstring = std::wstring(lpsid_wstring);
		}

		std::wstring result = tab(1) + L"{ \n";
			result+= tab(2) + L"\"SessionId\":\"" + std::to_wstring(sessionId) + L"\", \n";
			result+= tab(2) + L"\"SID\":\"" + sid_wstring + L"\", \n";
			result+= tab(2) + L"\"LogonName\":\"" + logonName + L"\", \n";
			result+= tab(2) + L"\"LogonDomainName\":\"" + logonDomainName + L"\", \n";
			result+= tab(2) + L"\"LogonType\":\"" + std::to_wstring(logonType) + L"\", \n";
			result+= tab(2) + L"\"LogonTypeName\":\"" + logonTypeName + L"\", \n";
			result+= tab(2) + L"\"AuthenticationPackage\":\"" + authenticationPackage + L"\", \n";
			log(3, L"🔈time_to_wstring startTime");
			result+= tab(2) + L"\"StartTime\":\"" + time_to_wstring(startTime) + L"\", \n";
			log(3, L"🔈time_to_wstring startTimeUtc");
			result+= tab(2) + L"\"StartTimeUtc\":\"" + time_to_wstring(startTimeUtc) + L"\", \n";
			result += tab(1) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈session clear");
	}
};

/*! structure contenant les artefacts
*/
struct Sessions {
	std::vector<Session> sessions; //!< tableau contenant tout les Session


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		PLUID pointer;
		ULONG nbSessions;
		NTSTATUS hr;

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Sessions :");
		log(0, L"*******************************************************************************************************************");

		log(3, L"🔈LsaEnumerateLogonSessions");
		hr = LsaEnumerateLogonSessions(&nbSessions, &pointer);
		if (hr != ERROR_SUCCESS) {
			log(2, L"🔥LsaEnumerateLogonSessions", hr);
			return hr;
		}
		for (ULONG i = 0; i < nbSessions; i++) {
			sessions.push_back(Session(&pointer[i]));
		}
		LsaFreeReturnBuffer(&pointer);
		return ERROR_SUCCESS;
	}
	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈sessions to_json");
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
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(conf._outputDir + "/Sessions.json");
		log(3, L"🔈ansi_to_utf8 result");
		myfile << ansi_to_utf8(result);
		myfile.close();
		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈sessions clear");
		for (Session temp : sessions)
			temp.clear();
	}

};