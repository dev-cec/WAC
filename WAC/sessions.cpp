/*! \file
 *  \brief Collection of the open logon sessions (see sessions.h).
 */
#include "sessions.h"

Session::Session(LUID* id) {
	/* `LsaGetLogonSessionData` ALLOCATES the structure itself and overwrites the
	   pointer: the `new SECURITY_LOGON_SESSION_DATA()` that used to be here was
	   lost at every session, and if the call failed the block from `new` would
	   have been handed to `LsaFreeReturnBuffer` — an allocator that had not
	   provided it. */
	PSECURITY_LOGON_SESSION_DATA data = NULL;
	_LARGE_INTEGER temp = { 0 };
	HRESULT hresult = 0;

	sessionId = ((LONGLONG)(id->HighPart) << 32) + id->LowPart;
	/* LUIDs reserved by Windows, always the same ones (winnt.h: SYSTEM_LUID,
	   ANONYMOUS_LOGON_LUID, LOCALSERVICE_LUID, NETWORKSERVICE_LUID). */
	switch (sessionId) {
	case 0x3E7: knownRole = L"SYSTEM";          break;
	case 0x3E6: knownRole = L"ANONYMOUS LOGON"; break;
	case 0x3E5: knownRole = L"LOCAL SERVICE";   break;
	case 0x3E4: knownRole = L"NETWORK SERVICE"; break;
	default: break;
	}
	log(1, L"➕Session : ");
	log(2, L"❇️Session Id : " + std::to_wstring(sessionId));
	log(3, L"🔈LsaGetLogonSessionData");
	hresult = LsaGetLogonSessionData(id, &data);
	if (hresult  == ERROR_SUCCESS) {
		/* FIX (a double shift, the same defect as the .lnk files).
		   LogonTime is a FILETIME, hence UTC. The code assigned it to the LOCAL
		   field then called LocalFileTimeToFileTime: the local key carried
		   unconverted UTC and the *Utc key carried UTC shifted by -2 h.
		   The symptom that revealed it: every session started 2 h BEFORE the
		   system's boot time — impossible. */
		temp = data->LogonTime;
		memcpy(&startTimeUtc, &temp, sizeof(startTimeUtc));
		log(3, L"🔈utcVersLocalSuspect startTime");
		utcToSuspectLocal(startTimeUtc, &startTime);
		logonName = std::wstring(data->UserName.Buffer).data();
		logonDomainName = std::wstring(data->LogonDomain.Buffer).data();
		logonType = data->LogonType;
		logonTypeName = logon_type(logonType);
		authenticationPackage = std::wstring(data->AuthenticationPackage.Buffer).data();

		// Converted HERE, while LSA's structure is still valid (see sessions.h).
		if (data->Sid) {
			LPWSTR sidText = NULL;
			log(3, L"🔈ConvertSidToStringSidW");
			if (ConvertSidToStringSidW(data->Sid, &sidText) && sidText) {
				sid = sidText;
				LocalFree(sidText);
			}
			else
				log(2, L"🔥ConvertSidToStringSidW", GetLastError());
		}
	}
	else {
		log(2, L"🔥LsaGetLogonSessionData", hresult);
	}
	// Only a SUCCESSFUL call provided a buffer to release.
	if (data) LsaFreeReturnBuffer(data);
}

Json Session::toJson() const {
	log(3, L"🔈session toJson");
	log(3, L"🔈timeToIso8601 startTime");
	Json o = Json::obj();
	o.add(L"SessionId",             Json::num(sessionId));      // a number, not a string
	o.add(L"SID",                   Json::str(sid));
	if (!knownRole.empty()) o.add(L"WellKnownRole", Json::str(knownRole));
	o.add(L"LogonName",             Json::str(logonName));
	o.add(L"LogonDomainName",       Json::str(logonDomainName));
	o.add(L"LogonType",             Json::num(logonType));      // a number, not a string
	o.add(L"LogonTypeName",         Json::str(logonTypeName));
	o.add(L"AuthenticationPackage", Json::str(authenticationPackage));
	o.add(L"StartTime",             Json::str(timeToIso8601Local(startTime)));
	o.add(L"StartTimeUtc",          Json::str(timeToIso8601Utc(startTimeUtc)));
	return o;
}

void Session::clear() {
	log(3, L"🔈session clear");
}

HRESULT Sessions::getData() {
	
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
		printProgressStep(L"Session", i + 1, nbSessions);
		sessions.push_back(Session(&pointer[i]));
	}
	LsaFreeReturnBuffer(&pointer);
	return ERROR_SUCCESS;
}

HRESULT Sessions::toJson() {
	log(3, L"🔈sessions toJson");
	Json arr = Json::arr();
	for (const Session& s : sessions) arr.push(s.toJson());
	return writeJsonFile("Sessions.json", arr);
}

void Sessions::clear() {
	log(3, L"🔈sessions clear");
	sessions.clear();   // destroys the elements -> really releases them
}
