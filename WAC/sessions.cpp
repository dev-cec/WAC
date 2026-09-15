#include "sessions.h"

Session::Session(LUID* id) {
	/* `LsaGetLogonSessionData` ALLOUE elle-même la structure et écrase le
	   pointeur : le `new SECURITY_LOGON_SESSION_DATA()` qui se trouvait ici
	   était perdu à chaque session, et en cas d'échec de l'appel le bloc issu de
	   `new` aurait été rendu à `LsaFreeReturnBuffer` — un allocateur qui ne
	   l'avait pas fourni. */
	PSECURITY_LOGON_SESSION_DATA data = NULL;
	_LARGE_INTEGER temp = { 0 };
	HRESULT hresult = 0;

	sessionId = ((LONGLONG)(id->HighPart) << 32) + id->LowPart;
	/* LUID reserves par Windows, toujours les memes (winnt.h :
	   SYSTEM_LUID, ANONYMOUS_LOGON_LUID, LOCALSERVICE_LUID, NETWORKSERVICE_LUID). */
	switch (sessionId) {
	case 0x3E7: roleConnu = L"SYSTEM";          break;
	case 0x3E6: roleConnu = L"ANONYMOUS LOGON"; break;
	case 0x3E5: roleConnu = L"LOCAL SERVICE";   break;
	case 0x3E4: roleConnu = L"NETWORK SERVICE"; break;
	default: break;
	}
	log(1, L"➕Session : ");
	log(2, L"❇️Session Id : " + std::to_wstring(sessionId));
	log(3, L"🔈LsaGetLogonSessionData");
	hresult = LsaGetLogonSessionData(id, &data);
	if (hresult  == ERROR_SUCCESS) {
		/* CORRECTION (double decalage, meme defaut que les .lnk).
		   LogonTime est un FILETIME, donc UTC. Le code l'affectait au champ
		   LOCAL puis appelait LocalFileTimeToFileTime : la cle locale portait de
		   l'UTC non converti et la cle *Utc de l'UTC decale de -2 h.
		   Symptome qui l'a revele : toutes les sessions demarraient 2 h AVANT
		   l'heure de demarrage du systeme — impossible. */
		temp = data->LogonTime;
		memcpy(&startTimeUtc, &temp, sizeof(startTimeUtc));
		log(3, L"🔈utcVersLocalSuspect startTime");
		utcVersLocalSuspect(startTimeUtc, &startTime);
		logonName = std::wstring(data->UserName.Buffer).data();
		logonDomainName = std::wstring(data->LogonDomain.Buffer).data();
		logonType = data->LogonType;
		logonTypeName = logon_type(logonType);
		authenticationPackage = std::wstring(data->AuthenticationPackage.Buffer).data();

		// Converti ICI, tant que la structure de LSA est valide (cf. sessions.h).
		if (data->Sid) {
			LPWSTR sidTexte = NULL;
			log(3, L"🔈ConvertSidToStringSidW");
			if (ConvertSidToStringSidW(data->Sid, &sidTexte) && sidTexte) {
				sid = sidTexte;
				LocalFree(sidTexte);
			}
			else
				log(2, L"🔥ConvertSidToStringSidW", GetLastError());
		}
	}
	else {
		log(2, L"🔥LsaGetLogonSessionData", hresult);
	}
	// Seul un appel REUSSI a fourni un tampon a liberer.
	if (data) LsaFreeReturnBuffer(data);
}

Json Session::toJson() const {
	log(3, L"🔈session toJson");
	log(3, L"🔈timeToIso8601 startTime");
	Json o = Json::obj();
	o.add(L"SessionId",             Json::num(sessionId));      // nombre, pas chaîne
	o.add(L"SID",                   Json::str(sid));
	if (!roleConnu.empty()) o.add(L"WellKnownRole", Json::str(roleConnu));
	o.add(L"LogonName",             Json::str(logonName));
	o.add(L"LogonDomainName",       Json::str(logonDomainName));
	o.add(L"LogonType",             Json::num(logonType));      // nombre, pas chaîne
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
	sessions.clear();   // detruit les elements -> libere reellement
}
