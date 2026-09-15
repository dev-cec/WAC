#include "events.h"

/* Un EVT_VARIANT porte son type dans data->Type. Le bit EVT_VARIANT_TYPE_ARRAY
   (0x80) signale un tableau : data->Count elements, lus via les champs *Arr.
   Les valeurs sont rendues BRUTES : json.h fait l'echappement, une seule fois. */
namespace {

//! Element d'indice i d'un EVT_VARIANT de type tableau.
Json arrayElementToJson(PEVT_VARIANT data, DWORD type, DWORD i) {
	switch (type) {
	case EvtVarTypeString:     return Json::str(data->StringArr[i] ? data->StringArr[i] : L"");
	case EvtVarTypeAnsiString: return Json::str(data->AnsiStringArr[i]
	                                  ? string_to_wstring(data->AnsiStringArr[i]) : L"");
	case EvtVarTypeSByte:      return Json::num((long long)data->SByteArr[i]);
	case EvtVarTypeByte:       return Json::num((unsigned long long)data->ByteArr[i]);
	case EvtVarTypeInt16:      return Json::num((long long)data->Int16Arr[i]);
	case EvtVarTypeUInt16:     return Json::num((unsigned long long)data->UInt16Arr[i]);
	case EvtVarTypeInt32:      return Json::num((long long)data->Int32Arr[i]);
	case EvtVarTypeUInt32:     return Json::num((unsigned long long)data->UInt32Arr[i]);
	case EvtVarTypeInt64:      return Json::num((long long)data->Int64Arr[i]);
	case EvtVarTypeUInt64:     return Json::num((unsigned long long)data->UInt64Arr[i]);
	case EvtVarTypeBoolean:    return Json::boolean(data->BooleanArr[i] != FALSE);
	case EvtVarTypeGuid:       return Json::str(guid_to_wstring(data->GuidArr[i]));
	case EvtVarTypeFileTime: {
		// FileTimeArr est un FILETIME : pas de recomposition a faire.
		// Les horodatages d'evenements sont en UTC.
		return Json::str(timeToIso8601Utc(data->FileTimeArr[i]));
	}
	case EvtVarTypeSysTime: {
		FILETIME ft = { 0 };
		if (!SystemTimeToFileTime(&data->SysTimeArr[i], &ft)) return Json::null();
		return Json::str(timeToIso8601Utc(ft));
	}
	default:
		log(2, L"🔥variantToJson : type tableau non gere : " + std::to_wstring(type));
		return Json::null();
	}
}

} // namespace

Json variantToJson(PEVT_VARIANT data) {
	if (!data) return Json::null();

	// Tableaux : meme type de base, data->Count elements.
	if (data->Type & EVT_VARIANT_TYPE_ARRAY) {
		const DWORD type = data->Type & EVT_VARIANT_TYPE_MASK;
		Json arr = Json::arr();
		for (DWORD i = 0; i < data->Count; ++i) arr.push(arrayElementToJson(data, type, i));
		return arr;
	}

	switch (data->Type) {
	case EvtVarTypeNull:       return Json::null();
	case EvtVarTypeString:     return Json::str(data->StringVal ? data->StringVal : L"");
	case EvtVarTypeAnsiString: return Json::str(data->AnsiStringVal
	                                  ? string_to_wstring(data->AnsiStringVal) : L"");
	case EvtVarTypeSByte:      return Json::num((long long)data->SByteVal);
	case EvtVarTypeByte:       return Json::num((unsigned long long)data->ByteVal);
	case EvtVarTypeInt16:      return Json::num((long long)data->Int16Val);
	case EvtVarTypeUInt16:     return Json::num((unsigned long long)data->UInt16Val);
	case EvtVarTypeInt32:      return Json::num((long long)data->Int32Val);
	case EvtVarTypeUInt32:     return Json::num((unsigned long long)data->UInt32Val);
	case EvtVarTypeInt64:      return Json::num((long long)data->Int64Val);
	case EvtVarTypeUInt64:     return Json::num((unsigned long long)data->UInt64Val);
	case EvtVarTypeSizeT:      return Json::num((unsigned long long)data->SizeTVal);
	case EvtVarTypeSingle:     return Json::str(std::to_wstring(data->SingleVal));
	case EvtVarTypeDouble:     return Json::str(std::to_wstring(data->DoubleVal));
	case EvtVarTypeBoolean:    return Json::boolean(data->BooleanVal != FALSE);
	case EvtVarTypeBinary:     return Json::str(dump_wstring((LPBYTE)data->BinaryVal, 0, (int)data->Count));
	case EvtVarTypeGuid:
		log(3, L"🔈guid_to_wstring EvtVarTypeGuid");
		return data->GuidVal ? Json::str(guid_to_wstring(*data->GuidVal)) : Json::null();
	case EvtVarTypeFileTime: {
		// CORRECTION : FileTimeVal est un ULONGLONG. Le cast (DWORD) direct
		// jetait les 32 bits hauts, rendant TOUTES les dates d'evenements fausses.
		const ULONGLONG v = data->FileTimeVal;
		FILETIME ft = { (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) };
		log(3, L"🔈timeToIso8601Utc EvtVarTypeFileTime");
		// Les horodatages d'evenements sont en UTC.
		return Json::str(timeToIso8601Utc(ft));
	}
	case EvtVarTypeSysTime: {
		FILETIME ft = { 0 };
		log(3, L"🔈SystemTimeToFileTime EvtVarTypeSysTime");
		if (!data->SysTimeVal || !SystemTimeToFileTime(data->SysTimeVal, &ft)) return Json::null();
		return Json::str(timeToIso8601Utc(ft));
	}
	case EvtVarTypeSid: {
		LPWSTR sid = nullptr;
		log(3, L"🔈ConvertSidToStringSidW EvtVarTypeSid");
		if (!data->SidVal || !ConvertSidToStringSidW(data->SidVal, &sid)) return Json::null();
		Json r = Json::str(sid);
		LocalFree(sid);                    // ConvertSidToStringSidW alloue : a liberer
		return r;
	}
	case EvtVarTypeHexInt32:
		log(3, L"🔈to_hex EvtVarTypeHexInt32");
		return Json::str(to_hex(data->Int32Val));
	case EvtVarTypeHexInt64:
		log(3, L"🔈to_hex EvtVarTypeHexInt64");
		return Json::str(to_hex(data->Int64Val));
	case EvtVarTypeEvtXml:     return Json::str(data->XmlVal ? data->XmlVal : L"");
	default:
		log(2, L"🔥variantToJson : type non gere : " + std::to_wstring(data->Type));
		return Json::null();
	}
}

Event::Event(EVT_HANDLE hevt, LPWSTR buffer, EVT_HANDLE hEvent) {
	PEVT_VARIANT bufferEvt = NULL;
	PEVT_VARIANT bufferEvt2 = NULL;
	DWORD bufferLengthNeeded2 = 0;
	DWORD bufferLength2 = 0;
	DWORD nbEvents = 0;
	HRESULT status = 0;

	EVT_HANDLE hContext = NULL;
	do {
		if (bufferLengthNeeded2 > bufferLength2) {
			free(bufferEvt);
			bufferLength2 = bufferLengthNeeded2;
			bufferEvt = (PEVT_VARIANT)malloc(bufferLength2);
		}
		log(3, L"🔈EvtCreateRenderContext hContext");
		hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
		if (hContext) {
			log(3, L"🔈EvtRender hContext");
			if (EvtRender(hContext,
				hEvent,
				EvtRenderEventValues,
				bufferLength2,
				bufferEvt,
				&bufferLengthNeeded2,
				&nbEvents) != FALSE) {
				status = ERROR_SUCCESS;
			}
			else {
				status = GetLastError();
				if (status != ERROR_INSUFFICIENT_BUFFER)
					log(2, L"🔥EvtRender hContext", status);

			}
		}
		else {
			status = GetLastError();
			if (status != ERROR_INSUFFICIENT_BUFFER)
				log(2, L"🔥EvtCreateRenderContext hContext", status);

		}
	} while (status == ERROR_INSUFFICIENT_BUFFER && hContext != NULL);

	bufferLength2 = 0;
	bufferLengthNeeded2 = 0;
	do {

		if (bufferLengthNeeded2 > bufferLength2) {
			free(bufferEvt2);
			bufferLength2 = bufferLengthNeeded2;
			bufferEvt2 = (PEVT_VARIANT)malloc(bufferLength2);
		}
		LPCWSTR ppValues[] = {
			L"Event/EventData/Data",
		};
		DWORD count = sizeof(ppValues) / sizeof(LPWSTR);
		log(3, L"🔈EvtCreateRenderContext hContext");
		hContext = EvtCreateRenderContext(count, ppValues, EvtRenderContextValues);
		if (hContext) {
			log(3, L"🔈EvtRender hContext");
			if (EvtRender(hContext,
				hEvent,
				EvtRenderEventValues,
				bufferLength2,
				bufferEvt2,
				&bufferLengthNeeded2,
				&nbEvents) != FALSE) {
				status = ERROR_SUCCESS;
			}
			else {
				status = GetLastError();
				if (status != ERROR_INSUFFICIENT_BUFFER)
					log(2, L"🔥EvtRender hContext", status);
			}
		}
		else {
			status = GetLastError();
			if (status != ERROR_INSUFFICIENT_BUFFER)
				log(2, L"🔥EvtCreateRenderContext hContext", status);

		}
	} while (status == ERROR_INSUFFICIENT_BUFFER);
	
	log(3, L"🔈variantToJson evtSystemEventID");
	log(3, L"🔈variantToJson evtSystemEventRecordId");
	evtSystemEventRecordId = variantToJson(&bufferEvt[9]);
	log(2, L"❇️Event Record Id " + EvtSystemEventRecordId);

	log(3, L"🔈variantToJson evtSystemProviderGuid");
	evtSystemProviderGuid = variantToJson(&bufferEvt[1]); // GUID
	
	evtSystemEventID = variantToJson(&bufferEvt[2]);
	log(3, L"🔈variantToJson evtSystemProviderName");
	evtSystemProviderName = variantToJson(&bufferEvt[0]);

	log(3, L"🔈variantToJson evtSystemQualifiers");
	evtSystemQualifiers = variantToJson(&bufferEvt[3]);
	
	log(3, L"🔈variantToJson evtSystemLevel");
	evtSystemLevel = variantToJson(&bufferEvt[4]);
	
	log(3, L"🔈variantToJson evtSystemTask");
	evtSystemTask = variantToJson(&bufferEvt[5]);
	
	log(3, L"🔈variantToJson evtSystemOpcode");
	evtSystemOpcode = variantToJson(&bufferEvt[6]);
	
	log(3, L"🔈variantToJson evtSystemKeywords");
	evtSystemKeywords = variantToJson(&bufferEvt[7]); // HEX
	
	log(3, L"🔈variantToJson evtSystemTimeCreated");
	evtSystemTimeCreated = variantToJson(&bufferEvt[8]); // FILETIME
	
	
	log(3, L"🔈variantToJson evtSystemActivityID");
	evtSystemActivityID = variantToJson(&bufferEvt[10]); // GUID
	
	log(3, L"🔈variantToJson evtSystemRelatedActivityID");
	evtSystemRelatedActivityID = variantToJson(&bufferEvt[11]); // GUID
	
	log(3, L"🔈variantToJson evtSystemProcessID");
	evtSystemProcessID = variantToJson(&bufferEvt[12]);
	
	log(3, L"🔈variantToJson evtSystemThreadID");
	evtSystemThreadID = variantToJson(&bufferEvt[13]);
	
	log(3, L"🔈variantToJson evtSystemChannel");
	evtSystemChannel = variantToJson(&bufferEvt[14]);
	
	log(3, L"🔈variantToJson evtSystemComputer");
	evtSystemComputer = variantToJson(&bufferEvt[15]);
	
	log(3, L"🔈variantToJson evtSystemUserID");
	evtSystemUserID = variantToJson(&bufferEvt[16]); //SID
	
	log(3, L"🔈variantToJson evtSystemVersion");
	evtSystemVersion = variantToJson(&bufferEvt[17]);
	
	log(3, L"🔈variantToJson evtEventData");
	// Toujours exposer un tableau, meme quand la valeur est scalaire : le schema de
	// sortie reste stable pour l'analyse. json.h gere l'indentation.
	Json donnees = variantToJson(&bufferEvt2[0]);
	if (donnees.kind() == Json::Kind::Arr) evtEventData = std::move(donnees);
	else { evtEventData = Json::arr(); evtEventData.push(std::move(donnees)); }

	free(bufferEvt);
	free(bufferEvt2);

	//Message
	EVT_HANDLE hmetadata = EvtOpenPublisherMetadata(hevt, buffer, NULL, 0, 0);
	DWORD messagesize = 0, messageSizeNeeded = 0;
	LPWSTR bufferMessage = NULL;
	do {
		free(bufferMessage);
		bufferMessage = (LPWSTR)malloc(messageSizeNeeded * sizeof(wchar_t));
		messagesize = messageSizeNeeded;
		log(3, L"🔈EvtFormatMessage hmetadata");
		if (!EvtFormatMessage(hmetadata, hEvent, NULL, 0, NULL, EvtFormatMessageEvent, messagesize, bufferMessage, &messageSizeNeeded)) {
			status = GetLastError();
			if (status != ERROR_INSUFFICIENT_BUFFER) {
				log(2, L"🔥EvtFormatMessage hmetadata", status);
				evtEventMessage = Json::str(L"");
			}
		}
		else {
			status = ERROR_SUCCESS;
			evtEventMessage = Json::str(bufferMessage ? bufferMessage : L"");
			free(bufferMessage);
			bufferMessage = NULL;      // sinon double free par le free() de la boucle
		}
	} while (status == ERROR_INSUFFICIENT_BUFFER);

	EvtClose(hmetadata);
}

Json Event::toJson() const {
	log(3, L"🔈event toJson");
	Json o = Json::obj();
	o.add(L"EvtSystemProviderName",      evtSystemProviderName);
	o.add(L"EvtSystemProviderGuid",      evtSystemProviderGuid);
	o.add(L"EvtSystemEventID",           evtSystemEventID);
	o.add(L"EvtSystemQualifiers",        evtSystemQualifiers);
	o.add(L"EvtSystemLevel",             evtSystemLevel);
	o.add(L"EvtSystemTask",              evtSystemTask);
	o.add(L"EvtSystemOpcode",            evtSystemOpcode);
	o.add(L"EvtSystemKeywords",          evtSystemKeywords);
	o.add(L"EvtSystemTimeCreated",       evtSystemTimeCreated);
	o.add(L"EvtSystemEventRecordId",     evtSystemEventRecordId);
	o.add(L"EvtSystemActivityID",        evtSystemActivityID);
	o.add(L"EvtSystemRelatedActivityID", evtSystemRelatedActivityID);
	o.add(L"EvtSystemProcessID",         evtSystemProcessID);
	o.add(L"EvtSystemThreadID",          evtSystemThreadID);
	o.add(L"EvtSystemChannel",           evtSystemChannel);
	o.add(L"EvtSystemComputer",          evtSystemComputer);
	o.add(L"EvtSystemUserID",            evtSystemUserID);
	o.add(L"EvtSystemVersion",           evtSystemVersion);
	o.add(L"EvtEventData",               evtEventData);
	o.add(L"EvtEventMessage",            evtEventMessage);
	return o;
}

HRESULT Events::getData() {
	EVT_RPC_LOGIN login = { NULL };
	EVT_HANDLE hevt = NULL;
	EVT_HANDLE hChannel = NULL;
	EVT_HANDLE hQuery = NULL;
	EVT_HANDLE hEvent = NULL;
	LPWSTR buffer = NULL;
	DWORD bufferLength1 = 0, bufferLengthNeeded1 = 0, count = 0;
	HRESULT status;

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Events : ");
	log(0, L"*******************************************************************************************************************");

	log(3, L"🔈EvtOpenSession");
	hevt = EvtOpenSession(EvtRpcLogin, &login, 0, 0);
	log(3, L"🔈EvtOpenChannelEnum");
	hChannel = EvtOpenChannelEnum(hevt, 0);
	wprintf(L"\n"); // pour mise en forme console sinon premier chanel sur mauvaise line
	do {
		log(1, L"➕Channel");
		//
		// Expand the buffer size if needed.
		//

		if (bufferLengthNeeded1 > bufferLength1) {
			free(buffer);
			bufferLength1 = bufferLengthNeeded1;
			buffer = (LPWSTR)malloc(bufferLength1 * sizeof(WCHAR));
		}

		//
		// Try to get the next channel name.
		//
		log(3, L"🔈EvtNextChannelPath");
		if (EvtNextChannelPath(hChannel, bufferLength1, buffer, &bufferLengthNeeded1) == FALSE) {
			status = GetLastError();
			if (status != ERROR_INSUFFICIENT_BUFFER)
				log(2, L"🔥Process32First", status);// show cause of failure
		}
		else {
			status = ERROR_SUCCESS;
			
			log(2, L"❇️Channel Name : " + std::wstring(buffer));
			wprintf(L"\t%ls%ls", buffer, L": ");
			log(3, L"🔈EvtQuery EvtQueryChannelPath");
			hQuery = EvtQuery(NULL, buffer, NULL, EvtQueryChannelPath);
			if (hQuery == NULL) {
				status = GetLastError();
				if (status != ERROR_INSUFFICIENT_BUFFER)
					log(2, L"🔥EvtQuery EvtQueryChannelPath", status);// show cause of failure
			}

			//
			// Read each event and render it as XML.
			//

			log(3, L"🔈EvtNext hQuery");
			/* Progression par canal : les gros journaux (System, Security,
			   Application) demandent plusieurs minutes par l'API Win32 sous
			   Windows 11 (cf. doc §10). Sans indicateur, l'opérateur ne distingue
			   pas une lecture qui avance d'un blocage, et risque d'interrompre la
			   collecte. Le total est inconnu : on affiche le compte courant. */
			/* Nombre d'enregistrements du canal, pour afficher un pourcentage
			   plutôt qu'un simple compteur : EvtNext ne le donne pas, mais
			   EvtGetLogInfo(EvtLogNumberOfLogRecords) le fournit. Un appel par
			   canal, négligeable devant la lecture. Si l'appel échoue, on
			   retombe sur un compteur sans pourcentage (total = 0). */
			unsigned long long totalEvt = 0;
			EVT_HANDLE hLog = EvtOpenLog(hevt, buffer, EvtOpenChannelPath);
			if (hLog) {
				EVT_VARIANT infoLog = { 0 };
				DWORD utilise = 0;
				if (EvtGetLogInfo(hLog, EvtLogNumberOfLogRecords, sizeof(infoLog),
				                  &infoLog, &utilise) && infoLog.Type == EvtVarTypeUInt64)
					totalEvt = infoLog.UInt64Val;
				EvtClose(hLog);
			}

			unsigned long long lus = 0;
			while (EvtNext(hQuery, 1, &hEvent, INFINITE, 0, &count) != FALSE) {
				log(1, L"➕Event");
				events.push_back(Event(hevt, buffer, hEvent));
				EvtClose(hEvent);
				// Tous les 250 événements : assez pour voir bouger, assez rare
				// pour que l'affichage ne coûte rien face au coût de lecture.
				if (++lus % 250 == 0)
					printProgress(buffer ? buffer : L"", lus, totalEvt, L"evt");
			}
			printProgressEnd();
			EvtClose(hQuery);
			// La progression a effacé la ligne du canal : on la réaffiche avant
			// le résultat, sinon le « OK » ne dit pas de quel canal il parle.
			wprintf(L"\t%ls: %llu evt ", buffer, lus);
			printSuccess();
		}

	} while ((status == ERROR_SUCCESS) || (status == ERROR_INSUFFICIENT_BUFFER));
	free(buffer);
	EvtClose(hChannel);
	EvtClose(hevt);
	return ERROR_SUCCESS;
}

HRESULT Events::toJson() {
	log(3, L"🔈Events toJson");
	Json arr = Json::arr();
	for (const Event& e : events) arr.push(e.toJson());
	return writeJsonFile("events.json", arr);
}

void Events::clear() {
	log(3, L"🔈Events clear");
	events.clear();   // detruit les elements -> libere reellement
}
