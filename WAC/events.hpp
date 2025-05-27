#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include <winevt.h>
#include "tools.h"

#pragma comment(lib, "Wevtapi.lib")


/*! conversion d'un VARIANT_TYPE en wstring
/*! conversion d'un VARIANT_TYPE en wstrings
* @param data est la donnée à transformée
*/
std::wstring VariantType_to_wstring(PEVT_VARIANT data) {

	switch (data->Type) {
	case EvtVarTypeString: {
		std::wstring temp = std::wstring(data->StringVal).data();
		log(3, L"🔈replaceAll EvtVarTypeString");
		temp = replaceAll(temp, L"\\", L"\\\\");
		temp = replaceAll(temp, L"\"", L"\\\"");
		temp = replaceAll(temp, L"\r", L"\\r");
		temp = replaceAll(temp, L"\n", L"\\n");
		temp = replaceAll(temp, L"\t", L"\\t");
		return L"\"" + temp + L"\"";
		break;
	}
	case EvtVarTypeAnsiString: {
		std::wstring temp = string_to_wstring(std::string(data->AnsiStringVal)).data();
		log(3, L"🔈replaceAll EvtVarTypeAnsiString");
		temp = replaceAll(temp, L"\\", L"\\\\");
		temp = replaceAll(temp, L"\"", L"\\\"");
		temp = replaceAll(temp, L"\r", L"\\r");
		temp = replaceAll(temp, L"\n", L"\\n");
		temp = replaceAll(temp, L"\t", L"\\t");
		return L"\"" + temp + L"\"";
		break;
	}
	case EvtVarTypeSByte: {
		return L"\"" + std::to_wstring(data->SByteVal) + L"\"";
		break;
	}
	case EvtVarTypeByte: {
		return L"\"" + std::to_wstring(data->ByteVal) + L"\"";
		break;
	}
	case EvtVarTypeInt16: {
		return L"\"" + std::to_wstring(data->Int16Val) + L"\"";
		break;
	}
	case EvtVarTypeUInt16: {
		return L"\"" + std::to_wstring(data->UInt16Val) + L"\"";
		break;
	}
	case EvtVarTypeInt32: {
		return L"\"" + std::to_wstring(data->Int32Val) + L"\"";
		break;
	}
	case EvtVarTypeUInt32: {
		return L"\"" + std::to_wstring(data->UInt32Val) + L"\"";
		break;
	}
	case EvtVarTypeInt64: {
		return L"\"" + std::to_wstring(data->Int64Val) + L"\"";
		break;
	}
	case EvtVarTypeUInt64: {
		return L"\"" + std::to_wstring(data->UInt64Val) + L"\"";
		break;
	}
	case EvtVarTypeSingle: {
		return  L"\"" + std::to_wstring(data->SingleVal) + L"\"";
		break;
	}
	case EvtVarTypeDouble: {
		return  L"\"" + std::to_wstring(data->DoubleVal) + L"\"";
		break;
	}
	case EvtVarTypeBoolean: {
		return  L"\"" + std::to_wstring(data->BooleanVal) + L"\"";
		break;
	}
	case EvtVarTypeGuid: {
		log(3, L"🔈guid_to_wstring EvtVarTypeGuid");
		return L"\"" + guid_to_wstring(*data->GuidVal) + L"\"";
		break;
	}
	case EvtVarTypeSizeT: {
		return  L"\"" + std::to_wstring(data->SizeTVal) + L"\"";
		break;
	}
	case EvtVarTypeFileTime: {
		log(3, L"🔈time_to_wstring EvtVarTypeFileTime");
		return L"\"" + time_to_wstring(FILETIME((DWORD)data->FileTimeVal)) + L"\"";
		break;
	}
	case EvtVarTypeSysTime: {
		FILETIME temp;
		log(3, L"🔈SystemTimeToFileTime EvtVarTypeSysTime");
		SystemTimeToFileTime(data->SysTimeVal, &temp);
		return L"\"" + time_to_wstring(temp) + L"\"";
		break;
	}
	case EvtVarTypeSid: {
		LPWSTR temp;
		log(3, L"🔈ConvertSidToStringSidW EvtVarTypeSid");
		ConvertSidToStringSidW(data->SidVal, &temp);
		return L"\"" + std::wstring(temp) + L"\"";
		break;
	}
	case EvtVarTypeHexInt32: {
		log(3, L"🔈to_hex EvtVarTypeHexInt32");
		return L"\"" + to_hex(data->Int32Val) + L"\"";
		break;
	}
	case EvtVarTypeHexInt64: {
		log(3, L"🔈to_hex EvtVarTypeHexInt64");
		return L"\"" + to_hex(data->Int64Val) + L"\"";
		break;
	}

	case 129: { // ARRAY STRING
		std::wstring result = L"";
		for (DWORD iElement = 0; iElement < data->Count; iElement++) {
			std::wstring temp = std::wstring(data->StringArr[iElement]).data();
			log(3, L"🔈replaceAll ARRAY STRING");
			temp = replaceAll(temp, L"\\", L"\\\\");
			temp = replaceAll(temp, L"\"", L"\\\"");
			temp = replaceAll(temp, L"\r", L"\\r");
			temp = replaceAll(temp, L"\n", L"\\n");
			temp = replaceAll(temp, L"\t", L"\\t");
			result += L"\"" + temp + L"\"";
			if (iElement < data->Count - 1)
				result += L",\n";
			else
				result += L"\n";
		}
		return result;
		break;
	}

	default: {
		log(2, L"🔥VariantType_to_wstring unknown : " + std::to_wstring(data->Type));
		return L"\"\"";
		break;
	}
	}
}
/*! structure contenant un événement */
struct Event {
	std::wstring evtSystemProviderName = L"";//!< nom du provider
	std::wstring evtSystemProviderGuid = L"";//!< GUID du provider
	std::wstring evtSystemEventID = L"";//!< id de l’événement
	std::wstring evtSystemQualifiers = L"";//!< qualificatifs de l'événement
	std::wstring evtSystemLevel = L"";//!< niveau de l'événement
	std::wstring evtSystemTask = L"";//!< tache
	std::wstring evtSystemOpcode = L"";//!< code d'opération
	std::wstring evtSystemKeywords = L"";//!< mots clés
	std::wstring evtSystemTimeCreated = L"";//!< date de création
	std::wstring evtSystemTimeCreatedUtc = L"";//!< date de création au format UTC
	std::wstring evtSystemEventRecordId = L"";//!< id de l'enregistrement
	std::wstring evtSystemActivityID = L"";//!< id de l'activité
	std::wstring evtSystemRelatedActivityID = L"";//!< id de l'activité en relation
	std::wstring evtSystemProcessID = L"";//!< id du process ayant généré l'événement
	std::wstring evtSystemThreadID = L"";//!< id du thread ayant généré l'événement
	std::wstring evtSystemChannel = L"";//!< nom du channel
	std::wstring evtSystemComputer = L""; //!< nom de l'ordinateur
	std::wstring evtSystemUserID = L"";//!< SID de l'utilisateur
	std::wstring evtSystemVersion = L"";//!< version
	std::wstring evtEventData = L""; //!<  Data supplémentaires de l’événement
	std::wstring evtEventMessage = L""; //!< message de l’événement

	/*! Constructeur
	* @param hevt est un handle sur la session ouverte par EvtOpenSession
	* @param buffer st le nom du channel contenant les événements
	* @hevent est un handle sur un événement
	
	*/
	Event(EVT_HANDLE hevt, LPWSTR buffer, EVT_HANDLE hEvent) {
		PEVT_VARIANT event = NULL;
		PEVT_VARIANT event2 = NULL;
		PEVT_VARIANT bufferEvt = NULL;
		PEVT_VARIANT bufferEvt2 = NULL;
		DWORD bufferLengthNeeded2 = 0;
		DWORD bufferLength2 = 0;
		DWORD count = 0;
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
		
		log(3, L"🔈VariantType_to_wstring evtSystemEventID");
		log(3, L"🔈VariantType_to_wstring evtSystemEventRecordId");
		evtSystemEventRecordId = VariantType_to_wstring(&bufferEvt[9]);
		log(2, L"❇️Event Record Id " + EvtSystemEventRecordId);

		log(3, L"🔈VariantType_to_wstring evtSystemProviderGuid");
		evtSystemProviderGuid = VariantType_to_wstring(&bufferEvt[1]); // GUID
		
		evtSystemEventID = VariantType_to_wstring(&bufferEvt[2]);
		log(3, L"🔈VariantType_to_wstring evtSystemProviderName");
		evtSystemProviderName = VariantType_to_wstring(&bufferEvt[0]);

		log(3, L"🔈VariantType_to_wstring evtSystemQualifiers");
		evtSystemQualifiers = VariantType_to_wstring(&bufferEvt[3]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemLevel");
		evtSystemLevel = VariantType_to_wstring(&bufferEvt[4]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemTask");
		evtSystemTask = VariantType_to_wstring(&bufferEvt[5]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemOpcode");
		evtSystemOpcode = VariantType_to_wstring(&bufferEvt[6]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemKeywords");
		evtSystemKeywords = VariantType_to_wstring(&bufferEvt[7]); // HEX
		
		log(3, L"🔈VariantType_to_wstring evtSystemTimeCreated");
		evtSystemTimeCreated = VariantType_to_wstring(&bufferEvt[8]); // FILETIME
		
		
		log(3, L"🔈VariantType_to_wstring evtSystemActivityID");
		evtSystemActivityID = VariantType_to_wstring(&bufferEvt[10]); // GUID
		
		log(3, L"🔈VariantType_to_wstring evtSystemRelatedActivityID");
		evtSystemRelatedActivityID = VariantType_to_wstring(&bufferEvt[11]); // GUID
		
		log(3, L"🔈VariantType_to_wstring evtSystemProcessID");
		evtSystemProcessID = VariantType_to_wstring(&bufferEvt[12]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemThreadID");
		evtSystemThreadID = VariantType_to_wstring(&bufferEvt[13]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemChannel");
		evtSystemChannel = VariantType_to_wstring(&bufferEvt[14]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemComputer");
		evtSystemComputer = VariantType_to_wstring(&bufferEvt[15]);
		
		log(3, L"🔈VariantType_to_wstring evtSystemUserID");
		evtSystemUserID = VariantType_to_wstring(&bufferEvt[16]); //SID
		
		log(3, L"🔈VariantType_to_wstring evtSystemVersion");
		evtSystemVersion = VariantType_to_wstring(&bufferEvt[17]);
		
		log(3, L"🔈VariantType_to_wstring evtEventData");
		std::wstring temp = VariantType_to_wstring(&bufferEvt2[0]);
		log(3, L"🔈replaceAll evtEventData");
		temp = replaceAll(temp, L"\n", L"\n\t\t");
		evtEventData = L"[\n\t\t" + temp + L"\n\t]"; // pour garantir d'avoir toujours un tableau formaté même si chaîne unique

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
					evtEventMessage = L"\"\"";
				}
			}
			else {
				status = ERROR_SUCCESS;
				std::wstring temp = std::wstring(bufferMessage).data();
				log(3, L"🔈replaceAll evtEventMessage");
				temp = replaceAll(temp, L"\\", L"\\\\");
				temp = replaceAll(temp, L"\"", L"\\\"");
				temp = replaceAll(temp, L"\r", L"\\r");
				temp = replaceAll(temp, L"\n", L"\\n");
				temp = replaceAll(temp, L"\t", L"\\t");
				evtEventMessage = L"\"" + temp + L"\"";
				free(bufferMessage);
			}
		} while (status == ERROR_INSUFFICIENT_BUFFER);

		EvtClose(hmetadata);
	}

	/*! conversion de l'objet au format json
	*/
	std::wstring to_json() {
		log(3, L"🔈event clear");
		std::wstring result = L"{\n";
		result += L"\t\"EvtSystemProviderName\" : " + evtSystemProviderName + L",\n";
		result += L"\t\"EvtSystemProviderGuid\" : " + evtSystemProviderGuid + L",\n"; // GUID
		result += L"\t\"EvtSystemEventID\" : " + evtSystemEventID + L",\n";
		result += L"\t\"EvtSystemQualifiers\" : " + evtSystemQualifiers + L",\n";
		result += L"\t\"EvtSystemLevel\" : " + evtSystemLevel + L",\n";
		result += L"\t\"EvtSystemTask\" : " + evtSystemTask + L",\n";
		result += L"\t\"EvtSystemOpcode\" : " + evtSystemOpcode + L",\n";
		result += L"\t\"EvtSystemKeywords\" : " + evtSystemKeywords + L",\n"; // HEX
		result += L"\t\"EvtSystemTimeCreated\" : " + evtSystemTimeCreated + L",\n"; // FILETIME
		result += L"\t\"EvtSystemEventRecordId\" : " + evtSystemEventRecordId + L",\n";
		result += L"\t\"EvtSystemActivityID\" : " + evtSystemActivityID + L",\n"; // GUID
		result += L"\t\"EvtSystemRelatedActivityID\" : " + evtSystemRelatedActivityID + L",\n"; // GUID
		result += L"\t\"EvtSystemProcessID\" : " + evtSystemProcessID + L",\n";
		result += L"\t\"EvtSystemThreadID\" : " + evtSystemThreadID + L",\n";
		result += L"\t\"EvtSystemChannel\" : " + evtSystemChannel + L",\n";
		result += L"\t\"EvtSystemComputer\" : " + evtSystemComputer + L",\n";
		result += L"\t\"EvtSystemUserID\" : " + evtSystemUserID + L",\n"; //SID
		result += L"\t\"EvtSystemVersion\" : " + evtSystemVersion + L",\n";
		result += L"\t\"EvtEventData\" : " + evtEventData + L",\n";
		result += L"\t\"EvtEventMessage\" : " + evtEventMessage + L"\n";
		result += L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {}
};

struct Events {

	std::vector<Event> events; //!< tableau contenant tout les Events
	
	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
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
		std::wcout << std::endl; // pour mise en forme console sinon premier chanel sur mauvaise line
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
				std::wcout << tab(1) << std::wstring(buffer) << L": ";
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
				while (EvtNext(hQuery, 1, &hEvent, INFINITE, 0, &count) != FALSE) {
					log(1, L"➕Event");
					events.push_back(Event(hevt, buffer, hEvent));
					EvtClose(hEvent);
				}
				EvtClose(hQuery);
				printSuccess();
			}

		} while ((status == ERROR_SUCCESS) || (status == ERROR_INSUFFICIENT_BUFFER));
		free(buffer);
		EvtClose(hChannel);
		EvtClose(hevt);
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
		log(3, L"🔈Events to_json");
		std::wstring result = L"[ \n";
		std::vector<Event>::iterator it;
		for (it = events.begin(); it != events.end(); it++) {
			result += it->to_json();
			if (it != events.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"\n]";

		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(conf._outputDir + "/events.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Events clear");
		for (Event temp : events)
			temp.clear();
	}
};