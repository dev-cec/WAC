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
* @param data est la donnée à transformée
*/
std::wstring VariantType_to_wstring(PEVT_VARIANT data) {

	switch (data->Type) {
	case EvtVarTypeString: {
		std::wstring temp = ansi_to_utf8(std::wstring(data->StringVal));
		temp = replaceAll(temp, L"\\", L"\\\\");
		temp = replaceAll(temp, L"\"", L"\\\"");
		temp = replaceAll(temp, L"\r", L"\\r");
		temp = replaceAll(temp, L"\n", L"\\n");
		temp = replaceAll(temp, L"\t", L"\\t");
		return L"\"" + temp + L"\"";
		break;
	}
	case EvtVarTypeAnsiString: {
		std::wstring temp = ansi_to_utf8(string_to_wstring(std::string(data->AnsiStringVal)));
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
		return L"\"" + guid_to_wstring(*data->GuidVal) + L"\"";
		break;
	}
	case EvtVarTypeSizeT: {
		return  L"\"" + std::to_wstring(data->SizeTVal) + L"\"";
		break;
	}
	case EvtVarTypeFileTime: {
		return L"\"" + time_to_wstring(FILETIME(data->FileTimeVal)) + L"\"";
		break;
	}
	case EvtVarTypeSysTime: {
		FILETIME temp;
		SystemTimeToFileTime(data->SysTimeVal, &temp);
		return L"\"" + time_to_wstring(temp) + L"\"";
		break;
	}
	case EvtVarTypeSid: {
		LPWSTR temp;
		ConvertSidToStringSidW(data->SidVal, &temp);
		return L"\"" + std::wstring(temp) + L"\"";
		break;
	}
	case EvtVarTypeHexInt32: {
		return L"\"" + to_hex(data->Int32Val) + L"\"";
		break;
	}
	case EvtVarTypeHexInt64: {
		return L"\"" + to_hex(data->Int64Val) + L"\"";
		break;
	}

	case 129: { // ARRAY STRING
		std::wstring result = L"";
		for (DWORD iElement = 0; iElement < data->Count; iElement++) {
			std::wstring temp = ansi_to_utf8(std::wstring(data->StringArr[iElement]));
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
	* @param errors pointeur vers un tableau contenant les erreurs de traitement
	*/
	Event(EVT_HANDLE hevt, LPWSTR buffer, EVT_HANDLE hEvent, std::vector<std::tuple<std::wstring, HRESULT>>* errors) {
		PEVT_VARIANT event = NULL, event2 = NULL;
		PEVT_VARIANT bufferEvt = NULL;
		PEVT_VARIANT bufferEvt2 = NULL;
		DWORD bufferLengthNeeded2 = 0;
		DWORD bufferLength2 = 0;
		DWORD count = 0;
		DWORD nbEvents;
		HRESULT status;

		EVT_HANDLE hContext = NULL;
		do {
			if (bufferLengthNeeded2 > bufferLength2) {
				free(bufferEvt);
				bufferLength2 = bufferLengthNeeded2;
				bufferEvt = (PEVT_VARIANT)malloc(bufferLength2);
			}
			hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
			if (hContext)
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
						errors->push_back({ std::wstring(buffer) + L" / LEvtCreateRenderContext : ", status });

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
			if (EvtRender(EvtCreateRenderContext(count, ppValues, EvtRenderContextValues),
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
					errors->push_back({ std::wstring(buffer) + L" / EvtRender : ", status });

			}
		} while (status == ERROR_INSUFFICIENT_BUFFER);

		evtSystemProviderName = VariantType_to_wstring(&bufferEvt[0]);
		evtSystemProviderGuid = VariantType_to_wstring(&bufferEvt[1]); // GUID
		evtSystemEventID = VariantType_to_wstring(&bufferEvt[2]);
		evtSystemQualifiers = VariantType_to_wstring(&bufferEvt[3]);
		evtSystemLevel = VariantType_to_wstring(&bufferEvt[4]);
		evtSystemTask = VariantType_to_wstring(&bufferEvt[5]);
		evtSystemOpcode = VariantType_to_wstring(&bufferEvt[6]);
		evtSystemKeywords = VariantType_to_wstring(&bufferEvt[7]); // HEX
		evtSystemTimeCreated = VariantType_to_wstring(&bufferEvt[8]); // FILETIME
		evtSystemEventRecordId = VariantType_to_wstring(&bufferEvt[9]);
		evtSystemActivityID = VariantType_to_wstring(&bufferEvt[10]); // GUID
		evtSystemRelatedActivityID = VariantType_to_wstring(&bufferEvt[11]); // GUID
		evtSystemProcessID = VariantType_to_wstring(&bufferEvt[12]);
		evtSystemThreadID = VariantType_to_wstring(&bufferEvt[13]);
		evtSystemChannel = VariantType_to_wstring(&bufferEvt[14]);
		evtSystemComputer = VariantType_to_wstring(&bufferEvt[15]);
		evtSystemUserID = VariantType_to_wstring(&bufferEvt[16]); //SID
		evtSystemVersion = VariantType_to_wstring(&bufferEvt[17]);
		std::wstring temp = VariantType_to_wstring(&bufferEvt2[0]);
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
			if (!EvtFormatMessage(hmetadata, hEvent, NULL, 0, NULL, EvtFormatMessageEvent, messagesize, bufferMessage, &messageSizeNeeded)) {
				status = GetLastError();
				if (status != ERROR_INSUFFICIENT_BUFFER) {
					errors->push_back({ std::wstring(buffer) + L" / EvtFormatMessage : ", status });
					evtEventMessage = L"\"\"";
				}
			}
			else {
				status = ERROR_SUCCESS;
				std::wstring temp = ansi_to_utf8(std::wstring(bufferMessage));
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
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData(AppliConf conf) {
		EVT_RPC_LOGIN login = { NULL };
		EVT_HANDLE hevt = NULL;
		EVT_HANDLE hChannel = NULL;
		EVT_HANDLE hQuery = NULL;
		EVT_HANDLE hEvent = NULL;
		LPWSTR buffer = NULL;
		DWORD bufferLength1 = 0, bufferLengthNeeded1 = 0, count = 0;
		HRESULT status;

		_conf = conf;
		hevt = EvtOpenSession(EvtRpcLogin, &login, 0, 0);
		hChannel = EvtOpenChannelEnum(hevt, 0);
		wprintf(L"\n", buffer);
		do {

			//
			// Expand the buffer size if needed.
			//

			if (bufferLengthNeeded1 > bufferLength1) {
				free(buffer);
				bufferLength1 = bufferLengthNeeded1;
				buffer = (LPWSTR)malloc(bufferLength1 * sizeof(WCHAR));
				if (buffer == NULL) {
					status = GetLastError();
					errors.push_back({ L" buffer malloc : ", status });
					break;
				}
			}

			//
			// Try to get the next channel name.
			//

			if (EvtNextChannelPath(hChannel, bufferLength1, buffer, &bufferLengthNeeded1) == FALSE) {
				status = GetLastError();
				if (status != ERROR_INSUFFICIENT_BUFFER)
					errors.push_back({ L" EvtNextChannelPath : ", status });
			}
			else {
				status = ERROR_SUCCESS;

				wprintf(L"\t%s : ", buffer);
				//if (std::wstring(buffer) == L"System") { // for test purpose only
				hQuery = EvtQuery(NULL, buffer, NULL, EvtQueryChannelPath);
				if (hQuery == NULL) {
					status = GetLastError();
					if (status != ERROR_INSUFFICIENT_BUFFER)
						errors.push_back({ std::wstring(buffer) + L" / EvtQuery : ", status });
				}

				//
				// Read each event and render it as XML.
				//


				while (EvtNext(hQuery, 1, &hEvent, INFINITE, 0, &count) != FALSE) {
					events.push_back(Event(hevt, buffer, hEvent, &errors));
					EvtClose(hEvent);
				}
				//}
				printSuccess();
			}

		} while ((status == ERROR_SUCCESS) || (status == ERROR_INSUFFICIENT_BUFFER));
		free(buffer);
		EvtClose(hQuery);
		EvtClose(hChannel);
		EvtClose(hevt);
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json()
	{
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
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		std::wofstream myfile;
		myfile.open(_conf._outputDir + "/events.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/events_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		for (Event temp : events)
			temp.clear();
	}
};