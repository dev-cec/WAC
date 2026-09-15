#pragma once
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include <winevt.h>
#include <sddl.h>
#include "tools.h"

#pragma comment(lib, "Wevtapi.lib")


/*! Convertit un EVT_VARIANT en valeur JSON typée.
* Les chaines sont rendues BRUTES (Json::str) : l'echappement est centralise
* dans json.h. Les entiers deviennent des nombres JSON, les types tableau des
* tableaux JSON.
* @param data la donnee a convertir
* @return la valeur JSON correspondante, Json::null() si le type est inconnu
*/
Json variantToJson(PEVT_VARIANT data);
/*! structure contenant un événement */
struct Event {
	Json evtSystemProviderName = Json::null();//!< nom du provider
	Json evtSystemProviderGuid = Json::null();//!< GUID du provider
	Json evtSystemEventID = Json::null();//!< id de l’événement
	Json evtSystemQualifiers = Json::null();//!< qualificatifs de l'événement
	Json evtSystemLevel = Json::null();//!< niveau de l'événement
	Json evtSystemTask = Json::null();//!< tache
	Json evtSystemOpcode = Json::null();//!< code d'opération
	Json evtSystemKeywords = Json::null();//!< mots clés
	Json evtSystemTimeCreated = Json::null();//!< date de création
	Json evtSystemTimeCreatedUtc = Json::null();//!< date de création au format UTC
	Json evtSystemEventRecordId = Json::null();//!< id de l'enregistrement
	Json evtSystemActivityID = Json::null();//!< id de l'activité
	Json evtSystemRelatedActivityID = Json::null();//!< id de l'activité en relation
	Json evtSystemProcessID = Json::null();//!< id du process ayant généré l'événement
	Json evtSystemThreadID = Json::null();//!< id du thread ayant généré l'événement
	Json evtSystemChannel = Json::null();//!< nom du channel
	Json evtSystemComputer = Json::null(); //!< nom de l'ordinateur
	Json evtSystemUserID = Json::null();//!< SID de l'utilisateur
	Json evtSystemVersion = Json::null();//!< version
	Json evtEventData = Json::null(); //!<  Data supplémentaires de l’événement
	Json evtEventMessage = Json::null(); //!< message de l’événement

	/*! Constructeur
	* @param hevt est un handle sur la session ouverte par EvtOpenSession
	* @param buffer st le nom du channel contenant les événements
	* @hevent est un handle sur un événement
	
	*/
	Event(EVT_HANDLE hevt, LPWSTR buffer, EVT_HANDLE hEvent);

	/*! conversion de l'objet au format json */
	Json toJson() const;

	/* liberation mémoire */
	void clear() {}
};

struct Events {

	std::vector<Event> events; //!< tableau contenant tout les Events
	
	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};