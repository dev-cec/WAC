#pragma once

/*  events.h — JOURNAUX D'ÉVÉNEMENTS WINDOWS.
 *
 *  Lus HORS LIGNE depuis les fichiers `.evtx` extraits par lecture brute, et non
 *  plus par l'API `wevtapi`. C'était le dernier collecteur à solliciter un
 *  service de la machine examinée (`EventLog`) : ce service peut inscrire ses
 *  propres entrées pendant qu'on l'interroge, l'appel prenait une vingtaine de
 *  minutes sous Windows 11, et la collecte montait à plus d'un gigaoctet de jeu
 *  de travail — donc de la pagination, donc des écritures sur le disque même
 *  qu'on s'efforce de ne pas modifier.
 *
 *  CHAÎNE DE TRAITEMENT
 *    raw_collect  extrait `\Windows\System32\winevt\Logs\*.evtx` sur le support
 *                 de collecte (lecture brute NTFS, aucune ouverture de fichier)
 *    evtx.h       décode chaque enregistrement en texte XML
 *    xml_light    analyse ce XML — le même lecteur que les tâches planifiées,
 *                 plutôt qu'un second décodeur propre aux événements
 *    events.cpp   remplit la structure ci-dessous et l'écrit AU FIL DE L'EAU
 *
 *  CE QUE LA LECTURE HORS LIGNE NE DONNE PAS. `EvtFormatMessage` rendait, pour
 *  environ un événement sur sept, le message en clair. Ce texte n'est pas dans
 *  le journal : il vient du fichier de ressources du fournisseur, qu'il faudrait
 *  analyser en propre (ressource `WEVT_TEMPLATE` et table de messages d'un
 *  binaire PE). Le champ est donc omis plutôt qu'écrit vide. Toutes les données
 *  de l'événement lui-même — identifiant, horodatage, fournisseur, canal, SID,
 *  processus, et l'intégralité de `EventData` — sont présentes.
 */

#include <windows.h>
#include <string>
#include <vector>
#include "tools.h"
#include "json.h"
#include "xml_light.h"

/*! Un événement, tel qu'il figure dans un journal.
 *
 *  Les champs gardent les noms de l'ancienne collecte par API : le schéma de
 *  sortie ne change pas, seule la source change. Une valeur absente du journal
 *  reste `null` — elle n'est pas remplacée par un zéro, qui se lirait comme une
 *  valeur relevée.
 */
struct Event {
	Json evtSystemProviderName = Json::null();      //!< nom du fournisseur
	Json evtSystemProviderGuid = Json::null();      //!< GUID du fournisseur
	Json evtSystemEventID = Json::null();           //!< identifiant de l'événement
	Json evtSystemQualifiers = Json::null();        //!< qualificatifs (événements classiques)
	Json evtSystemLevel = Json::null();             //!< niveau
	Json evtSystemTask = Json::null();              //!< tâche
	Json evtSystemOpcode = Json::null();            //!< code d'opération
	Json evtSystemKeywords = Json::null();          //!< mots clés
	Json evtSystemTimeCreated = Json::null();       //!< date de création (UTC)
	Json evtSystemEventRecordId = Json::null();     //!< identifiant de l'enregistrement
	Json evtSystemActivityID = Json::null();        //!< identifiant d'activité
	Json evtSystemRelatedActivityID = Json::null(); //!< identifiant d'activité liée
	Json evtSystemProcessID = Json::null();         //!< processus émetteur
	Json evtSystemThreadID = Json::null();          //!< fil d'exécution émetteur
	Json evtSystemChannel = Json::null();           //!< canal
	Json evtSystemComputer = Json::null();          //!< nom de l'ordinateur
	Json evtSystemUserID = Json::null();            //!< SID de l'utilisateur
	Json evtSystemVersion = Json::null();           //!< version du schéma de l'événement
	Json evtEventData = Json::null();               //!< données propres à l'événement
	/*! Nom du fichier journal d'où l'événement provient.
	*
	*  PROVENANCE. Un même canal peut être porté par plusieurs fichiers : le
	*  journal courant et ses archives, qu'une machine conserve côte à côte avec
	*  des numéros d'enregistrement qui se recouvrent. Sans ce champ, deux
	*  événements de même canal et de même numéro sont indiscernables, et rien
	*  ne dit lequel vient d'où — ce qui interdit de trancher entre un doublon
	*  légitime et un défaut de lecture.
	*/
	Json evtSourceLog = Json::null();

	/*! Construit l'événement depuis le XML décodé d'un enregistrement.
	*  @param racine élément `<Event>` analysé par xml_light
	*  @param canal canal déduit du nom de fichier, employé si le XML ne le porte
	*         pas (les journaux archivés omettent parfois `<Channel>`)
	*  @param identifiant numéro d'enregistrement lu dans l'en-tête binaire,
	*         employé si le XML ne porte pas `<EventRecordID>`
	*/
	/*! @param nomFichier nom du fichier journal, consigné comme provenance */
	Event(const XmlNode& racine, const std::wstring& canal,
	      unsigned long long identifiant, const std::wstring& nomFichier);

	/*! conversion de l'objet au format json */
	Json toJson() const;

	/* liberation mémoire */
	void clear() {}
};

/*! Collecte de tous les journaux extraits.
 *
 *  Aucun tableau d'événements n'est conservé : chacun est écrit puis oublié
 *  (cf. EcrivainJsonTableau). C'est ce qui ramène la collecte des journaux à une
 *  empreinte mémoire constante, quelle que soit la taille des journaux.
 */
struct Events {
	unsigned long long lus = 0;          //!< enregistrements écrits
	unsigned long long illisibles = 0;   //!< enregistrements écartés
	unsigned long long fichiers = 0;     //!< journaux parcourus

	/*! Lit les journaux extraits et écrit `events.json` au fil de l'eau.
	*  @return ERROR_SUCCESS, S_FALSE si des enregistrements ont été écartés,
	*          ou un code d'erreur si aucun journal n'a pu être lu
	*/
	HRESULT getData();

	/*! Rien à sérialiser : `getData()` a déjà écrit le fichier.
	*  Conservé pour que le déroulé de main.cpp reste le même pour tous les
	*  collecteurs.
	*/
	HRESULT toJson() { return ERROR_SUCCESS; }

	/* liberation mémoire */
	void clear() {}
};
