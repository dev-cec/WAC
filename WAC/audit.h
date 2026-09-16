/*  audit.h — journal d'investigation : ce que WAC a fait, quand, et ce que ça a laissé.
 *
 *  POURQUOI. Toute collecte sur un système vivant laisse des traces. La bonne
 *  pratique forensique n'est pas de les effacer — ce serait de l'anti-forensique,
 *  et ça compromettrait la recevabilité — mais de les DOCUMENTER, pour qu'un
 *  analyste puisse distinguer, dans les artefacts, ce qui vient du suspect de ce
 *  qui vient de l'outil.
 *
 *  Sans ce journal, un événement 7036 ou un accès fichier horodaté pendant la
 *  collecte est indiscernable d'une action du suspect. C'est une source d'erreur
 *  d'interprétation, et une prise pour la contestation d'une expertise.
 *
 *  Le journal couvre trois choses :
 *    1. le CONTEXTE de la collecte (outil, version, ligne de commande, machine,
 *       opérateur, fuseau horaire, début/fin) — la chaîne de possession ;
 *    2. chaque OPÉRATION menée, horodatée en UTC et en heure locale, avec son
 *       résultat ;
 *    3. l'EMPREINTE attendue de chaque opération : quelle trace elle laisse et où
 *       la retrouver. C'est ce qui rend le journal exploitable à l'analyse.
 *
 *  Sortie : `investigation.json`, dans le dossier de sortie, au même format que
 *  les autres artefacts (cf. json.h).
 *
 *  Références : RFC 3227 (collecte et archivage de preuves), ISO/IEC 27037
 *  (identification, collecte et préservation de preuves numériques).
 */
#pragma once
#include <windows.h>
#include <string>

/*! Empreinte attendue d'une opération : la trace qu'elle laisse sur le système
 *  examiné. Sert à renseigner le champ `Footprint` du journal.
 *
 *  Les valeurs sont volontairement descriptives plutôt que codées : elles sont
 *  destinées à être lues par un analyste humain dans le rapport.
 */
namespace Footprint {
	//! Lecture brute du volume : pas d'accès fichier, donc aucun horodatage
	//! modifié ; un audit d'accès aux objets (si activé) peut la journaliser.
	extern const wchar_t* VOLUME_BRUT;
	//! Ouverture d'une ruche extraite (copie sur l'USB) : n'affecte pas l'original.
	extern const wchar_t* RUCHE_COPIE;
	//! Lecture d'un fichier d'artefact extrait (copie sur l'USB) : journaux
	//! d'événements, Prefetch, jumplists. Aucun accès à l'original.
	extern const wchar_t* FICHIER_COPIE;
	//! Modification documentée du bloc de base d'une ruche COPIÉE (cf. hive_recover.h).
	extern const wchar_t* RUCHE_PATCH;
	//! Application des journaux de transaction à une ruche COPIÉE, avec journal
	//! d'annulation (cf. hive_recover.h).
	extern const wchar_t* RUCHE_REJEU;
	//! Une seule énumération du gestionnaire de services, en lecture : relève
	//! l'état courant sans ouvrir de handle par service.
	extern const wchar_t* SCM;
	//! Lecture d'une clé du registre local (ProfileList) : aucun appel RPC,
	//! aucune sollicitation de LSASS.
	extern const wchar_t* COMPTES_LOCAUX;
	//! Énumération de processus : ouvre des handles de processus (audit possible).
	extern const wchar_t* PROCESSUS;
	//! Interrogation des sessions ouvertes via LSA / Terminal Services.
	extern const wchar_t* SESSIONS;
	//! Écriture sur le support de collecte (clé USB), jamais sur la cible.
	extern const wchar_t* ECRITURE_USB;
}

/*! Ouvre le journal : relève le contexte de la collecte (machine, opérateur,
 *  fuseau, ligne de commande) et l'horodatage de début.
 *  À appeler une fois, au plus tôt dans `main`.
 *  @param argc nombre d'arguments de la ligne de commande
 *  @param argv arguments de la ligne de commande
 */
void auditInit(int argc, char* argv[]);

/*! Consigne une opération.
 *  @param operation ce qui a été fait, ex. L"EnumServicesStatusExW"
 *  @param cible sur quoi, ex. L"\\Windows\\System32\\config\\SYSTEM" (peut être vide)
 *  @param resultat HRESULT de l'opération
 *  @param footprint trace attendue (une constante de `Footprint`)
 */
void auditRecord(const std::wstring& operation,
                 const std::wstring& cible,
                 HRESULT resultat,
                 const wchar_t* footprint);

/*! Clôt le journal (horodatage de fin, durée) et écrit `investigation.json`.
 *  À appeler en toute fin de collecte, après le dernier collecteur.
 *  @return ERROR_SUCCESS, ou un code d'erreur d'écriture
 */
HRESULT auditWrite();
