#pragma once

/*  scheduledTasks.h — tâches planifiées, lues HORS LIGNE.
 *
 *  POURQUOI HORS LIGNE. La version précédente passait par le Task Scheduler COM
 *  (`CoCreateInstance(CLSID_TaskScheduler)`), ce qui coûtait deux choses :
 *    - une trace d'exécution — sollicitation du service Schedule et entrées dans
 *      `Microsoft-Windows-TaskScheduler/Operational` ;
 *    - du temps : plusieurs appels d'interface par tâche, sur 217 tâches.
 *  `scheduledTasks` était en outre le SEUL consommateur de COM dans WAC (audit
 *  du 2026-09-15) : le basculer permet de supprimer COM entièrement.
 *
 *  SOURCES DE DONNÉES
 *    - définition : un fichier XML par tâche sous `\\Windows\\System32\\Tasks\`,
 *      extrait en brut ; l'arborescence donne le chemin de la tâche ;
 *    - historique : valeur binaire `DynamicInfo` sous
 *      `SOFTWARE\…\\CurrentVersion\\Schedule\\TaskCache\\Tasks\{GUID}`, reliée à la
 *      tâche par `TaskCache\\Tree\<chemin>\Id`.
 *
 *  CE QUI EST PERDU, ET POURQUOI C'EST ACCEPTABLE
 *  `NextRun` et `NumberOfMissedRuns` ne sont pas stockés : le planificateur les
 *  calcule à chaud. Ce sont des PROJECTIONS, pas des traces d'activité passée :
 *  elles n'ont aucune valeur probante. Les champs ne sont donc PAS émis du tout —
 *  une clé vide dans le JSON se lirait comme un échec de lecture, alors que la
 *  donnée n'existe simplement pas hors ligne.
 *  `State` n'est plus que « activé / désactivé » (lu dans le XML) : l'état
 *  « en cours d'exécution » est par nature volatil.
 */

#include "binaires.h"
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "json.h"
#include "trans_id.h"
#include "quickdigest5.h"

/*! Déclencheur d'une tâche planifiée. */
struct Trigger {
	std::wstring type;      //!< nom de l'élément XML (TimeTrigger, LogonTrigger…)
	std::wstring interval;  //!< répétition (ISO 8601 de durée, ex. « PT1H »)
	std::wstring debut;     //!< StartBoundary : première échéance prévue
	bool         actif = true; //!< Enabled du déclencheur
};

/*! Action exécutée par une tâche planifiée. */
struct Action {
	std::wstring type;       //!< « Exec » ou « ComHandler »
	std::wstring command;    //!< exécutable (Exec)
	EmpreinteBinaire empreinte; //!< empreintes de l'exécutable, si --binary
	std::wstring arguments;  //!< arguments de la ligne de commande
	std::wstring workingDir; //!< répertoire de travail
	std::wstring classId;    //!< CLSID (ComHandler)
	std::wstring data;       //!< données passées au gestionnaire COM
};

/*! Une tâche planifiée, reconstituée depuis son XML et le TaskCache. */
struct ScheduledTask {
	std::wstring name;                 //!< nom de la tâche (nom du fichier)
	std::wstring path;                 //!< chemin dans l'arborescence (ex. \\Microsoft\\Windows\…)
	std::wstring description;
	std::wstring author;
	std::wstring runAs;                //!< compte d'exécution (UserId du principal)
	std::wstring runAsSid;             //!< SID si UserId en est un
	std::wstring state;                //!< « Enabled » / « Disabled »
	bool         enabled = true;
	FILETIME     lastRunTime = { 0 };      //!< heure locale, dérivée de l'UTC
	FILETIME     lastRunTimeUtc = { 0 };   //!< depuis DynamicInfo (UTC)
	LONG         lastTaskResult = 0;       //!< code de retour de la dernière exécution
	std::wstring registrationDate;         //!< Date du XML, telle qu'écrite
	std::wstring sourceXml;                //!< chemin du XML d'origine, pour la traçabilité
	std::vector<Action>  actions;
	std::vector<Trigger> triggers;

	/*! conversion de l'objet au format json */
	Json toJson() const;

	/* liberation mémoire */
	void clear();
};

/*! Ensemble des tâches planifiées. */
struct ScheduledTasks {
	std::vector<ScheduledTask> scheduledTasks;

	/*! Lit les tâches depuis les XML extraits et enrichit avec le TaskCache.
	 *  N'utilise ni COM ni le service Schedule.
	 */
	HRESULT getData();

	/*! conversion de l'objet au format json */
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};
