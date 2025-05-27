#pragma once

#define _WIN32_DCOM

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include <windows.h>
#include <taskschd.h>
#include <lm.h>
#include <comdef.h>
#include <sddl.h>
#include <lmerr.h>
#include "tools.h"
#include "trans_id.h"
#include "quickdigest5.hpp"

/*structure représentant une trigger d'une tâche planifiée
*/
struct Trigger {
	TASK_TRIGGER_TYPE2 type; //!< type de trigger pour l’exécution de la tâche
	std::wstring interval=L"";//!< délai entre 2 exécution

	/* liberation mémoire */
	void clear() {}
};
/*structure représentant une action d'une tâche planifiée
*/
struct Action {
	TASK_ACTION_TYPE type; //!< type de l'action au format numérique
	std::wstring command = L"";//!< ligne de commande exécutée
	std::wstring md5 = L"";//!< hash md5 de l'executable
	std::wstring arguments = L"";//!< arguments de la ligne de commande exécutée
	std::wstring classId = L"";//!< classId pour ACTION COM HANDLER
	std::wstring data = L"";//!< data pour ACTION COM HANDLER

	/*liberation mémoire */
	void clear(){}
};

/*structure représentant une tâche planifiée
* Documentation : https://learn.microsoft.com/fr-fr/windows/win32/api/taskschd/nn-taskschd-iregisteredtask
* Documentation : https://learn.microsoft.com/fr-fr/windows/win32/api/taskschd/nn-taskschd-itaskdefinition
*/
struct ScheduledTask {
	ITaskDefinition* ppDefinition = NULL;//!< la définition de la tâche.
	VARIANT_BOOL pEnabled = false; //!< valeur booléenne qui indique si la tâche inscrite est activée.
	FILETIME pLastRunTime = { 0 }; //!< heure à laquelle la tâche inscrite a été exécutée pour la dernière fois.
	FILETIME pLastRunTimeUtc = { 0 }; //!< heure à laquelle la tâche inscrite a été exécutée pour la dernière fois au format UTC.
	LONG pLastTaskResult = 0; //!< les résultats qui ont été retournés lors de la dernière exécution de la tâche inscrite.
	BSTR pName = BSTR(L""); //!< le nom de la tâche inscrite.
	FILETIME pNextRunTime = { 0 }; //!< l’heure à laquelle l’exécution prochaine de la tâche inscrite est planifiée.
	FILETIME pNextRunTimeUtc = { 0 }; //!< l’heure à laquelle l’exécution prochaine de la tâche inscrite est planifiée au format UTC.
	LONG pNumberOfMissedRuns = 0; //!< le nombre de fois où la tâche inscrite a manqué une exécution planifiée.
	std::wstring pPath = L"";//!<  le chemin d’accès à l’emplacement où la tâche inscrite est stockée.
	std::wstring escapedPath = L"";//!<  le chemin d’accès à l’emplacement où la tâche inscrite est stockée.
	TASK_STATE pState; //!< L’état opérationnel de la tâche inscrite.
	std::vector<Action> pActions; //!< Contient les actions effectuées par la tâche..
	std::wstring pAuthor = L"";//!< créateur de la tâche planifiée
	std::wstring pDescription = L"";//!< description de la tâche planifiée
	std::wstring pRunAs = L"";//!< compte utilisé pour exécutée la tâche
	std::wstring runAsSid = L"";//!< SID du compte utilisé pour exécutée la tâche
	std::vector<Trigger> triggers;//!< triggers de a tâche planifiée
	/*! Constructeur
	* @param task est une tâche planifiée au format virtuel IRegisteredTask. Ce format étant complexe à manipuler on en extrait les infos qui nous intéressent.
	* @param pfolder est le sous-repertoire contenant la tâche planifiée
	*/
	ScheduledTask(IRegisteredTask* task) {
		IActionCollection* pActionCollection = NULL; // Ensemble des actions
		IUnknown* ppEnum = NULL; // pour itérer la collection
		IEnumVARIANT* pEnum = NULL; // pour itérer la collection
		VARIANT var; // pour itérer la collection
		ULONG lFetch = 0; // pour itérer la collection
		IAction* pAction = NULL; // pour itérer la collection
		IDispatch* pDisp = NULL; // pour itérer la collection
		TASK_ACTION_TYPE pType; // pour itérer la collection
		DATE tempD; // pour itérer la collection
		SYSTEMTIME tempST; // pour itérer la collection
		IRegistrationInfo* infos;// pour itérer la collection
		IPrincipal* principal;// pour itérer la collection
		ITriggerCollection* pTriggerCollection;// pour itérer la collection

		log(3, L"🔈get_Definition ppDefinition");
		HRESULT hr = task->get_Definition(&ppDefinition);

		BSTR temp = BSTR(L"");
		log(3, L"🔈get_Enabled pEnabled");
		hr = task->get_Enabled(&pEnabled);
		log(3, L"🔈get_LastRunTime pLastRunTime");
		hr = task->get_LastRunTime(&tempD);
		//conversion de DATE en FILETIME
		log(3, L"🔈VariantTimeToSystemTime pLastRunTime");
		VariantTimeToSystemTime(tempD, &tempST);
		log(3, L"🔈SystemTimeToFileTime pLastRunTime");
		SystemTimeToFileTime(&tempST, &pLastRunTime);
		log(3, L"🔈LocalFileTimeToFileTime pLastRunTimeUtc");
		LocalFileTimeToFileTime(&pLastRunTime, &pLastRunTimeUtc);

		log(3, L"🔈get_LastTaskResult pLastTaskResult");
		hr = task->get_LastTaskResult(&pLastTaskResult);
		log(3, L"🔈get_Name pName");
		hr = task->get_Name(&pName);
		log(2, L"❇️Scheduled task name : " + bstr_to_wstring(pName));
		log(3, L"🔈get_NextRunTime pNextRunTime");
		hr = task->get_NextRunTime(&tempD);

		//conversion de DATE en FILETIME
		log(3, L"🔈VariantTimeToSystemTime pNextRunTime");
		VariantTimeToSystemTime(tempD, &tempST);
		log(3, L"🔈SystemTimeToFileTime pNextRunTime");
		SystemTimeToFileTime(&tempST, &pNextRunTime);
		log(3, L"🔈LocalFileTimeToFileTime pNextRunTimeUtc");
		LocalFileTimeToFileTime(&pNextRunTime, &pNextRunTimeUtc);
		
		log(3, L"🔈get_RegistrationInfo infos");
		ppDefinition->get_RegistrationInfo(&infos);
		log(3, L"🔈get_Author pAuthor");
		infos->get_Author(&temp);
		log(3, L"🔈bstr_to_wstring pAuthor");
		pAuthor = bstr_to_wstring(temp);
		log(3, L"🔈replaceAll pAuthor");
		pAuthor = replaceAll(pAuthor, L"\\", L"\\\\");
		pAuthor= replaceAll(pAuthor, L"\"", L"\\\"");
		log(3, L"🔈get_Description pDescription");
		infos->get_Description(&temp);
		log(3, L"🔈bstr_to_wstring pDescription");
		pDescription = bstr_to_wstring(temp);
		log(3, L"🔈get_Principal principal");
		ppDefinition->get_Principal(&principal);
		log(3, L"🔈get_UserId pRunAs");
		principal->get_UserId(&temp);
		log(3, L"🔈bstr_to_wstring pRunAs");
		pRunAs = bstr_to_wstring(temp);
		LPUSER_INFO_4 info4 = NULL;
		LPWSTR tempSid = NULL;
		std::wstring SID = L"";
		//get SID of user
		if (pRunAs != L"") {
			log(3, L"🔈NetUserGetInfo info4");
			if(NetUserGetInfo(NULL, pRunAs.c_str(), 4, (LPBYTE*)&info4) == NERR_Success){
				log(3, L"🔈ConvertSidToStringSidW info4");
				ConvertSidToStringSidW(info4->usri4_user_sid, &tempSid);
				log(3, L"🔈runAsSid info4");
				runAsSid = std::wstring(tempSid);
				NetApiBufferFree(info4);
			}
		}
		log(3, L"🔈get_NumberOfMissedRuns task");
		hr = task->get_NumberOfMissedRuns(&pNumberOfMissedRuns);
		log(3, L"🔈get_Path task");
		hr = task->get_Path(&temp);
		log(3, L"🔈bstr_to_wstring pPath");
		pPath = bstr_to_wstring(temp);
		log(3, L"🔈replaceAll escapedPath");
		escapedPath = replaceAll(pPath,L"\\",L"\\\\");//escape
		escapedPath = replaceAll(escapedPath,L"\"",L"\\\"");//escape
		log(3, L"🔈get_State pState");
		hr = task->get_State(&pState);

		//Liste des actions
		log(3, L"🔈get_Actions pActionCollection");
		ppDefinition->get_Actions(&pActionCollection);

		// Get the Enumerator object on the collection object.
		log(3, L"🔈get__NewEnum ppEnum");
		pActionCollection->get__NewEnum(&ppEnum);
		log(3, L"🔈QueryInterface pEnum");
		ppEnum->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);

		// Enumerate the collection.
		VariantInit(&var);
		log(3, L"🔈Next pEnum");
		hr = pEnum->Next(1, &var, &lFetch);
		while (hr == S_OK)
		{
			if (lFetch == 1)
			{
				Action a;
				pDisp = V_DISPATCH(&var);
				log(3, L"🔈QueryInterface pAction");
				pDisp->QueryInterface(IID_IAction, (void**)&pAction);
				log(3, L"🔈get_Type pAction");
				pAction->get_Type(&a.type);
				if (a.type == TASK_ACTION_EXEC) {
					log(3, L"🔈get_Path pAction");
					((IExecAction*)pAction)->get_Path(&temp);
					log(3, L"🔈bstr_to_wstring command");
					a.command = bstr_to_wstring(temp);

					
					//calcul hash avant escape
					char appdata[MAX_PATH];
					log(3, L"🔈replaceAll temp");
					std::wstring wp(replaceAll(a.command, L"\"", L""));
					log(3, L"🔈wstring_to_string p");
					std::string p=wstring_to_string(wp); // remove " in path
					log(3, L"🔈ExpandEnvironmentStringsA command");
					ExpandEnvironmentStringsA(p.c_str(), appdata, MAX_PATH); // replace env variable by their value in path
					log(3, L"🔈fileToHash md5Source " + a.command);
					a.md5 = QuickDigest5::fileToHash(appdata); // calcul hash

					log(3, L"🔈replaceAll command");
					a.command= replaceAll(a.command,L"\\",L"\\\\");
					a.command = replaceAll(a.command,L"\"",L"\\\"");
					log(3, L"🔈get_Arguments pAction");
					((IExecAction*)pAction)->get_Arguments(&temp);
					log(3, L"🔈bstr_to_wstring arguments");
					a.arguments = bstr_to_wstring(temp);
					log(3, L"🔈replaceAll arguments");
					a.arguments = replaceAll(a.arguments, L"\\", L"\\\\");
					a.arguments = replaceAll(a.arguments, L"\"", L"\\\"");
				}
				if (a.type == TASK_ACTION_COM_HANDLER) {
					log(3, L"🔈get_ClassId pAction");
					((IComHandlerAction*)pAction)->get_ClassId(&temp);
					a.classId = bstr_to_wstring(temp);
					log(3, L"🔈get_Data pAction");
					((IComHandlerAction*)pAction)->get_Data(&temp);
					log(3, L"🔈bstr_to_wstring data");
					a.data = bstr_to_wstring(temp);
				}
				pActions.push_back(a);
				pAction->Release();
				pDisp->Release();
			}
			VariantClear(&var);
			VariantInit(&var);
			hr = pEnum->Next(1, &var, &lFetch);
		}

		//Triggers
		//Liste des actions
		log(3, L"🔈get_Triggers ppDefinition");
		ppDefinition->get_Triggers(&pTriggerCollection);

		// Get the Enumerator object on the collection object.
		log(3, L"🔈get__NewEnum pTriggerCollection");
		pTriggerCollection->get__NewEnum(&ppEnum);
		log(3, L"🔈QueryInterface ppEnum");
		ppEnum->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);

		// Enumerate the collection.
		VariantInit(&var);
		log(3, L"🔈Next pEnum");
		hr = pEnum->Next(1, &var, &lFetch);
		while (hr == S_OK)
		{
			if (lFetch == 1)
			{
				ITrigger* pTrigger;
				Trigger trigger;
				pDisp = V_DISPATCH(&var);
				log(3, L"🔈QueryInterface pDisp");
				pDisp->QueryInterface(IID_ITrigger, (void**)&pTrigger);
				IRepetitionPattern* pattern;
				log(3, L"🔈get_Repetition pTrigger");
				pTrigger->get_Repetition(&pattern);
				log(3, L"🔈get_Interval interval");
				pattern->get_Interval(&temp);
				log(3, L"🔈bstr_to_wstring interval");
				trigger.interval = bstr_to_wstring(temp);
				log(3, L"🔈get_Type trigger");
				pTrigger->get_Type(&trigger.type);

				triggers.push_back(trigger);
				pTrigger->Release();
				pDisp->Release();
			}
			VariantClear(&var);
			VariantInit(&var);
			hr = pEnum->Next(1, &var, &lFetch);
		}

		if (pEnum) pEnum->Release();
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈Scheduled task");
		std::wstring result = tab(1) + L"{\n"
			+ tab(2) + L"\"Name\":\"" + pName + L"\",\n"
			+ tab(2) + L"\"Description\":\"" + pDescription + L"\",\n"
			+ tab(2) + L"\"Author\":\"" + pAuthor + L"\",\n"
			+ tab(2) + L"\"Enabled\":\"" + bool_to_wstring(pEnabled) + L"\",\n"
			+ tab(2) + L"\"RunAs\":\"" + pRunAs + L"\",\n"
			+ tab(2) + L"\"RunAsSID\":\"" + runAsSid + L"\",\n"
			+ tab(2) + L"\"Path\":\"" + escapedPath + L"\",\n"
			+ tab(2) + L"\"State\":\"" + task_state(pState) + L"\",\n"
			+ tab(2) + L"\"LastRun\":\"" + time_to_wstring(pLastRunTime) + L"\",\n"
			+ tab(2) + L"\"LastRunUtc\":\"" + time_to_wstring(pLastRunTimeUtc) + L"\",\n"
			+ tab(2) + L"\"NextRun\":\"" + time_to_wstring(pNextRunTime) + L"\",\n"
			+ tab(2) + L"\"NextRunUtc\":\"" + time_to_wstring(pNextRunTimeUtc) + L"\",\n"
			+ tab(2) + L"\"LastTaskResult\":\"" + std::to_wstring(pLastTaskResult) + L"\",\n"
			+ tab(2) + L"\"NumberOfMissedRuns\":\"" + std::to_wstring(pNumberOfMissedRuns) + L"\",\n"
			+ tab(2) + L"\"Actions\": [\n";

		std::vector<Action>::iterator it;
		for (it = pActions.begin(); it != pActions.end(); it++) {
			result += tab(3) + L"{\n";
			if (it->type == TASK_ACTION_EXEC) {
				log(3, L"🔈task_action_type");
				result += tab(4) + L"\"Type\":\"" + task_action_type(it->type) + L"\",\n";
				result += tab(4) + L"\"Md5\":\"" + it->md5 + L"\",\n";
				result += tab(4) + L"\"Command\":\"" + it->command + L"\",\n";
				result += tab(4) + L"\"Arguments\":\"" + it->arguments + L"\"\n";
			}
			else if (it->type == TASK_ACTION_COM_HANDLER) {
				log(3, L"🔈task_action_type");
				result += tab(4) + L"\"Type\":\"" + task_action_type(it->type) + L"\",\n";
				result += tab(4) + L"\"ClassId\":\"" + it->classId + L"\",\n";
				log(3, L"🔈trans_guid_to_wstring classId");
				std::wstring temp = trans_guid_to_wstring(it->classId);
				log(3, L"🔈replaceAll classId Name");
				temp = replaceAll(temp, L"\\", L"\\\\");
				temp = replaceAll(temp, L"\"", L"\\\"");
				result += tab(4) + L"\"ClassId Name\":\"" + temp + L"\",\n";
				result += tab(4) + L"\"data\":\"" + it->data + L"\"\n";
			}
			else {
				log(3, L"🔈task_action_type");
				result += tab(4) + L"\"Type\":\"" + task_action_type(it->type) + L"\"\n";
			}

			result += tab(3) + L"}";
			if (it != pActions.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(2) + L"],\n"
		+tab(2) + L"\"Triggers\": [\n";

		std::vector<Trigger>::iterator it2;
		for (it2 = triggers.begin(); it2 != triggers.end(); it2++) {
			result += tab(3) + L"{\n";
			if (it2->type == TASK_TRIGGER_TIME) {
				log(3, L"🔈task_trigger_type");
				result += tab(4) + L"\"Type\":\"" + task_trigger_type(it2->type) + L"\",\n"
					+ tab(4) + L"\"Interval\":\"" + it2->interval + L"\"\n";
			}
			else {
				log(3, L"🔈task_trigger_type");
				result += tab(4) + L"\"Type\":\"" + task_trigger_type(it2->type) + L"\"\n";
			}
			result += tab(3) + L"}";
			if (it2 != triggers.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(2) + L"]\n";


		result += tab(1) + L"}";

		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Scheduled task clear");
		for (Trigger temp : triggers)
			temp.clear();
	}
};

/*! structure contenant l'ensemble des artefacts
*/
struct ScheduledTasks {
	std::vector<ScheduledTask> scheduledTasks; //!< tableau contenant tout les ScheduledTask

	/*! Fonction permettant de parcourir les taches planifiées d'un dossier
	* @param pRootFolder est le dossier à parcourir
	* @pService est le service de tâches planifiées
	*/
	HRESULT getTasks(ITaskFolder* pfolder, ITaskService* pService) {
		
		//  -------------------------------------------------------
		//  Get the registered tasks in the folder.
		IRegisteredTaskCollection* pTaskCollection = NULL;
		log(3, L"🔈GetTasks pTaskCollection");
		HRESULT hr = pfolder->GetTasks(NULL, &pTaskCollection);
		if (hr != S_OK)
		{
			log(2, L"🔥GetTasks pTaskCollection", hr);
			return hr;
		}

		LONG numTasks = 0;
		log(3, L"🔈get_Count numTasks");
		hr = pTaskCollection->get_Count(&numTasks);
		TASK_STATE taskState;
		for (LONG i = 1; i <= numTasks; i++)
		{
			IRegisteredTask* pRegisteredTask = NULL;
			log(3, L"🔈get_Item pRegisteredTask");
			hr = pTaskCollection->get_Item(_variant_t(i), &pRegisteredTask);
			if (SUCCEEDED(hr))
			{
				log(1, L"➕ScheduledTask");
				ScheduledTask s = ScheduledTask(pRegisteredTask);
				scheduledTasks.push_back(s);
			}
			else {
				log(2, L"🔥get_Item pRegisteredTask", hr);
				continue;
			}
			pRegisteredTask->Release();
		}
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parcourir les dossiers contenant des taches planifiées
	* @param folder est le dossier à parcourir
	* @pService est le service de tâches planifiées
	*/
	HRESULT getFolders(std::wstring folder, ITaskService* pService) {
		ITaskFolder* pFolder = NULL;
		ITaskFolderCollection* pRootFoldersCollection = NULL;
		HRESULT hr=0;

		log(3, L"🔈wstring_to_bstr pRootFolder");
		BSTR bstrRootFolder = wstring_to_bstr(folder);

		log(3, L"🔈GetFolder pRootFolder");
		hr = pService->GetFolder(bstrRootFolder, &pFolder);
		if (SUCCEEDED(hr)) {
			log(3, L"🔈getTasks pRootFolder");
			hr = getTasks(pFolder, pService);
			if (SUCCEEDED(hr)) {
				// on récupère tous les sous-repertoires
				log(3, L"🔈GetFolders pRootFoldersCollection");
				hr = pFolder->GetFolders(0, &pRootFoldersCollection);
				if (SUCCEEDED(hr)) {
					LONG numFolders = 0;
					log(3, L"🔈get_Count pRootFoldersCollection");
					hr = pRootFoldersCollection->get_Count(&numFolders);
					if (SUCCEEDED(hr)) {
						for (LONG i = 1; i <= numFolders; i++)
						{
							log(3, L"🔈get_Item pRootFoldersCollection");
							hr = pRootFoldersCollection->get_Item(_variant_t(i), &pFolder);
							if (SUCCEEDED(hr)) {
								BSTR bstr;
								std::wstring finale;
								log(3, L"🔈get_Name pFolder");
								pFolder->get_Name(&bstr);

								//concatenation
								log(3, L"🔈bstr_to_wstring finale");
								finale = folder + L"\\" + bstr_to_wstring(bstr);

								log(3, L"🔈getFolders finale");
								getFolders(finale, pService);
							}
						}
					}
					else {
						log(2, L"🔥get_Count pRootFoldersCollection", hr);
					}
				}
				else {
					log(2, L"🔥GetFolders pRootFolder", hr);
				}
			}
			else {
				log(2, L"🔥getTasks pRootFolder", hr);
			}
		} else{
			log(2, L"🔥GetFolder pRootFolder", hr);
			return hr;
		}
		pFolder->Release();
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		HRESULT hr=0;

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Scheduled tasks : ");
		log(0, L"*******************************************************************************************************************");

		//  ------------------------------------------------------
		//  Create an instance of the Task Service. 
		ITaskService* pService = NULL;
		log(3, L"🔈CoCreateInstance");
		hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService); 
		if (hr!=S_OK)
		{
			log(2, L"🔥CoCreateInstance", hr);
			return hr;
		}
		
		//  Connect to the task service.CLSID_TaskScheduler
		log(3, L"🔈Connect pService");
		hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
		if (hr!=S_OK)
		{
			log(2, L"🔥Connect pService", hr);
			return hr;
		}
		//  ------------------------------------------------------
		//  Get the folders list 
		ITaskFolder* pRootFolder = NULL;
		log(3, L"🔈getFolders");
		getFolders(L"", pService);

		pService->Release();
		return ERROR_SUCCESS;
	}
	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		std::wofstream myfile;
		std::wstring result = L"[\n";
		std::vector<ScheduledTask>::iterator it;
		for (it = scheduledTasks.begin(); it != scheduledTasks.end(); it++) {

			result += it->to_json();
			if (it != scheduledTasks.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"]";
		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(conf._outputDir + "/ScheduledTasks.json");
		log(3, L"🔈ansi_to_utf8 result");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈scheduled tasks clear");
		for (ScheduledTask temp : scheduledTasks)
			temp.clear();
	}
};

