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

/*structure représentant une trigger d'une tâche planifiée
*/
struct Trigger {

	TASK_TRIGGER_TYPE2 type; //!< type de trigger pour l’exécution de la tâche
	BSTR interval = BSTR(L"");//!< délai entre 2 exécution

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Trigger clear");
	}
};
/*structure représentant une action d'une tâche planifiée
*/
struct Action {
	TASK_ACTION_TYPE type; //!< type de l'action au format numérique
	BSTR command = BSTR(L"");//!< ligne de commande exécutée
	std::wstring command_escaped = L"";//!< ligne de commande exécutée
	BSTR arguments = BSTR(L"");//!< arguments de la ligne de commande exécutée
	std::wstring arguments_escaped = L"";//!< arguments de la ligne de commande exécutée
	BSTR classId = BSTR(L"");//!< classId pour ACTION COM HANDLER
	BSTR data = BSTR(L"");//!< data pour ACTION COM HANDLER

	/*liberation mémoire */
	void clear() {
		log(3, L"🔈Action clear");
	}
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
	BSTR pPath = BSTR(L"");//!<  le chemin d’accès à l’emplacement où la tâche inscrite est stockée.
	std::wstring escapedPath = L"";//!<  le chemin d’accès à l’emplacement où la tâche inscrite est stockée.
	TASK_STATE pState; //!< L’état opérationnel de la tâche inscrite.
	std::vector<Action> pActions; //!< Contient les actions effectuées par la tâche..
	BSTR pAuthor = BSTR(L"");//!< créateur de la tâche planifiée
	BSTR pDescription = BSTR(L"");//!< description de la tâche planifiée
	BSTR pRunAs = BSTR(L"");//!< compte utilisé pour exécutée la tâche
	std::wstring runAsSid = L"";//!< SID du compte utilisé pour exécutée la tâche
	std::vector<Trigger> triggers;//!< triggers de a tâche planifiée
	/*! Constructeur
	* @param task est une tâche planifiée au format virtuel IRegisteredTask. Ce format étant complexe à manipuler on en extrait les infos qui nous intéressent.
	* @param pfolder est le sous-repertoire contenant la tâche planifiée
	*/
	ScheduledTask(IRegisteredTask* task, BSTR pFolder) {
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
		HRESULT hr = 0;
		LPUSER_INFO_4 info4 = NULL;
		LPWSTR temp = NULL;

		log(1, L"➕ Scheduled task ");
		hr = task->get_Name(&pName);
		log(2, L"❇️ Scheduled task name : " + bstr_to_wstring(pName));
		hr = task->get_Enabled(&pEnabled);
		hr = task->get_LastRunTime(&tempD);

		//conversion de DATE en FILETIME
		log(3, L"🔈VariantTimeToSystemTime");
		VariantTimeToSystemTime(tempD, &tempST);
		log(3, L"🔈SystemTimeToFileTime");
		SystemTimeToFileTime(&tempST, &pLastRunTime);
		log(3, L"🔈LocalFileTimeToFileTime");
		LocalFileTimeToFileTime(&pLastRunTime, &pLastRunTimeUtc);

		hr = task->get_LastTaskResult(&pLastTaskResult);
		hr = task->get_NextRunTime(&tempD);

		std::wstring SID = L"";
		//get SID of user
		if (pRunAs != BSTR(L"")) {
			log(3, L"🔈NetUserGetInfo");
			if (NetUserGetInfo(NULL, bstr_to_wstring(pRunAs).c_str(), 4, (LPBYTE*)&info4) == NERR_Success) {
				log(3, L"🔈ConvertSidToStringSidW");
				ConvertSidToStringSidW(info4->usri4_user_sid, &temp);
				runAsSid = std::wstring(temp);
				NetApiBufferFree(info4);
			}
			else {
				log(2, L"🔥 NetUserGetInfo", GetLastError());
			}
		}

		//conversion de DATE en FILETIME
		log(3, L"🔈VariantTimeToSystemTime");
		VariantTimeToSystemTime(tempD, &tempST);
		log(3, L"🔈SystemTimeToFileTime");-
		SystemTimeToFileTime(&tempST, &pNextRunTime);
		log(3, L"🔈LocalFileTimeToFileTime");
		LocalFileTimeToFileTime(&pNextRunTime, &pNextRunTimeUtc);

		hr = task->get_NumberOfMissedRuns(&pNumberOfMissedRuns);
		hr = task->get_Path(&pPath);
		log(3, L"🔈bstr_to_wstring pPath");
		escapedPath = bstr_to_wstring(pPath);//escape
		hr = task->get_State(&pState);

		hr = task->get_Definition(&ppDefinition);
		if (SUCCEEDED(hr)) {
			log(3, L"🔈get_RegistrationInfo");
			hr = ppDefinition->get_RegistrationInfo(&infos);
			if (SUCCEEDED(hr)) {
				infos->get_Author(&pAuthor);
				infos->get_Description(&pDescription);
			}
			else {
				log(2, L"🔥 get_RegistrationInfo", hr);
			}
			log(3, L"🔈get_Principal");
			hr = ppDefinition->get_Principal(&principal);
			if (SUCCEEDED(hr)) {
				principal->get_UserId(&pRunAs);
			}
			else {
				log(2, L"🔥 get_Principal", hr);
			}

			//Liste des actions
			log(3, L"🔈get_Actions");
			hr = ppDefinition->get_Actions(&pActionCollection);
			if (SUCCEEDED(hr)) {
				// Get the Enumerator object on the collection object.
				log(3, L"🔈get__NewEnum ppEnum");
				hr = pActionCollection->get__NewEnum(&ppEnum);
				if (SUCCEEDED(hr)) {
					log(3, L"🔈QueryInterface pEnum");
					hr = ppEnum->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);
					if (SUCCEEDED(hr)) {
						// Enumerate the collection.
						VariantInit(&var);
						hr = pEnum->Next(1, &var, &lFetch);
						while (hr == S_OK)
						{
							if (lFetch == 1)
							{
								Action a;
								pDisp = V_DISPATCH(&var);
								log(3, L"🔈QueryInterface pAction");
								hr = pDisp->QueryInterface(IID_IAction, (void**)&pAction);
								if (SUCCEEDED(hr)) {
									pAction->get_Type(&a.type);
									if (a.type == TASK_ACTION_EXEC) {
										((IExecAction*)pAction)->get_Path(&a.command);
										log(3, L"🔈bstr_to_wstring command");
										a.command_escaped = bstr_to_wstring(a.command);
										((IExecAction*)pAction)->get_Arguments(&a.arguments);
										log(3, L"🔈bstr_to_wstring arguments");
										a.arguments_escaped = bstr_to_wstring(a.arguments);
									}
									if (a.type == TASK_ACTION_COM_HANDLER) {
										((IComHandlerAction*)pAction)->get_ClassId(&a.classId);
										((IComHandlerAction*)pAction)->get_Data(&a.data);
										log(3, L"🔈bstr_to_wstring arguments");
										a.arguments_escaped = bstr_to_wstring(a.arguments);
									}
									pActions.push_back(a);
									pAction->Release();
									pDisp->Release();
								}
								else {
									log(2, L"🔥 QueryInterface pAction", hr);
								}
							}
							VariantClear(&var);
							VariantInit(&var);
							hr = pEnum->Next(1, &var, &lFetch);
						}
					}
					else {
						log(2, L"🔥 QueryInterface penum", hr);
					}
				}
				else {
					log(2, L"🔥 get__NewEnum ppEnum", hr);
				}
			}
			else {
				log(2, L"🔥 get_Actions", hr);
			}
			//Triggers
			log(3, L"🔈get_Triggers");
			hr = ppDefinition->get_Triggers(&pTriggerCollection);
			if (SUCCEEDED(hr)) {
				// Get the Enumerator object on the collection object.
				log(3, L"🔈get__NewEnum ppEnum");
				hr = pTriggerCollection->get__NewEnum(&ppEnum);
				if (SUCCEEDED(hr)) {
					log(3, L"🔈QueryInterface pEnum");
					hr = ppEnum->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);
					if (SUCCEEDED(hr)) {
						// Enumerate the collection.
						VariantInit(&var);
						hr = pEnum->Next(1, &var, &lFetch);
						while (hr == S_OK)
						{
							if (lFetch == 1)
							{
								ITrigger* pTrigger;
								Trigger trigger;
								pDisp = V_DISPATCH(&var);
								log(3, L"🔈QueryInterface pTrigger");
								hr = pDisp->QueryInterface(IID_ITrigger, (void**)&pTrigger);
								if (SUCCEEDED(hr)) {
									IRepetitionPattern* pattern;
									pTrigger->get_Repetition(&pattern);
									pattern->get_Interval(&trigger.interval);
									pTrigger->get_Type(&trigger.type);
									triggers.push_back(trigger);
									pTrigger->Release();
									pDisp->Release();
								}
								else {
									log(2, L"🔥 QueryInterface pTrigger", hr);
								}
							}
							VariantClear(&var);
							VariantInit(&var);
							hr = pEnum->Next(1, &var, &lFetch);
						}

						if (pEnum) pEnum->Release();
					}
					else {
						log(2, L"🔥 QueryInterface pEnum", hr);
					}
				}
				else {
					log(2, L"🔥 get__NewEnum ppEnum", hr);
				}
			}
			else {
				log(2, L"🔥 get_Triggers", hr);
			}
		}
		else {
			log(2, L"🔥 get_Definition", hr);
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈to_json");
		std::wstring result = tab(1) + L"{\n"
			+ tab(2) + L"\"Name\":\"" + bstr_to_wstring(pName) + L"\",\n"
			+ tab(2) + L"\"Description\":\"" + bstr_to_wstring(pDescription) + L"\",\n"
			+ tab(2) + L"\"Author\":\"" + bstr_to_wstring(pAuthor) + L"\",\n"
			+ tab(2) + L"\"Enabled\":\"" + bool_to_wstring(pEnabled) + L"\",\n"
			+ tab(2) + L"\"RunAs\":\"" + bstr_to_wstring(pRunAs) + L"\",\n"
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
				result += tab(4) + L"\"Type\":\"" + task_action_type(it->type) + L"\",\n";
				result += tab(4) + L"\"Command\":\"" + it->command_escaped + L"\",\n";
				result += tab(4) + L"\"Arguments\":\"" + it->arguments_escaped + L"\"\n";
			}
			else if (it->type == TASK_ACTION_COM_HANDLER) {
				result += tab(4) + L"\"Type\":\"" + task_action_type(it->type) + L"\",\n";
				result += tab(4) + L"\"ClassId\":\"" + bstr_to_wstring(it->classId) + L"\",\n";
				std::wstring temp = trans_guid_to_wstring(bstr_to_wstring(it->classId));
				temp = replaceAll(temp, L"\\", L"\\\\");
				temp = replaceAll(temp, L"\"", L"\\\"");
				result += tab(4) + L"\"ClassId Name\":\"" + temp + L"\",\n";
				result += tab(4) + L"\"data\":\"" + bstr_to_wstring(it->data) + L"\"\n";
			}
			else
				result += tab(4) + L"\"Type\":\"" + task_action_type(it->type) + L"\"\n";

			result += tab(3) + L"}";
			if (it != pActions.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(2) + L"],\n"
			+ tab(2) + L"\"Triggers\": [\n";

		std::vector<Trigger>::iterator it2;
		for (it2 = triggers.begin(); it2 != triggers.end(); it2++) {
			result += tab(3) + L"{\n";
			if (it2->type == TASK_TRIGGER_TIME) {
				result += tab(4) + L"\"Type\":\"" + task_trigger_type(it2->type) + L"\",\n"
					+ tab(4) + L"\"Interval\":\"" + bstr_to_wstring(it2->interval) + L"\"\n";
			}
			else {
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

	HRESULT getFolders(std::vector<BSTR>* folders, BSTR folder, ITaskService* pService) {
		log(1, L"➕ Folder");
		log(2, L"❇️ Folder Name : Root" + bstr_to_wstring(folder));
		ITaskFolder* pRootFolder = NULL;
		ITaskFolder* pFolder = NULL;
		ITaskFolderCollection* pRootFoldersCollection = NULL;
		HRESULT hr;
		folders->push_back(folder);

		log(3, L"🔈GetFolder");
		hr = pService->GetFolder(_bstr_t(folder), &pRootFolder);
		if (hr != S_OK)
		{
			log(2, L"🔥 GetFolder", hr);
			return hr;
		}
		//  -------------------------------------------------------
		//  Get the registered tasks in the folder.
		IRegisteredTaskCollection* pTaskCollection = NULL;
		log(3, L"🔈GetTasks");
		hr = pRootFolder->GetTasks(NULL, &pTaskCollection);
		if (hr != S_OK)
		{
			log(2, L"🔥 GetTasks", hr);
			return hr;
		}
		LONG numTasks = 0;
		log(3, L"🔈get_Count numTasks");
		hr = pTaskCollection->get_Count(&numTasks);
		if (SUCCEEDED(hr)) {
			TASK_STATE taskState;
			for (LONG i = 1; i <= numTasks; i++)
			{
				IRegisteredTask* pRegisteredTask = NULL;
				log(3, L"🔈get_Item pRegisteredTask");
				hr = pTaskCollection->get_Item(_variant_t(i), &pRegisteredTask);
				if (SUCCEEDED(hr))
				{
					ScheduledTask s = ScheduledTask(pRegisteredTask, folder);
					scheduledTasks.push_back(s);
				}
				else {
					log(2, L"🔥 get_Item pRegisteredTask ", hr);
					continue;
				}
			}
		}
		else {
			log(2, L"🔥 get_Count numTasks", hr);
			return hr;
		}

		// on récupère tous les sous-repertoires
		log(1, L"➕ Subfolders");
		log(3, L"🔈GetFolders pRootFoldersCollection");
		hr = pRootFolder->GetFolders(0, &pRootFoldersCollection);
		if (SUCCEEDED(hr)) {
			LONG numFolders = 0;
			log(3, L"🔈get_Count numFolders");
			hr = pRootFoldersCollection->get_Count(&numFolders);
			if (SUCCEEDED(hr)) {
				for (LONG i = 1; i <= numFolders; i++)
				{
					log(3, L"🔈get_Item pFolder");
					hr = pRootFoldersCollection->get_Item(_variant_t(i), &pFolder);
					if (SUCCEEDED(hr)) {
						BSTR bstr, finale;
						pFolder->get_Name(&bstr);
						//concatenation
						finale = bstr_concat(folder, bstr_t(L"\\"));
						finale = bstr_concat(finale, bstr);
						hr = getFolders(folders, finale, pService);
						if (FAILED(hr))
						{
							log(2, L"getFolders", hr);
							return hr;
						}
					}
					else {
						log(2, L"🔥 get_Item pFolder", hr);
						continue;
					}
				}
			}
			else {
				log(2, L"🔥 get_Count numFolders", hr);
				return hr;
			}

		}
		else {
			log(2, L"🔥 GetFolder pRootFoldersCollection", hr);
			return hr;
		}
		pRootFolder->Release();
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		HRESULT hr;
		ITaskService* pService = NULL;


		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️ Scheduled Tasks :");
		log(0, L"*******************************************************************************************************************");

		//  Create an instance of the Task Service. 
		log(3, L"🔈CoCreateInstance");
		hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
		if (hr != S_OK)
		{
			log(2, L"🔥 CoCreateInstance", hr);
			return hr;
		}

		log(3, L"🔈Connect pService");
		//  Connect to the task service.CLSID_TaskScheduler
		hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
		if (hr != S_OK)
		{
			log(2, L"🔥 Connect pService", hr);
			return hr;
		}
		//  ------------------------------------------------------
		//  Get the folders list 
		ITaskFolder* pRootFolder = NULL;
		std::vector<BSTR> folders; // continent la liste des repertoires
		hr = getFolders(&folders, _bstr_t(L""), pService);
		pService->Release();
		if (FAILED(hr)) {
			log(2,L"getFolders", hr);
			return hr;
		}
		pService->Release();
		return ERROR_SUCCESS;
	}
	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈to_json");
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
		myfile << result;
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Scheduled tasks clear");
		for (ScheduledTask temp : scheduledTasks)
			temp.clear();
	}
};

