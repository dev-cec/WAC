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
#include <comdef.h>
#include <sddl.h>
#include <lmerr.h>
#include "tools.h"
#include "trans_id.h"


/*structure représentant une trigger d'une tâche planifiée
*/
struct Trigger {
	TASK_TRIGGER_TYPE2 type; //!< type de trigger pour l’exécution de la tâche
	BSTR interval=BSTR(L"");//!< délai entre 2 exécution
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

		HRESULT hr = task->get_Definition(&ppDefinition);
		hr = task->get_Enabled(&pEnabled);
		hr = task->get_LastRunTime(&tempD);
		//conversion de DATE en FILETIME
		VariantTimeToSystemTime(tempD, &tempST);
		SystemTimeToFileTime(&tempST, &pLastRunTime);
		LocalFileTimeToFileTime(&pLastRunTime, &pLastRunTimeUtc);

		hr = task->get_LastTaskResult(&pLastTaskResult);
		hr = task->get_Name(&pName);
		hr = task->get_NextRunTime(&tempD);

		ppDefinition->get_RegistrationInfo(&infos);
		infos->get_Author(&pAuthor);
		infos->get_Description(&pDescription);

		ppDefinition->get_Principal(&principal);
		principal->get_UserId(&pRunAs);
		LPUSER_INFO_4 info4 = NULL;
		LPWSTR temp = NULL;
		std::wstring SID = L"";
		//get SID of user
		if (pRunAs != BSTR(L"")) {
			if(NetUserGetInfo(NULL, bstr_to_wstring(pRunAs).c_str(), 4, (LPBYTE*)&info4) == NERR_Success){
				ConvertSidToStringSidW(info4->usri4_user_sid, &temp);
				runAsSid = std::wstring(temp);
			}
		}

		//conversion de DATE en FILETIME
		VariantTimeToSystemTime(tempD, &tempST);
		SystemTimeToFileTime(&tempST, &pNextRunTime);
		LocalFileTimeToFileTime(&pNextRunTime, &pNextRunTimeUtc);

		hr = task->get_NumberOfMissedRuns(&pNumberOfMissedRuns);
		hr = task->get_Path(&pPath);
		escapedPath = bstr_to_wstring(pPath);//escape
		hr = task->get_State(&pState);

		//Liste des actions
		ppDefinition->get_Actions(&pActionCollection);

		// Get the Enumerator object on the collection object.
		pActionCollection->get__NewEnum(&ppEnum);
		ppEnum->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);

		// Enumerate the collection.
		VariantInit(&var);
		hr = pEnum->Next(1, &var, &lFetch);
		while (hr == S_OK)
		{
			if (lFetch == 1)
			{
				Action a;
				pDisp = V_DISPATCH(&var);
				pDisp->QueryInterface(IID_IAction, (void**)&pAction);
				pAction->get_Type(&a.type);
				if (a.type == TASK_ACTION_EXEC) {
					((IExecAction*)pAction)->get_Path(&a.command);
					a.command_escaped = bstr_to_wstring(a.command);
					((IExecAction*)pAction)->get_Arguments(&a.arguments);
					a.arguments_escaped = bstr_to_wstring(a.arguments);
				}
				if (a.type == TASK_ACTION_COM_HANDLER) {
					((IComHandlerAction*)pAction)->get_ClassId(&a.classId);
					((IComHandlerAction*)pAction)->get_Data(&a.data);
					a.arguments_escaped = bstr_to_wstring(a.arguments);
				}
				pActions.push_back(a);
				pAction->Release();
				pAction = NULL;
				pDisp->Release();
				pDisp = NULL;
			}
			VariantClear(&var);
			VariantInit(&var);
			hr = pEnum->Next(1, &var, &lFetch);
		}

		//Triggers
		//Liste des actions
		ppDefinition->get_Triggers(&pTriggerCollection);

		// Get the Enumerator object on the collection object.
		pTriggerCollection->get__NewEnum(&ppEnum);
		ppEnum->QueryInterface(IID_IEnumVARIANT, (void**)&pEnum);

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
				pDisp->QueryInterface(IID_ITrigger, (void**)&pTrigger);
				IRepetitionPattern* pattern;
				pTrigger->get_Repetition(&pattern);
				pattern->get_Interval(&trigger.interval);
				pTrigger->get_Type(&trigger.type);
				triggers.push_back(trigger);
				pTrigger->Release();
				pTrigger = NULL;
				pDisp->Release();
				pDisp = NULL;
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
		+tab(2) + L"\"Triggers\": [\n";

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
};

/*! structure contenant l'ensemble des artefacts
*/
struct ScheduledTasks {
	std::vector<ScheduledTask> scheduledTasks; //!< tableau contenant tout les ScheduledTask
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	HRESULT getFolders(std::vector<BSTR>* folders, BSTR folder, ITaskService* pService) {
		ITaskFolder* pRootFolder = NULL;
		ITaskFolderCollection* pRootFoldersCollection = NULL;
		HRESULT hr;
		folders->push_back(folder);
		hr = pService->GetFolder(_bstr_t(folder), &pRootFolder);
		if (FAILED(hr))
		{
			errors.push_back({ L"Unable to get folder pointer", hr });
			
			return ERROR_UNIDENTIFIED_ERROR;
		}
		pRootFolder->GetFolders(0, &pRootFoldersCollection);
		pRootFolder->Release();
		// on récupère tous les sous-repertoires
		LONG numFolders = 0;
		hr = pRootFoldersCollection->get_Count(&numFolders);
		for (LONG i = 1; i <= numFolders; i++)
		{
			hr = pRootFoldersCollection->get_Item(_variant_t(i), &pRootFolder);
			BSTR bstr, finale;
			pRootFolder->get_Name(&bstr);
			//concatenation
			finale = bstr_concat(folder, bstr_t(L"\\"));
			finale = bstr_concat(finale, bstr);
			getFolders(folders, finale, pService);
		}
		return ERROR_SUCCESS;
	}

	/*! Fonction permettant de parser les objets
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	*/
	HRESULT getData(AppliConf conf) {
		_conf = conf;
		HRESULT hr;

		//  ------------------------------------------------------
		//  Create an instance of the Task Service. 
		ITaskService* pService = NULL;

		hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService); 
		if (hr!=S_OK)
		{
			errors.push_back({ L"Failed to co-create an instance of the TaskService class", hr });
			return hr;
		}
		
		//  Connect to the task service.CLSID_TaskScheduler
		hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
		if (hr!=S_OK)
		{
			errors.push_back({ L"Failed to connect to ITaskService", hr });
			pService->Release();
			return hr;
		}
		//  ------------------------------------------------------
		//  Get the folders list 
		ITaskFolder* pRootFolder = NULL;
		std::vector<BSTR> folders; // continent la liste des repertoires
		getFolders(&folders, _bstr_t(L""), pService);

		//Pour chaque repertoire
		for (BSTR f : folders) {
			hr = pService->GetFolder(_bstr_t(f), &pRootFolder);
			
			if (hr!=S_OK)
			{
				errors.push_back({ L"Unable to get folder pointer", hr });
				return hr;
			}
			//  -------------------------------------------------------
			//  Get the registered tasks in the folder.
			IRegisteredTaskCollection* pTaskCollection = NULL;
			hr = pRootFolder->GetTasks(NULL, &pTaskCollection);
			pRootFolder->Release();
			if (hr != S_OK)
			{
				errors.push_back({ L"Unable to get saved tasks", hr });
				
				return 1;
			}
			LONG numTasks = 0;
			hr = pTaskCollection->get_Count(&numTasks);

			TASK_STATE taskState;
			for (LONG i = 1; i <= numTasks; i++)
			{
				IRegisteredTask* pRegisteredTask = NULL;
				hr = pTaskCollection->get_Item(_variant_t(i), &pRegisteredTask);

				if (SUCCEEDED(hr))
				{
					ScheduledTask s = ScheduledTask(pRegisteredTask, f);
					scheduledTasks.push_back(s);
				}
			}
		}
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
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(_conf._outputDir + "/ScheduledTasks.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir + "/ScheduledTasks_errors.txt");
			myfile << result;
			myfile.close();
		}
		return ERROR_SUCCESS;
	}
};

