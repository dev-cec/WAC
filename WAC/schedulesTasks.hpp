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


/*structure repr�sentant une trigger d'une t�che planifi�e
*/
struct Trigger {
	TASK_TRIGGER_TYPE2 type; //!< type de trigger pour l�ex�cution de la t�che
	BSTR interval=BSTR(L"");//!< d�lai entre 2 ex�cution
};
/*structure repr�sentant une action d'une t�che planifi�e
*/
struct Action {
	TASK_ACTION_TYPE type; //!< type de l'action au format num�rique
	BSTR command = BSTR(L"");//!< ligne de commande ex�cut�e
	std::wstring command_escaped = L"";//!< ligne de commande ex�cut�e
	BSTR arguments = BSTR(L"");//!< arguments de la ligne de commande ex�cut�e
	std::wstring arguments_escaped = L"";//!< arguments de la ligne de commande ex�cut�e
	BSTR classId = BSTR(L"");//!< classId pour ACTION COM HANDLER
	BSTR data = BSTR(L"");//!< data pour ACTION COM HANDLER
};

/*structure repr�sentant une t�che planifi�e
* Documentation : https://learn.microsoft.com/fr-fr/windows/win32/api/taskschd/nn-taskschd-iregisteredtask
* Documentation : https://learn.microsoft.com/fr-fr/windows/win32/api/taskschd/nn-taskschd-itaskdefinition
*/
struct ScheduledTask {
	ITaskDefinition* ppDefinition = NULL;//!< la d�finition de la t�che.
	VARIANT_BOOL pEnabled = false; //!< valeur bool�enne qui indique si la t�che inscrite est activ�e.
	FILETIME pLastRunTime = { 0 }; //!< heure � laquelle la t�che inscrite a �t� ex�cut�e pour la derni�re fois.
	FILETIME pLastRunTimeUtc = { 0 }; //!< heure � laquelle la t�che inscrite a �t� ex�cut�e pour la derni�re fois au format UTC.
	LONG pLastTaskResult = 0; //!< les r�sultats qui ont �t� retourn�s lors de la derni�re ex�cution de la t�che inscrite.
	BSTR pName = BSTR(L""); //!< le nom de la t�che inscrite.
	FILETIME pNextRunTime = { 0 }; //!< l�heure � laquelle l�ex�cution prochaine de la t�che inscrite est planifi�e.
	FILETIME pNextRunTimeUtc = { 0 }; //!< l�heure � laquelle l�ex�cution prochaine de la t�che inscrite est planifi�e au format UTC.
	LONG pNumberOfMissedRuns = 0; //!< le nombre de fois o� la t�che inscrite a manqu� une ex�cution planifi�e.
	BSTR pPath = BSTR(L"");//!<  le chemin d�acc�s � l�emplacement o� la t�che inscrite est stock�e.
	std::wstring escapedPath = L"";//!<  le chemin d�acc�s � l�emplacement o� la t�che inscrite est stock�e.
	TASK_STATE pState; //!< L��tat op�rationnel de la t�che inscrite.
	std::vector<Action> pActions; //!< Contient les actions effectu�es par la t�che..
	BSTR pAuthor = BSTR(L"");//!< cr�ateur de la t�che planifi�e
	BSTR pDescription = BSTR(L"");//!< description de la t�che planifi�e
	BSTR pRunAs = BSTR(L"");//!< compte utilis� pour ex�cut�e la t�che
	std::wstring runAsSid = L"";//!< SID du compte utilis� pour ex�cut�e la t�che
	std::vector<Trigger> triggers;//!< triggers de a t�che planifi�e
	/*! Constructeur
	* @param task est une t�che planifi�e au format virtuel IRegisteredTask. Ce format �tant complexe � manipuler on en extrait les infos qui nous int�ressent.
	* @param pfolder est le sous-repertoire contenant la t�che planifi�e
	*/
	ScheduledTask(IRegisteredTask* task, BSTR pFolder) {
		IActionCollection* pActionCollection = NULL; // Ensemble des actions
		IUnknown* ppEnum = NULL; // pour it�rer la collection
		IEnumVARIANT* pEnum = NULL; // pour it�rer la collection
		VARIANT var; // pour it�rer la collection
		ULONG lFetch = 0; // pour it�rer la collection
		IAction* pAction = NULL; // pour it�rer la collection
		IDispatch* pDisp = NULL; // pour it�rer la collection
		TASK_ACTION_TYPE pType; // pour it�rer la collection
		DATE tempD; // pour it�rer la collection
		SYSTEMTIME tempST; // pour it�rer la collection
		IRegistrationInfo* infos;// pour it�rer la collection
		IPrincipal* principal;// pour it�rer la collection
		ITriggerCollection* pTriggerCollection;// pour it�rer la collection

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
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remont�es lors du traitement des objets
	AppliConf _conf = {0};//! contient les param�tres de l'application issue des param�tres de la ligne de commande

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
		// on r�cup�re tous les sous-repertoires
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
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
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
		std::filesystem::create_directory(_conf._outputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
		myfile.open(_conf._outputDir + "/ScheduledTasks.json");
		myfile << result;
		myfile.close();

		if (_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //cr�e le repertoire, pas d'erreur s'il existe d�j�
			myfile.open(_conf._errorOutputDir + "/ScheduledTasks_errors.txt");
			myfile << result;
			myfile.close();
		}
		return ERROR_SUCCESS;
	}
};

