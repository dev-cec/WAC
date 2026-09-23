#include "services.h"
#include <algorithm>

namespace {

/*  `cheminBinaire` a rejoint tools : la resolution des prefixes de chemins
 *  Windows (\SystemRoot\, %SystemRoot%\, \??\) sert aussi a localiser les
 *  fichiers de ressources des fournisseurs d'evenements (cf. event_messages.cpp).
 */

/*! Empreintes d'un fichier désigné par la ruche.
*
* Près de 200 des 697 services d'une machine Windows 11 pointent sur
* `svchost.exe` : EmpreinteFichier ne lit chaque fichier qu'une fois pour toute
* la collecte, quel que soit le nombre d'artefacts qui le citent.
*/
BinaryFingerprint binaryFingerprint(const std::wstring& hiveValue) {
	if (!conf.binary || hiveValue.empty()) return BinaryFingerprint();
	return FingerprintFile(binaryPath(hiveValue));
}

/*! Relève l'état courant de tous les services en UNE énumération.
*
*  POURQUOI UNE SEULE FOIS. La version d'origine ouvrait un handle par service
*  (`OpenServiceW`, et de surcroît avec `SC_MANAGER_ALL_ACCESS` alors qu'un droit
*  de lecture suffisait — ce qui faisait échouer la lecture sur les services
*  protégés). Ici le SCM est interrogé une fois, en lecture seule, et
*  l'appariement se fait en mémoire.
*
*  @param etats reçoit l'état indexé par nom de service en minuscules
*  @return ERROR_SUCCESS si l'énumération a abouti
*/
HRESULT readLiveStates(std::map<std::wstring, ServiceState>& states) {
	log(3, L"🔈OpenSCManager");
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
	if (!hSCM) {
		const HRESULT error = GetLastError();
		log(2, L"🔥OpenSCManager : etat courant des services non releve", error);
		return error;
	}

	HRESULT result = ERROR_SUCCESS;
	DWORD neededBytes = 0, count = 0;
	log(3, L"🔈EnumServicesStatusExW (dimensionnement)");
	EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
	                      SERVICE_STATE_ALL, NULL, 0, &neededBytes, &count, 0, NULL);
	if (neededBytes == 0) {
		CloseServiceHandle(hSCM);
		return ERROR_SUCCESS;   // aucun service : pas une erreur
	}

	std::vector<BYTE> buffer(neededBytes);
	DWORD rest = 0;
	log(3, L"🔈EnumServicesStatusExW");
	if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
	                          SERVICE_STATE_ALL, buffer.data(), (DWORD)buffer.size(),
	                          &rest, &count, 0, NULL)) {
		const LPENUM_SERVICE_STATUS_PROCESS list = (LPENUM_SERVICE_STATUS_PROCESS)buffer.data();
		for (DWORD i = 0; i < count; ++i) {
			if (!list[i].lpServiceName) continue;
			ServiceState e;
			e.status    = serviceState_to_wstring(list[i].ServiceStatusProcess.dwCurrentState);
			e.processId = list[i].ServiceStatusProcess.dwProcessId;
			states.emplace(toLower(list[i].lpServiceName), e);
		}
		log(2, L"❇️Etat courant releve pour " + std::to_wstring(states.size()) + L" services");
	}
	else {
		result = GetLastError();
		log(2, L"🔥EnumServicesStatusExW", result);
	}
	CloseServiceHandle(hSCM);
	return result;
}

/*! Ajoute une valeur qui peut être un texte, une référence de ressource MUI, ou
* une référence de fichier INF portant son propre libellé de repli.
*
* Le nom du champ dit de quoi il s'agit : `<nom>` pour un texte exploitable,
* `<nom>Resource` pour la référence brute — les deux à la fois quand la valeur
* contient l'un et l'autre.
*
* Les pilotes déclarent leur nom sous la forme
* `@disk.inf,%disk_ServiceDesc%;Disk Driver` : Windows y place lui-même, après
* le point-virgule, le libellé à utiliser si le fichier INF n'est pas
* disponible. Ce repli est du texte utilisable et il serait absurde de le
* jeter — il concerne la quasi-totalité des ~400 pilotes de la ruche.
*/
void addTextOrResource(Json& o, const std::wstring& name, const std::wstring& value) {
	if (value.empty()) return;
	if (value.front() != L'@') {              // texte direct
		o.add(name.c_str(), Json::str(value));
		return;
	}
	const size_t pointVirgule = value.rfind(L';');
	if (pointVirgule != std::wstring::npos && pointVirgule + 1 < value.size())
		o.add(name.c_str(), Json::str(value.substr(pointVirgule + 1)));
	o.add((name + L"Resource").c_str(), Json::str(value));
}

} // namespace

Json ServiceStruct::toJson() const {
	log(3, L"🔈service toJson");
	Json o = Json::obj();
	o.add(L"Name",        Json::str(serviceName));
	/* `DisplayName` et `Description` sont, pour la quasi-totalite des services
	   systeme, des references de ressource MUI (« @schedsvc.dll,-100 ») que seul
	   un chargement de module resoudrait. Elles sont donc restituees dans un
	   champ qui dit ce qu'elles sont, plutot que presentees comme des noms.
	   `Name` reste l'identifiant exploitable : c'est celui qu'emploient les
	   journaux et les commandes. */
	addTextOrResource(o, L"DisplayName", serviceDisplayName);
	addTextOrResource(o, L"Description", serviceDescription);
	o.add(L"Type",        Json::str(serviceType));
	o.add(L"StartType",   Json::str(serviceStartType));
	if (!serviceErrorControl.empty()) o.add(L"ErrorControl", Json::str(serviceErrorControl));
	/* Un pilote n'a pas de compte d'execution : `Owner` vide est un fait, pas
	   une lecture manquee — il n'est donc pas emis. */
	if (!serviceOwner.empty())  o.add(L"Owner",  Json::str(serviceOwner));
	if (!serviceBinary.empty()) o.add(L"Binary", Json::str(serviceBinary));   // valeur BRUTE
	addFingerprints(o, serviceFingerprint);

	/* Pour un service hébergé dans svchost.exe, `Binary` ne nomme que svchost :
	   la DLL est le code réellement exécuté. Émise seulement si elle existe,
	   pour que sa présence signale un service hébergé. */
	if (!serviceDll.empty()) {
		o.add(L"ServiceDll", Json::str(serviceDll));
		addFingerprints(o, serviceDllFingerprint, L"ServiceDll");
	}
	// Persistance possible : commande relancée quand le service échoue.
	if (!serviceFailureCommand.empty())
		o.add(L"FailureCommand", Json::str(serviceFailureCommand));
	if (!serviceGroup.empty()) o.add(L"Group", Json::str(serviceGroup));
	if (!dependencies.empty()) {
		Json d = Json::arr();
		for (const std::wstring& dep : dependencies) d.push(Json::str(dep));
		o.add(L"DependOnService", d);
	}

	/* Instant de création ou de dernière modification du service : la donnée que
	   le gestionnaire de services ne fournit pas, et souvent la plus parlante. */
	o.add(L"LastWriteTime",    Json::str(timeToIso8601Local(lastWriteTime)));
	o.add(L"LastWriteTimeUtc", Json::str(timeToIso8601Utc(lastWriteTimeUtc)));

	/* État volatil. Le drapeau accompagne la valeur : sans lui, « arrêté » et
	   « non relevé » se confondraient. */
	o.add(L"LiveStatusAvailable", Json::boolean(stateRead));
	if (stateRead) {
		o.add(L"Status",    Json::str(serviceStatus));
		o.add(L"ProcessId", Json::num(serviceProcessId));
	}
	return o;
}

void ServiceStruct::clear() {
	log(3, L"🔈service clear");
}

HRESULT Services::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Services :");
	log(0, L"*******************************************************************************************************************");

	if (!conf.CurrentControlSet) {
		log(2, L"🔥CurrentControlSet indisponible : services non collectes");
		return ERROR_INVALID_HANDLE;
	}

	ORHKEY hServices = NULL;
	log(3, L"🔈OROpenKey CurrentControlSet\\Services");
	HRESULT hresult = OROpenKey(conf.CurrentControlSet, L"Services", &hServices);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenKey CurrentControlSet\\Services", hresult);
		return hresult;
	}

	DWORD nSubKeys = 0;
	log(3, L"🔈ORQueryInfoKey CurrentControlSet\\Services");
	hresult = ORQueryInfoKey(hServices, NULL, NULL, &nSubKeys, NULL, NULL, NULL,
	                         NULL, NULL, NULL, NULL);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey CurrentControlSet\\Services", hresult);
		ORCloseKey(hServices);
		return hresult;
	}

	// État courant relevé AVANT le parcours : une seule sollicitation du SCM.
	std::map<std::wstring, ServiceState> states;
	const bool statesAvailable = (readLiveStates(states) == ERROR_SUCCESS);

	services.reserve(nSubKeys);
	WCHAR keyName[MAX_KEY_NAME] = L"";
	for (DWORD i = 0; i < nSubKeys; ++i) {
		printProgressStep(L"Service", i + 1, nSubKeys);
		DWORD size = MAX_KEY_NAME;
		log(3, L"🔈OREnumKey Services " + std::to_wstring(i));
		hresult = OREnumKey(hServices, i, keyName, &size, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥OREnumKey Services " + std::to_wstring(i), hresult);
			continue;
		}

		ORHKEY hService = NULL;
		log(3, L"🔈OROpenKey Services\\" + std::wstring(keyName));
		if (OROpenKey(hServices, keyName, &hService) != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey Services\\" + std::wstring(keyName));
			continue;
		}

		ServiceStruct s;
		s.serviceName = keyName;
		log(1, L"➕Service");
		log(2, L"❇️Service name : " + s.serviceName);

		log(3, L"🔈ORQueryInfoKey Services\\" + s.serviceName);
		ORQueryInfoKey(hService, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		               &s.lastWriteTimeUtc);
		log(3, L"🔈utcVersLocalSuspect lastWriteTime");
		utcToSuspectLocal(s.lastWriteTimeUtc, &s.lastWriteTime);

		getRegSzValue(hService, nullptr, L"DisplayName", &s.serviceDisplayName);
		if (s.serviceDisplayName.empty()) s.serviceDisplayName = s.serviceName;
		getRegSzValue(hService, nullptr, L"Description",  &s.serviceDescription);
		getRegSzValue(hService, nullptr, L"ImagePath",    &s.serviceBinary);
		getRegSzValue(hService, nullptr, L"ObjectName",   &s.serviceOwner);
		getRegSzValue(hService, nullptr, L"Group",        &s.serviceGroup);
		getRegSzValue(hService, nullptr, L"FailureCommand", &s.serviceFailureCommand);
		getRegMultiSzValue(hService, nullptr, L"DependOnService", &s.dependencies);

		DWORD value = 0;
		/* `Type` est obligatoire pour tout service enregistre. Certaines
		   sous-cles de `Services` n'en portent pas : ce sont des CONTENEURS de
		   parametres (WinSock2, EventLog\..., Tcpip\Parameters...), pas des
		   services. Les emettre remplissait services.json d'entrees vides, qui
		   se lisent comme des lectures echouees. */
		bool estUnService = false;
		if (getRegDwordValue(hService, nullptr, L"Type", &value) == ERROR_SUCCESS) {
			s.serviceType = serviceType_to_wstring((int)value);
			estUnService = true;
		}
		if (!estUnService) {
			log(2, L"🔈Services\\" + s.serviceName + L" : pas de valeur Type, "
			       L"conteneur de parametres ignore");
			ORCloseKey(hService);
			continue;
		}
		if (getRegDwordValue(hService, nullptr, L"Start", &value) == ERROR_SUCCESS)
			s.serviceStartType = serviceStart_to_wstring((int)value);
		if (getRegDwordValue(hService, nullptr, L"ErrorControl", &value) == ERROR_SUCCESS) {
			/* SERVICE_ERROR_IGNORE=0 … SERVICE_ERROR_CRITICAL=3. Traduit ici
			   plutôt que dans trans_id : quatre valeurs, un seul appelant. */
			PCWSTR labels[] = { L"SERVICE_ERROR_IGNORE", L"SERVICE_ERROR_NORMAL",
			                      L"SERVICE_ERROR_SEVERE", L"SERVICE_ERROR_CRITICAL" };
			s.serviceErrorControl = (value <= 3) ? labels[value]
			                                      : L"SERVICE_ERROR_UNKNOWN";
		}

		// ServiceDll : le code réellement chargé pour un service hébergé.
		getRegSzValue(hService, L"Parameters", L"ServiceDll", &s.serviceDll);

		s.serviceFingerprint    = binaryFingerprint(s.serviceBinary);
		s.serviceDllFingerprint = binaryFingerprint(s.serviceDll);

		// Appariement avec l'état courant, insensible à la casse.
		if (statesAvailable) {
			const auto it = states.find(toLower(s.serviceName));
			if (it != states.end()) {
				s.stateRead      = true;
				s.serviceStatus   = it->second.status;
				s.serviceProcessId = it->second.processId;
			}
		}

		services.push_back(std::move(s));
		ORCloseKey(hService);
	}
	ORCloseKey(hServices);
	log(2, L"❇️" + std::to_wstring(services.size()) + L" services releves dans la ruche");
	return ERROR_SUCCESS;
}

HRESULT Services::toJson() {
	log(3, L"🔈services toJson");
	Json arr = Json::arr();
	for (const ServiceStruct& s : services) arr.push(s.toJson());
	return writeJsonFile("services.json", arr);
}

void Services::clear() {
	log(3, L"🔈services clear");
	services.clear();   // detruit les elements -> libere reellement
}
