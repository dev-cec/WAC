#include "services.h"
#include <algorithm>

namespace {

/*! \file
 *  \brief Services and drivers, read offline from the SYSTEM hive.
 *
 *  `binaryPath` has moved to tools: resolving the Windows path prefixes
 *  (`\SystemRoot\`, `%SystemRoot%\`, `\??\`) also serves to locate the resource files
 *  of the event providers (see event_messages.cpp).
 */

/*! Fingerprints of a file named by the hive.
*
* Nearly 200 of the 697 services of a Windows 11 machine point to
* `svchost.exe`: FingerprintFile reads each file only once for the whole
* collection, whatever the number of artefacts that cite it.
*/
BinaryFingerprint binaryFingerprint(const std::wstring& hiveValue) {
	if (!conf.binary || hiveValue.empty()) return BinaryFingerprint();
	return FingerprintFile(binaryPath(hiveValue));
}

/*! Reads the current state of every service in ONE enumeration.
*
*  WHY ONLY ONCE. The original version opened a handle per service
*  (`OpenServiceW`, and moreover with `SC_MANAGER_ALL_ACCESS` while a read right
*  was enough — which made the reading fail on the protected services). Here the
*  SCM is queried once, read-only, and the matching is done in memory.
*
*  @param states receives the state indexed by service name in lower case
*  @return ERROR_SUCCESS if the enumeration succeeded
*/
HRESULT readLiveStates(std::map<std::wstring, ServiceState>& states) {
	log(3, L"🔈OpenSCManager");
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
	if (!hSCM) {
		const HRESULT error = GetLastError();
		log(2, L"🔥OpenSCManager: current state of the services not read", error);
		return error;
	}

	HRESULT result = ERROR_SUCCESS;
	DWORD neededBytes = 0, count = 0;
	log(3, L"🔈EnumServicesStatusExW (dimensionnement)");
	EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER,
	                      SERVICE_STATE_ALL, NULL, 0, &neededBytes, &count, 0, NULL);
	if (neededBytes == 0) {
		CloseServiceHandle(hSCM);
		return ERROR_SUCCESS;   // no service: not an error
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
		log(2, L"❇️Current state read for " + std::to_wstring(states.size()) + L" services");
	}
	else {
		result = GetLastError();
		log(2, L"🔥EnumServicesStatusExW", result);
	}
	CloseServiceHandle(hSCM);
	return result;
}

/*! Adds a value that may be a text, a MUI resource reference, or a reference to
* an INF file carrying its own fallback label.
*
* The field's name says what it is: `<name>` for a usable text,
* `<name>Resource` for the raw reference — both at once when the value holds
* one and the other.
*
* The drivers declare their name in the form
* `@disk.inf,%disk_ServiceDesc%;Disk Driver`: Windows itself puts there, after
* the semicolon, the label to use if the INF file is not available. That
* fallback is usable text and it would be absurd to throw it away — it concerns
* nearly all of the ~400 drivers of the hive.
*/
void addTextOrResource(Json& o, const std::wstring& name, const std::wstring& value) {
	if (value.empty()) return;
	if (value.front() != L'@') {              // plain text
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
	/* `DisplayName` and `Description` are, for nearly all system services, MUI
	   resource references ("@schedsvc.dll,-100") that only a module load would
	   resolve. They are therefore returned in a field that says what they are,
	   rather than presented as names.
	   `Name` remains the usable identifier: it is the one the logs and the
	   commands use. */
	addTextOrResource(o, L"DisplayName", serviceDisplayName);
	addTextOrResource(o, L"Description", serviceDescription);
	o.add(L"Type",        Json::str(serviceType));
	o.add(L"StartType",   Json::str(serviceStartType));
	if (!serviceErrorControl.empty()) o.add(L"ErrorControl", Json::str(serviceErrorControl));
	/* A driver has no account to run as: an empty `Owner` is a fact, not a failed
	   reading — so it is not emitted. */
	if (!serviceOwner.empty())  o.add(L"Owner",  Json::str(serviceOwner));
	if (!serviceBinary.empty()) o.add(L"Binary", Json::str(serviceBinary));   // RAW value
	addFingerprints(o, serviceFingerprint);

	/* For a service hosted in svchost.exe, `Binary` only names svchost: the DLL
	   is the code really executed. Emitted only if it exists, so that its
	   presence signals a hosted service. */
	if (!serviceDll.empty()) {
		o.add(L"ServiceDll", Json::str(serviceDll));
		addFingerprints(o, serviceDllFingerprint, L"ServiceDll");
	}
	// A possible persistence: a command run again when the service fails.
	if (!serviceFailureCommand.empty())
		o.add(L"FailureCommand", Json::str(serviceFailureCommand));
	if (!serviceGroup.empty()) o.add(L"Group", Json::str(serviceGroup));
	if (!dependencies.empty()) {
		Json d = Json::arr();
		for (const std::wstring& dep : dependencies) d.push(Json::str(dep));
		o.add(L"DependOnService", d);
	}

	/* Instant of the creation or the last modification of the service: the piece
	   of data the service manager does not provide, and often the most
	   telling. */
	o.add(L"LastWriteTime",    Json::str(timeToIso8601Local(lastWriteTime)));
	o.add(L"LastWriteTimeUtc", Json::str(timeToIso8601Utc(lastWriteTimeUtc)));

	/* Volatile state. The flag goes along with the value: without it, "stopped"
	   and "not read" would be confused. */
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
		log(2, L"🔥CurrentControlSet unavailable: services not collected");
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

	// Current state read BEFORE the walk: one single solicitation of the SCM.
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
		log(3, L"🔈utcToSuspectLocal lastWriteTime");
		s.lastWriteTime = utcToSuspectLocal(s.lastWriteTimeUtc);

		getRegSzValue(hService, nullptr, L"DisplayName", &s.serviceDisplayName);
		if (s.serviceDisplayName.empty()) s.serviceDisplayName = s.serviceName;
		getRegSzValue(hService, nullptr, L"Description",  &s.serviceDescription);
		getRegSzValue(hService, nullptr, L"ImagePath",    &s.serviceBinary);
		getRegSzValue(hService, nullptr, L"ObjectName",   &s.serviceOwner);
		getRegSzValue(hService, nullptr, L"Group",        &s.serviceGroup);
		getRegSzValue(hService, nullptr, L"FailureCommand", &s.serviceFailureCommand);
		getRegMultiSzValue(hService, nullptr, L"DependOnService", &s.dependencies);

		DWORD value = 0;
		/* `Type` is mandatory for every registered service. Some subkeys of
		   `Services` do not carry one: they are CONTAINERS of parameters
		   (WinSock2, EventLog\..., Tcpip\Parameters...), not services. Emitting
		   them filled services.json with empty entries, which read as failed
		   readings. */
		bool isService = false;
		if (getRegDwordValue(hService, nullptr, L"Type", &value) == ERROR_SUCCESS) {
			s.serviceType = serviceType_to_wstring((int)value);
			isService = true;
		}
		if (!isService) {
			log(2, L"🔈Services\\" + s.serviceName + L": no Type value, "
			       L"parameter container skipped");
			ORCloseKey(hService);
			continue;
		}
		if (getRegDwordValue(hService, nullptr, L"Start", &value) == ERROR_SUCCESS)
			s.serviceStartType = serviceStart_to_wstring((int)value);
		if (getRegDwordValue(hService, nullptr, L"ErrorControl", &value) == ERROR_SUCCESS) {
			/* SERVICE_ERROR_IGNORE=0 … SERVICE_ERROR_CRITICAL=3. Translated here
			   rather than in trans_id: four values, one single caller. */
			PCWSTR labels[] = { L"SERVICE_ERROR_IGNORE", L"SERVICE_ERROR_NORMAL",
			                      L"SERVICE_ERROR_SEVERE", L"SERVICE_ERROR_CRITICAL" };
			s.serviceErrorControl = (value <= 3) ? labels[value]
			                                      : L"SERVICE_ERROR_UNKNOWN";
		}

		// ServiceDll: the code really loaded for a hosted service.
		getRegSzValue(hService, L"Parameters", L"ServiceDll", &s.serviceDll);

		s.serviceFingerprint    = binaryFingerprint(s.serviceBinary);
		s.serviceDllFingerprint = binaryFingerprint(s.serviceDll);

		// Matching with the current state, without regard to case.
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
	log(2, L"❇️" + std::to_wstring(services.size()) + L" services read in the hive");
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
	services.clear();   // destroys the elements -> really releases them
}
