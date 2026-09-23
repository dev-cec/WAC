/*! \file
 *  \brief Reading of the Run and RunOnce keys (see reg_run.h).
 */
#include "reg_run.h"

Json Run::toJson() {
	log(3, L"🔈Run toJson");
	Json o = Json::obj();
	o.add(L"SID",              Json::str(Sid));
	o.add(L"SIDName",          Json::str(SidName));
	o.add(L"Key",              Json::str(Key));
	o.add(L"Name",             Json::str(Name));
	o.add(L"Value",            Json::str(Value));      // raw command line
	o.add(L"LastWriteTime",    Json::str(timeToIso8601Local(lastWriteTime)));
	o.add(L"LastWriteTimeUtc", Json::str(timeToIso8601Utc(lastWriteTimeUtc)));
	return o;
}

void Run::clear() {
	log(3, L"🔈Run clear");
}

HRESULT Runs::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Runs :");
	log(0, L"*******************************************************************************************************************");

	HRESULT hresult = 0;
	ORHKEY hKey = NULL;
	ORHKEY Offhive = NULL;
	DWORD nSubkeys = 0;
	DWORD nValues = 0;
	DWORD bufferSize = 0;
	DWORD dType = 0;
	WCHAR valueName[MAX_VALUE_NAME] = L"";
	FILETIME lastWriteTimeUtc = { 0 };
	std::wstring hive = L"";
	std::wstring runKeys[2] = { L"Run",L"RunOnce" };
	for (std::wstring runKey : runKeys) {
		log(3, L"🔈OROpenKey HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
		hresult = OROpenKey(conf.Software, (L"Microsoft\\Windows\\CurrentVersion\\" + runKey).c_str(), &hKey);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey, hresult);
			continue;
		}

		log(3, L"🔈ORQueryInfoKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥ORQueryInfoKey HKLM\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\" + runKey, hresult);
			continue;
		}
		for (int i = 0; i < (int)nValues; i++) {
			printProgressStep(L"Run", (unsigned)i + 1, nValues);
			log(1, L"➕Run ");
			Run run;
			bufferSize = MAX_VALUE_NAME;
			run.lastWriteTimeUtc = lastWriteTimeUtc;
			log(3, L"🔈utcVersLocalSuspect lastWriteTime");
			utcToSuspectLocal(lastWriteTimeUtc, &run.lastWriteTime);
			DWORD cData = MAX_DATA;
			log(3, L"🔈OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i));
			hresult = OREnumValue(hKey, i, valueName, &bufferSize, &dType, NULL, &cData);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i), hresult);
			}
			if (dType != REG_SZ) {
				log(2, L"🔥OREnumValue " + std::wstring(valueName) + L" not REG_SZ type");
				continue;
			}
			run.Name = valueName;
			log(2, L"❇️Run Name : " + run.Name);
			run.Sid = L"";
			run.SidName = L"HKLM";
			run.Key = runKey;
			log(3, L"🔈getRegSzValue " + std::wstring(valueName));
			hresult = getRegSzValue(hKey, nullptr, valueName, &run.Value);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥getRegSzValue " + std::wstring(valueName), hresult);
			}
			log(3, L"🔈replaceAll Value");
			//save
			runs.push_back(run);
		}
		for (std::tuple<std::wstring, std::wstring> profileEntry : conf.profiles) {
			// open the user hive
			log(3, L"🔈replaceAll Profile");
			hive = extractedPath(std::get<1>(profileEntry)) + L"\\ntuser.dat";
			log(3, L"🔈OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat");
			hresult = OROpenHive(hive.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat", hresult);
				continue;
			}

			log(3, L"🔈OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
			hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey).c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey, hresult);
				continue;
			}

			log(3, L"🔈ORQueryInfoKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey);
			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥ORQueryInfoKey Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey, hresult);
				continue;
			}

			for (int i = 0; i < (int)nValues; i++) {
				log(1, L"➕Run ");
				Run run;
				bufferSize = MAX_VALUE_NAME;
				DWORD cData = MAX_DATA;
				run.lastWriteTimeUtc = lastWriteTimeUtc;
				log(3, L"🔈utcVersLocalSuspect lastWriteTime");
				utcToSuspectLocal(lastWriteTimeUtc, &run.lastWriteTime);
				log(3, L"🔈OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i));
				hresult = OREnumValue(hKey, i, valueName, &bufferSize, &dType, NULL, &cData);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OREnumValue Software\\Microsoft\\Windows\\CurrentVersion\\" + runKey + L" " + std::to_wstring(i), hresult);
				}
				if (dType != REG_SZ) {
					log(2, L"🔥OREnumValue " + std::wstring(valueName) + L" not REG_SZ type");
					continue;
				}
				run.Name = valueName;
				log(2, L"❇️Run Name : " + run.Name);
				run.Sid = std::get<0>(profileEntry);
				log(3, L"🔈getNameFromSid Sid");
				run.SidName = getNameFromSid(run.Sid);
				run.Key = runKey;
				log(3, L"🔈getRegSzValue " + std::wstring(valueName));
				hresult = getRegSzValue(hKey, nullptr, valueName, &run.Value);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥getRegSzValue " + std::wstring(valueName), hresult);
				}
				log(3, L"🔈replaceAll Value");
				//save
				runs.push_back(run);
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Runs::toJson() {
	log(3, L"🔈Runs to_jon");
	Json arr = Json::arr();
	for (Run& e : runs) arr.push(e.toJson());
	return writeJsonFile("run.json", arr);
}

void Runs::clear() {
	log(3, L"🔈Runs clear");
	runs.clear();   // destroys the elements -> really releases them
}
