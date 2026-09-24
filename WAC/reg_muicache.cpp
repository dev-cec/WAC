/*! \file
 *  \brief Reading of the MUICache key (see reg_muicache.h).
 */
#include "reg_muicache.h"

Muicache::Muicache(ORHKEY hKey, std::wstring valueName, std::wstring profile) {
	
	HRESULT hresult = 0;

	name = valueName;
	log(2, L"❇️muicache Name : " + name);
	sid = profile;
	log(3, L"🔈getNameFromSid sidName");
	sidName = getNameFromSid(sid);

	log(3, L"🔈getRegSzValue valueName");
	hresult = getRegSzValue(hKey, nullptr, valueName.c_str(), &data);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegSzValue Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache\\" + std::wstring(valueName), hresult);
	}
	else {
	}
}

Json Muicache::toJson() {
	log(3, L"🔈Muicache toJson");
	Json o = Json::obj();
	o.add(L"SID",     Json::str(sid));
	o.add(L"SIDName", Json::str(sidName));
	o.add(L"Name",    Json::str(name));    // raw path
	o.add(L"Data",    Json::str(data));
	return o;
}

void Muicache::clear() {
	log(3, L"🔈Muicache clear");
}

HRESULT Muicaches::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Muicache : ");
	log(0, L"*******************************************************************************************************************");


	HRESULT hresult=0;
	ORHKEY hKey=NULL;
	ORHKEY Offhive=NULL;
	DWORD nSubkeys = 0;
	DWORD nValues=0;
	DWORD dType = 0;
	WCHAR valueName[MAX_VALUE_NAME]=L"";

	std::wstring hive = L"";
	for (std::tuple<std::wstring, std::wstring> profileEntry : conf.profiles) {
		// open the user hive
		log(3, L"🔈replaceAll profile");
		hive = extractedPath(std::get<1>(profileEntry)) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat";
		log(3, L"🔈OROpenHive " + std::get<1>(profileEntry) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
		hresult = OROpenHive(hive.c_str(), &Offhive);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive " + std::get<1>(profileEntry) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat", GetLastError());
			continue;
		};

		log(3, L"🔈OROpenKey Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\MuiCache");
		hresult = OROpenKey(Offhive, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", &hKey);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey Local Settings\\\\Software\\\\Microsoft\\\\Windows\\\\Shell\\\\MuiCache", hresult );
			continue;
		};

		log(3, L"🔈ORQueryInfoKey MuiCache");
		hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥ORQueryInfoKey MuiCache", hresult );
			continue;
		};

		for (int i = 0; i < (int)nValues; i++) {
			printProgressStep(L"Muicache", (unsigned)i + 1, nValues);
			DWORD bufferSize = MAX_VALUE_NAME;
			DWORD cData = MAX_DATA;
			log(3, L"🔈OREnumValue " + std::to_wstring(i));
			hresult = OREnumValue(hKey, i, valueName, &bufferSize, &dType, NULL, &cData);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OREnumValue " + std::to_wstring(i), hresult);
				continue;
			};
			if (dType != REG_SZ) {
				log(2, L"🔥OREnumValue " + std::wstring(valueName) + L" not REG_SZ type");
				continue;
			}
			//save
			log(1, L"➕Muicache");
			muicaches.push_back(Muicache(hKey, valueName, std::get<0>(profileEntry)));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Muicaches::toJson() {
	log(3, L"🔈Muicaches toJson");
	Json arr = Json::arr();
	for (Muicache& e : muicaches) arr.push(e.toJson());
	return writeJsonFile("muicache.json", arr);
}

void Muicaches::clear() {
	log(3, L"🔈Muicaches clear");
	muicaches.clear();   // destroys the elements -> really releases them
}
