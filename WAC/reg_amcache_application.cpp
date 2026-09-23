/*! \file
 *  \brief Reading of Amcache's InventoryApplication (see reg_amcache_application.h).
 */
#include "reg_amcache_application.h"

AmcacheApplication::AmcacheApplication(ORHKEY hKey_amcache) {
	log(3, L"🔈getRegSzValue Name");
	getRegSzValue(hKey_amcache, nullptr, L"Name", &Name);
	log(2, L"❇️AmcacheApplication Name : " + Name);
	log(3, L"🔈getRegSzValue Publisher");
	getRegSzValue(hKey_amcache, nullptr, L"Publisher", &Publisher);
	log(3, L"🔈getRegSzValue RootDirPath");
	getRegSzValue(hKey_amcache, nullptr, L"RootDirPath", &RootDirPath);
	log(3, L"🔈getRegSzValue Version");
	getRegSzValue(hKey_amcache, nullptr, L"Version", &Version);
	// the date is stored as REG_SZ, so it must be converted back to a FILETIME to get the right format and the right time zone
	std::wstring temp;
	log(3, L"🔈getRegSzValue InstallDate");
	getRegSzValue(hKey_amcache, nullptr, L"InstallDate", &temp);
	if (!temp.empty()) {
		FILETIME filetime = { 0 };
		log(3, L"🔈wstring_to_filetime InstallDate");
		filetime = wstring_to_filetime(temp);
		log(3, L"🔈timeToIso8601 InstallDate");
		InstallDate = timeToIso8601Local(filetime);
		log(3, L"🔈timeToIso8601 InstallDateUtc");
		InstallDateUtc = localTimeToIso8601Utc(filetime);
	}
}

Json AmcacheApplication::toJson() {
	log(3, L"🔈AmcacheApplication toJson");
	Json o = Json::obj();
	o.add(L"Name",           Json::str(Name));
	o.add(L"Publisher",      Json::str(Publisher));
	o.add(L"RootDirPath",    Json::str(RootDirPath));   // raw path
	o.add(L"Version",        Json::str(Version));
	o.add(L"InstallDate",    Json::str(InstallDate));
	o.add(L"InstallDateUtc", Json::str(InstallDateUtc));
	return o;
}

void AmcacheApplication::clear() {
	log(3, L"🔈AmcacheApplication clear");
}

HRESULT AmcacheApplications::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Amcache Applications :");
	log(0, L"*******************************************************************************************************************");

	HRESULT hresult = NULL;
	ORHKEY hKey = NULL;
	ORHKEY hKey_amcache = NULL;
	ORHKEY Offhive = NULL;
	DWORD nSubkeys = 0;
	DWORD nValues = 0;
	DWORD bufferSize = 0;
	WCHAR subKey[MAX_VALUE_NAME]=L"";
	std::wstring hive = conf.mountpoint + L"\\Windows\\AppCompat\\Programs\\Amcache.hve";

	log(3, L"🔈OROpenHive C:\\Windows\\AppCompat\\Programs\\Amcache.hve");
	hresult = OROpenHive(hive.c_str(), &Offhive);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenHive C:\\Windows\\AppCompat\\Programs\\Amcache.hve", hresult);
		return hresult;
	}
	log(3, L"🔈OROpenHive Root\\InventoryApplication");
	hresult = OROpenKey(Offhive, L"Root\\InventoryApplication", &hKey);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenHive Root\\InventoryApplication", hresult);
		return hresult;
	}
	log(3, L"🔈ORQueryInfoKey Root\\InventoryApplication");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey Root\\InventoryApplication" , hresult );
		return hresult;
	};

	for (int i = 0; i < (int)nSubkeys; i++) {
		printProgressStep(L"AmcacheApplication", (unsigned)i + 1, nSubkeys);
		bufferSize = MAX_VALUE_NAME;
		log(3, L"🔈OREnumKey Root\\InventoryApplication " + std::to_wstring(1));
		hresult = OREnumKey(hKey, i, subKey, &bufferSize, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥OREnumKey Root\\InventoryApplication " + std::to_wstring(1), hresult );
			continue;
		}
		log(3, L"🔈OROpenKey Root\\InventoryApplication\\" + std::wstring(subKey));
		hresult = OROpenKey(hKey, subKey, &hKey_amcache);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey Root\\InventoryApplication\\" + std::wstring(subKey), hresult);
			continue;
		}
		
		log(1, L"➕AmcacheApplication ");
		//save
		amcacheapplications.push_back(AmcacheApplication(hKey_amcache));
	}
	return ERROR_SUCCESS;
}

HRESULT AmcacheApplications::toJson() {
	log(3, L"🔈AmcacheApplications toJson");
	Json arr = Json::arr();
	for (AmcacheApplication& e : amcacheapplications) arr.push(e.toJson());
	return writeJsonFile("amcache_applications.json", arr);
}

void AmcacheApplications::clear() {
	log(3, L"🔈AmcacheApplications clear");
	amcacheapplications.clear();   // destroys the elements -> really releases them
}
