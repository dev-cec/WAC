#include "reg_shimcache.h"

Json Shimcache::toJson() {
	log(3, L"🔈Shimcache toJson");
	Json o = Json::obj();
	o.add(L"Path",                Json::str(path));      // raw path
	addFingerprints(o, fingerprint);
	o.add(L"LastModification",    Json::str(lastModification));
	o.add(L"LastModificationUtc", Json::str(lastModificationUtc));
	o.add(L"Executes",            Json::boolean(executed));   // a real boolean
	return o;
}	//! Releases the memory held by the entry.

void Shimcache::clear() {
	log(3, L"🔈Shimcache clear");
}

HRESULT Shimcaches::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Shimcaches :");
	log(0, L"*******************************************************************************************************************");

	//variables
	HRESULT hresult=0;
	ORHKEY hKey=NULL;
	LPBYTE data = NULL;

	log(3, L"🔈OROpenKey CurrentControlSet\\Control\\Session Manager\\AppCompatCache");
	hresult = OROpenKey(conf.CurrentControlSet, L"Control\\Session Manager\\AppCompatCache", &hKey);
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
		log(2, L"🔥OROpenKey CurrentControlSet\\Control\\Session Manager\\AppCompatCache", hresult );
		return hresult;
	}

	DWORD size=0;
	log(3, L"🔈getRegBinaryValue AppCompatCache");
	hresult = getRegBinaryValue(hKey, nullptr, L"AppCompatCache", &data, &size);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue AppCompatCache", hresult );
		return hresult;
	}
	DWORD offset = *reinterpret_cast<DWORD*>(data);
	while (offset < size) {
		printProgressStep(L"Shimcache", offset, size);
		Shimcache shimcache;
		std::wstring signature = std::wstring(data + offset, data + offset + 4).data();
		if (signature == L"10ts") {
			offset += 12;//unused
			short int name_length = *reinterpret_cast<short int*>(data + offset);
			offset += 2;
			shimcache.path = std::wstring((LPWSTR)(data + offset), (LPWSTR)(data + offset) + name_length / sizeof(wchar_t)).data();

			// Fingerprint on the normalised path (quotes, \??\), read raw.
			shimcache.fingerprint = FingerprintFile(shimcache.path);
			shimcache.path = replaceAll(shimcache.path, L"\t", L" "); // replace tab by space. seen in values
			offset += name_length;
			FILETIME filetime = *reinterpret_cast<FILETIME*>(data + offset);
			log(3, L"🔈timeToIso8601 lastModification");
			shimcache.lastModification = timeToIso8601Local(filetime);
			log(3, L"🔈timeToIso8601 lastModificationUtc");
			shimcache.lastModificationUtc = localTimeToIso8601Utc(filetime);
			offset += 8;
			int data_length = *reinterpret_cast<int*>(data + offset);
			offset += data_length;
			short int executed = *reinterpret_cast<short int*>(data + offset);
			shimcache.executed = executed;
			offset += 4; // 2 unused

			//save 
			log(1, L"➕Shimcache ");
			log(2, L"❇️Shimcache Path : " + shimcache.path);
			shimcaches.push_back(shimcache);
		}
	}

	delete [] data;
	return ERROR_SUCCESS;
}

HRESULT Shimcaches::toJson() {
	log(3, L"🔈Shimcaches toJson");
	Json arr = Json::arr();
	for (Shimcache& e : shimcaches) arr.push(e.toJson());
	return writeJsonFile("shimcache.json", arr);
}

void Shimcaches::clear() {
	log(3, L"🔈Shimcaches clear");
	shimcaches.clear();   // destroys the elements -> really releases them
}
