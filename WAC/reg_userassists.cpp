#include "reg_userassists.h"

UserAssist::UserAssist(std::wstring hKey, LPWSTR valueName, LPBYTE data, std::wstring _sid) {
	// Codage ANSI mais on veut de l'utf8
	log(3, L"🔈ROT13 Name");
	Name = ROT13(valueName); // Rot13 du nom de la Value pour récupérer le nom de l’exécutable
	log(2, L"❇️UserAssist Name : " + Name);
	Sid = _sid;
	log(3, L"🔈getNameFromSid SidName");
	SidName = getNameFromSid(Sid);
	Class = hKey;
	//conversion des GUID Directory
	std::wsmatch pieces_match;
	std::wregex key(L"[\\{][a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}[\\}]");
	log(3, L"🔈regex_search Name");
	if (std::regex_search(Name, pieces_match, key)) {
		for (std::wstring s : pieces_match) {
			std::wstring n = trans_guid_to_wstring(s);
			log(3, L"🔈replaceAll Regex Name");
			Name = replaceAll(Name, s, n);
		}
	}
	Count = *reinterpret_cast<int*>(data + 4); // conversion en integer du nombre d'exécutions à partir du little endian
	FocusCount = *reinterpret_cast<int*>(data + 8); // conversion en integer du nombre d'exécutions à partir du little endian
	FILETIME filetime = *reinterpret_cast<FILETIME*>(data + 60);
	log(3, L"🔈timeToIso8601 DateLocale");
	DateLocale = timeToIso8601Local(filetime); // récupération de la date de dernière exécution sous forme de tableau de bytes
	if (DateLocale != L"") { // si la date est vide
		// sinon on la convertie en UTC
		log(3, L"🔈timeToIso8601 DateLocaleUtc");
		DateLocaleUtc = localTimeToIso8601Utc(filetime); // récupération de la date de dernière exécution sous forme de tableau de bytes
	}
}

Json UserAssist::toJson() {
	log(3, L"🔈UserAssist toJson");
	Json o = Json::obj();
	o.add(L"SID",           Json::str(Sid));
	o.add(L"SIDName",       Json::str(SidName));
	o.add(L"Class",         Json::str(Class));
	o.add(L"Name",          Json::str(Name));
	o.add(L"Count",         Json::num((long long)Count));
	o.add(L"FocusCount",    Json::num((long long)FocusCount));
	o.add(L"DateLocale",    Json::str(DateLocale));
	o.add(L"DateLocaleUtc", Json::str(DateLocaleUtc));
	return o;
}

void UserAssist::clear() {
	log(3, L"🔈UserAssist clear");
}

HRESULT UserAssists::getData() {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️User assists :");
	log(0, L"*******************************************************************************************************************");

	HRESULT hresult = 0;
	ORHKEY hKey = NULL;
	DWORD nSubkeys = 0;
	DWORD nValues = 0;
	DWORD dType = 0;
	WCHAR valueName[MAX_VALUE_NAME] = L"";
	DWORD bufferSize = 0;
	ORHKEY Offhive = NULL;
	std::wstring hive = L"";
	std::wstring userassitsKey[2] = { L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" }; // les GUID à lire pour les userassists
	for (std::wstring key : userassitsKey) {
		for (std::tuple<std::wstring, std::wstring> profileEntry : conf.profiles) {
			//ouverture de la ruche user
			log(3, L"🔈replaceAll profile");
			hive = extractedPath(std::get<1>(profileEntry)) + L"\\ntuser.dat";
			log(3, L"🔈OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat");
			hresult = OROpenHive(hive.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat", hresult);
				continue;
			}

			std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\" + key + L"\\count\\";
			log(3, L"🔈OROpenKey " + subkey);
			hresult = OROpenKey(Offhive, subkey.c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey " + subkey);
				continue;
			}

			log(3, L"🔈ORQueryInfoKey " + subkey);
			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥ORQueryInfoKey " + subkey);
				continue;
			}
			for (DWORD i = 0; i < nValues; i++) {
				printProgressStep(L"UserAssist", i + 1, nValues);
				DWORD dataSize = 0;
				LPBYTE data = NULL;
				do {
					if (data != NULL)
						delete[] data;
					data = new BYTE[dataSize];
					log(3, L"🔈OREnumValue " + subkey + L" " + std::to_wstring(i));
					hresult = OREnumValue(hKey, i, valueName, &bufferSize, &dType, data, &dataSize);
				} while (hresult == ERROR_MORE_DATA);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OREnumValue " + subkey + L" " + std::to_wstring(i), hresult);
					continue;
				}
				//save
				log(1, L"➕UserAssist ");
				userassists.push_back(UserAssist(key, valueName, data, std::get<0>(profileEntry)));

				delete[] data;
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT UserAssists::toJson() {
	log(3, L"🔈UserAssists toJson");
	Json arr = Json::arr();
	for (UserAssist& u : userassists) arr.push(u.toJson());
	return writeJsonFile("userassists.json", arr);
}

void UserAssists::clear() {
	log(3, L"🔈UserAssists clear");
	userassists.clear();   // detruit les elements -> libere reellement
}
