/*! \file
 *  \brief Reading of the UserAssist keys (see reg_userassists.h).
 */
#include "reg_userassists.h"
#include <cstring>

UserAssist::UserAssist(std::wstring hKey, const std::wstring& valueName, const std::vector<BYTE>& data, std::wstring _sid) {
	log(3, L"🔈ROT13 Name");
	Name = ROT13(valueName); // ROT13 of the value's name, to recover the executable's name
	log(2, L"❇️UserAssist Name : " + Name);
	Sid = _sid;
	log(3, L"🔈getNameFromSid SidName");
	SidName = getNameFromSid(Sid);
	Class = hKey;
	// conversion of the known folder GUIDs
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
	// The caller guarantees ENTRY_SIZE bytes; read by copy, the buffer carries no alignment guarantee.
	if (data.size() < ENTRY_SIZE) return;
	std::memcpy(&Count, data.data() + 4, 4);        // number of runs
	std::memcpy(&FocusCount, data.data() + 8, 4);   // number of times the window got the focus
	/* The last run is a FILETIME in UTC. It used to be read as a LOCAL time:
	   both keys came out shifted by the time-zone offset — measured on the
	   test VM, raw_hive_test.exe started at 13:48:24 UTC (its Prefetch: 13:48:28)
	   was published at 11:48:24 UTC. */
	std::memcpy(&lastRunUtc, data.data() + 60, sizeof(lastRunUtc));
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
	o.add(L"DateLocale",    Json::str(utcTimeToIso8601Local(lastRunUtc)));
	o.add(L"DateLocaleUtc", Json::str(timeToIso8601Utc(lastRunUtc)));
	return o;
}

void UserAssist::clear() {
	log(3, L"🔈UserAssist clear");
}

HRESULT UserAssists::getData() {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️User assists :");
	log(0, L"*******************************************************************************************************************");

	const std::wstring userAssistKeys[2] = { L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" }; // executables, shortcuts
	for (const std::wstring& key : userAssistKeys) {
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
			const std::wstring hive = extractedPath(std::get<1>(profileEntry)) + L"\\ntuser.dat";
			ORHKEY userHive = NULL;
			log(3, L"🔈OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat");
			HRESULT hresult = OROpenHive(hive.c_str(), &userHive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat", hresult);
				continue;
			}
			const std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\" + key + L"\\count";
			ORHKEY hKey = NULL;
			log(3, L"🔈OROpenKey " + subkey);
			hresult = OROpenKey(userHive, subkey.c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey " + subkey, hresult);
				ORCloseHive(userHive);
				continue;
			}
			std::wstring valueName;
			DWORD type = 0;
			std::vector<BYTE> data;
			for (DWORD i = 0; ; ++i) {
				log(3, L"🔈enumRegistryValue " + subkey + L" " + std::to_wstring(i));
				hresult = enumRegistryValue(hKey, i, valueName, type, data);
				if (hresult == ERROR_NO_MORE_ITEMS) break;
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥enumRegistryValue " + subkey + L" " + std::to_wstring(i), hresult);
					break;
				}
				if (data.size() != UserAssist::ENTRY_SIZE) {
					// Not a program entry (UEME_CTLSESSION: session statistics).
					log(2, L"🔈UserAssist " + ROT13(valueName) + L": " + std::to_wstring(data.size())
					     + L" bytes, not an entry of " + std::to_wstring(UserAssist::ENTRY_SIZE) + L": skipped");
					continue;
				}
				log(1, L"➕UserAssist ");
				userassists.push_back(UserAssist(key, valueName, data, std::get<0>(profileEntry)));
			}
			ORCloseKey(hKey);
			ORCloseHive(userHive);
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
	userassists.clear();   // destroys the elements -> really releases them
}
