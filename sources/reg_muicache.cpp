/*! \file
 *  \brief Reading of the MUICache key (see reg_muicache.h).
 */
#include "reg_muicache.h"

Muicache::Muicache(ORHKEY hKey, std::wstring valueName, std::wstring profile) {
	
	HRESULT hresult = 0;

	name = valueName;
	log(2, L"❇️muicache Name : " + name);
	sid = profile;

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
	addUser(o, sid);
	o.add(L"Name",    Json::str(name));    // raw path
	o.add(L"Data",    Json::str(data));
	return o;
}

void Muicache::clear() {
	log(3, L"🔈Muicache clear");
}

namespace {

/*! The REG_SZ values of a MUICache key of one hive, as entries of `sid`;
 *  the hive and the key closed whatever happens. A hive or a key that is not
 *  there is not an error: the other form of the cache is.
 *  @param hive the hive's working copy
 *  @param key the MUICache key in it
 *  @param sid the user whose hive it is
 *  @param entries receives the entries */
void readMuiCacheKey(const std::wstring& hive, const wchar_t* key, const std::wstring& sid, std::vector<Muicache>& entries) {
	std::error_code ec;
	if (!std::filesystem::is_regular_file(hive, ec)) return;
	ORHKEY root = nullptr, muiKey = nullptr;
	HRESULT hr = OROpenHive(hive.c_str(), &root);
	if (hr != ERROR_SUCCESS) {
		log(2, L"🔥OROpenHive " + hive, hr);
		return;
	}
	if (OROpenKey(root, key, &muiKey) == ERROR_SUCCESS) {
		DWORD nValues = 0;
		hr = ORQueryInfoKey(muiKey, nullptr, nullptr, nullptr, nullptr, nullptr, &nValues, nullptr, nullptr, nullptr, nullptr);
		if (hr != ERROR_SUCCESS) log(2, L"🔥ORQueryInfoKey MuiCache " + hive, hr);
		for (DWORD i = 0; hr == ERROR_SUCCESS && i < nValues; ++i) {
			printProgressStep(L"Muicache", i + 1, nValues);
			WCHAR valueName[MAX_VALUE_NAME] = L"";
			DWORD nameSize = MAX_VALUE_NAME, type = 0, dataSize = MAX_DATA;
			const HRESULT value = OREnumValue(muiKey, i, valueName, &nameSize, &type, nullptr, &dataSize);
			if (value != ERROR_SUCCESS) {
				log(2, L"🔥OREnumValue " + std::to_wstring(i), value);
				continue;
			}
			// XP's key also holds LangID, a binary: not an entry.
			if (type != REG_SZ) continue;
			log(1, L"➕Muicache");
			entries.push_back(Muicache(muiKey, valueName, sid));
		}
		ORCloseKey(muiKey);
	}
	ORCloseHive(root);
}

} // namespace

HRESULT Muicaches::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Muicache : ");
	log(0, L"*******************************************************************************************************************");
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring profile = extractedPath(std::get<1>(profileEntry));
		// Vista and later: UsrClass.dat. Windows XP and Server 2003: NTUSER.DAT, ShellNoRoam.
		readMuiCacheKey(profile + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat",
		                L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", std::get<0>(profileEntry), muicaches);
		readMuiCacheKey(profile + L"\\ntuser.dat", L"Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
		                std::get<0>(profileEntry), muicaches);
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
