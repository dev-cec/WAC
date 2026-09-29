/*! \file
 *  \brief Reading of the Run and RunOnce keys (see reg_run.h).
 */
#include "reg_run.h"

Json Run::toJson() {
	log(3, L"🔈Run toJson");
	Json o = Json::obj();
	o.add(L"Hive",             Json::str(Hive));
	o.add(L"SID",              Json::str(Sid));
	o.add(L"SIDName",          Json::str(SidName));
	o.add(L"Key",              Json::str(Key));
	o.add(L"Name",             Json::str(Name));
	o.add(L"Type",             Json::str(Type));
	o.add(L"Value",            Json::str(Value));      // raw command line
	o.add(L"LastWriteTime",    Json::str(utcTimeToIso8601Local(lastWriteTimeUtc)));
	o.add(L"LastWriteTimeUtc", Json::str(timeToIso8601Utc(lastWriteTimeUtc)));
	return o;
}

void Run::clear() {
	log(3, L"🔈Run clear");
}

namespace {

/*! Reads the Run and RunOnce keys under `base` in one hive.
 *
 *  ONE reading for every hive. The machine-wide keys and each user's used to
 *  be read by two copies of the same loop; each user hive was opened for each
 *  key and never closed; and only REG_SZ values were kept, while a Run value
 *  is as often REG_EXPAND_SZ (%ProgramFiles%…) — those entries were dropped.
 *  @param root the hive (or the SOFTWARE hive's root)
 *  @param base the path of the keys' parent, ending with a backslash
 *  @param hive the hive's name, for the output (SOFTWARE, DEFAULT, NTUSER.DAT)
 *  @param sid the SID of the user the hive belongs to; empty for machine-wide
 *  @param sidName that user's name, or HKLM for machine-wide
 *  @param runs receives the entries */
void readRunKeys(ORHKEY root, const std::wstring& base, const std::wstring& hive,
                 const std::wstring& sid, const std::wstring& sidName, std::vector<Run>& runs) {
	for (const wchar_t* key : { L"Run", L"RunOnce" }) {
		ORHKEY hKey = NULL;
		log(3, L"🔈OROpenKey " + hive + L"\\" + base + key);
		if (OROpenKey(root, (base + key).c_str(), &hKey) != ERROR_SUCCESS) continue;
		FILETIME lastWriteTimeUtc = { 0 };
		DWORD nValues = 0;
		if (ORQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc) == ERROR_SUCCESS)
			for (DWORD i = 0; i < nValues; ++i) {
				printProgressStep(L"Run", (unsigned)i + 1, nValues);
				std::wstring name;
				DWORD type = 0;
				std::vector<BYTE> data;
				if (enumRegistryValue(hKey, i, name, type, data) != ERROR_SUCCESS) continue;
				if (type != REG_SZ && type != REG_EXPAND_SZ) {
					log(2, L"🔥Run value " + name + L" neither REG_SZ nor REG_EXPAND_SZ");
					continue;
				}
				Run run;
				run.Hive = hive;
				run.Sid = sid;
				run.SidName = sidName;
				run.Key = key;
				run.Name = name;
				run.Type = type == REG_EXPAND_SZ ? L"REG_EXPAND_SZ" : L"REG_SZ";
				run.Value = readWideZ(data.data(), data.size(), 0);   // bounded by the value
				run.lastWriteTimeUtc = lastWriteTimeUtc;
				log(2, L"❇️Run : " + hive + L" " + run.Name);
				runs.push_back(run);
			}
		ORCloseKey(hKey);
	}
}

//! Opens a hive file of the working copy, reads its Run keys, closes it.
void readRunKeysOfHive(const std::wstring& file, const std::wstring& hive,
                       const std::wstring& sid, std::vector<Run>& runs) {
	ORHKEY root = NULL;
	log(3, L"🔈OROpenHive " + file);
	const HRESULT hresult = OROpenHive(file.c_str(), &root);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenHive " + file, hresult);
		return;
	}
	readRunKeys(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\", hive, sid, getNameFromSid(sid), runs);
	ORCloseHive(root);
}

} // namespace

HRESULT Runs::getData() {
	log(0, L"ℹ️Runs :");
	// Machine-wide, in SOFTWARE (already open).
	if (conf.Software) readRunKeys(conf.Software, L"Microsoft\\Windows\\CurrentVersion\\", L"SOFTWARE", L"", L"HKLM", runs);
	/* The DEFAULT hive: HKEY_USERS\.DEFAULT, the profile of the system account
	   (S-1-5-18) — what runs there starts with the system, whoever logs on. */
	readRunKeysOfHive(conf.mountpoint + L"\\Windows\\system32\\config\\DEFAULT", L"DEFAULT", L"S-1-5-18", runs);
	// Each user, in their NTUSER.DAT: whose logon starts the program.
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		readRunKeys(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\", L"NTUSER.DAT", sid, getNameFromSid(sid), runs);
	});
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
