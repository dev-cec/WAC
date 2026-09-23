/*! \file
 *  \brief Reading of the LastVisitedMRU keys (see reg_mru_apps.h).
 */
#include "reg_mru_apps.h"

Json MruApp::toJson() const {
	log(3, L"🔈MruApp toJson");
	Json o = Json::obj();
	o.add(L"ID",      Json::num(id));
	o.add(L"Name",    Json::str(name));
	o.add(L"SID",     Json::str(sid));
	o.add(L"SIDName", Json::str(sidName));
	o.add(L"Source",  Json::str(source));
	log(3, L"🔈timeToIso8601 lastWriteTime");
	o.add(L"LastWriteTime",    Json::str(timeToIso8601Local(lastWriteTime)));
	log(3, L"🔈timeToIso8601 lastWriteTimeUtc");
	o.add(L"LastWriteTimeUtc", Json::str(timeToIso8601Utc(lastWriteTimeUtc)));
	Json items = Json::arr();
	for (const std::unique_ptr<IdList>& item : shellitems) items.push(item->toJson());
	o.add(L"ShellItems", std::move(items));
	return o;
}


HRESULT MruApps::getData(int _level) {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Mru Apps : ");
	log(0, L"*******************************************************************************************************************");

	HRESULT hresult = NULL;
	ORHKEY hKey = NULL;
	ORHKEY Offhive = NULL;
	std::wstring hive = L"";
	level = _level;

	//HKEY_USERS
	for (std::tuple<std::wstring, std::wstring> profileEntry : conf.profiles) {
		std::wstring keynames[3] = { L"LastVisitedMRU",L"LastVisitedPidlMRU",L"LastVisitedPidlMRULegacy" };
		for (std::wstring keyname : keynames) {
			// open the user hive
			log(3, L"🔈replaceAll profile");
			hive = extractedPath(std::get<1>(profileEntry)) + L"\\ntuser.dat";
			log(3, L"🔈OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat");
			hresult = OROpenHive(hive.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + std::get<1>(profileEntry) + L"\\ntuser.dat", hresult);
				continue;
			}
			log(3, L"🔈OROpenHive Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname);
			hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname).c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname, hresult);
				continue;
			}

			log(3, L"🔈parse");
			hresult = parse(hKey, std::get<0>(profileEntry), keyname, &mruApps, 1, false);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥parse", hresult);
				continue;
			};
		}
	}
	return ERROR_SUCCESS;
}

HRESULT MruApps::parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<MruApp>* out, unsigned int level, bool _Parentiszip) {
	HRESULT hresult = NULL;
	std::vector<unsigned int> ids;
	/* NULL, and not a buffer of MAX_DATA (1 MiB): `getRegBinaryValue` allocates
	   the exact size of the value itself. The buffer allocated up front was lost
	   at every call — and `parse` is RECURSIVE, so as many times as there are
	   levels of keys. It leaked entirely, moreover, on the two error paths
	   below, which released nothing. */
	LPBYTE data = NULL;
	unsigned int pos = 0;
	DWORD mruListSize = 0;
	FILETIME lastWriteTimeUtc = { 0 };
	DWORD nSubkeys = 0, nValues = 0;

	log(3, L"🔈ORQueryInfoKey hKey");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey hKey", hresult);
		delete[] data;
		return hresult;
	}

	log(3, L"🔈getRegBinaryValue hKey\\MRUListEx");
	hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &data, &mruListSize);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥parse", hresult);
		// getRegBinaryValue allocates BEFORE reading: the buffer exists even on failure.
		delete[] data;
		return hresult;
	}
	while (pos < mruListSize) {
		int id = *reinterpret_cast<int*>(data + pos);
		if (id == 0xffffffff) break;
		ids.push_back(id);
		pos += 4;
	}

	delete[] data;
	data = NULL;

	for (int id : ids) {
		bool Parentiszip = false | _Parentiszip;
		log(1, L"➕MruApp");
		printProgress(L"MruApp (level " + std::to_wstring(level) + L")",
		              ++nWalked, 0, L"mru");
		MruApp mruApp;
		mruApp.id = id;
		log(2, L"❇️MruApp id" + id);
		mruApp.lastWriteTimeUtc = lastWriteTimeUtc;
		log(3, L"🔈utcVersLocalSuspect lastWriteTime");
		utcToSuspectLocal(lastWriteTimeUtc, &mruApp.lastWriteTime);
		mruApp.level = level;
		mruApp.sid = sid;
		log(3, L"🔈getNameFromSid sidName");
		mruApp.sidName = getNameFromSid(sid);
		mruApp.source = source;
		log(3, L"🔈getRegBinaryValue hKey\\" + std::to_wstring(id));
		DWORD dataSize = 0;
		hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &data, &dataSize);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue hKey\\" + std::to_wstring(id), hresult);
			continue;
		}
		size_t offset = 0;
		mruApp.name = std::wstring((wchar_t*)(data)).data();
		offset += mruApp.name.size() * 2 + 2;
		while (offset < dataSize) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(data + offset);
			if (size == 0) break;
			else {
				log(3, L"🔈IdList");
				auto shellitem = std::make_unique<IdList>(data + offset, level + 2, Parentiszip);
				if (shellitem->shellItem->is_zip == true)
					Parentiszip = true;
				offset += size;
				mruApp.shellitems.push_back(std::move(shellitem));
			}
		}
		delete[] data;
		data = NULL;

		//save
		out->push_back(std::move(mruApp));
	}
	return ERROR_SUCCESS;
}

HRESULT MruApps::toJson() {
	log(3, L"🔈MruApps toJson");
	Json arr = Json::arr();
	for (const MruApp& m : mruApps) arr.push(m.toJson());
	return writeJsonFile("mruApps.json", arr);
}

void MruApps::clear() {
	log(3, L"🔈MruApps clear");
	mruApps.clear();   // destroys the unique_ptr -> really releases them
}
