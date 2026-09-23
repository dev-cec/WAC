/*! \file
 *  \brief Reading of the OpenSaveMRU keys (see reg_mru.h).
 */
#include "reg_mru.h"

Json Mru::toJson() const {
	log(3, L"🔈Mru toJson");
	Json o = Json::obj();
	o.add(L"ID",        Json::num(id));
	o.add(L"Extension", Json::str(extension));
	o.add(L"SID",       Json::str(sid));
	o.add(L"SIDName",   Json::str(sidName));
	o.add(L"Source",    Json::str(source));
	log(3, L"🔈timeToIso8601 lastWriteTime");
	o.add(L"LastWriteTime",    Json::str(timeToIso8601Local(lastWriteTime)));
	log(3, L"🔈timeToIso8601 lastWriteTimeUtc");
	o.add(L"LastWriteTimeUtc", Json::str(timeToIso8601Utc(lastWriteTimeUtc)));
	Json items = Json::arr();
	for (const std::unique_ptr<IdList>& item : shellitems) items.push(item->toJson());
	o.add(L"ShellItems", std::move(items));
	return o;
}


HRESULT Mrus::getData(int _level) {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Mrus : ");
	log(0, L"*******************************************************************************************************************");

	HRESULT hresult = NULL;
	ORHKEY hKey = NULL;
	ORHKEY hSubKey=NULL;
	ORHKEY Offhive=NULL;
	DWORD nSubkeys=0, nValues=0, bufferSize = 0;
	WCHAR valueName[MAX_VALUE_NAME] = L"";
	std::wstring hive = L"";
	level = _level;
	//HKEY_USERS
	for (std::tuple<std::wstring, std::wstring> profileEntry : conf.profiles) {
		std::wstring keynames[2] = { L"OpenSavePidlMRU",L"OpenSaveMRU" };
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
			log(3, L"🔈OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname);
			hresult = OROpenKey(Offhive, (L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname).c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\" + keyname, hresult);
				continue;
			}

			log(3, L"🔈ORQueryInfoKey hKey");
			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥ORQueryInfoKey hKey", hresult);
				continue;
			}

			for (int i = 1; i < (int)nSubkeys; i++) {//i=0 = *, on passe
				bufferSize = MAX_KEY_NAME;
				log(3, L"🔈OREnumKey hKey");
				hresult = OREnumKey(hKey, i, valueName, &bufferSize, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OREnumKey hkey", hresult);
					continue;
				}
				log(3, L"🔈OROpenKey hkey\\" + std::wstring(valueName));
				hresult = OROpenKey(hKey, valueName, &hSubKey);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey hkey\\" + std::wstring(valueName), hresult);
					continue;
				}
				hresult = parse(hSubKey, std::get<0>(profileEntry), keyname, &mrus, 1, false, valueName);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥parse", hresult);
					continue;
				}
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Mrus::parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Mru>* out, unsigned int level, bool _Parentiszip, std::wstring extension) {
	HRESULT hresult = NULL;
	std::vector<unsigned int> ids;
	LPBYTE data = NULL;
	FILETIME lastWriteTimeUtc = { 0 };
	DWORD nSubkeys = 0, nValues = 0;

	unsigned int pos = 0;
	DWORD mruListSize = 0;

	log(3, L"🔈ORQueryInfoKey hKey");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey hKey", hresult);
		return hresult;
	}

	log(3, L"🔈getRegBinaryValue hkey\\MRUListEx");
	hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &data, &mruListSize);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue hkey\\MRUListEx", hresult);
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
		log(1, L"➕Mru");
		printProgress(L"Mru (level " + std::to_wstring(level) + L")",
		              ++nWalked, 0, L"mru");
		Mru mru;
		mru.id = id;
		log(2, L"❇️Mru id" + id);
		mru.lastWriteTimeUtc = lastWriteTimeUtc;
		log(3, L"🔈utcVersLocalSuspect lastWriteTime");
		utcToSuspectLocal(lastWriteTimeUtc, &mru.lastWriteTime);
		mru.extension = extension;
		mru.level = level;
		mru.sid = sid;
		log(3, L"🔈getNameFromSid sidName");
		mru.sidName = getNameFromSid(sid);
		mru.source = source;
		log(3, L"🔈getRegBinaryValue hkey\\" + std::to_wstring(id));
		DWORD dataSize = 0;
		hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &data, &dataSize);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue hkey\\" + std::to_wstring(id), hresult);
			continue;
		}
		unsigned int offset = 0;
		while (offset + 2 <= dataSize) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(data + offset);
			if (size == 0) break;
			// Each shell item declares its size: it must fit in what is left of the
			// value, which is the real buffer. Every read inside the item is then
			// bounded by that size (see readWideZ).
			if (size < 3 || size > dataSize - offset) {
				log(2, L"🔥Mru: shell item of " + std::to_wstring(size) + L" bytes overruns the value, walk stopped", ERROR_INVALID_DATA);
				break;
			}
			else {
				log(3, L"🔈IdList");
				auto shellitem = std::make_unique<IdList>(data + offset, level + 2, Parentiszip);
				if (shellitem->shellItem->is_zip == true)
					Parentiszip = true;
				offset += size;
				mru.shellitems.push_back(std::move(shellitem));
			}
		}
		delete[] data;
		data = NULL;

		//save
		out->push_back(std::move(mru));

	}
	return ERROR_SUCCESS;
}

HRESULT Mrus::toJson() {
	log(3, L"🔈Mrus toJson");
	Json arr = Json::arr();
	for (const Mru& m : mrus) arr.push(m.toJson());
	return writeJsonFile("mrus.json", arr);
}

void Mrus::clear() {
	log(3, L"🔈Mrus clear");
	mrus.clear();   // destroys the unique_ptr -> really releases them
}
