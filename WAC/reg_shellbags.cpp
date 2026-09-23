/*! \file
 *  \brief Reading of the BagMRU tree (see reg_shellbags.h).
 */
#include "reg_shellbags.h"

Json Shellbag::toJson() const {
	log(3, L"🔈Shellbag toJson");
	Json o = Json::obj();
	o.add(L"ID",      Json::num(id));
	o.add(L"Parent",  Json::num(Parent));
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
	Json children = Json::arr();
	for (const Shellbag& c : childs) children.push(c.toJson());
	o.add(L"Childs", std::move(children));
	return o;
}


HRESULT Shellbags::getData(int _level) {

	HRESULT hresult = NULL;
	ORHKEY hKey = NULL;
	ORHKEY Offhive = NULL;
	std::wstring hive = L"";
	level = _level;
	//HKEY_USERS
	for (std::tuple<std::wstring, std::wstring> profileEntry : conf.profiles) {
		// open the user hive
		log(3, L"🔈replaceAll profile");
		hive = extractedPath(std::get<1>(profileEntry)) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat";
		log(3, L"🔈OROpenHive " + std::get<1>(profileEntry) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
		hresult = OROpenHive(hive.c_str(), &Offhive);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive " + std::get<1>(profileEntry) + +L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat", hresult);
			continue;
		}

		log(3, L"🔈OROpenKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
		hresult = OROpenKey(Offhive, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", &hKey);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive OROpenKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", hresult);
			continue;
		}

		log(3, L"🔈parse hKey");
		hresult = parse(hKey, std::get<0>(profileEntry), L"BagMRU", &shellbags, 1, false);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥parse hKey", hresult);
			continue;
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Shellbags::parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Shellbag>* out, unsigned int level, bool _Parentiszip,  unsigned int Parent) {
	HRESULT hresult = NULL;
	ORHKEY hKeyChilds;
	std::vector<unsigned int> ids;
	// NULL: getRegBinaryValue allocates exactly the needed size (see reg_mru_apps.cpp).
	// The 1 MiB allocated up front was wasted at every level of the recursion.
	LPBYTE data = NULL;
	unsigned int pos = 0;
	DWORD mruListSize = 0;
	DWORD nSubkeys = 0, nValues = 0;;
	FILETIME lastWriteTimeUtc = { 0 };

	log(3, L"🔈ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", hresult);
	}

	log(3, L"🔈getRegBinaryValue hKey\\MRUListEx");
	hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &data, &mruListSize);
	if (hresult == ERROR_SUCCESS) {
		while (pos < mruListSize) {
			int id = *reinterpret_cast<int*>(data + pos);
			if (id == 0xffffffff) break;
			ids.push_back(id);
			pos += 4;
		}
	}
	else {
		log(2, L"🔥getRegBinaryValue hKey\\MRUListEx", hresult);
	}

	delete[] data;
	data = NULL;

	for (int id : ids) {
		bool Parentiszip = false | _Parentiszip;
		DWORD dataSize = 0;
		log(1, L"➕Shellbag");
		/* Displayed at EVERY shellbag, without rate limiting: there are few of them
		   (a few dozen) but each requires the recursive parsing of IdLists, that is
		   several seconds. The step of 50 of printProgressStep would never have
		   fired here — hence the impression of being stuck. */
		printProgress(L"Shellbag (level " + std::to_wstring(level) + L")",
		              ++nWalked, 0, L"bag");
		Shellbag shellbag;
		shellbag.id = id;
		log(2, L"❇️Shellbag id : " + id);
		shellbag.lastWriteTimeUtc = lastWriteTimeUtc;
		log(3, L"🔈utcVersLocalSuspect lastWriteTime");
		utcToSuspectLocal(lastWriteTimeUtc, &shellbag.lastWriteTime);
		shellbag.Parent = Parent;
		shellbag.level = level;
		shellbag.sid = sid;
		log(3, L"🔈getNameFromSid sidName");
		shellbag.sidName = getNameFromSid(sid);
		shellbag.source = source;
		log(3, L"🔈getRegBinaryValue hKey\\" + std::to_wstring(id));
		hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &data, &dataSize);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue hKey\\" + std::to_wstring(id));
		}

		unsigned int offset = 0;
		while (offset + 2 <= dataSize) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(data + offset);
			if (size == 0) break;
			// Each shell item declares its size: it must fit in what is left of the
			// value, which is the real buffer. Every read inside the item is then
			// bounded by that size (see readWideZ).
			if (size < 3 || size > dataSize - offset) {
				log(2, L"🔥Shellbag: shell item of " + std::to_wstring(size) + L" bytes overruns the value, walk stopped", ERROR_INVALID_DATA);
				break;
			}
			else {
				log(3, L"🔈IdList");
				auto shellitem = std::make_unique<IdList>(data + offset, level + 2, Parentiszip);
				if (shellitem->shellItem->is_zip == true)
					Parentiszip = true;
				offset += size;
				shellbag.shellitems.push_back(std::move(shellitem));
			}
		}
		delete[] data;
		data = NULL;

		//Childs
		log(3, L"🔈OROpenKey hKey\\" + std::to_wstring(id));
		hresult = OROpenKey(hKey, std::to_wstring(id).c_str(), &hKeyChilds);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey hKey\\" + std::to_wstring(id), hresult);
			continue;
		}
		log(3, L"🔈parse");
		hresult = parse(hKeyChilds, sid, source, &shellbag.childs, level + 3, Parentiszip, id);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥parse", hresult);
			continue;
		}
		//save
		out->push_back(std::move(shellbag));
	}

	return ERROR_SUCCESS;
}

HRESULT Shellbags::toJson() {
	log(3, L"🔈Shellbags toJson");
	Json arr = Json::arr();
	for (const Shellbag& b : shellbags) arr.push(b.toJson());
	return writeJsonFile("shellbags.json", arr);
}

void Shellbags::clear() {
	log(3, L"🔈Shellbags clear");
	shellbags.clear();   // destroys the unique_ptr -> really releases them
}
