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
	o.add(L"LastWriteTime",    Json::str(utcTimeToIso8601Local(lastWriteTimeUtc)));
	log(3, L"🔈timeToIso8601 lastWriteTimeUtc");
	o.add(L"LastWriteTimeUtc", Json::str(timeToIso8601Utc(lastWriteTimeUtc)));
	o.add(L"MruPosition",      Json::num(mruPosition));
	o.add(L"KeyLastWriteTime",    Json::str(utcTimeToIso8601Local(keyLastWriteTimeUtc)));
	o.add(L"KeyLastWriteTimeUtc", Json::str(timeToIso8601Utc(keyLastWriteTimeUtc)));
	if (nodeSlot) o.add(L"NodeSlot", Json::num(*nodeSlot));
	Json items = Json::arr();
	for (const std::unique_ptr<IdList>& item : shellitems) items.push(item->toJson());
	o.add(L"ShellItems", std::move(items));
	Json subfolders = Json::arr();
	for (const Shellbag& c : children) subfolders.push(c.toJson());
	o.add(L"Children", std::move(subfolders));
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
			ORCloseHive(Offhive);
			continue;
		}

		log(3, L"🔈parse hKey");
		hresult = parse(hKey, std::get<0>(profileEntry), L"BagMRU", &shellbags, 1, false);
		if (hresult != ERROR_SUCCESS) log(2, L"🔥parse hKey", hresult);
		ORCloseKey(hKey);
		ORCloseHive(Offhive);
	}
	return ERROR_SUCCESS;
}

HRESULT Shellbags::parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Shellbag>* out, unsigned int level, bool _Parentiszip,  unsigned int Parent) {
	HRESULT hresult = NULL;
	ORHKEY hKeyChildren;
	std::vector<unsigned int> ids;
	DWORD nSubkeys = 0, nValues = 0;;
	FILETIME lastWriteTimeUtc = { 0 };

	log(3, L"🔈ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", hresult);
	}

	log(3, L"🔈getRegBinaryValue hKey\\MRUListEx");
	hresult = readMruListEx(hKey, ids);
	if (hresult != ERROR_SUCCESS) log(2, L"🔥getRegBinaryValue hKey\\MRUListEx", hresult);

	int mruPosition = 0;
	for (int id : ids) {
		bool Parentiszip = false | _Parentiszip;
		log(1, L"➕Shellbag");
		/* Displayed at EVERY shellbag, without rate limiting: there are few of them
		   (a few dozen) but each requires the recursive parsing of IdLists, that is
		   several seconds. The step of 50 of printProgressStep would never have
		   fired here — hence the impression of being stuck. */
		printProgress(text(Text::ProgressLevel, { L"Shellbag", std::to_wstring(level) }),
		              ++nWalked, 0, L"bag");
		Shellbag shellbag;
		shellbag.id = id;
		shellbag.mruPosition = mruPosition++;   // MRUListEx lists the most recent first
		log(2, L"❇️Shellbag id : " + id);
		shellbag.lastWriteTimeUtc = lastWriteTimeUtc;
		shellbag.Parent = Parent;
		shellbag.level = level;
		shellbag.sid = sid;
		log(3, L"🔈getNameFromSid sidName");
		shellbag.sidName = getNameFromSid(sid);
		shellbag.source = source;
		log(3, L"🔈getRegBinaryValue hKey\\" + std::to_wstring(id));
		std::vector<BYTE> value;
		hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), value);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue hKey\\" + std::to_wstring(id));
		}

		BYTE* data = value.data();
		const size_t dataSize = value.size();
		size_t offset = 0;
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
		// The folders browsed below this one. The folder is kept even when its
		// key cannot be opened: it used to be dropped with everything below it.
		log(3, L"🔈OROpenKey hKey\\" + std::to_wstring(id));
		hresult = OROpenKey(hKey, std::to_wstring(id).c_str(), &hKeyChildren);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey hKey\\" + std::to_wstring(id), hresult);
		}
		else {
			/* The folder's own key: written when the folder is first added, and
			   again only when a subfolder is browsed. SBECmd's "FirstInteracted"
			   is this time for a folder without subfolders; its "LastInteracted"
			   is the parent key's time for the folder at MRU position 0 — two
			   readings of these times, published here as the times themselves. */
			ORQueryInfoKey(hKeyChildren, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
			               nullptr, nullptr, nullptr, &shellbag.keyLastWriteTimeUtc);
			DWORD nodeSlot = 0;
			if (getRegDwordValue(hKeyChildren, nullptr, L"NodeSlot", &nodeSlot) == ERROR_SUCCESS)
				shellbag.nodeSlot = nodeSlot;
			log(3, L"🔈parse");
			hresult = parse(hKeyChildren, sid, source, &shellbag.children, level + 3, Parentiszip, id);
			if (hresult != ERROR_SUCCESS) log(2, L"🔥parse", hresult);
			ORCloseKey(hKeyChildren);
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
