/*! \file
 *  \brief Reading of the BagMRU tree (see reg_shellbags.h).
 */
#include "reg_shellbags.h"

Json Shellbag::toJson() const {
	log(3, L"🔈Shellbag toJson");
	Json o = Json::obj();
	o.add(L"ID",      Json::num(id));
	o.add(L"Parent",  Json::num(Parent));
	addUser(o, sid);
	o.add(L"Hive",    Json::str(hive));
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


namespace {

/*! Where Windows keeps a user's shellbags. UsrClass.dat holds those of
 *  Explorer's folders; NTUSER.DAT keeps another tree — network locations,
 *  "Computers and Devices", the desktop —, which SBECmd reads too and WAC used
 *  to miss (compared on the test VM). */
const struct { const wchar_t* file; const wchar_t* hive; const wchar_t* key; } SHELLBAG_TREES[] = {
	{ L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat", L"UsrClass.dat", L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU" },
	{ L"\\ntuser.dat", L"NTUSER.DAT", L"Software\\Microsoft\\Windows\\Shell\\BagMRU" },
};

//! Names the hive of a tree just read, down to its leaves.
void setHive(Shellbag& bag, const std::wstring& hive) {
	bag.hive = hive;
	for (Shellbag& child : bag.children) setHive(child, hive);
}

} // namespace

HRESULT Shellbags::getData(int _level) {
	level = _level;
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		for (const auto& tree : SHELLBAG_TREES) {
			const std::wstring hive = extractedPath(std::get<1>(profileEntry)) + tree.file;
			ORHKEY offhive = NULL;
			HRESULT hresult = OROpenHive(hive.c_str(), &offhive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + std::get<1>(profileEntry) + tree.file, hresult);
				continue;
			}
			ORHKEY hKey = NULL;
			hresult = OROpenKey(offhive, tree.key, &hKey);
			if (hresult != ERROR_SUCCESS) {
				// A user who never browsed a folder of that kind has no such tree.
				log(2, L"❇️No " + std::wstring(tree.key) + L" in " + tree.hive + L" of " + std::get<0>(profileEntry));
				ORCloseHive(offhive);
				continue;
			}
			const size_t first = shellbags.size();
			hresult = parse(hKey, std::get<0>(profileEntry), L"BagMRU", &shellbags, 1, false);
			if (hresult != ERROR_SUCCESS) log(2, L"🔥parse " + std::wstring(tree.key), hresult);
			for (size_t k = first; k < shellbags.size(); ++k) setHive(shellbags[k], tree.hive);
			ORCloseKey(hKey);
			ORCloseHive(offhive);
		}
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
