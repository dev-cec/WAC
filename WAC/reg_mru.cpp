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


HRESULT Mrus::getData(int _niveau) {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Mrus : ");
	log(0, L"*******************************************************************************************************************");

	HRESULT hresult = NULL;
	ORHKEY hKey = NULL;
	ORHKEY hSubKey=NULL;
	ORHKEY Offhive=NULL;
	DWORD nSubkeys=0, nValues=0, tailleTampon = 0;
	WCHAR nomValeur[MAX_VALUE_NAME] = L"";
	std::wstring ruche = L"";
	niveau = _niveau;
	//HKEY_USERS
	for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
		std::wstring keynames[2] = { L"OpenSavePidlMRU",L"OpenSaveMRU" };
		for (std::wstring keyname : keynames) {
			//ouverture de la ruche user
			log(3, L"🔈replaceAll profile");
			ruche = cheminExtrait(std::get<1>(profile)) + L"\\ntuser.dat";
			log(3, L"🔈OROpenHive " + std::get<1>(profile) + L"\\ntuser.dat");
			hresult = OROpenHive(ruche.c_str(), &Offhive);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenHive " + std::get<1>(profile) + L"\\ntuser.dat", hresult);
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
				tailleTampon = MAX_KEY_NAME;
				log(3, L"🔈OREnumKey hKey");
				hresult = OREnumKey(hKey, i, nomValeur, &tailleTampon, NULL, NULL, NULL);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OREnumKey hkey", hresult);
					continue;
				}
				log(3, L"🔈OROpenKey hkey\\" + std::wstring(nomValeur));
				hresult = OROpenKey(hKey, nomValeur, &hSubKey);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥OROpenKey hkey\\" + std::wstring(nomValeur), hresult);
					continue;
				}
				hresult = parse(hSubKey, std::get<0>(profile), keyname, &mrus, 1, false, nomValeur);
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥parse", hresult);
					continue;
				}
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Mrus::parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Mru>* out, unsigned int niveau, bool _Parentiszip, std::wstring extension) {
	HRESULT hresult = NULL;
	std::vector<unsigned int> ids;
	LPBYTE donnees = NULL;
	FILETIME lastWriteTimeUtc = { 0 };
	DWORD nSubkeys = 0, nValues = 0;

	unsigned int pos = 0;
	DWORD taille = 0;

	log(3, L"🔈ORQueryInfoKey hKey");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey hKey", hresult);
		return hresult;
	}

	log(3, L"🔈getRegBinaryValue hkey\\MRUListEx");
	hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &donnees, &taille);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue hkey\\MRUListEx", hresult);
		return hresult;
	}
	while (pos < taille) {
		int id = *reinterpret_cast<int*>(donnees + pos);
		if (id == 0xffffffff) break;
		ids.push_back(id);
		pos += 4;
	}

	delete[] donnees;
	donnees = NULL;
	for (int id : ids) {
		bool Parentiszip = false | _Parentiszip;
		log(1, L"➕Mru");
		printProgress(L"Mru (niveau " + std::to_wstring(niveau) + L")",
		              ++nbParcourus, 0, L"mru");
		Mru mru;
		mru.id = id;
		log(2, L"❇️Mru id" + id);
		mru.lastWriteTimeUtc = lastWriteTimeUtc;
		log(3, L"🔈utcVersLocalSuspect lastWriteTime");
		utcVersLocalSuspect(lastWriteTimeUtc, &mru.lastWriteTime);
		mru.extension = extension;
		mru.niveau = niveau;
		mru.sid = sid;
		log(3, L"🔈getNameFromSid sidName");
		mru.sidName = getNameFromSid(sid);
		mru.source = source;
		log(3, L"🔈getRegBinaryValue hkey\\" + std::to_wstring(id));
		hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &donnees, &taille);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue hkey\\" + std::to_wstring(id), hresult);
			continue;
		}
		unsigned int offset = 0;
		while (offset < taille) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(donnees + offset);
			if (size == 0) break;
			else {
				log(3, L"🔈IdList");
				auto shellitem = std::make_unique<IdList>(donnees + offset, niveau + 2, Parentiszip);
				if (shellitem->shellItem->is_zip == true)
					Parentiszip = true;
				offset += size;
				mru.shellitems.push_back(std::move(shellitem));
			}
		}
		delete[] donnees;
		donnees = NULL;

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
	mrus.clear();   // detruit les unique_ptr -> libere reellement
}
