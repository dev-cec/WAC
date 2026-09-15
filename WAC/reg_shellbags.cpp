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
	Json enfants = Json::arr();
	for (const Shellbag& c : childs) enfants.push(c.toJson());
	o.add(L"Childs", std::move(enfants));
	return o;
}


HRESULT Shellbags::getData(int _niveau) {

	HRESULT hresult = NULL;
	ORHKEY hKey = NULL;
	ORHKEY Offhive = NULL;
	std::wstring ruche = L"";
	niveau = _niveau;
	//HKEY_USERS
	for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
		//ouverture de la ruche user
		log(3, L"🔈replaceAll profile");
		ruche = conf.mountpoint + replaceAll(std::get<1>(profile), conf.systemDrive, L"") + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat";
		log(3, L"🔈OROpenHive " + std::get<1>(profile) + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
		hresult = OROpenHive(ruche.c_str(), &Offhive);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive " + std::get<1>(profile) + +L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat", hresult);
			continue;
		}

		log(3, L"🔈OROpenKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
		hresult = OROpenKey(Offhive, L"Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", &hKey);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive OROpenKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", hresult);
			continue;
		}

		log(3, L"🔈parse hKey");
		hresult = parse(hKey, std::get<0>(profile), L"BagMRU", &shellbags, 1, false);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥parse hKey", hresult);
			continue;
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Shellbags::parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Shellbag>* out, unsigned int niveau, bool _Parentiszip,  unsigned int Parent) {
	HRESULT hresult = NULL;
	ORHKEY hKeyChilds;
	std::vector<unsigned int> ids;
	// NULL : getRegBinaryValue alloue a la taille exacte (cf. reg_mru_apps.cpp).
	// L'allocation d'avance de 1 Mo etait perdue a chaque niveau de recursion.
	LPBYTE donnees = NULL;
	unsigned int pos = 0;
	DWORD taille = 0;
	DWORD nSubkeys = 0, nValues = 0;;
	FILETIME lastWriteTimeUtc = { 0 };

	log(3, L"🔈ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", hresult);
	}

	log(3, L"🔈getRegBinaryValue hKey\\MRUListEx");
	hresult = getRegBinaryValue(hKey, L"", L"MRUListEx", &donnees, &taille);
	if (hresult == ERROR_SUCCESS) {
		while (pos < taille) {
			int id = *reinterpret_cast<int*>(donnees + pos);
			if (id == 0xffffffff) break;
			ids.push_back(id);
			pos += 4;
		}
	}
	else {
		log(2, L"🔥getRegBinaryValue hKey\\MRUListEx", hresult);
	}

	delete[] donnees;
	donnees = NULL;

	for (int id : ids) {
		bool Parentiszip = false | _Parentiszip;
		DWORD taille = 0;
		log(1, L"➕Shellbag");
		/* Affiche a CHAQUE shellbag, sans limitation de frequence : ils sont peu
		   nombreux (quelques dizaines) mais chacun demande le parsing recursif
		   d'IdLists, soit plusieurs secondes. Le pas de 50 de printProgressStep
		   ne se serait jamais declenche ici — d'ou l'impression de blocage. */
		printProgress(L"Shellbag (niveau " + std::to_wstring(niveau) + L")",
		              ++nbParcourus, 0, L"bag");
		Shellbag shellbag;
		shellbag.id = id;
		log(2, L"❇️Shellbag id : " + id);
		shellbag.lastWriteTimeUtc = lastWriteTimeUtc;
		log(3, L"🔈utcVersLocalSuspect lastWriteTime");
		utcVersLocalSuspect(lastWriteTimeUtc, &shellbag.lastWriteTime);
		shellbag.Parent = Parent;
		shellbag.niveau = niveau;
		shellbag.sid = sid;
		log(3, L"🔈getNameFromSid sidName");
		shellbag.sidName = getNameFromSid(sid);
		shellbag.source = source;
		log(3, L"🔈getRegBinaryValue hKey\\" + std::to_wstring(id));
		hresult = getRegBinaryValue(hKey, L"", std::to_wstring(id).c_str(), &donnees, &taille);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegBinaryValue hKey\\" + std::to_wstring(id));
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
				shellbag.shellitems.push_back(std::move(shellitem));
			}
		}
		delete[] donnees;
		donnees = NULL;

		//Childs
		log(3, L"🔈OROpenKey hKey\\" + std::to_wstring(id));
		hresult = OROpenKey(hKey, std::to_wstring(id).c_str(), &hKeyChilds);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey hKey\\" + std::to_wstring(id), hresult);
			continue;
		}
		log(3, L"🔈parse");
		hresult = parse(hKeyChilds, sid, source, &shellbag.childs, niveau + 3, Parentiszip, id);
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
	shellbags.clear();   // detruit les unique_ptr -> libere reellement
}
