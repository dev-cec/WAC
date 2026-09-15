#include "jumplist_automatic.h"

AutomaticDestination::AutomaticDestination(std::filesystem::path _path, std::wstring _sid) {
	Sid = _sid;
	
	//path retourne un codage ANSI mais on veut de l'UTF8
	path = _path.wstring();
	log(3, L"🔈replaceAll pathOriginal");
	// Chemin BRUT : l'echappement est centralise dans json.h (§11).
	pathOriginal = replaceAll(path, conf.mountpoint, conf.systemDrive);
	log(2, L"❇️AutomaticDestination Path : " + pathOriginal);

	// get user name
	log(3, L"🔈getNameFromSid SidName");
	SidName = getNameFromSid(Sid);

	//conversion de l'appid contenu dans le nom de fichier en nom d'application
	std::wstring::size_type const p(_path.filename().wstring().find_last_of('.'));
	std::wstring baseName = _path.filename().wstring().substr(0, p);
	log(3, L"🔈from_appId application");
	application = from_appId(baseName);

	//ouverture du fichier
	std::ifstream file(_path, std::ios::binary);
	if (file.good()) {
		file.unsetf(std::ios::skipws);
		file.seekg(0, std::ios::end);
		const size_t size = file.tellg();
		file.seekg(0, std::ios::beg);
		/* PROPRIÉTÉ CONFIÉE AU TYPE. Le tampon était nu et n'était libéré qu'à
		   la toute fin de la fonction, alors que QUATRE `return` prématurés la
		   quittent avant : échec d'analyse OLE, DestList vide ou illisible. Le
		   contenu entier du fichier — plusieurs centaines de kilo-octets —
		   fuyait à chaque fois, et ces cas sont fréquents sur une machine
		   réelle, où beaucoup de jumplists sont vides ou partiels. */
		std::unique_ptr<BYTE[]> tampon = std::make_unique<BYTE[]>(size);
		LPBYTE buffer = tampon.get();
		file.read(reinterpret_cast<CHAR*>(buffer), size);
		file.close();
		//récupération des dates
		log(3, L"🔈CreateFile hFile");
		HANDLE hFile = CreateFile(_path.wstring().c_str(),  // name of the write
			GENERIC_READ,          // open for reading
			0,                      // do not share
			NULL,                   // default security
			OPEN_EXISTING,          // open existing file only
			FILE_ATTRIBUTE_NORMAL,  // normal file
			NULL);                  // no attr. template
		if (hFile != INVALID_HANDLE_VALUE) {
			FILE_BASIC_INFO fileInfo;
			log(3, L"🔈GetFileInformationByHandleEx hFile");
			if (GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO))) {
				memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
				memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
				memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
				log(3, L"🔈utcVersLocalSuspect createdUtc");
				utcVersLocalSuspect(createdUtc, &created);
				log(3, L"🔈utcVersLocalSuspect modifiedUtc");
				utcVersLocalSuspect(modifiedUtc, &modified);
				log(3, L"🔈utcVersLocalSuspect accessedUtc");
				utcVersLocalSuspect(accessedUtc, &accessed);
			}
			else {
				log(2, L"🔥GetFileInformationByHandleEx hFile", GetLastError());// show cause of failure
			}
		}
		else {
			log(2, L"🔥CreateFile hFile", GetLastError());// show cause of failure
		}
		CloseHandle(hFile);
		//parsing
		try {
			log(3, L"🔈oleParser buffer");
			ole = oleParser(buffer, size);
		}
		// Par REFERENCE : attrapee par valeur, l'exception etait tronquee a sa
		// classe de base et le message du type reel perdu.
		catch (const std::exception&) {
			log(2, L"🔥oleparser", ERROR_INVALID_DATA);// show cause of failure
			return;
		}

		// 2. Find DestList
		log(3, L"🔈ole.findDirectory destlistDirectory");
		Directory destlistDirectory = ole.findDirectory(L"destlist");
		std::vector<BYTE> destlistDirectoryBytes;
		if (destlistDirectory.directorySize <= 0) // Directory vide, rien à faire
			return;
		log(3, L"🔈ole.Getdata destlistDirectory");
		destlistDirectoryBytes = ole.Getdata(destlistDirectory);
		if (destlistDirectoryBytes.empty()) {// rien à faire
			log(2, L"🔥ole.Getdata destlistDirectory", ERROR_EMPTY);// show cause of failure
			return;
		}
		// 3. Process DestList entries
		log(3, L"🔈DestFileDirectory destlistArray");
		DestFileDirectory destlistArray = DestFileDirectory(&destlistDirectoryBytes[0]);

		// 4. For each DestList entry, find the corresponding Directory entry where DestListEntry.EntryNumber == DirectoryEntry.Name
		size_t iEntree = 0;
		for (const DestFile& df : destlistArray.destfiles) {
			// Chaque entree DestList entraine le parsing d'un LNK complet.
			printProgress(L"Jumplist " + std::filesystem::path(path).filename().wstring(),
			              ++iEntree, destlistArray.destfiles.size(), L"lnk");
			
			log(3, L"🔈ole.findDirectory d");
			Directory d = ole.findDirectory(to_hex(df.entryNumber));
			if (d.name != L"") {
				// 5. Once we have the Directory entry for the lnk file, we can go get the bytes that make up the lnk file.
				log(3, L"🔈ole.Getdata d");
				std::vector<BYTE> directoryBytes = ole.Getdata(d);
				log(3, L"🔈RecentDoc");
				recentDocs.push_back(RecentDoc(&directoryBytes[0], directoryBytes.size(), path, _sid));
			}
			else {
				log(2, L"🔥ole.findDirectory d", ERROR_EMPTY);// show cause of failure
				return;
			}
		}
		// Le tampon est rendu par son unique_ptr, y compris sur sortie anticipee.
	}
};

Json AutomaticDestination::toJson() {
	log(3, L"🔈AutomaticDestination toJson");
	Json o = Json::obj();
	o.add(L"File",        Json::str(pathOriginal));
	o.add(L"SID",         Json::str(Sid));
	o.add(L"SIDName",     Json::str(SidName));
	o.add(L"Application", Json::str(application));
	o.add(L"Created",     Json::str(timeToIso8601Local(created)));
	o.add(L"CreatedUtc",  Json::str(timeToIso8601Utc(createdUtc)));
	o.add(L"Modified",    Json::str(timeToIso8601Local(modified)));
	o.add(L"ModifiedUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"Accessed",    Json::str(timeToIso8601Local(accessed)));
	o.add(L"AccessedUtc", Json::str(timeToIso8601Utc(accessedUtc)));
	Json lnks = Json::arr();
	for (RecentDoc& r : recentDocs) lnks.push(r.toJson());
	o.add(L"LNKs", std::move(lnks));
	return o;
};

void AutomaticDestination::clear() {
	log(3, L"🔈AutomaticDestination clear");
	recentDocs.clear();   // detruit les elements -> libere reellement
}

HRESULT JumplistAutomatics::getData() {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️JumplistAutomatics : ");
	log(0, L"*******************************************************************************************************************");

	const std::wstring rep = L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations";
	for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
		log(3, L"🔈replaceAll Profile");
		std::wstring temp = replaceAll(std::get<1>(profile), conf.systemDrive, L"");
		const std::filesystem::path repertoire = conf.mountpoint + temp + rep;
		const std::vector<std::filesystem::path> fichiers =
			listFilesByExtension(repertoire, { L".automaticDestinations-ms" });
		size_t iFichier = 0;
		for (const std::filesystem::path& fichier : fichiers) {
			log(1, L"➕AutomaticDestination");
			printProgress(L"Jumplist " + fichier.filename().wstring(),
			              ++iFichier, fichiers.size(), L"fic");
			automaticDestinations.push_back(AutomaticDestination(fichier, std::get<0>(profile)));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT JumplistAutomatics::toJson() {
	log(3, L"🔈JumplistAutomatics toJson");
	Json arr = Json::arr();
	for (AutomaticDestination& a : automaticDestinations) arr.push(a.toJson());
	return writeJsonFile("jumplistAutomaticDestinations.json", arr);
};

void JumplistAutomatics::clear() {
	log(3, L"🔈AutomaticDestinations clear");
	automaticDestinations.clear();   // detruit les elements -> libere reellement
}
