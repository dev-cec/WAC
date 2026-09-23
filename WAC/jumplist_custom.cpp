#include "jumplist_custom.h"

CustomDestinationCategory::CustomDestinationCategory(LPBYTE buffer, size_t buffersize, std::wstring _path, std::wstring _sid) {
	int pos = 0;

	nbentries = *reinterpret_cast<unsigned int*>(buffer + 4);
	pos += 4;
	//decoupage du fichier pour identifier tous les fichiers LNK
	for (int x = 0; x < buffersize - pos - 23; x++) {
		int s = *reinterpret_cast<int*>(buffer + pos + x); // = 0x4C = 76 pour un LNK
		if (s == 76) {
			GUID guid = *reinterpret_cast<GUID*>(buffer + pos + x + 4);
			log(3, L"🔈guid_to_wstring guid");
			std::wstring wguid = guid_to_wstring(guid);

			if (wguid.compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
				log(3, L"🔈RecentDoc");
				recentDocs.push_back(RecentDoc(buffer + pos + x, buffersize - pos - x, _path, _sid));
			}
		}
	}
};

Json CustomDestinationCategory::toJson() {
	log(3, L"🔈CustomDestinationCategory toJson");
	Json arr = Json::arr();
	for (RecentDoc& r : recentDocs) arr.push(r.toJson());
	Json o = Json::obj();
	o.add(L"recentDocs", std::move(arr));
	return o;
}

void CustomDestinationCategory::clear() {
	log(3, L"🔈CustomDestinationCategory clear");
}

CustomDestination::CustomDestination(std::filesystem::path _path, std::wstring _sid) {
	Sid = _sid;
	log(3, L"🔈getNameFromSid Sid");
	SidName = getNameFromSid(Sid);
	//path retourne un codage ANSI mais on veut de l'UTF8
	path = _path.wstring();
	log(3, L"🔈replaceAll pathOriginal");
	// Chemin BRUT : l'echappement est centralise dans json.h.
	pathOriginal = originalPath(path);
	log(2, L"❇️CustomDestination Path : " + pathOriginal);
	std::ifstream file(std::filesystem::path(path), std::ios::binary);
	if (file.good())
	{
		file.unsetf(std::ios::skipws);
		file.seekg(0, std::ios::end);
		const size_t size = file.tellg();
		file.seekg(0, std::ios::beg);
		/* Même motif que jumplist_automatic : propriété portée par le type,
		   pour que toute sortie de la fonction rende le tampon. */
		std::unique_ptr<BYTE[]> bufferOwner = std::make_unique<BYTE[]>(size);
		LPBYTE buffer = bufferOwner.get();
		file.read(reinterpret_cast<CHAR*>(buffer), size);
		file.close();

		//récupération des dates
		log(3, L"🔈CreateFile hFile");
		HANDLE hFile = CreateFile(path.c_str(),  // name of the write
			GENERIC_READ,          // open for reading
			0,                      // do not share
			NULL,                   // default security
			OPEN_EXISTING,          // open existing file only
			FILE_ATTRIBUTE_NORMAL,  // normal file
			NULL);                  // no attr. template
		if (hFile != INVALID_HANDLE_VALUE) {
			FILE_BASIC_INFO fileInfo = { 0 };

			GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO));
			memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
			memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
			memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
			utcToSuspectLocal(createdUtc, &created);
			utcToSuspectLocal(modifiedUtc, &modified);
			utcToSuspectLocal(accessedUtc, &accessed);
		}
		else {
			log(2, L"🔥CreateFile hFile ",GetLastError());
		}
		CloseHandle(hFile);

		//conversion de l'appid contenu dans le nom de fichier en nom d'application
		std::wstring baseName = _path.stem(); // nom de fichier sans extension
		log(3, L"🔈from_appId application");
		application = from_appId(baseName);
		typeInt = *reinterpret_cast<unsigned int*>(buffer);
		switch (typeInt) {
		case 0: {
			log(2, L"🔥"+ pathOriginal + L" : Custom category", ERROR_UNSUPPORTED_TYPE);
			type = L"Custom category";
			break;
		}
		case 1: {
			log(2, L"🔥" + pathOriginal + L" : Known category",ERROR_UNSUPPORTED_TYPE );
			type = L"Known category";
			break;
		}
		case 2: {
			type = L"User tasks";
			break;
		}
		default:break;
		}

		//Control de la taille du fichier pour recherche de fichier LNK
		if ((size > 24) && (typeInt == 2)) {
			log(3, L"🔈CustomDestinationCategory");
			category = std::make_unique<CustomDestinationCategory>(buffer, size, path, _sid);
		}
		else {
			log(2, L"🔥" + pathOriginal + L" : no LNK to parse",ERROR_EMPTY );
		}
		// Le tampon est rendu par son unique_ptr.
	}
};

Json CustomDestination::toJson() {
	log(3, L"🔈CustomDestination toJson");
	Json o = Json::obj();
	o.add(L"SID",         Json::str(Sid));
	o.add(L"SIDName",     Json::str(SidName));
	o.add(L"Application", Json::str(application));
	o.add(L"Path",        Json::str(pathOriginal));
	o.add(L"Type",        Json::str(type));
	o.add(L"Created",     Json::str(timeToIso8601Local(created)));
	o.add(L"CreatedUtc",  Json::str(timeToIso8601Utc(createdUtc)));
	o.add(L"Modified",    Json::str(timeToIso8601Local(modified)));
	o.add(L"ModifiedUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"Accessed",    Json::str(timeToIso8601Local(accessed)));
	o.add(L"AccessedUtc", Json::str(timeToIso8601Utc(accessedUtc)));
	if (category) o.merge(category->toJson());   // champs mis a plat (schema d'origine)
	return o;
}

void CustomDestination::clear() {
	log(3, L"🔈CustomDestination clear");
	/* La garde manquait : `categorie` est nul dès qu'un Custom Destination ne
	   porte pas de lnk — cas que `toJson()` teste explicitement juste au-dessus.
	   L'appel se faisait donc sur un pointeur nul. La libération, elle, est
	   maintenant assurée par le `unique_ptr`. */
	if (category) category->clear();
	category.reset();
}

HRESULT JumplistCustoms::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️JumplistCustoms : ");
	log(0, L"*******************************************************************************************************************");


	const std::wstring rep = L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations";
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		// cheminExtrait() gere le cas d'un profil situe sur un autre volume que
		// Windows, que replaceAll(conf.systemDrive) laissait absolu.
		const std::filesystem::path directory =
			extractedPath(std::get<1>(profileEntry)) + rep;
		const std::vector<std::filesystem::path> files =
			listFilesByExtension(directory, { L".customDestinations-ms" });
		size_t iFile = 0;
		for (const std::filesystem::path& file : files) {
			log(1, L"➕CustomDestination");
			printProgress(L"Jumplist " + file.filename().wstring(),
			              ++iFile, files.size(), L"fic");
			customDestinations.push_back(CustomDestination(file, std::get<0>(profileEntry)));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT JumplistCustoms::toJson() {
	log(3, L"🔈JumplistCustoms toJson");
	Json arr = Json::arr();
	for (CustomDestination& c : customDestinations) arr.push(c.toJson());
	return writeJsonFile("jumplistCustomDestinations.json", arr);
};

void JumplistCustoms::clear() {
	log(3, L"🔈CustomDestinations clear");
	customDestinations.clear();   // detruit les elements -> libere reellement
}
