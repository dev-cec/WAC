#include "jumplist_custom.h"

CustomDestinationCategory::CustomDestinationCategory(LPBYTE buffer, size_t buffersize, std::wstring _path, std::wstring _sid) {
	int pos = 0;

	nbentries = *reinterpret_cast<unsigned int*>(buffer + 4);
	pos += 4;
	// split the file to identify every LNK file
	for (int x = 0; x < buffersize - pos - 23; x++) {
		int s = *reinterpret_cast<int*>(buffer + pos + x); // = 0x4C = 76 for a LNK
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
	// path returns ANSI encoding, but UTF-8 is wanted
	path = _path.wstring();
	log(3, L"🔈replaceAll pathOriginal");
	// RAW path: the escaping is centralised in json.h.
	pathOriginal = originalPath(path);
	log(2, L"❇️CustomDestination Path : " + pathOriginal);
	std::ifstream file(std::filesystem::path(path), std::ios::binary);
	if (file.good())
	{
		file.unsetf(std::ios::skipws);
		file.seekg(0, std::ios::end);
		const size_t size = file.tellg();
		file.seekg(0, std::ios::beg);
		/* Same pattern as jumplist_automatic: ownership carried by the type, so
		   that every exit of the function releases the buffer. */
		std::unique_ptr<BYTE[]> bufferOwner = std::make_unique<BYTE[]>(size);
		LPBYTE buffer = bufferOwner.get();
		file.read(reinterpret_cast<CHAR*>(buffer), size);
		file.close();

		// read the dates
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

		// turn the AppID held in the file name into an application name
		std::wstring baseName = _path.stem(); // file name without its extension
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

		// Check of the file's size, to look for a LNK file
		if ((size > 24) && (typeInt == 2)) {
			log(3, L"🔈CustomDestinationCategory");
			category = std::make_unique<CustomDestinationCategory>(buffer, size, path, _sid);
		}
		else {
			log(2, L"🔥" + pathOriginal + L" : no LNK to parse",ERROR_EMPTY );
		}
		// The buffer is released by its unique_ptr.
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
	if (category) o.merge(category->toJson());   // fields flattened (the original schema)
	return o;
}

void CustomDestination::clear() {
	log(3, L"🔈CustomDestination clear");
	/* The guard was missing: `category` is null as soon as a Custom Destination
	   carries no lnk — a case that `toJson()` tests explicitly just above. The
	   call was therefore made on a null pointer. The release, for its part, is
	   now ensured by the `unique_ptr`. */
	if (category) category->clear();
	category.reset();
}

HRESULT JumplistCustoms::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️JumplistCustoms : ");
	log(0, L"*******************************************************************************************************************");


	const std::wstring rep = L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations";
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		// extractedPath() handles the case of a profile on another volume than
		// Windows, which replaceAll(conf.systemDrive) left absolute.
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
	customDestinations.clear();   // destroys the elements -> really releases them
}
