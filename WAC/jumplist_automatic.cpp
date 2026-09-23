/*! \file
 *  \brief Reading of the automatic jump lists (see jumplist_automatic.h).
 */
#include "jumplist_automatic.h"

AutomaticDestination::AutomaticDestination(std::filesystem::path _path, std::wstring _sid) {
	Sid = _sid;
	
	// path returns ANSI encoding, but UTF-8 is wanted
	path = _path.wstring();
	log(3, L"🔈replaceAll pathOriginal");
	// RAW path: the escaping is centralised in json.h.
	pathOriginal = originalPath(path);
	log(2, L"❇️AutomaticDestination Path : " + pathOriginal);

	// get user name
	log(3, L"🔈getNameFromSid SidName");
	SidName = getNameFromSid(Sid);

	// turn the AppID held in the file name into an application name
	std::wstring::size_type const p(_path.filename().wstring().find_last_of('.'));
	std::wstring baseName = _path.filename().wstring().substr(0, p);
	log(3, L"🔈from_appId application");
	application = from_appId(baseName);

	// open the file
	std::ifstream file(_path, std::ios::binary);
	if (file.good()) {
		file.unsetf(std::ios::skipws);
		file.seekg(0, std::ios::end);
		const size_t size = file.tellg();
		file.seekg(0, std::ios::beg);
		/* OWNERSHIP GIVEN TO THE TYPE. The buffer was raw and was released only at
		   the very end of the function, while FOUR early `return`s leave it
		   before that: OLE parsing failure, DestList empty or unreadable. The
		   whole content of the file — several hundred kilobytes — leaked every
		   time, and those cases are frequent on a real machine, where many jump
		   lists are empty or partial. */
		std::unique_ptr<BYTE[]> bufferOwner = std::make_unique<BYTE[]>(size);
		LPBYTE buffer = bufferOwner.get();
		file.read(reinterpret_cast<CHAR*>(buffer), size);
		file.close();
		// read the dates
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
				utcToSuspectLocal(createdUtc, &created);
				log(3, L"🔈utcVersLocalSuspect modifiedUtc");
				utcToSuspectLocal(modifiedUtc, &modified);
				log(3, L"🔈utcVersLocalSuspect accessedUtc");
				utcToSuspectLocal(accessedUtc, &accessed);
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
		// By REFERENCE: caught by value, the exception was truncated to its base
		// class and the message of the real type lost.
		catch (const std::exception&) {
			log(2, L"🔥oleparser", ERROR_INVALID_DATA);// show cause of failure
			return;
		}

		// 2. Find DestList
		log(3, L"🔈ole.findDirectory destlistDirectory");
		Directory destlistDirectory = ole.findDirectory(L"destlist");
		std::vector<BYTE> destlistDirectoryBytes;
		if (destlistDirectory.directorySize <= 0) // Directory empty, nothing to do
			return;
		log(3, L"🔈ole.Getdata destlistDirectory");
		destlistDirectoryBytes = ole.Getdata(destlistDirectory);
		if (destlistDirectoryBytes.empty()) {// nothing to do
			log(2, L"🔥ole.Getdata destlistDirectory", ERROR_EMPTY);// show cause of failure
			return;
		}
		// 3. Process DestList entries
		log(3, L"🔈DestFileDirectory destlistArray");
		DestFileDirectory destlistArray = DestFileDirectory(destlistDirectoryBytes.data(), destlistDirectoryBytes.size());

		// 4. For each DestList entry, find the corresponding Directory entry where DestListEntry.EntryNumber == DirectoryEntry.Name
		size_t iEntry = 0;
		for (const DestFile& df : destlistArray.destfiles) {
			// Each DestList entry means parsing a complete LNK.
			printProgress(L"Jumplist " + std::filesystem::path(path).filename().wstring(),
			              ++iEntry, destlistArray.destfiles.size(), L"lnk");
			
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
		// The buffer is released by its unique_ptr, including on an early exit.
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
	recentDocs.clear();   // destroys the elements -> really releases them
}

HRESULT JumplistAutomatics::getData() {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️JumplistAutomatics : ");
	log(0, L"*******************************************************************************************************************");

	const std::wstring rep = L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations";
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		// extractedPath() handles the case of a profile on another volume than
		// Windows, which replaceAll(conf.systemDrive) left absolute.
		const std::filesystem::path directory =
			extractedPath(std::get<1>(profileEntry)) + rep;
		const std::vector<std::filesystem::path> files =
			listFilesByExtension(directory, { L".automaticDestinations-ms" });
		size_t iFile = 0;
		for (const std::filesystem::path& file : files) {
			log(1, L"➕AutomaticDestination");
			printProgress(L"Jumplist " + file.filename().wstring(),
			              ++iFile, files.size(), L"fic");
			automaticDestinations.push_back(AutomaticDestination(file, std::get<0>(profileEntry)));
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
	automaticDestinations.clear();   // destroys the elements -> really releases them
}
