/*! \file
 *  \brief Reading of the automatic jump lists (see jumplist_automatic.h).
 */
#include "jumplist_automatic.h"
#include "consigne.h"

AutomaticDestination::AutomaticDestination(std::filesystem::path _path, std::wstring _sid) {
	Sid = _sid;
	
	// the path in UTF-16, as Windows holds it
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
		// The dates of the file ON THE EXAMINED MACHINE, as the raw reading recorded
		// them: the working copy's own are those of the collection (ExhibitSourceTimes).
		if (!ExhibitSourceTimes(_path.wstring(), createdUtc, modifiedUtc, accessedUtc))
			log(2, L"🔥Source timestamps not recorded: " + _path.wstring());
		parse(buffer, size);
		// The buffer is released by its unique_ptr.
	}
};

void AutomaticDestination::parse(LPBYTE buffer, size_t size) {
	// 1. The OLE container. A malformed one throws: nothing more is read.
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
	if (destlistDirectory.directorySize <= 0) // Directory empty, nothing to do
		return;
	std::vector<BYTE> destlistDirectoryBytes;
	try {
		log(3, L"🔈ole.Getdata destlistDirectory");
		destlistDirectoryBytes = ole.Getdata(destlistDirectory);
	}
	catch (const std::exception&) {
		log(2, L"🔥ole.Getdata destlistDirectory", ERROR_INVALID_DATA);
		return;
	}
	if (destlistDirectoryBytes.empty()) {// nothing to do
		log(2, L"🔥ole.Getdata destlistDirectory", ERROR_EMPTY);// show cause of failure
		return;
	}
	// 3. Process DestList entries
	log(3, L"🔈DestFileDirectory destlistArray");
	DestFileDirectory destlistArray = DestFileDirectory(destlistDirectoryBytes.data(), destlistDirectoryBytes.size());

	/* 4. Each DestList entry names, by its number, the stream holding its
	   shortcut. An entry whose stream is missing or unreadable is kept, with
	   its DestList data: it used to END the walk, losing every entry after it. */
	size_t iEntry = 0;
	for (const DestFile& df : destlistArray.destfiles) {
		printProgress(L"Jumplist " + std::filesystem::path(path).filename().wstring(),
		              ++iEntry, destlistArray.destfiles.size(), L"lnk");
		JumplistEntry entry{ df, std::nullopt };
		log(3, L"🔈ole.findDirectory d");
		/* The stream's name: the entry number in lower-case hexadecimal WITHOUT
		   padding — "1" … "f", "10". It was padded to two digits ("01"): the
		   streams of entries 1 to 15 were never found, and the first fifteen
		   files opened with every application were lost. Checked against
		   olefile's listing of real jump lists. */
		const std::wstring streamName = to_hex(df.entryNumber, 1);
		const Directory d = ole.findDirectory(streamName);
		if (d.name.empty()) {
			log(2, L"🔥ole.findDirectory " + streamName + L": no stream for this DestList entry", ERROR_EMPTY);
		}
		else {
			try {
				log(3, L"🔈ole.Getdata d");
				std::vector<BYTE> directoryBytes = ole.Getdata(d);
				if (!directoryBytes.empty()) {
					log(3, L"🔈RecentDoc");
					entry.lnk.emplace(directoryBytes.data(), directoryBytes.size(), path, Sid);
				}
			}
			catch (const std::exception&) {
				log(2, L"🔥ole.Getdata " + streamName, ERROR_INVALID_DATA);
			}
		}
		entries.push_back(std::move(entry));
	}
}

Json AutomaticDestination::toJson() {
	log(3, L"🔈AutomaticDestination toJson");
	Json o = Json::obj();
	o.add(L"File",        Json::str(pathOriginal));
	o.add(L"SID",         Json::str(Sid));
	o.add(L"SIDName",     Json::str(SidName));
	o.add(L"Application", Json::str(application));
	o.add(L"Created",     Json::str(utcTimeToIso8601Local(createdUtc)));
	o.add(L"CreatedUtc",  Json::str(timeToIso8601Utc(createdUtc)));
	o.add(L"Modified",    Json::str(utcTimeToIso8601Local(modifiedUtc)));
	o.add(L"ModifiedUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"Accessed",    Json::str(utcTimeToIso8601Local(accessedUtc)));
	o.add(L"AccessedUtc", Json::str(timeToIso8601Utc(accessedUtc)));
	/* Each item: the shortcut's fields, and under "DestList" the entry that
	   points to it — last access, host, droid GUIDs, pin status. Those were
	   read and never published. An item holding only "DestList" is an entry
	   whose shortcut stream was missing. */
	Json lnks = Json::arr();
	for (JumplistEntry& e : entries) {
		Json item = e.lnk ? e.lnk->toJson() : Json::obj();
		item.add(L"DestList", e.destList.toJson());
		lnks.push(std::move(item));
	}
	o.add(L"LNKs", std::move(lnks));
	return o;
};

void AutomaticDestination::clear() {
	log(3, L"🔈AutomaticDestination clear");
	entries.clear();   // destroys the elements -> really releases them
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
			              ++iFile, files.size(), L"files");
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
