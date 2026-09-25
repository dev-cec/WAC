/*! \file
 *  \brief Decoding of the .lnk shortcuts of the Recent folder (see recent_docs.h).
 */
#include "recent_docs.h"
#include "consigne.h"

namespace {

/*! Reads a StringData field of a .lnk shortcut.
*
*  FORMAT (MS-SHLLINK). Each field is a count of CHARACTERS on two bytes,
*  followed by the characters themselves — **without a null terminator**. The
*  original code ignored that count and built the string up to the first zero
*  met: right by accident when Windows writes one, but otherwise the string
*  overflowed onto the next field, and on a truncated or forged file the reading
*  went out of the buffer.
*
*  @param buffer start of the .lnk file in memory
*  @param size total size of the buffer
*  @param offset position of the field
*  @param next receives the position of the next field
*  @return the string read, or "" if the field is inconsistent
*/
std::wstring readStringData(LPBYTE buffer, size_t size, size_t offset, size_t* next) {
	*next = offset;
	if (offset + 2 > size) {
		log(2, L"🔥StringData outside the buffer at offset " + std::to_wstring(offset));
		return L"";
	}
	const unsigned short nbCar = *reinterpret_cast<unsigned short*>(buffer + offset);
	const size_t bytes = (size_t)nbCar * sizeof(wchar_t);
	if (offset + 2 + bytes > size) {
		log(2, L"🔥StringData declares " + std::to_wstring(nbCar)
		     + L" characters, beyond the buffer");
		return L"";
	}
	*next = offset + 2 + bytes;
	return std::wstring((wchar_t*)(buffer + offset + 2), nbCar);
}

} // namespace

void RecentDoc::parseLNK(LPBYTE buffer, size_t size) {
	/* Every field of a shortcut is read at an offset the file itself declares.
	   A truncated or forged .lnk must not make WAC read past its buffer: these
	   two accessors return 0 outside it, and each structure (header, ID list,
	   LinkInfo) is checked against the buffer before it is walked. */
	auto u16 = [&](size_t at) -> unsigned int {
		return (at <= size && size - at >= 2) ? *reinterpret_cast<unsigned short*>(buffer + at) : 0u; };
	auto u32 = [&](size_t at) -> unsigned int {
		return (at <= size && size - at >= 4) ? *reinterpret_cast<unsigned int*>(buffer + at) : 0u; };
	if (size < 76) {
		log(2, L"🔥LNK: file shorter than its 76-byte header", ERROR_INVALID_DATA);
		return;
	}
	unsigned int header_size = u32(0);
	guid = *reinterpret_cast<GUID*>(buffer + 4);
	log(3, L"🔈guid_to_wstring guid");
	if (guid_to_wstring(guid).compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
		flags = LinkFlags(u32(20));
		unsigned int fileAttributes = u32(24);
		log(3, L"🔈FileAttributes");
		attributes = FileAttributes(fileAttributes);
		/* FIX (a double shift, the same defect as the mirrored FAT dates).
		   In the header of a .lnk file, the target's CreationTime /
		   LastAccessTime / LastWriteTime are in UTC (MS-SHLLINK 2.1). The code
		   assigned them to the LOCAL fields then called LocalFileTimeToFileTime:
		   the local key therefore carried unconverted UTC, and the *Utc key
		   carried UTC shifted once too often.
		   The right way round: the native value is UTC, and the local one is
		   derived from it.
		   The test "if the formatted date is not empty" that surrounded the
		   conversion is removed: formatting a date to find out whether it is null
		   is useless, and converting a null date has no effect. */
		targetCreatedUtc = *reinterpret_cast<FILETIME*>(buffer + 28);

		targetAccessedUtc = *reinterpret_cast<FILETIME*>(buffer + 36);

		targetModifiedUtc = *reinterpret_cast<FILETIME*>(buffer + 44);
		iconIndex = u32(56);
		log(3, L"🔈showCommandOption commandOption");
		commandOption = showCommandOption(u32(60)); //
		//debug
		if (commandOption == L"UNKOWN")
			log(2, L"🔥commandOption Unknown 0x" + to_hex(u32(60)));

		//-------------------------------------------------------------------------
		// Shell item id list (starts at 76 with 2 byte length -> so we can skip):
		//-------------------------------------------------------------------------

		unsigned short int LinkTargetIDList_size = 0;
		int LinkTargetIDList_offset = header_size;
		if (flags.HasLinkTargetIDList)
		{
			LinkTargetIDList_size = u16(LinkTargetIDList_offset); //size of item id list

			/* The list runs from offset 78 to 78 + its declared size. The loop
			   compared the absolute OFFSET with the SIZE, which stopped it up to
			   78 bytes before the end of the list: the last items were lost —
			   often the one that names the target. Seen on the test VM: a shortcut
			   whose list holds a root folder and a URI item came out with no item
			   at all, its twin with the root folder only. */
			const size_t listEnd = std::min(size, (size_t)LinkTargetIDList_offset + 2 + LinkTargetIDList_size);
			size_t offset = (size_t)LinkTargetIDList_offset + 2;
			while (offset + 2 <= listEnd) {
				const unsigned short item_size = (unsigned short)u16(offset);
				if (item_size == 0) break;                              // terminal item
				if (item_size < 3 || item_size > listEnd - offset) {    // item overruns the list
					log(2, L"🔥LNK: shell item of " + std::to_wstring(item_size)
					     + L" bytes overruns the ID list, walk stopped", ERROR_INVALID_DATA);
					break;
				}
				idLists.push_back(IdList(buffer + offset, 2)); // lvl 1 is object itself
				offset += item_size;
			}

		}
		//-------------------------------------------------------------------------
		// File location info:
		//-------------------------------------------------------------------------
		// Follows the shell item id list and starts with 4 byte structure length,
		// followed by 4 byte offset for skipping.
		//-------------------------------------------------------------------------
		unsigned int LinkInfo_size = 0;
		int LinkInfo_offset = LinkTargetIDList_offset + 2 + LinkTargetIDList_size;

		if (flags.HasLinkInfo) {
			LinkInfo_size = u32(LinkInfo_offset);
			// The LinkInfo strings are read within the LinkInfo structure, which
			// must itself fit in the file.
			const size_t infoEnd = ((size_t)LinkInfo_offset + LinkInfo_size <= size)
			                       ? (size_t)LinkInfo_offset + LinkInfo_size : size;
			unsigned int link_flags = u32(LinkInfo_offset + 8);
			bool VolumeIDAndLocalBasePath = link_flags & 0x1;
			bool CommonNetworkRelativeLinkAndPathSuffix = link_flags & 0x2;
			//-------------------------------------------------------------------------
			// Volume Id info:
			//-------------------------------------------------------------------------
			unsigned int volumeId_offset = u32(LinkInfo_offset + 12); //volume id offset
			if (VolumeIDAndLocalBasePath == true && volumeId_offset != 0) {
				unsigned int driveType = u32(LinkInfo_offset + volumeId_offset + 4);
				log(3, L"🔈driveType_to_wstring volumeDriveType");
				volumeDriveType = driveType_to_wstring(driveType);
				//debug
				if (volumeDriveType == L"BAD TYPE")
					log(2, L"🔥volumeDriveType BAD TYPE 0x" + to_hex(driveType), ERROR_UNSUPPORTED_TYPE);
				unsigned int serial = u32(LinkInfo_offset + volumeId_offset + 8);
				
				log(3, L"🔈to_hex volumeSerial");
				volumeSerial = to_hex(serial);
				transform(volumeSerial.begin(), volumeSerial.end(), volumeSerial.begin(), ::toupper);
				
				/*  VOLUME LABEL. The .lnk specification is explicit: a value of 0x14
				    in VolumeLabelOffset signals that the label is NOT at that
				    place, but in UTF-16 at the offset given by
				    VolumeLabelOffsetUnicode, just after.
				    The code did read that second offset but reused the first one,
				    and treated the string as ANSI: the label came out wrong —
				    every other byte being a zero, it most often came out
				    truncated at the first character. */
				unsigned int labeloffset = u32(LinkInfo_offset + volumeId_offset + 12);
				if (labeloffset != 0x14) {
					log(3, L"🔈decodeText volumeLabel (ANSI)");
					volumeLabel = decodeText(readNarrowZ(buffer, infoEnd, (size_t)LinkInfo_offset + volumeId_offset + labeloffset));
				}
				else {
					unsigned int labeloffsetunicode = u32(LinkInfo_offset + volumeId_offset + 16);
					log(3, L"🔈volumeLabel (UTF-16)");
					volumeLabel = readWideZ(buffer, infoEnd,
					                        (size_t)LinkInfo_offset + volumeId_offset + labeloffsetunicode);
				}
			}
			//-------------------------------------------------------------------------
			// Local path std::string (ending with 0x00):
			//-------------------------------------------------------------------------
			/* Two defects fixed here (MS-SHLLINK 2.3):
			   - the path was read even without the VolumeIDAndLocalBasePath flag,
			     whose offset is then 0: the LinkInfo header was read as a string;
			   - a LinkInfo header of 0x24 bytes or more carries, at +28, the offset
			     of a UNICODE copy of the path. The ANSI one loses every character
			     outside the code page — seen on a real machine: "‐" became "-",
			     a Chinese file name "??????.docx". The Unicode copy now prevails. */
			const unsigned int LocalPath_offset = u32(LinkInfo_offset + 16); //local path offset from start of fileinfo
			const unsigned int linkInfoHeaderSize = u32(LinkInfo_offset + 4);
			const unsigned int LocalPathUnicode_offset = (linkInfoHeaderSize >= 0x24) ? u32(LinkInfo_offset + 28) : 0;
			if (VolumeIDAndLocalBasePath && LocalPathUnicode_offset != 0) {
				log(3, L"🔈readWideZ target (UTF-16)");
				target = readWideZ(buffer, infoEnd, (size_t)LinkInfo_offset + LocalPathUnicode_offset);
			}
			else if (VolumeIDAndLocalBasePath && LocalPath_offset != 0) {
				log(3, L"🔈decodeText target");
				target = decodeText(readNarrowZ(buffer, infoEnd, (size_t)LinkInfo_offset + LocalPath_offset));
			}
			// RAW value: the escaping is centralised in json.h.
			if (conf.binary && !target.empty()) {
				/* Raw reading: opening the target through the API would update its
				   last access date — on the very document whose shortcut attests
				   the opening. */
				log(3, L"🔈FingerprintFile on the target " + target);
				targetFingerprint = FingerprintFile(target);
			}
			//-------------------------------------------------------------------------
			// Common Network Relative Link info:
			//-------------------------------------------------------------------------
			unsigned int network_offset = u32(LinkInfo_offset + 20); //common network offset
			if (CommonNetworkRelativeLinkAndPathSuffix && network_offset != 0) {
				unsigned int net_flags = u32(LinkInfo_offset + network_offset + 4);
				/* Bitwise tests. They were written `net_flags && 0x1`, a LOGICAL and:
				   both flags came out true as soon as any flag was set. */
				bool ValidDevice = (net_flags & 0x1) != 0;
				bool ValidNetType = (net_flags & 0x2) != 0;
				unsigned int NetNameOffset = u32(LinkInfo_offset + network_offset + 8);
				log(3, L"🔈decodeText netName");
				netName = decodeText(readNarrowZ(buffer, infoEnd, (size_t)LinkInfo_offset + network_offset + NetNameOffset));
				unsigned int DeviceNameOffset = u32(LinkInfo_offset + network_offset + 12);
				if (ValidDevice == true && DeviceNameOffset != 0) {
					log(3, L"🔈decodeText netDeviceName");
					// Read at DeviceNameOffset: it was read at NetNameOffset, so the
					// device name always repeated the network name.
					netDeviceName = decodeText(readNarrowZ(buffer, infoEnd, (size_t)LinkInfo_offset + network_offset + DeviceNameOffset));
				}
				if (ValidNetType == true) {
					log(3, L"🔈networkProvider_to_wstring netProviderType");
					// NetworkProviderType is at offset 16 (MS-SHLLINK 2.3.2); it was
					// read at 14, across two fields.
					netProviderType = networkProvider_to_wstring(u32(LinkInfo_offset + network_offset + 16));
					//debug
					if (netProviderType == L"BAD NET PROVIDER")
						log(2, L"🔥netProviderType Unknown 0x" + to_hex(u32(LinkInfo_offset + network_offset + 16)), ERROR_UNSUPPORTED_TYPE);
				}
			}
		}
		else
			target = L"";

		//-------------------------------------------------------------------------
		// String Data info:
		//-------------------------------------------------------------------------
		int stringData_offset = LinkInfo_offset + LinkInfo_size;

		/* The five StringData fields follow one another, each giving the position of
		   the next by its length. A single wrong offset therefore shifts
		   everything that follows: that is exactly what happened here,
		   `arguments_size` being read at the offset of the WORKING DIRECTORY
		   instead of its own. The `iconLocation` field, computed from that size,
		   was therefore read in the wrong place. RAW values: the escaping is
		   centralised in json.h. */
		size_t next = (size_t)stringData_offset;
		description      = flags.HasName         ? readStringData(buffer, size, next, &next) : L"";
		relativePath     = flags.HasRelativePath ? readStringData(buffer, size, next, &next) : L"";
		workingDirectory = flags.HasWorkingDir   ? readStringData(buffer, size, next, &next) : L"";
		arguments        = flags.HasArguments    ? readStringData(buffer, size, next, &next) : L"";
		iconLocation     = flags.HasIconLocation ? readStringData(buffer, size, next, &next) : L"";
	}
}

RecentDoc::RecentDoc(std::filesystem::path _path, std::wstring _sid) {
	//Parsing
	Sid = _sid;
	// the path in UTF-16, as Windows holds it
	path = _path.wstring();
	log(3, L"🔈replaceAll path_original");
	path_original = originalPath(path);
	log(2, L"❇️RecentDoc path " + path_original);
	target = L"";
	if (_path.extension() == ".lnk" || _path.extension() == ".LNK") {
		std::ifstream file(_path, std::ios::binary);
		if (file.good())
		{
			file.unsetf(std::ios::skipws);
			file.seekg(0, std::ios::end);
			const size_t size = file.tellg();
			file.seekg(0, std::ios::beg);

			std::vector<BYTE> content(size);
			LPBYTE buffer = content.data();
			file.read(reinterpret_cast<CHAR*>(buffer), size);
			file.close();
			if (conf.binary) {
				log(3, L"🔈fileToHash md5Source " + _path.wstring());
				md5Source = QuickDigest5::fileToHash(_path);
			}
			log(3, L"🔈parseLNK");
			parseLNK(buffer, size);
		}
	}
	if (_path.extension() == ".url" || _path.extension() == ".URL") {
		std::ifstream file(_path);
		std::string line;
		if (file.is_open()) {
			getline(file, line); //skip first line
			getline(file, line);
			// strip the leading "URL=" (a shorter line would throw std::out_of_range)
			line = line.size() >= 4 ? line.substr(4) : std::string();
			log(3, L"🔈decodeURIComponent line");
			line = decodeURIComponent(line);
			// Decoded %xx escapes are UTF-8 bytes, not ANSI.
			log(3, L"🔈decodeText (UTF-8) line");
			target = decodeText(line, CP_UTF8);
			file.close();
		}
	}

	// The dates of the file ON THE EXAMINED MACHINE, as the raw reading recorded
	// them: the working copy's own are those of the collection (ExhibitSourceTimes).
	if (!ExhibitSourceTimes(_path.wstring(), sourceCreatedUtc, sourceModifiedUtc, sourceAccessedUtc))
		log(2, L"🔥Source timestamps not recorded: " + _path.wstring());
}

RecentDoc::RecentDoc(LPBYTE buffer, size_t size, std::wstring _path, std::wstring _sid) {
	Sid = _sid;
	path = _path;

	path_original = originalPath(path);
	log(2, L"❇️RecentDoc path " + path_original);
	if (conf.binary) {
		log(3, L"🔈fileToHash md5Source " + _path);
		md5Source = QuickDigest5::fileToHash(_path);
	}
	target = L"";
	log(3, L"🔈parseLNK");
	parseLNK(buffer, size);
}

Json RecentDoc::toJson() {
	log(3, L"🔈RecentDoc toJson");
	Json o = Json::obj();
	o.add(L"Path",              Json::str(path_original));
	if (!md5Source.empty()) o.add(L"Md5Source", Json::str(md5Source));
	o.add(L"Target",            Json::str(target));
	addFingerprints(o, targetFingerprint, L"", L"Target");
	o.add(L"SourceCreated",     Json::str(utcTimeToIso8601Local(sourceCreatedUtc)));
	o.add(L"SourceCreatedUtc",  Json::str(timeToIso8601Utc(sourceCreatedUtc)));
	o.add(L"SourceModified",    Json::str(utcTimeToIso8601Local(sourceModifiedUtc)));
	o.add(L"SourceModifiedUtc", Json::str(timeToIso8601Utc(sourceModifiedUtc)));
	o.add(L"SourceAccessed",    Json::str(utcTimeToIso8601Local(sourceAccessedUtc)));
	o.add(L"SourceAccessedUtc", Json::str(timeToIso8601Utc(sourceAccessedUtc)));
	o.add(L"TargetCreated",     Json::str(utcTimeToIso8601Local(targetCreatedUtc)));
	o.add(L"TargetCreatedUtc",  Json::str(timeToIso8601Utc(targetCreatedUtc)));
	o.add(L"TargetModified",    Json::str(utcTimeToIso8601Local(targetModifiedUtc)));
	o.add(L"TargetModifiedUtc", Json::str(timeToIso8601Utc(targetModifiedUtc)));
	o.add(L"TargetAccessed",    Json::str(utcTimeToIso8601Local(targetAccessedUtc)));
	o.add(L"TargetAccessedUtc", Json::str(timeToIso8601Utc(targetAccessedUtc)));
	o.add(L"LNKFlags",          Json::str(flags.to_wstring()));
	o.add(L"FileAttributes",    Json::str(attributes.to_wstring()));
	o.add(L"IconIndex",         Json::num((long long)iconIndex));   // count
	o.add(L"CommandOption",     Json::str(commandOption));
	o.add(L"Description",       Json::str(description));
	o.add(L"RelativePath",      Json::str(relativePath));
	o.add(L"WorkingDirectory",  Json::str(workingDirectory));
	o.add(L"Arguments",         Json::str(arguments));
	o.add(L"IconLocation",      Json::str(iconLocation));
	o.add(L"VolumeDriveType",   Json::str(volumeDriveType));
	o.add(L"VolumeSerial",      Json::str(volumeSerial));
	o.add(L"VolumeLabel",       Json::str(volumeLabel));
	o.add(L"NetName",           Json::str(netName));
	o.add(L"NetProviderType",   Json::str(netProviderType));
	o.add(L"NetDeviceName",     Json::str(netDeviceName));
	Json ids = Json::arr();
	for (IdList& id : idLists) ids.push(id.toJson());
	o.add(L"IdList", std::move(ids));
	return o;
}

void RecentDoc::clear() {
	log(3, L"🔈RecentDoc clear");
	idLists.clear();   // destroys the elements -> really releases them
}

HRESULT RecentDocs::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Recent Docs : ");
	log(0, L"*******************************************************************************************************************");

	const std::wstring reps[2] = { L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent", L"\\AppData\\Roaming\\Microsoft\\Office\\Recent" };
	for (const std::wstring& rep : reps) {
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
			// extractedPath() handles the case of a profile on another volume than
			// Windows, which replaceAll(conf.systemDrive) left absolute.
			const std::filesystem::path directory =
				extractedPath(std::get<1>(profileEntry)) + rep;
			const std::vector<std::filesystem::path> files =
				listFilesByExtension(directory, { L".lnk", L".url" });
			size_t iFile = 0;
			for (const std::filesystem::path& file : files) {
				log(1, L"➕RecentDoc");
				printProgress(L"RecentDoc " + file.filename().wstring(),
				              ++iFile, files.size(), L"lnk");
				recentdocs.push_back(RecentDoc(file, std::get<0>(profileEntry)));
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT RecentDocs::toJson() {
	log(3, L"🔈RecentDocs toJson");
	Json arr = Json::arr();
	for (RecentDoc& r : recentdocs) arr.push(r.toJson());
	return writeJsonFile("recentdocs.json", arr);
}

void RecentDocs::clear() {
	log(3, L"🔈RecentDocs clear");
	recentdocs.clear();   // destroys the elements -> really releases them
}
