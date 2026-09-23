/*! \file
 *  \brief Reading of OLE / CFB compound files, as automatic jump lists use them (see oleparser.h).
 */
#include "oleparser.h"

std::wstring Directory::getType(BYTE value) {
	switch (value) {
	case 0: return L"Empty"; break;
	case 1: return L"Storage"; break;
	case 2: return L"Stream"; break;
	case 3: return L"LockBytes"; break;
	case 4: return L"Property"; break;
	case 5: return L"RootStorage"; break;
	default: return L"Unknown"; break;
	}
}

std::wstring Directory::getNodeColor(BYTE value) {
	switch (value) {
	case 0: return L"Red"; break;
	case 1: return L"Black"; break;
	default: return L"Unknown"; break;
	}
}

Directory::Directory(LPBYTE data) {
	nameLength = *reinterpret_cast<short int*>(data + 64);
	name = std::wstring((wchar_t*)(data)).data();
	log(3, L"🔈getType type");
	type = getType(data[66]);
	log(3, L"🔈getNodeColor nodeColor");
	nodeColor = getNodeColor(data[67]);
	previousDirectoryId = *reinterpret_cast<int*>(data + 68);
	nextDirectoryId = *reinterpret_cast<int*>(data + 72);
	subDirectoryId = *reinterpret_cast<int*>(data + 76);
	log(3, L"🔈guid_to_wstring classId");
	classId = guid_to_wstring(*reinterpret_cast<GUID*>(data + 80));
	userFlags = *reinterpret_cast<unsigned int*>(data + 96);
	created = *reinterpret_cast<FILETIME*>(data + 100);
	log(3, L"🔈LocalFileTimeToFileTime createdUtc");
	LocalFileTimeToFileTime(&created, &createdUtc);
	modified = *reinterpret_cast<FILETIME*>(data + 108);
	log(3, L"🔈LocalFileTimeToFileTime modifiedUtc");
	LocalFileTimeToFileTime(&modified, &modifiedUtc);
	firstSectorID = *reinterpret_cast<unsigned int*>(data + 116);
	directorySize = *reinterpret_cast<unsigned int*>(data + 120);
};

Json Directory::toJson() {
	log(3, L"🔈Directory toJson");
	Json o = Json::obj();
	o.add(L"DirectoryName",          Json::str(name));
	o.add(L"DirectoryType",          Json::str(type));
	o.add(L"NodeColor",              Json::str(nodeColor));
	o.add(L"PreviousDirectoryId",    Json::num((long long)previousDirectoryId));
	o.add(L"NextDirectoryId",        Json::num((long long)nextDirectoryId));
	o.add(L"SubDirectoryId",         Json::num((long long)subDirectoryId));
	o.add(L"ClassId",                Json::str(classId));
	o.add(L"UserFlags",              Json::num((long long)userFlags));
	o.add(L"CreationTime",           Json::str(timeToIso8601Local(created)));
	o.add(L"CreationTimeUtc",        Json::str(timeToIso8601Utc(createdUtc)));
	o.add(L"ModifiedTime",           Json::str(timeToIso8601Local(modified)));
	o.add(L"ModifiedTimeUtc",        Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"FirstDirectorySectorId", Json::num((long long)firstSectorID));
	o.add(L"DirectorySize",          Json::num((long long)directorySize));
	return o;
}

DestFile::DestFile(LPBYTE buffer) {
	log(3, L"🔈guid_to_wstring guidDroidVolume");
	guidDroidVolume = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈guid_to_wstring guidDroidFile");
	guidDroidFile = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 24));
	log(3, L"🔈guid_to_wstring guidBirthDroidVolume");
	guidBirthDroidVolume = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 56));
	log(3, L"🔈guid_to_wstring guidBirthDroidFile");
	guidBirthDroidFile = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 56));
	log(3, L"🔈string_to_wstring hostname");
	hostname = string_to_wstring(std::string((char*)(buffer + 72)));
	entryNumber = *reinterpret_cast<unsigned int*>(buffer + 88);
	lastModificationTimeUtc = *reinterpret_cast<FILETIME*>(buffer + 100);
	log(3, L"🔈timeToIso8601 lastModificationTimeUtc");
	if (timeToIso8601Utc(lastModificationTimeUtc) != L"") {
		log(3, L"🔈utcVersLocalSuspect lastModificationTimeUtc");
		utcToSuspectLocal(lastModificationTimeUtc, &lastModificationTime);
	}
	pinStatus = *reinterpret_cast<int*>(buffer + 108);
	pathObjectSize = *reinterpret_cast<unsigned short int*>(buffer + 128);
	pathObject = std::wstring((wchar_t*)(buffer + 130)).data();
	size = 130 + pathObjectSize * 2 + 4; // +2 end of string +2 unknown
};

std::wstring DestFile::getPinnedStatus() {
	if (pinStatus >= 0)
		return L"Pinned";
	else
		return L"Unpinned";
}

Json DestFile::toJson() {
	log(3, L"🔈DestFile toJson");
	Json o = Json::obj();
	o.add(L"GuidDroidVolume",         Json::str(guidDroidVolume));
	o.add(L"GuidDroidFile",           Json::str(guidDroidFile));
	o.add(L"GuidBirthDroidVolume",    Json::str(guidBirthDroidVolume));
	o.add(L"GuidBirthDroidFile",      Json::str(guidBirthDroidFile));
	o.add(L"Hostname",                Json::str(hostname));
	o.add(L"EntryNumber",             Json::num((long long)entryNumber));
	o.add(L"LastModificationTimeUtc", Json::str(timeToIso8601Utc(lastModificationTimeUtc)));
	o.add(L"LastModificationTime",    Json::str(timeToIso8601Local(lastModificationTime)));
	// FIX: "Pinned"/"Unpinned" was inserted without quotes -> invalid JSON
	o.add(L"PinStatus",               Json::str(getPinnedStatus()));
	o.add(L"PathObject",              Json::str(pathObject));
	return o;
}

DestFileDirectory::DestFileDirectory(LPBYTE buffer) {
	formatVersion = *reinterpret_cast<int*>(buffer);
	numberOfEntries = *reinterpret_cast<int*>(buffer + 4);
	numberPinnedEntries = *reinterpret_cast<int*>(buffer + 8);
	int offset = 32;
	for (int x = 0; x < numberOfEntries; x++) {
		log(3, L"🔈DestFile");
		DestFile d = DestFile(buffer + offset);
		offset += d.size; // the size varies from one entry to the next, because of the path's length
		destfiles.push_back(d);
	}
};

Json DestFileDirectory::toJson() {
	log(3, L"🔈DestFileDirectory toJson");
	Json arr = Json::arr();
	for (DestFile& d : destfiles) arr.push(d.toJson());   // a reference: no more copy
	return arr;
}

namespace {

/*! 2^exponent, as an integer, or 0 if the exponent falls outside the plausible
 *  bounds of the CFB format. Avoids `pow` (floating point) and the truncation
 *  of a cast to a type that is too small: the value returned serves to compute
 *  offsets. */
int powerOfTwoOrZero(unsigned int exponent) {
	// CFB uses 9 (512 B) or 12 (4096 B) for the sectors, 6 (64 B) for the short
	// sectors. [6, 16] is tolerated and the rest rejected.
	if (exponent < 6 || exponent > 16) return 0;
	return 1 << exponent;
}

} // namespace

oleHeader::oleHeader(LPBYTE buffer, size_t _bufferSize) {
	signature = *reinterpret_cast<unsigned long long*>(buffer);
	if (signature != _signature) {
		log(2, L"🔥oleHeader signature " + to_hex(signature), ERROR_NDIS_BAD_VERSION);
		throw std::runtime_error("bad signature");
	}
	littleIndian = (*reinterpret_cast<short int*>(buffer + 28) == (short)0xfffe); //0xfeff = big indian
	if (littleIndian == false) {
		log(2, L"🔥Big indian Format not Handle, please handle this file specifically");
		throw std::runtime_error("Big indian Format not Handle, please handle this file specifically");
	}

	versionMinor = *reinterpret_cast<unsigned short*>(buffer + 24); // Minor version at offset 24
	versionMajor = *reinterpret_cast<unsigned short*>(buffer + 26); // Major version at offset 26

	/* The sector sizes are stored as a POWER OF 2. The exponent comes from the
	   file parsed: not validated, it produces absurd sizes (exponent 15 ->
	   -32768 on a short, exponent 16 -> 0) which then served to compute every
	   offset, hence reads out of bounds on a forged file. */
	sectorSize      = powerOfTwoOrZero(*reinterpret_cast<unsigned short*>(buffer + 30)); // offset 30
	shortSectorSize = powerOfTwoOrZero(*reinterpret_cast<unsigned short*>(buffer + 32)); // offset 32
	if (sectorSize == 0 || shortSectorSize == 0 || shortSectorSize > sectorSize) {
		log(2, L"🔥oleHeader: invalid sector sizes — sector " + std::to_wstring(sectorSize)
		     + L", short sector " + std::to_wstring(shortSectorSize), ERROR_FILE_CORRUPT);
		throw std::runtime_error("bad sector size");
	}

	/* The major version imposes the sector size (MS-CFB): an inconsistency
	   signals a corruption or a falsification, which is useful information for
	   the report. */
	const int expected = (versionMajor == 3) ? 512 : (versionMajor == 4) ? 4096 : 0;
	if (expected != 0 && sectorSize != expected)
		log(2, L"🔥oleHeader inconsistent: major version " + std::to_wstring(versionMajor)
		     + L" expects sectors of " + std::to_wstring(expected)
		     + L" B, the header declares " + std::to_wstring(sectorSize) + L" o");
	totalSATSectors = *reinterpret_cast<int*>(buffer + 44); // Total Sector Allocation Table(SAT) sectors at offset 44
	directoryStreamFirstSectorId = *reinterpret_cast<int*>(buffer + 48); // Sector ID of first sector used by Directory at offset 48
	minimumStandardStreamSize = *reinterpret_cast<unsigned int*>(buffer + 56); // Minimum size of a standard stream in bytes at offset 56
	SSATFirstSectorId = *reinterpret_cast<int*>(buffer + 60); // Sector ID of the first sector used for the Short Sector Allocation Table(SSAT) at offset 60
	totalSSATSectors = *reinterpret_cast<unsigned int*>(buffer + 64); // Total sectors used for SSAT at offset 64
	MSATFirstSectorId = *reinterpret_cast<int*>(buffer + 68);
	MSATTotalSectors = *reinterpret_cast<int*>(buffer + 72);
	// Process MSAT
	if (_bufferSize < 516)
		throw std::length_error("File corrupt - file smaller than header size"); // header = 76 + 109*4 + 4

	for (int i = 0; i < 109; i++) {
		int addr = *reinterpret_cast<int*>(buffer + 76 + i * 4);

		if (addr >= 0) {
			if (i < totalSATSectors) {
				log(3, L"🔈SATSectors");
				SATSectors.push_back(addr * sectorSize + 512); // 512 is for the header
			}
			else {
				log(2, L"🔥The total number of sectors was larger than the one expected from the header data",ERROR_FILE_CORRUPT);
				throw std::length_error("File corrupt - The total number of sectors was larger than the one expected from the header data");
			}
		}
	}
}

oleParser::oleParser(LPBYTE _buffer, size_t _bufferSize) {
	buffer = _buffer;
	bufferSize = _bufferSize;

	// 0. Process header
	header = oleHeader(buffer, _bufferSize);

	//Big Files
	if (header.MSATFirstSectorId > -2) {
		int maxSlotsPerBlock = header.sectorSize / 4;
		int remainingSlots = header.totalSATSectors - 109; // 109 for header part already done
		int remainingByteLen = 4 * remainingSlots;
		int msatOffset = (header.MSATFirstSectorId + 1) * header.sectorSize;
		int startOffset = 0;
		/* A `unique_ptr` as a precaution: the function throws exceptions almost
		   everywhere ("file corrupt …"), and a `throw` added between this
		   allocation and its manual release would leak silently. */
		std::unique_ptr<BYTE[]> msatBuffer = std::make_unique<BYTE[]>(remainingByteLen);
		LPBYTE remainingBytes = msatBuffer.get();
		while (remainingSlots > 0) {
			if (remainingSlots > maxSlotsPerBlock) {
				// in this case we have to only take so many
				for (int x = 0; x < header.sectorSize - 4; x++) {
					remainingBytes[x] = buffer[msatOffset + x];
				}
				remainingSlots -= maxSlotsPerBlock - 1;
				int newOffset = *reinterpret_cast<int*>(buffer + msatOffset + (4 * (maxSlotsPerBlock - 1)));
				msatOffset = (newOffset + 1) * header.sectorSize;
				startOffset += (maxSlotsPerBlock - 1) * 4;
			}
			else {
				//copy it and be done with it
				for (int x = 0; x < remainingSlots * 4; x++) {
					remainingBytes[startOffset + x] = buffer[msatOffset + x];
					remainingSlots -= remainingSlots;
				}
			}
		}

		remainingSlots = header.totalSATSectors - 109;

		for (int i = 0; i < remainingSlots; i += 4)
		{
			int sectorId = *reinterpret_cast<int*>(remainingBytes + i * 4) * header.sectorSize + 512; // 512 is for the header
			header.SATSectors.push_back(sectorId);
		}
		// The buffer is released by its unique_ptr.
	}

	//We need to get all the bytes that make up the SectorAllocationTable
	//start with empty array to hold our bytes


	for (int sector : header.SATSectors)
	{
		if (sector + header.sectorSize > _bufferSize)
			throw std::length_error("file corrupt - Error copying data from the Sector Allocation Table");

		//fill the Sat
		for (int x = 0; x < header.sectorSize; x += 4) { // for each "sector", sectorSize integers are copied
			log(3, L"🔈*reinterpret_cast<int*> sat");
			sat.push_back(*reinterpret_cast<int*>(buffer + sector + x));
		}
	}

	//Just as with the SAT, but this time, with the SmallSectorAllocationTable
	if (header.SSATFirstSectorId != -2)
	{
		log(3, L"🔈GetIntFromSat ssat");
		ssat = GetIntFromSat(header.SSATFirstSectorId);
	}

	// 1. Process all Directory entries
	// https://github.com/EricZimmerman/OleCf/blob/master/OleCf/OleCfFile.cs#L138

	log(3, L"🔈GetBytesFromSat dirBytes");
	std::vector<BYTE> dirBytes = GetBytesFromSat(header.directoryStreamFirstSectorId);
	LPBYTE pDirBytes = &dirBytes[0];
	int dirIndex = 0;
	if (dirIndex + 128 > dirBytes.size())
		throw std::length_error("file corrupt - Error copying data from directory index");

	while (dirIndex < dirBytes.size())
	{
		log(3, L"🔈*reinterpret_cast<short int*> dirLen");
		int dirLen = *reinterpret_cast<short int*>(pDirBytes + dirIndex + 64);
		if (pDirBytes[dirIndex + 66] != 0 && dirLen > 0) { //0 is empty directory structure
			log(3, L"🔈Directory d");
			Directory d = Directory(pDirBytes + dirIndex);
			directories.push_back(d);
		}
		dirIndex += 128;
	}

	//the Root Entry directory item contains all the sectors we need for small sector stuff, so get the data and cut it up so we can use it later
   //when we are done we will have a list of byte arrays, each 64 bytes long, that we can string together later based on SSAT

	log(3, L"🔈findDirectory rootEntry");
	rootEntry = findDirectory(L"root entry");
	if (rootEntry.name != L"" && rootEntry.directorySize > 0) {
		std::vector<BYTE> b = GetBytesFromSat((int)rootEntry.firstSectorID);
		int shortIndex = 0;
		while (shortIndex < b.size())
		{
			std::vector<BYTE> shortChunk;
			if (shortIndex + header.shortSectorSize > b.size())
				throw std::length_error("file corrupt - Error copying data for short sector");

			for (int x = 0; x < header.shortSectorSize; x++)
				shortChunk.push_back(b[shortIndex + x]);
			shortSectors.push_back(shortChunk);
			shortIndex += header.shortSectorSize;
		}
	}
};

Directory oleParser::findDirectory(std::wstring name) {

	transform(name.begin(), name.end(), name.begin(), towlower);
	for (Directory d : directories) {
		transform(d.name.begin(), d.name.end(), d.name.begin(), towlower);
		if (d.name == name)
			return d;
	}
	return Directory();
}

std::vector<int> oleParser::sectorChain(const std::vector<int>& table, int first) {
	std::vector<int> string;
	int current = first;
	// A chain cannot be longer than the table: beyond that, it loops.
	while (string.size() <= table.size()) {
		if (current < 0 || (size_t)current >= table.size())
			throw std::length_error("file corrupt - sector index out of range");
		string.push_back(current);
		const int next = table[current];
		if (next < 0) return string;        // -2 ENDOFCHAIN and other markers
		current = next;
	}
	throw std::length_error("file corrupt - cyclic sector chain");
}

std::vector<int> oleParser::GetIntFromSat(int sectorNumber) {
	const size_t sectorSize = (size_t)header.sectorSize;
	std::vector<int> retBytes;
	for (int i : sectorChain(sat, sectorNumber))
	{
		const size_t index = 512 + sectorSize * (size_t)i;   // header + relative offset
		if (index >= bufferSize)
			throw std::length_error("file corrupt - Error retrieving data from SAT");
		// A sector can be truncated at the end of the file: what is left is read.
		const size_t readSize = (bufferSize - index < sectorSize) ? bufferSize - index : sectorSize;
		for (size_t x = 0; x + 4 <= readSize; x += 4) {
			log(3, L"🔈*reinterpret_cast<int*> retBytes");
			retBytes.push_back(*reinterpret_cast<int*>(buffer + index + x));
		}
	}
	return retBytes;
};

std::vector<BYTE> oleParser::GetBytesFromSat(int sectorNumber) {
	const size_t sectorSize = (size_t)header.sectorSize;
	std::vector<BYTE> retBytes;
	for (int i : sectorChain(sat, sectorNumber))
	{
		const size_t index = 512 + sectorSize * (size_t)i;   // header + relative offset
		if (index >= bufferSize)
			throw std::length_error("file corrupt - Error retrieving data from SAT");
		// A sector can be truncated at the end of the file: what is left is read.
		const size_t readSize = (bufferSize - index < sectorSize) ? bufferSize - index : sectorSize;
		retBytes.insert(retBytes.end(), buffer + index, buffer + index + readSize);
	}
	return retBytes;
};

std::vector<BYTE> oleParser::GetBytesFromSSat(int sectorNumber) {
	std::vector<BYTE> retBytes;
	const size_t size = (size_t)header.shortSectorSize;
	for (int i : sectorChain(ssat, sectorNumber))
	{
		// FIX: the test was `i > size()`, which let i == size() through.
		if ((size_t)i >= shortSectors.size() || size > shortSectors[i].size())
			throw std::length_error("file corrupt - Error retrieving data from SSAT");
		const std::vector<BYTE>& sector = shortSectors[i];
		retBytes.insert(retBytes.end(), sector.begin(), sector.begin() + size);
	}
	return retBytes;
}
