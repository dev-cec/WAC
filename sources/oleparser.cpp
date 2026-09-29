/*! \file
 *  \brief Reading of OLE / CFB compound files, as automatic jump lists use them (see oleparser.h).
 */
#include "oleparser.h"

Directory::Directory(LPBYTE data) {
	// The name field of a CFB directory entry is 64 bytes: the read stops there.
	name = readWideZ(data, 64, 0);
	firstSectorID = *reinterpret_cast<unsigned int*>(data + 116);
	directorySize = *reinterpret_cast<unsigned int*>(data + 120);
}

DestFile::DestFile(LPBYTE buffer, size_t limit) {
	// The fixed part of an entry is 130 bytes; below that the entry is truncated.
	if (limit < 130) {
		size = 0;
		return;
	}
	log(3, L"🔈guid_to_wstring guidDroidVolume");
	guidDroidVolume = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈guid_to_wstring guidDroidFile");
	guidDroidFile = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 24));
	log(3, L"🔈guid_to_wstring guidBirthDroidVolume");
	// Birth droid volume at 40: it was read at 56, the offset of the birth droid
	// FILE, so both birth GUIDs came out identical.
	guidBirthDroidVolume = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 40));
	log(3, L"🔈guid_to_wstring guidBirthDroidFile");
	guidBirthDroidFile = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 56));
	log(3, L"🔈decodeText hostname");
	hostname = decodeText(readNarrowZ(buffer, 88, 72));   // 16-byte NetBIOS field
	entryNumber = *reinterpret_cast<unsigned int*>(buffer + 88);
	lastModificationTimeUtc = *reinterpret_cast<FILETIME*>(buffer + 100);
	log(3, L"🔈timeToIso8601 lastModificationTimeUtc");
	if (timeToIso8601Utc(lastModificationTimeUtc) != L"") {
	}
	pinStatus = *reinterpret_cast<int*>(buffer + 108);
	pathObjectSize = *reinterpret_cast<unsigned short int*>(buffer + 128);
	// The path is read on its DECLARED length, itself bounded by the stream.
	const size_t chars = std::min<size_t>(pathObjectSize, (limit - 130) / 2);
	pathObject = readWideZ(buffer, 130 + chars * 2, 130);
	size = 130 + pathObjectSize * 2 + 4; // +2 end of string +2 unknown
	if (size > limit) size = 0;          // truncated entry: the walk stops
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
	o.add(L"LastModificationTime",    Json::str(utcTimeToIso8601Local(lastModificationTimeUtc)));
	// FIX: "Pinned"/"Unpinned" was inserted without quotes -> invalid JSON
	o.add(L"PinStatus",               Json::str(getPinnedStatus()));
	o.add(L"PathObject",              Json::str(pathObject));
	return o;
}

DestFileDirectory::DestFileDirectory(LPBYTE buffer, size_t size) {
	if (size < 32) return;                 // no room for the header
	formatVersion = *reinterpret_cast<int*>(buffer);
	numberOfEntries = *reinterpret_cast<int*>(buffer + 4);
	numberPinnedEntries = *reinterpret_cast<int*>(buffer + 8);
	size_t offset = 32;
	// The entry count comes from the file: the walk also stops at the end of the
	// stream, and on an entry that does not fit.
	for (int x = 0; x < numberOfEntries && offset < size; x++) {
		log(3, L"🔈DestFile");
		DestFile d = DestFile(buffer + offset, size - offset);
		if (d.size == 0) break;
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
	/* The header is 512 bytes (76 of fields, then 109 SAT sector ids): its
	   size is checked BEFORE anything is read. The check used to come after
	   the signature and the first 76 bytes. */
	if (_bufferSize < 512)
		throw std::length_error("File corrupt - file smaller than the header");
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
	MSATFirstSectorId = *reinterpret_cast<int*>(buffer + 68);
	// The first 109 SAT sector ids are in the header (the MSAT's head).
	for (int i = 0; i < 109; i++) {
		int addr = *reinterpret_cast<int*>(buffer + 76 + i * 4);

		if (addr >= 0) {
			if (i < totalSATSectors) {
				log(3, L"🔈SATSectorIds");
				SATSectorIds.push_back(addr);
			}
			else {
				log(2, L"🔥The total number of sectors was larger than the one expected from the header data",ERROR_FILE_CORRUPT);
				throw std::length_error("File corrupt - The total number of sectors was larger than the one expected from the header data");
			}
		}
	}
}

size_t oleParser::sectorOffset(int id) const {
	return ((size_t)id + 1) * (size_t)header.sectorSize;
}

oleParser::oleParser(LPBYTE _buffer, size_t _bufferSize) {
	buffer = _buffer;
	bufferSize = _bufferSize;

	// 0. Process header
	header = oleHeader(buffer, _bufferSize);
	const size_t sectorSize = (size_t)header.sectorSize;
	const size_t sectorsInFile = bufferSize / sectorSize;
	// A SAT of more sectors than the file holds cannot be real.
	if (header.totalSATSectors < 0 || (size_t)header.totalSATSectors > sectorsInFile)
		throw std::length_error("file corrupt - SAT larger than the file");

	/* THE REST OF THE MSAT, beyond the 109 ids of the header: a chain of
	   sectors, each holding sectorSize / 4 - 1 SAT sector ids and, in its last
	   slot, the id of the next one. The previous code read those sectors with
	   no bound at all, stopped its last copy after ONE byte (its counter was
	   reset inside the copy loop), then kept one id in four. */
	int next = header.MSATFirstSectorId;
	const size_t idsPerSector = sectorSize / 4 - 1;
	size_t visited = 0;
	while (next >= 0 && header.SATSectorIds.size() < (size_t)header.totalSATSectors) {
		if (++visited > sectorsInFile)
			throw std::length_error("file corrupt - cyclic MSAT chain");
		const size_t offset = sectorOffset(next);
		if (!fits(bufferSize, offset, sectorSize))
			throw std::length_error("file corrupt - MSAT sector outside the file");
		for (size_t k = 0; k < idsPerSector && header.SATSectorIds.size() < (size_t)header.totalSATSectors; ++k) {
			const int id = *reinterpret_cast<int*>(buffer + offset + 4 * k);
			if (id >= 0) header.SATSectorIds.push_back(id);
		}
		next = *reinterpret_cast<int*>(buffer + offset + 4 * idsPerSector);
	}

	// The SAT itself: the concatenation of its sectors, read as 32-bit ids.
	for (int id : header.SATSectorIds) {
		const size_t offset = sectorOffset(id);
		if (!fits(bufferSize, offset, sectorSize))
			throw std::length_error("file corrupt - Error copying data from the Sector Allocation Table");
		for (size_t x = 0; x < sectorSize; x += 4)
			sat.push_back(*reinterpret_cast<int*>(buffer + offset + x));
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
	if (dirBytes.size() < 128)
		throw std::length_error("file corrupt - Error copying data from directory index");

	// Entries of 128 bytes; a partial one at the end is not read.
	for (size_t dirIndex = 0; dirIndex + 128 <= dirBytes.size(); dirIndex += 128) {
		const LPBYTE entry = dirBytes.data() + dirIndex;
		const short dirLen = *reinterpret_cast<short int*>(entry + 64);
		if (entry[66] != 0 && dirLen > 0) { //0 is empty directory structure
			log(3, L"🔈Directory d");
			directories.push_back(Directory(entry));
		}
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
		const size_t index = sectorOffset(i);
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
		const size_t index = sectorOffset(i);
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

std::vector<BYTE> oleParser::Getdata(const Directory& d) {
	if (d.directorySize <= 0) return {};
	/* Streams smaller than the cutoff the header declares live in short
	   sectors; the cutoff was hard-coded to 4096, its usual value. */
	const size_t cutoff = header.minimumStandardStreamSize ? header.minimumStandardStreamSize : 4096;
	std::vector<BYTE> bytes = ((size_t)d.directorySize >= cutoff)
	                          ? GetBytesFromSat((int)d.firstSectorID)
	                          : GetBytesFromSSat((int)d.firstSectorID);
	/* A chain ends on a whole sector: the stream is cut to its declared size.
	   The padding of its last sector used to be handed on as data — to the
	   DestList walk and to the shortcut parser. */
	if (bytes.size() > (size_t)d.directorySize) bytes.resize((size_t)d.directorySize);
	return bytes;
}
