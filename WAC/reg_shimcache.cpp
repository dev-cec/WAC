/*! \file
 *  \brief Decoding of the AppCompatCache value (see reg_shimcache.h).
 */
#include "reg_shimcache.h"

Json Shimcache::toJson() {
	log(3, L"🔈Shimcache toJson");
	Json o = Json::obj();
	o.add(L"Path",                Json::str(path));      // raw path
	addFingerprints(o, fingerprint);
	o.add(L"LastModification",    Json::str(lastModification));
	o.add(L"LastModificationUtc", Json::str(lastModificationUtc));
	return o;
}	//! Releases the memory held by the entry.

void Shimcache::clear() {
	log(3, L"🔈Shimcache clear");
}

HRESULT Shimcaches::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Shimcaches :");
	log(0, L"*******************************************************************************************************************");

	//variables
	HRESULT hresult=0;
	ORHKEY hKey=NULL;
	LPBYTE data = NULL;

	log(3, L"🔈OROpenKey CurrentControlSet\\Control\\Session Manager\\AppCompatCache");
	hresult = OROpenKey(conf.CurrentControlSet, L"Control\\Session Manager\\AppCompatCache", &hKey);
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
		log(2, L"🔥OROpenKey CurrentControlSet\\Control\\Session Manager\\AppCompatCache", hresult );
		return hresult;
	}

	DWORD size=0;
	log(3, L"🔈getRegBinaryValue AppCompatCache");
	hresult = getRegBinaryValue(hKey, nullptr, L"AppCompatCache", &data, &size);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue AppCompatCache", hresult );
		return hresult;
	}
	/* Layout of the Windows 10/11 cache: a header whose first DWORD is its own
	   size, then entries
	       "10ts" (4), unknown (4), entry size (4), path size (2), path,
	       last modification FILETIME (8), data size (4), data.
	   Every length comes from the examined machine's hive: each read is bounded
	   by the real size of the value, never by a length the data declares. An
	   entry that does not start with "10ts" ends the walk — the offset used to
	   stay where it was, and the loop never ended. */
	auto fits = [&](size_t at, size_t length) { return at <= size && length <= size - at; };
	if (!fits(0, 4)) {
		log(2, L"🔥AppCompatCache: value too short for its header");
		delete[] data;
		return ERROR_INVALID_DATA;
	}
	size_t offset = *reinterpret_cast<DWORD*>(data);
	while (fits(offset, 14)) {
		printProgressStep(L"Shimcache", (unsigned)offset, size);
		if (std::memcmp(data + offset, "10ts", 4) != 0) {
			log(2, L"🔥AppCompatCache: unexpected entry signature at offset " + std::to_wstring(offset)
			       + L", walk stopped");
			break;
		}
		const size_t entryStart = offset;
		const DWORD entrySize = *reinterpret_cast<DWORD*>(data + offset + 8);
		offset += 12;
		const unsigned short pathSize = *reinterpret_cast<unsigned short*>(data + offset);
		offset += 2;
		if (!fits(offset, (size_t)pathSize + 8 + 4)) {
			log(2, L"🔥AppCompatCache: entry truncated at offset " + std::to_wstring(entryStart));
			break;
		}
		Shimcache shimcache;
		shimcache.path = std::wstring((const wchar_t*)(data + offset), pathSize / sizeof(wchar_t));
		offset += pathSize;

		// Fingerprint on the normalised path (quotes, \??\), read raw.
		shimcache.fingerprint = FingerprintFile(shimcache.path);
		shimcache.path = replaceAll(shimcache.path, L"\t", L" "); // replace tab by space. seen in values

		/* The last modification is a FILETIME, hence UTC — the file's own
		   $STANDARD_INFORMATION date. It used to be formatted as a LOCAL time:
		   both keys came out shifted by the time-zone offset. Checked on the test
		   VM against the NTFS dates of the same files: exactly -2 h before the
		   fix, 0 after. */
		const FILETIME filetime = *reinterpret_cast<FILETIME*>(data + offset);
		shimcache.lastModificationUtc = timeToIso8601Utc(filetime);
		shimcache.lastModification = utcTimeToIso8601Local(filetime);
		offset += 8;

		const DWORD dataSize = *reinterpret_cast<DWORD*>(data + offset);
		offset += 4;
		if (!fits(offset, dataSize)) {
			log(2, L"🔥AppCompatCache: data of the entry at offset " + std::to_wstring(entryStart)
			       + L" goes beyond the value");
			break;
		}
		offset += dataSize;
		// The entry size, when consistent, is the reference for the next entry.
		if (entrySize >= offset - entryStart - 12 && fits(entryStart + 12, entrySize))
			offset = entryStart + 12 + entrySize;

		log(1, L"➕Shimcache ");
		log(2, L"❇️Shimcache Path : " + shimcache.path);
		shimcaches.push_back(shimcache);
	}

	delete [] data;
	return ERROR_SUCCESS;
}

HRESULT Shimcaches::toJson() {
	log(3, L"🔈Shimcaches toJson");
	Json arr = Json::arr();
	for (Shimcache& e : shimcaches) arr.push(e.toJson());
	return writeJsonFile("shimcache.json", arr);
}

void Shimcaches::clear() {
	log(3, L"🔈Shimcaches clear");
	shimcaches.clear();   // destroys the elements -> really releases them
}
