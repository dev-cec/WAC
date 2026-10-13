/*! \file
 *  \brief Decoding of the AppCompatCache value (see reg_shimcache.h).
 */
#include "reg_shimcache.h"

namespace {
/*! Header size of the Windows 8 and 8.1 value. Its first DWORD does not tell
 *  them apart: 0x80 under Windows 8, 0 under Windows 8.1 (measured, build
 *  9600) — neither a magic number nor, for 8.1, a size. */
const size_t WINDOWS_8_HEADER_SIZE = 0x80;
} // namespace

Json Shimcache::toJson() {
	log(3, L"🔈Shimcache toJson");
	Json o = Json::obj();
	o.add(L"Path",                Json::str(path));      // raw path
	o.add(L"CachePosition",       Json::num((unsigned long long)position));
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

	/* The key holding the value: AppCompatCache since Server 2003,
	   AppCompatibility under Windows XP — where the collector, looking at the
	   first only, found nothing and the cache passed for missing. */
	for (const wchar_t* key : { L"Control\\Session Manager\\AppCompatCache", L"Control\\Session Manager\\AppCompatibility" }) {
		log(3, std::wstring(L"🔈OROpenKey CurrentControlSet\\") + key);
		hresult = OROpenKey(conf.CurrentControlSet, key, &hKey);
		if (hresult == ERROR_SUCCESS || hresult == ERROR_MORE_DATA) break;
	}
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
		log(2, L"🔥OROpenKey CurrentControlSet\\Control\\Session Manager\\AppCompatCache or AppCompatibility", hresult );
		return hresult;
	}

	std::vector<BYTE> value;
	log(3, L"🔈getRegBinaryValue AppCompatCache");
	hresult = getRegBinaryValue(hKey, nullptr, L"AppCompatCache", value);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue AppCompatCache", hresult );
		return hresult;
	}
	const BYTE* data = value.data();
	const size_t size = value.size();
	/* Layout of the Windows 10/11 cache: a header whose first DWORD is its own
	   size, then entries
	       "10ts" (4), unknown (4), entry size (4), path size (2), path,
	       last modification FILETIME (8), data size (4), data.
	   Every length comes from the examined machine's hive: each read is bounded
	   by the real size of the value, never by a length the data declares. An
	   entry that does not start with "10ts" ends the walk — the offset used to
	   stay where it was, and the loop never ended. */
	if (!fits(size, 0, 4)) {
		log(2, L"🔥AppCompatCache: value too short for its header");
		return ERROR_INVALID_DATA;
	}
	size_t offset = *reinterpret_cast<const DWORD*>(data);
	/* THE FORMAT, AS THE VALUE STATES IT. Its first DWORD is a magic number
	   up to Windows 7 (0xDEADBEEF, 0xBADC0FFE, 0xBADC0FEE), then the size of
	   the header: 0x80 under Windows 8 and, measured, 0 under Windows 8.1 —
	   both with a header of 0x80 bytes, told apart by the tag of the first
	   entry, "00ts" or "10ts" —, 0x30 or 0x34 since Windows 10. The
	   artefact table says which ones are decoded (pieceFormat). An older
	   value used to give an empty list — "no program was ever shimmed" —:
	   it is now declared "unsupported format". */
	formatSignature = (unsigned)offset;
	if ((offset == WINDOWS_8_HEADER_SIZE || offset == 0) && fits(size, WINDOWS_8_HEADER_SIZE, 4))
		formatSignature = *reinterpret_cast<const DWORD*>(data + WINDOWS_8_HEADER_SIZE);
	if (!pieceFormat("shimcache", formatSignature).decoded) {
		log(2, L"❇️AppCompatCache in an unsupported format, signature 0x" + to_hex(formatSignature));
		unsupportedFormat = true;
		return ERROR_SUCCESS;
	}
	while (fits(size, offset, 14)) {
		printProgressStep(L"Shimcache", (unsigned)offset, size);
		if (std::memcmp(data + offset, "10ts", 4) != 0) {
			log(2, L"🔥AppCompatCache: unexpected entry signature at offset " + std::to_wstring(offset)
			       + L", walk stopped");
			break;
		}
		const size_t entryStart = offset;
		const DWORD entrySize = *reinterpret_cast<const DWORD*>(data + offset + 8);
		offset += 12;
		const unsigned short pathSize = *reinterpret_cast<const unsigned short*>(data + offset);
		offset += 2;
		if (!fits(size, offset, (size_t)pathSize + 8 + 4)) {
			log(2, L"🔥AppCompatCache: entry truncated at offset " + std::to_wstring(entryStart));
			break;
		}
		Shimcache shimcache;
		shimcache.path = std::wstring((const wchar_t*)(data + offset), pathSize / sizeof(wchar_t));
		offset += pathSize;

		// Fingerprint on the normalised path (quotes, \??\), read raw.
		shimcache.fingerprint = FingerprintFile(shimcache.path);
		/* A packaged application's entry is not a path but tab-separated fields
		   (version, architecture, package name, publisher). The tabs were
		   replaced by spaces "because JSON does not support them" — it escapes
		   them: the value is now kept as Windows stores it (B-015, against
		   AppCompatCacheParser). */
		shimcache.position = shimcaches.size();

		/* The last modification is a FILETIME, hence UTC — the file's own
		   $STANDARD_INFORMATION date. It used to be formatted as a LOCAL time:
		   both keys came out shifted by the time-zone offset. Checked on the test
		   VM against the NTFS dates of the same files: exactly -2 h before the
		   fix, 0 after. */
		const FILETIME filetime = *reinterpret_cast<const FILETIME*>(data + offset);
		shimcache.lastModificationUtc = timeToIso8601Utc(filetime);
		shimcache.lastModification = utcTimeToIso8601Local(filetime);
		offset += 8;

		const DWORD dataSize = *reinterpret_cast<const DWORD*>(data + offset);
		offset += 4;
		if (!fits(size, offset, dataSize)) {
			log(2, L"🔥AppCompatCache: data of the entry at offset " + std::to_wstring(entryStart)
			       + L" goes beyond the value");
			break;
		}
		offset += dataSize;
		// The entry size, when consistent, is the reference for the next entry.
		if (entrySize >= offset - entryStart - 12 && fits(size, entryStart + 12, entrySize))
			offset = entryStart + 12 + entrySize;

		log(1, L"➕Shimcache ");
		log(2, L"❇️Shimcache Path : " + shimcache.path);
		shimcaches.push_back(shimcache);
	}

	return ERROR_SUCCESS;
}

HRESULT Shimcaches::toJson() {
	log(3, L"🔈Shimcaches toJson");
	if (unsupportedFormat) return writeUnsupportedFormat("shimcache.json", L"Shimcache", "shimcache", formatSignature);
	Json arr = Json::arr();
	for (Shimcache& e : shimcaches) arr.push(e.toJson());
	return writeJsonFile("shimcache.json", arr);
}

void Shimcaches::clear() {
	log(3, L"🔈Shimcaches clear");
	shimcaches.clear();   // destroys the elements -> really releases them
	unsupportedFormat = false;
	formatSignature = 0;
}
