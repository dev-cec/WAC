/*! \file
 *  \brief Decoding of the AppCompatCache value (see reg_shimcache.h).
 */
#include "reg_shimcache.h"

namespace {
/*! Header size of the Windows 8 and 8.1 value. Its first DWORD does not tell
 *  them apart: 0 under Windows 8 and 8.1 (measured, builds 9200 and 9600) —
 *  neither a magic number nor a size. */
const size_t WINDOWS_8_HEADER_SIZE = 0x80;
//! The tag of a Windows 8 entry, "00ts", as the first DWORD after that header.
const unsigned SHIMCACHE_WINDOWS_8 = 0x73743030;

/*! THE WINDOWS XP VALUE (magic 0xDEADBEEF), measured on the XP VM: a header
 *  of 0x190 bytes — the magic, the maximum number of entries (96), the
 *  number in use, a DWORD, then the LRU table: 96 DWORDs, the entry index at
 *  each cache position, the most recent first — and entries of 552 bytes:
 *  the path (UTF-16, 528 bytes, null-terminated), the file's last
 *  modification, its size (8 bytes), the time Windows updated the entry. */
const unsigned WINDOWS_XP_MAGIC = 0xDEADBEEF;
const size_t WINDOWS_XP_HEADER_SIZE = 0x190;
const size_t WINDOWS_XP_LRU_AT = 0x10;
const size_t WINDOWS_XP_MAX_ENTRIES = 96;
const size_t WINDOWS_XP_ENTRY = 552;
const size_t WINDOWS_XP_PATH = 528;

} // namespace

/*! A value whose entries are a table of fixed size, each pointing at its
 *  path, stored after the table: Windows 7 and Vista. An entry starts the
 *  same way in both — path length (2), its room (2), then the path's
 *  offset (4 bytes in 32 bits; 8 after 4 reserved bytes in 64 bits), then
 *  the file's last modification —; the header and what follows the date
 *  differ. */
struct ShimcachePathTable {
	unsigned magic;          //!< the value's first DWORD
	size_t header;           //!< the header: the magic, the number of entries, reserved bytes
	size_t entry64, entry32; //!< an entry of the 64-bit layout, and of the 32-bit one
	const wchar_t* release;  //!< for the log
};

namespace {
/*! Windows 7 and Server 2008 R2: a header of 0x80 bytes; after the date,
 *  insertion and shim flags (2 × 4), data size and offset (2 × 8, or 2 × 4
 *  in 32 bits). */
const ShimcachePathTable WINDOWS_7_TABLE = { 0xBADC0FEE, 0x80, 48, 32, L"Windows 7" };
/*! Vista: a header of 8 bytes; after the date, insertion and shim flags
 *  (2 × 4), nothing more. Measured on Vista SP2 x86: 88 entries of 24 bytes,
 *  the paths at the end of the value, the first entry's last — as on
 *  Windows 7 —, identical to what dissect.target reads. Server 2003 writes
 *  the same magic with the file's size in place of the flags: not measured,
 *  its form is not decoded (the table picks it by the examined version). */
const ShimcachePathTable VISTA_TABLE = { 0xBADC0FFE, 8, 32, 24, L"Vista" };
} // namespace

Json Shimcache::toJson() {
	log(3, L"🔈Shimcache toJson");
	Json o = Json::obj();
	o.add(L"Path",                Json::str(path));      // raw path
	o.add(L"CachePosition",       Json::num((unsigned long long)position));
	addFingerprints(o, fingerprint);
	o.add(L"LastModification",    Json::str(lastModification));
	o.add(L"LastModificationUtc", Json::str(lastModificationUtc));
	if (fileSizeKnown) o.add(L"FileSize", Json::num(fileSize));
	if (lastUpdateUtc.dwLowDateTime || lastUpdateUtc.dwHighDateTime) {
		o.add(L"LastUpdate",    Json::str(utcTimeToIso8601Local(lastUpdateUtc)));
		o.add(L"LastUpdateUtc", Json::str(timeToIso8601Utc(lastUpdateUtc)));
	}
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
	ORCloseKey(hKey);   // the value is copied: the key, which holds its hive, is not kept
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue AppCompatCache", hresult );
		return hresult;
	}
	return parse(value);
}

HRESULT Shimcaches::parse(const std::vector<BYTE>& value) {
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
	   the header: 0 under Windows 8 and 8.1 (measured on both; 0x80 is
	   accepted too) — both with a header of 0x80 bytes, told apart by the
	   tag of the first entry, "00ts" or "10ts" —, 0x30 or 0x34 since
	   Windows 10. The
	   artefact table says which ones are decoded (pieceFormat). An older
	   value used to give an empty list — "no program was ever shimmed" —:
	   it is now declared "unsupported format". */
	formatSignature = (unsigned)offset;
	if ((offset == WINDOWS_8_HEADER_SIZE || offset == 0) && fits(size, WINDOWS_8_HEADER_SIZE, 4))
		formatSignature = *reinterpret_cast<const DWORD*>(data + WINDOWS_8_HEADER_SIZE);
	// Vista and Server 2003 share their magic: the examined version tells their forms apart.
	if (!pieceFormat("shimcache", formatSignature, conf.examinedVersion).decoded) {
		log(2, L"❇️AppCompatCache in an unsupported format, signature 0x" + to_hex(formatSignature));
		unsupportedFormat = true;
		return ERROR_SUCCESS;
	}
	/* WINDOWS 8 AND 8.1, the "00ts" and "10ts" entries after a header of
	   0x80 bytes: after the path, the name of a package (its size on 2
	   bytes, then UTF-16) and two DWORDs of flags (insertion, shim), then
	   the date and the data as since Windows 10. Measured on the Windows 8.1
	   VM — its 147 entries each end at the byte their size announces, the
	   last at the end of the value — and on the Windows 8 VM: the same
	   layout under "00ts", its package size 0.
	   The flags are not given: what they say of an execution is not proven
	   (decision of 2026-09-30, "executed" not reported). */
	if (formatSignature == WINDOWS_7_TABLE.magic) return parsePathTable(data, size, WINDOWS_7_TABLE);
	if (formatSignature == VISTA_TABLE.magic) return parsePathTable(data, size, VISTA_TABLE);
	if (formatSignature == WINDOWS_XP_MAGIC) return parseWindowsXp(data, size);
	const bool windows8 = offset == 0 || offset == WINDOWS_8_HEADER_SIZE;
	if (windows8) offset = WINDOWS_8_HEADER_SIZE;
	// Every entry carries the tag of the first: "00ts" on Windows 8, "10ts" since 8.1.
	const char* tag = formatSignature == SHIMCACHE_WINDOWS_8 ? "00ts" : "10ts";
	while (fits(size, offset, 14)) {
		printProgressStep(L"Shimcache", (unsigned)offset, size);
		if (std::memcmp(data + offset, tag, 4) != 0) {
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
		const std::wstring path((const wchar_t*)(data + offset), pathSize / sizeof(wchar_t));
		offset += pathSize;
		if (windows8) {
			// Package name and the two flag DWORDs, skipped; the date and data size must still fit.
			const size_t packageSize = fits(size, offset, 2) ? *reinterpret_cast<const unsigned short*>(data + offset) : 0;
			if (!fits(size, offset, 2 + packageSize + 8 + 8 + 4)) {
				log(2, L"🔥AppCompatCache: entry truncated at offset " + std::to_wstring(entryStart));
				break;
			}
			offset += 2 + packageSize + 8;
		}

		const FILETIME modified = *reinterpret_cast<const FILETIME*>(data + offset);
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
		addEntry(path, modified);
	}

	return ERROR_SUCCESS;
}

void Shimcaches::addEntry(const std::wstring& path, const FILETIME& lastModifiedUtc) {
	Shimcache shimcache;
	shimcache.path = path;
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
	shimcache.lastModificationUtc = timeToIso8601Utc(lastModifiedUtc);
	shimcache.lastModification = utcTimeToIso8601Local(lastModifiedUtc);
	log(1, L"➕Shimcache ");
	log(2, L"❇️Shimcache Path : " + shimcache.path);
	shimcaches.push_back(std::move(shimcache));
}

HRESULT Shimcaches::parsePathTable(const BYTE* data, size_t size, const ShimcachePathTable& table) {
	/* WINDOWS 7 AND VISTA (see ShimcachePathTable): a header — the magic,
	   the number of entries —, then a table of entries, the paths stored
	   after it, each entry pointing at its own. Windows stores the paths at
	   the END of the value, the first entry's last (measured on Windows 7
	   x64: 102 entries, the first path at byte 14,856 of 14,928; on Vista
	   x86 alike). The layout is the one whose first entry points
	   between the end of its table and the end of the value — with its
	   reserved DWORD at zero in the 64-bit one; read the other way, either
	   gives an offset out of the value. Neither fits: nothing is guessed.
	   Every offset comes from the hive: bounded by the value. */
	if (!fits(size, 0, table.header)) return ERROR_INVALID_DATA;
	const size_t count = *reinterpret_cast<const DWORD*>(data + 4);
	size_t entrySize = 0;
	for (const size_t candidate : { table.entry64, table.entry32 }) {
		if (count == 0 || count > (size - table.header) / candidate) continue;
		const BYTE* first = data + table.header;
		const bool wideCandidate = candidate == table.entry64;
		const uint64_t pathOffset = wideCandidate ? *reinterpret_cast<const uint64_t*>(first + 8)
		                                          : *reinterpret_cast<const DWORD*>(first + 4);
		const bool reservedClear = !wideCandidate || *reinterpret_cast<const DWORD*>(first + 4) == 0;
		if (reservedClear && pathOffset >= table.header + count * candidate && pathOffset < size) {
			entrySize = candidate;
			break;
		}
	}
	if (count == 0) return ERROR_SUCCESS;
	if (entrySize == 0) {
		log(2, L"🔥AppCompatCache of " + std::wstring(table.release) + L": neither the 64-bit nor the 32-bit layout fits its first entry");
		return ERROR_INVALID_DATA;
	}
	const bool wide = entrySize == table.entry64;
	for (size_t i = 0; i < count; ++i) {
		const BYTE* e = data + table.header + i * entrySize;
		const size_t pathLength = *reinterpret_cast<const unsigned short*>(e);
		const uint64_t pathOffset = wide ? *reinterpret_cast<const uint64_t*>(e + 8) : *reinterpret_cast<const DWORD*>(e + 4);
		const FILETIME modified = *reinterpret_cast<const FILETIME*>(e + (wide ? 16 : 8));
		if (pathOffset > size || !fits(size, (size_t)pathOffset, pathLength)) {
			log(2, L"🔥AppCompatCache of " + std::wstring(table.release) + L": path of entry " + std::to_wstring(i) + L" beyond the value");
			continue;
		}
		addEntry(std::wstring((const wchar_t*)(data + pathOffset), pathLength / sizeof(wchar_t)), modified);
	}
	return ERROR_SUCCESS;
}

HRESULT Shimcaches::parseWindowsXp(const BYTE* data, size_t size) {
	if (!fits(size, 0, WINDOWS_XP_HEADER_SIZE)) {
		log(2, L"🔥AppCompatCache of Windows XP: value shorter than its header");
		return ERROR_INVALID_DATA;
	}
	// The number in use, bounded by the table's 96 slots and by the value's size.
	const size_t room = (size - WINDOWS_XP_HEADER_SIZE) / WINDOWS_XP_ENTRY;
	const size_t count = std::min<size_t>({ readLittleEndian<uint32_t>(data + 8), WINDOWS_XP_MAX_ENTRIES, room });
	std::vector<bool> seen(count, false);
	for (size_t position = 0; position < count; ++position) {
		const size_t index = readLittleEndian<uint32_t>(data + WINDOWS_XP_LRU_AT + 4 * position);
		if (index >= count || seen[index]) {
			log(2, L"🔥AppCompatCache of Windows XP: position " + std::to_wstring(position) + L" names no entry in use");
			continue;
		}
		seen[index] = true;
		const BYTE* entry = data + WINDOWS_XP_HEADER_SIZE + index * WINDOWS_XP_ENTRY;
		std::wstring path;
		for (size_t i = 0; i + 1 < WINDOWS_XP_PATH; i += 2) {
			const wchar_t c = (wchar_t)readLittleEndian<uint16_t>(entry + i);
			if (c == 0) break;
			path += c;
		}
		FILETIME modified, updated;
		std::memcpy(&modified, entry + WINDOWS_XP_PATH, sizeof modified);
		std::memcpy(&updated, entry + WINDOWS_XP_PATH + 16, sizeof updated);
		addEntry(path, modified);
		Shimcache& added = shimcaches.back();
		added.fileSize = readLittleEndian<uint64_t>(entry + WINDOWS_XP_PATH + 8);
		added.fileSizeKnown = true;
		added.lastUpdateUtc = updated;
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
