/*! \file
 *  \brief Reading of every Amcache table (see reg_amcache.h).
 */
#include "reg_amcache.h"

namespace {

const uint8_t RECENT_FILE_CACHE_SIGNATURE[8] = { 0xFE, 0xFF, 0xEE, 0xFF, 0x11, 0x22, 0x00, 0x00 };
const size_t RECENT_FILE_CACHE_HEADER = 20;      //!< the signature, then 12 bytes not known
const uintmax_t RECENT_FILE_CACHE_MAX = 16u << 20; //!< a few KiB in practice
const wchar_t RECENT_FILE_CACHE[] = L"\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf";

/*! A text date Windows writes in UTC ("month/day/year hour:minute:second"):
 *  its UTC and local forms, to the second. */
void addUtcTextDate(std::vector<std::pair<std::wstring, Json>>& values, const std::wstring& name, const std::wstring& text) {
	const FILETIME utc = wstring_to_filetime(text);
	values.emplace_back(name, Json::str(utcTimeToIso8601Local(utc, Precision::Second)));
	values.emplace_back(name + L"Utc", Json::str(timeToIso8601Utc(utc, Precision::Second)));
}

/*! The names of the values of the Windows 8 and 8.1 tables whose meaning was
 *  confirmed (see the file's header); the others are given unnamed. */
const wchar_t* windows8Name(const std::wstring& table, const std::wstring& name) {
	if (table == L"File") {
		if (name == L"15") return L"LongPath";
		if (name == L"100") return L"ProgramId";
	}
	if (table == L"Programs") {
		if (name == L"0") return L"Name";
		if (name == L"1") return L"Version";
		if (name == L"2") return L"Publisher";
		if (name == L"7") return L"UninstallKeys";
		if (name == L"Files") return L"Files";
	}
	return nullptr;
}

/*! Converts one value of a Windows 8 or 8.1 table: named if its meaning was
 *  confirmed, else given unnamed — its name, type and value as stored. */
void addWindows8Value(AmcacheEntry& e, const std::wstring& name, DWORD type, const std::vector<BYTE>& data) {
	const Json value = registryValueToJson(type, data);
	const std::wstring text = type == REG_SZ ? readWideZ(data.data(), data.size(), 0) : L"";
	// "0000" + the SHA-1 of the file, as in FileId since Windows 10.
	if (e.table == L"File" && name == L"101" && text.size() == 44 && text.compare(0, 4, L"0000") == 0) {
		e.values.emplace_back(L"AmcacheSha1", Json::str(text.substr(4)));
		return;
	}
	if (const wchar_t* named = windows8Name(e.table, name)) {
		e.values.emplace_back(named, value);
		return;
	}
	Json unnamed = Json::obj();
	unnamed.add(L"Name", Json::str(name));
	unnamed.add(L"Type", Json::str(registryTypeName(type)));
	unnamed.add(L"Value", value);
	e.unnamed.push_back(std::move(unnamed));
}

/*! Converts one value by its name (see the file's header), or as stored. */
void addValue(AmcacheEntry& e, const std::wstring& name, DWORD type, const std::vector<BYTE>& data) {
	if (e.table == L"File" || e.table == L"Programs") return addWindows8Value(e, name, type, data);
	const Json value = registryValueToJson(type, data);
	const std::wstring text = type == REG_SZ ? readWideZ(data.data(), data.size(), 0) : L"";
	const bool driver = e.table == L"InventoryDriverBinary";
	// "0000" + the SHA-1 of the file: FileId of an executable, DriverId of a driver.
	if ((name == L"FileId" || (name == L"DriverId" && driver)) && text.size() == 44 && text.compare(0, 4, L"0000") == 0)
		e.values.emplace_back(L"AmcacheSha1", Json::str(text.substr(4)));
	else if (!text.empty() && (name == L"LinkDate" || (name == L"InstallDate" && e.table == L"InventoryApplication")
	                           || (name == L"DriverLastWriteTime" && driver)))
		addUtcTextDate(e.values, name, text);
	else if (name == L"DriverTimeStamp" && type == REG_DWORD && data.size() >= 4) {
		// The driver's PE TimeDateStamp: seconds since 1970, UTC by definition.
		DWORD seconds; memcpy(&seconds, data.data(), 4);
		const FILETIME utc = unixToFiletime(seconds);
		e.values.emplace_back(L"DriverTimeStamp",    Json::str(utcTimeToIso8601Local(utc, Precision::Second)));
		e.values.emplace_back(L"DriverTimeStampUtc", Json::str(timeToIso8601Utc(utc, Precision::Second)));
	}
	else if (name == L"LowerCaseLongPath")
		e.values.emplace_back(L"LongPath", value);
	else
		e.values.emplace_back(registryNameToJsonKey(name), value);
}

} // namespace

AmcacheEntry::AmcacheEntry(ORHKEY key, const std::wstring& _table, const std::wstring& name, const std::wstring& _volume)
	: table(_table), keyName(name), volume(_volume) {
	DWORD nValues = 0, maxName = 0, maxData = 0;
	if (ORQueryInfoKey(key, nullptr, nullptr, nullptr, nullptr, nullptr, &nValues,
	                   &maxName, &maxData, nullptr, &keyLastWriteUtc) != ERROR_SUCCESS) {
		log(2, L"🔥Amcache: key " + table + L"\\" + name + L" unreadable", ERROR_BADDB);
		return;
	}
	std::vector<wchar_t> valueName(maxName + 1);
	std::vector<BYTE> data;
	for (DWORD i = 0; i < nValues; ++i) {
		DWORD nameLength = (DWORD)valueName.size(), type = 0, size = 0;
		// Size first, then the data: a value larger than announced is not
		// truncated. The size query answers ERROR_MORE_DATA, as offreg's does.
		const DWORD probe = OREnumValue(key, i, valueName.data(), &nameLength, &type, nullptr, &size);
		if (probe != ERROR_SUCCESS && probe != ERROR_MORE_DATA) {
			log(2, L"🔥Amcache: value " + std::to_wstring(i) + L" of " + table + L"\\" + keyName + L" unreadable", probe);
			continue;
		}
		data.assign(size, 0);
		nameLength = (DWORD)valueName.size();
		const DWORD read = OREnumValue(key, i, valueName.data(), &nameLength, &type, data.data(), &size);
		if (read != ERROR_SUCCESS) {
			log(2, L"🔥Amcache: value " + std::to_wstring(i) + L" of " + table + L"\\" + keyName + L" unreadable", read);
			continue;
		}
		data.resize(size);
		addValue(*this, std::wstring(valueName.data(), nameLength), type, data);
	}
	if (table == L"File") {
		/* The key's name is the file's $MFT reference in hexadecimal: the
		   sequence number above 36 bits of record number. Measured on the
		   Windows 8.1 VM: the 14 entries of C: whose file is still there give
		   the record and sequence mft.json gives that file. A file of a volume
		   that is not NTFS (the UDF of a disc, measured) has another
		   identifier there, with a null sequence that NTFS never gives a
		   file: no reference is then given. */
		wchar_t* end = nullptr;
		const unsigned long long reference = wcstoull(keyName.c_str(), &end, 16);
		if (!keyName.empty() && end && *end == L'\0' && (reference >> 36) != 0) {
			mftEntry = reference & 0xFFFFFFFFFULL;
			mftSequence = reference >> 36;
			mftReferenceKnown = true;
		}
	}
	if (table != L"InventoryApplicationFile" && table != L"File") return;
	bool sha1 = false;
	unsigned long long size = 0;
	for (const auto& [n, v] : values) {
		// With --binary, the file the entry names is fingerprinted if it is still there.
		if (n == L"LongPath" && v.kind() == Json::Kind::Str) fingerprint = FingerprintFile(v.text());
		if (n == L"AmcacheSha1") sha1 = true;
		if (n == L"Size" && v.kind() == Json::Kind::Num) size = std::stoull(v.text());
	}
	/* Amcache hashes only the first 31,457,280 bytes (30 MiB) of a file: the
	   SHA-1 of a larger file is not that of the file — measured on the test
	   VM, mrt.exe and OneDriveSetup.exe. Said beside it, so that no one
	   concludes to a modified file from a hash that never covered it whole. */
	const unsigned long long AMCACHE_HASHED_BYTES = 31457280ULL;
	if (sha1 && size > AMCACHE_HASHED_BYTES)
		values.emplace_back(L"AmcacheSha1CoversBytes", Json::num(AMCACHE_HASHED_BYTES));
}

Json AmcacheEntry::toJson(bool withTable) const {
	Json o = Json::obj();
	if (withTable) o.add(L"Table", Json::str(table));
	o.add(L"KeyName", Json::str(keyName));
	o.add(L"VolumeGuid", Json::str(volume));
	if (mftReferenceKnown) {
		Json reference = Json::obj();
		reference.add(L"EntryIndex", Json::num(mftEntry));
		reference.add(L"SequenceNumber", Json::num(mftSequence));
		o.add(L"MftReference", std::move(reference));
	}
	o.add(L"KeyLastWriteTime",    Json::str(utcTimeToIso8601Local(keyLastWriteUtc)));
	o.add(L"KeyLastWriteTimeUtc", Json::str(timeToIso8601Utc(keyLastWriteUtc)));
	for (const auto& [name, value] : values) o.add(name, value);
	if (!unnamed.empty()) {
		Json list = Json::arr();
		for (const Json& u : unnamed) list.push(u);
		o.add(L"UnnamedValues", std::move(list));
	}
	addFingerprints(o, fingerprint);
	return o;
}

bool decodeRecentFileCache(const std::vector<uint8_t>& bytes, std::vector<std::wstring>& paths) {
	paths.clear();
	if (bytes.size() < RECENT_FILE_CACHE_HEADER
	    || memcmp(bytes.data(), RECENT_FILE_CACHE_SIGNATURE, sizeof RECENT_FILE_CACHE_SIGNATURE) != 0) return false;
	size_t at = RECENT_FILE_CACHE_HEADER;
	while (fits(bytes.size(), at, 4)) {
		const size_t characters = readLittleEndian<uint32_t>(bytes.data() + at);
		// The characters and their null, within the file: a count beyond it is forged or cut.
		if (characters == 0 || characters > (bytes.size() - at - 4) / 2 || !fits(bytes.size(), at + 4, characters * 2 + 2)) {
			log(2, L"🔥RecentFileCache.bcf: entry at " + std::to_wstring(at) + L" outside the file, reading stopped");
			break;
		}
		std::wstring path;
		for (size_t i = 0; i < characters; ++i) path += (wchar_t)readLittleEndian<uint16_t>(bytes.data() + at + 4 + 2 * i);
		paths.push_back(std::move(path));
		at += 4 + characters * 2 + 2;
	}
	return true;
}

HRESULT Amcache::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Amcache :");
	log(0, L"*******************************************************************************************************************");
	const bool recent = readRecentFileCache();
	const HRESULT hr = readHive();
	// Windows 7 without KB2952664 has no Amcache.hve: RecentFileCache.bcf is its answer.
	return (hr != ERROR_SUCCESS && recent) ? ERROR_SUCCESS : hr;
}

bool Amcache::readRecentFileCache() {
	const std::wstring file = extractedPath(RECENT_FILE_CACHE);
	std::error_code ec;
	if (!std::filesystem::is_regular_file(file, ec)) return false;
	std::vector<uint8_t> bytes;
	if (!readWholeFile(file, RECENT_FILE_CACHE_MAX, bytes) || !decodeRecentFileCache(bytes, recentFiles)) {
		log(2, L"🔥RecentFileCache.bcf unreadable, or without its signature: " + file, ERROR_INVALID_DATA);
		return false;
	}
	recentFileCache = originalPath(file);
	log(2, L"❇️RecentFileCache.bcf: " + std::to_wstring(recentFiles.size()) + L" path(s)");
	return true;
}

HRESULT Amcache::readHive() {
	const std::wstring path = conf.mountpoint + L"\\Windows\\AppCompat\\Programs\\Amcache.hve";
	ORHKEY hive = nullptr, root = nullptr;
	HRESULT hr = OROpenHive(path.c_str(), &hive);
	if (hr != ERROR_SUCCESS) {
		log(2, L"🔥OROpenHive: " + path, hr);
		return hr;
	}
	hr = OROpenKey(hive, L"Root", &root);
	if (hr != ERROR_SUCCESS) {
		log(2, L"🔥OROpenKey: Amcache Root", hr);
		ORCloseHive(hive);
		return hr;
	}
	DWORD nTables = 0;
	ORQueryInfoKey(root, nullptr, nullptr, &nTables, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
	wchar_t name[MAX_VALUE_NAME];
	for (DWORD t = 0; t < nTables; ++t) {
		DWORD length = MAX_VALUE_NAME;
		if (OREnumKey(root, t, name, &length, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;
		const std::wstring table(name, length);
		// The inventory tables, and File and Programs of Windows 8 and 8.1;
		// Root also holds a few bookkeeping keys.
		const bool windows8 = table == L"File" || table == L"Programs";
		if (table.compare(0, 9, L"Inventory") != 0 && !windows8) continue;
		ORHKEY tableKey = nullptr;
		if (OROpenKey(root, table.c_str(), &tableKey) != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey: Amcache " + table, ERROR_BADDB);
			continue;
		}
		DWORD nEntries = 0;
		ORQueryInfoKey(tableKey, nullptr, nullptr, &nEntries, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
		log(2, L"❇️Amcache " + table + L": " + std::to_wstring(nEntries) + L" entry(ies)");
		for (DWORD i = 0; i < nEntries; ++i) {
			printProgressStep(L"Amcache " + table, i + 1, nEntries);
			length = MAX_VALUE_NAME;
			if (OREnumKey(tableKey, i, name, &length, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;
			const std::wstring entryName(name, length);
			ORHKEY entryKey = nullptr;
			if (OROpenKey(tableKey, entryName.c_str(), &entryKey) != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey: Amcache " + table + L"\\" + entryName, ERROR_BADDB);
				continue;
			}
			if (table == L"File") readVolumeFiles(entryKey, entryName);
			else entries.emplace_back(entryKey, table, entryName);
			ORCloseKey(entryKey);
		}
		ORCloseKey(tableKey);
	}
	ORCloseKey(root);
	ORCloseHive(hive);
	return ERROR_SUCCESS;
}

void Amcache::readVolumeFiles(ORHKEY volumeKey, const std::wstring& volume) {
	DWORD nFiles = 0;
	ORQueryInfoKey(volumeKey, nullptr, nullptr, &nFiles, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
	wchar_t name[MAX_VALUE_NAME];
	for (DWORD i = 0; i < nFiles; ++i) {
		DWORD length = MAX_VALUE_NAME;
		if (OREnumKey(volumeKey, i, name, &length, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;
		const std::wstring fileName(name, length);
		ORHKEY fileKey = nullptr;
		if (OROpenKey(volumeKey, fileName.c_str(), &fileKey) != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey: Amcache File\\" + volume + L"\\" + fileName, ERROR_BADDB);
			continue;
		}
		entries.emplace_back(fileKey, L"File", fileName, volume);
		ORCloseKey(fileKey);
	}
}

HRESULT Amcache::toJson() {
	Json applications = Json::arr(), files = Json::arr(), others = Json::arr();
	for (const AmcacheEntry& e : entries) {
		if (e.table == L"InventoryApplication" || e.table == L"Programs") applications.push(e.toJson(false));
		else if (e.table == L"InventoryApplicationFile" || e.table == L"File") files.push(e.toJson(false));
		else others.push(e.toJson(true));
	}
	for (const std::wstring& path : recentFiles) {
		Json o = Json::obj();
		o.add(L"Table", Json::str(L"RecentFileCache"));
		o.add(L"Source", Json::str(recentFileCache));
		o.add(L"Path", Json::str(path));
		files.push(std::move(o));
	}
	HRESULT hr = writeJsonFile("amcache_applications.json", applications);
	const HRESULT hrFiles = writeJsonFile("amcache_application_files.json", files);
	const HRESULT hrOthers = writeJsonFile("amcache_inventory.json", others);
	if (hr == ERROR_SUCCESS) hr = hrFiles;
	if (hr == ERROR_SUCCESS) hr = hrOthers;
	return hr;
}

void Amcache::clear() {
	entries.clear();   // destroys the elements -> really releases them
	recentFiles.clear();
}
