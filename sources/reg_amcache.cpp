/*! \file
 *  \brief Reading of every Amcache table (see reg_amcache.h).
 */
#include "reg_amcache.h"

namespace {

/*! A text date Windows writes in UTC ("month/day/year hour:minute:second"):
 *  its UTC and local forms, to the second. */
void addUtcTextDate(std::vector<std::pair<std::wstring, Json>>& values, const std::wstring& name, const std::wstring& text) {
	const FILETIME utc = wstring_to_filetime(text);
	values.emplace_back(name, Json::str(utcTimeToIso8601Local(utc, Precision::Second)));
	values.emplace_back(name + L"Utc", Json::str(timeToIso8601Utc(utc, Precision::Second)));
}

/*! Converts one value by its name (see the file's header), or as stored. */
void addValue(AmcacheEntry& e, const std::wstring& name, DWORD type, const std::vector<BYTE>& data) {
	const Json value = registryValueToJson(type, data);
	const std::wstring text = type == REG_SZ ? readWideZ(data.data(), data.size(), 0) : L"";
	const bool driver = e.table == L"InventoryDriverBinary";
	// "0000" + the SHA-1 of the file: FileId of an executable, DriverId of a driver.
	if ((name == L"FileId" || (name == L"DriverId" && driver)) && text.size() == 44 && text.compare(0, 4, L"0000") == 0)
		e.values.emplace_back(L"Sha1", Json::str(text.substr(4)));
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

AmcacheEntry::AmcacheEntry(ORHKEY key, const std::wstring& _table, const std::wstring& name)
	: table(_table), keyName(name) {
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
	if (table != L"InventoryApplicationFile") return;
	bool sha1 = false;
	unsigned long long size = 0;
	for (const auto& [n, v] : values) {
		// With --binary, the file the entry names is fingerprinted if it is still there.
		if (n == L"LongPath" && v.kind() == Json::Kind::Str) fingerprint = FingerprintFile(v.text());
		if (n == L"Sha1") sha1 = true;
		if (n == L"Size" && v.kind() == Json::Kind::Num) size = std::stoull(v.text());
	}
	/* Amcache hashes only the first 31,457,280 bytes (30 MiB) of a file: the
	   SHA-1 of a larger file is not that of the file — measured on the test
	   VM, mrt.exe and OneDriveSetup.exe. Said beside it, so that no one
	   concludes to a modified file from a hash that never covered it whole. */
	const unsigned long long AMCACHE_HASHED_BYTES = 31457280ULL;
	if (sha1 && size > AMCACHE_HASHED_BYTES)
		values.emplace_back(L"Sha1CoversBytes", Json::num(AMCACHE_HASHED_BYTES));
}

Json AmcacheEntry::toJson(bool withTable) const {
	Json o = Json::obj();
	if (withTable) o.add(L"Table", Json::str(table));
	o.add(L"KeyName", Json::str(keyName));
	o.add(L"KeyLastWriteTime",    Json::str(utcTimeToIso8601Local(keyLastWriteUtc)));
	o.add(L"KeyLastWriteTimeUtc", Json::str(timeToIso8601Utc(keyLastWriteUtc)));
	for (const auto& [name, value] : values) o.add(name, value);
	addFingerprints(o, fingerprint);
	return o;
}

HRESULT Amcache::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Amcache :");
	log(0, L"*******************************************************************************************************************");
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
		// The inventory tables; Root also holds a few bookkeeping keys.
		if (table.compare(0, 9, L"Inventory") != 0) continue;
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
			entries.emplace_back(entryKey, table, entryName);
			ORCloseKey(entryKey);
		}
		ORCloseKey(tableKey);
	}
	ORCloseKey(root);
	ORCloseHive(hive);
	return ERROR_SUCCESS;
}

HRESULT Amcache::toJson() {
	Json applications = Json::arr(), files = Json::arr(), others = Json::arr();
	for (const AmcacheEntry& e : entries) {
		if (e.table == L"InventoryApplication") applications.push(e.toJson(false));
		else if (e.table == L"InventoryApplicationFile") files.push(e.toJson(false));
		else others.push(e.toJson(true));
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
}
