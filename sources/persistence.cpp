/*! \file
 *  \brief Registry persistence beyond the Run keys (see persistence.h).
 */
#include "persistence.h"

namespace {

//! Which hive a rule reads.
enum class Hive { Software, System, NtUser, UsrClass };

/*! One place to read. `key` may hold ONE `*` segment: every subkey there
 *  (the executables of IFEO, the monitors, the CLSIDs). An empty `value` reads
 *  every value of the key; "(default)" the unnamed one. */
struct Rule {
	const wchar_t* mechanism;
	Hive hive;
	const wchar_t* key;      //!< from the hive's root; SYSTEM's from CurrentControlSet
	const wchar_t* value;
	bool binary;             //!< the value names a file to fingerprint (--binary)
};

const Rule RULES[] = {
	{ L"IFEO Debugger", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*", L"Debugger", true },
	{ L"IFEO GlobalFlag", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*", L"GlobalFlag", false },
	{ L"SilentProcessExit MonitorProcess", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*", L"MonitorProcess", true },
	{ L"AppInit_DLLs", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", false },
	{ L"AppInit_DLLs", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", false },
	{ L"AppInit_DLLs (32-bit)", Hive::Software, L"WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", false },
	{ L"AppInit_DLLs (32-bit)", Hive::Software, L"WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", false },
	{ L"AppCertDlls", Hive::System, L"Control\\Session Manager\\AppCertDlls", L"", true },
	{ L"Winlogon Shell", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", false },
	{ L"Winlogon Userinit", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", false },
	{ L"Winlogon Taskman", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Taskman", true },
	{ L"Winlogon AppSetup", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"AppSetup", false },
	{ L"Winlogon Notify", Hive::Software, L"Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\*", L"DLLName", true },
	{ L"Winlogon Shell (user)", Hive::NtUser, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", false },
	{ L"LSA Authentication Packages", Hive::System, L"Control\\Lsa", L"Authentication Packages", false },
	{ L"LSA Security Packages", Hive::System, L"Control\\Lsa", L"Security Packages", false },
	{ L"LSA Notification Packages", Hive::System, L"Control\\Lsa", L"Notification Packages", false },
	{ L"LSA Security Packages (OSConfig)", Hive::System, L"Control\\Lsa\\OSConfig", L"Security Packages", false },
	{ L"Print monitor", Hive::System, L"Control\\Print\\Monitors\\*", L"Driver", true },
	{ L"BootExecute", Hive::System, L"Control\\Session Manager", L"BootExecute", false },
	{ L"Active Setup StubPath", Hive::Software, L"Microsoft\\Active Setup\\Installed Components\\*", L"StubPath", true },
	{ L"NetSh helper", Hive::Software, L"Microsoft\\NetSh", L"", true },
	{ L"COM InprocServer32 (user)", Hive::UsrClass, L"CLSID\\*\\InprocServer32", L"(default)", true },
	{ L"COM LocalServer32 (user)", Hive::UsrClass, L"CLSID\\*\\LocalServer32", L"(default)", true },
};

//! A value's type as its name.
std::wstring typeName(DWORD type) {
	switch (type) {
	case REG_SZ: return L"REG_SZ";
	case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
	case REG_MULTI_SZ: return L"REG_MULTI_SZ";
	case REG_DWORD: return L"REG_DWORD";
	default: return L"0x" + to_hex(type);
	}
}

/*! The strings of a value, read within its bytes: one for a string or a
 *  DWORD (in hexadecimal), each string of a REG_MULTI_SZ; none otherwise. */
std::vector<std::wstring> valueStrings(DWORD type, const std::vector<BYTE>& data) {
	std::vector<std::wstring> out;
	if (type == REG_SZ || type == REG_EXPAND_SZ) out.push_back(readWideZ(data.data(), data.size(), 0));
	else if (type == REG_MULTI_SZ) out = multiWstring_to_vector(const_cast<LPBYTE>(data.data()), (int)data.size());
	else if (type == REG_DWORD && data.size() >= sizeof(DWORD)) {
		DWORD v = 0;
		memcpy(&v, data.data(), sizeof(DWORD));
		// Eight digits, as the registry editor shows a DWORD: 0x00000200.
		wchar_t text[11];
		swprintf(text, 11, L"0x%08X", (unsigned)v);
		out.push_back(text);
	}
	return out;
}

/*! Reads one key for a rule: the named value, or every value.
 *  @param root the hive, or the CurrentControlSet key for SYSTEM
 *  @param path the key, `*` already replaced */
void readKey(ORHKEY root, const std::wstring& path, const Rule& rule, const std::wstring& hive,
             const std::wstring& sid, std::vector<PersistenceEntry>& out) {
	ORHKEY key = NULL;
	if (OROpenKey(root, path.c_str(), &key) != ERROR_SUCCESS) return;
	FILETIME lastWriteUtc = { 0 };
	ORQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &lastWriteUtc);
	const std::wstring wanted = rule.value;
	for (DWORD i = 0;; ++i) {
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
		const std::wstring shown = name.empty() ? L"(default)" : name;
		if (!wanted.empty() && _wcsicmp(shown.c_str(), wanted.c_str()) != 0) continue;
		PersistenceEntry e;
		e.mechanism = rule.mechanism;
		e.hive = hive;
		e.sid = sid;
		e.key = path;
		e.name = shown;
		e.type = typeName(type);
		e.values = valueStrings(type, data);
		e.keyLastWriteUtc = lastWriteUtc;
		if (rule.binary && conf.binary && e.values.size() == 1 && !e.values[0].empty())
			e.fingerprint = FingerprintFile(binaryPath(e.values[0]));
		out.push_back(std::move(e));
	}
	ORCloseKey(key);
}

/*! Applies a rule to one hive: its key, or each subkey at its `*`. */
void apply(ORHKEY root, const Rule& rule, const std::wstring& hive, const std::wstring& sid,
           std::vector<PersistenceEntry>& out) {
	const std::wstring key = rule.key;
	const size_t star = key.find(L'*');
	if (star == std::wstring::npos) { readKey(root, key, rule, hive, sid, out); return; }
	const std::wstring parent = key.substr(0, star - 1), rest = key.substr(star + 1);   // "…\\" "*" "\\…"
	ORHKEY parentKey = NULL;
	if (OROpenKey(root, parent.c_str(), &parentKey) != ERROR_SUCCESS) return;
	std::vector<std::wstring> subkeys;
	wchar_t name[512];
	for (DWORD i = 0;; ++i) {
		DWORD length = (DWORD)(sizeof(name) / sizeof(name[0]));
		if (OREnumKey(parentKey, i, name, &length, NULL, NULL, NULL) != ERROR_SUCCESS) break;
		subkeys.emplace_back(name, length);
	}
	ORCloseKey(parentKey);
	for (const std::wstring& sub : subkeys) readKey(root, parent + L"\\" + sub + rest, rule, hive, sid, out);
}

/*! Opens a user hive of the working copy, applies its rules, closes it. */
void readUserHive(const std::wstring& file, Hive kind, const std::wstring& hiveName, const std::wstring& sid,
                  std::vector<PersistenceEntry>& out) {
	ORHKEY root = NULL;
	if (OROpenHive(file.c_str(), &root) != ERROR_SUCCESS) {
		log(2, L"🔥OROpenHive " + file);
		return;
	}
	for (const Rule& rule : RULES) if (rule.hive == kind) apply(root, rule, hiveName, sid, out);
	ORCloseHive(root);
}

} // namespace

Json PersistenceEntry::toJson() const {
	Json o = Json::obj();
	o.add(L"Mechanism", Json::str(mechanism));
	o.add(L"Hive", Json::str(hive));
	o.add(L"SID", Json::str(sid));
	if (!sid.empty()) o.add(L"SIDName", Json::str(getNameFromSid(sid)));
	o.add(L"Key", Json::str(key));
	o.add(L"Name", Json::str(name));
	o.add(L"Type", Json::str(type));
	if (values.size() == 1) o.add(L"Value", Json::str(values[0]));
	else {
		Json list = Json::arr();
		for (const std::wstring& v : values) list.push(Json::str(v));
		o.add(L"Values", std::move(list));
	}
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	addFingerprints(o, fingerprint, L"", L"");
	return o;
}

HRESULT Persistence::getData() {
	log(0, L"ℹ️Persistence :");
	for (const Rule& rule : RULES) {
		if (rule.hive == Hive::Software && conf.Software) apply(conf.Software, rule, L"SOFTWARE", L"", entries_);
		else if (rule.hive == Hive::System && conf.CurrentControlSet) apply(conf.CurrentControlSet, rule, L"SYSTEM", L"", entries_);
	}
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring profile = extractedPath(std::get<1>(profileEntry));
		readUserHive(profile + L"\\ntuser.dat", Hive::NtUser, L"NTUSER.DAT", std::get<0>(profileEntry), entries_);
		readUserHive(profile + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat", Hive::UsrClass,
		             L"UsrClass.dat", std::get<0>(profileEntry), entries_);
	}
	return ERROR_SUCCESS;
}

HRESULT Persistence::toJson() {
	Json list = Json::arr();
	for (const PersistenceEntry& e : entries_) list.push(e.toJson());
	return writeJsonFile("persistence.json", list);
}

void Persistence::clear() {
	entries_.clear();
}
