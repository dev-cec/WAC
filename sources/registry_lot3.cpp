/*! \file
 *  \brief Registry artefacts of the third lot (see registry_lot3.h).
 */
#include "registry_lot3.h"
#include "idList.h"
#include "recent_docs.h"
#include "ip_address.h"
#include <algorithm>

namespace {

/*! Every value of an open key, typed as the hive stores it, under its
 *  PascalCase name.
 *  @param key the key
 *  @param out receives the values */
void readAllValues(ORHKEY key, std::vector<std::pair<std::wstring, Json>>& out) {
	for (DWORD i = 0;; ++i) {
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
		out.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
	}
}

/*! Reads every program of an Uninstall key.
 *  @param root the hive's root
 *  @param path the Uninstall key under it
 *  @param scope "Machine", "Machine (32-bit)" or "User"
 *  @param sid the user, for "User"
 *  @param out receives the programs */
void readUninstall(ORHKEY root, const std::wstring& path, const wchar_t* scope, const std::wstring& sid,
                   std::vector<InstalledProgram>& out) {
	for (const std::wstring& name : subkeys(root, path)) {
		ORHKEY key = NULL;
		if (OROpenKey(root, (path + L"\\" + name).c_str(), &key) != ERROR_SUCCESS) {
			log(2, L"🔥Uninstall: " + path + L"\\" + name + L" unreadable", ERROR_BADDB);
			continue;
		}
		InstalledProgram p;
		p.scope = scope;
		p.sid = sid;
		p.keyName = name;
		p.keyLastWriteUtc = lastWrite(key);
		readAllValues(key, p.values);
		ORCloseKey(key);
		out.push_back(std::move(p));
	}
}

/*! Reads the MSI products Windows Installer registered: one subkey per SID
 *  under Installer\\UserData, one per product under it, its InstallProperties
 *  holding the same values as an Uninstall key (and LocalPackage, the cached
 *  .msi).
 *  @param out receives the products, Scope "MSI product" */
void readMsiProducts(std::vector<InstalledProgram>& out) {
	const std::wstring USER_DATA = L"Microsoft\\Windows\\CurrentVersion\\Installer\\UserData";
	for (const std::wstring& sid : subkeys(conf.Software, USER_DATA)) {
		const std::wstring products = USER_DATA + L"\\" + sid + L"\\Products";
		for (const std::wstring& code : subkeys(conf.Software, products)) {
			ORHKEY key = NULL;
			if (OROpenKey(conf.Software, (products + L"\\" + code + L"\\InstallProperties").c_str(), &key) != ERROR_SUCCESS) continue;
			InstalledProgram p;
			p.scope = L"MSI product";
			p.sid = sid;
			p.keyName = code;
			p.keyLastWriteUtc = lastWrite(key);
			readAllValues(key, p.values);
			ORCloseKey(key);
			out.push_back(std::move(p));
		}
	}
}

} // namespace

// ------------------------------------------------------------ Installed programs

Json InstalledProgram::toJson() const {
	Json o = Json::obj();
	o.add(L"Scope", Json::str(scope));
	if (!sid.empty()) addUser(o, sid);
	o.add(L"KeyName", Json::str(keyName));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	// InstallDate is the day as written (YYYYMMDD), without time or time zone.
	for (const auto& [name, value] : values) o.add(name, value);
	return o;
}

HRESULT InstalledPrograms::getData() {
	const std::wstring UNINSTALL = L"Microsoft\\Windows\\CurrentVersion\\Uninstall";
	if (conf.Software) {
		readUninstall(conf.Software, UNINSTALL, L"Machine", L"", programs_);
		readUninstall(conf.Software, L"WOW6432Node\\" + UNINSTALL, L"Machine (32-bit)", L"", programs_);
		readMsiProducts(programs_);
	}
	forEachProfileHive(L"\\ntuser.dat", [this, &UNINSTALL](ORHKEY root, const std::wstring& sid) {
		readUninstall(root, L"Software\\" + UNINSTALL, L"User", sid, programs_);
	});
	return ERROR_SUCCESS;
}

HRESULT InstalledPrograms::toJson() { return writeList("installed_programs.json", programs_); }
void InstalledPrograms::clear() { programs_.clear(); }

// ------------------------------------------------------------ Defender configuration

Json DefenderExclusion::toJson() const {
	Json o = Json::obj();
	o.add(L"Source", Json::str(source));
	o.add(L"Kind", Json::str(kind));
	o.add(L"Value", Json::str(value));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

Json DefenderSettings::toJson() const {
	Json o = Json::obj();
	o.add(L"Source", Json::str(source));
	o.add(L"Key", Json::str(key));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	for (const auto& [name, value] : values) o.add(name, value);
	return o;
}

HRESULT DefenderConfiguration::getData() {
	if (!conf.Software) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const std::pair<const wchar_t*, const wchar_t*> ROOTS[] = {
		{ L"Settings", L"Microsoft\\Windows Defender" },
		{ L"Policy",   L"Policies\\Microsoft\\Windows Defender" } };
	// The keys whose values say whether, and how, Defender protects.
	const wchar_t* SETTINGS[] = { L"", L"Real-Time Protection", L"Features", L"Spynet",
	                              L"Scan", L"Threats\\ThreatIDDefaultAction", L"UX Configuration" };
	for (const auto& [source, root] : ROOTS) {
		// Exclusions: one subkey per kind, one value per excluded item (its name).
		for (const std::wstring& kind : subkeys(conf.Software, std::wstring(root) + L"\\Exclusions")) {
			ORHKEY key = NULL;
			if (OROpenKey(conf.Software, (std::wstring(root) + L"\\Exclusions\\" + kind).c_str(), &key) != ERROR_SUCCESS) continue;
			const FILETIME written = lastWrite(key);
			for (DWORD i = 0;; ++i) {
				DefenderExclusion e;
				DWORD type = 0;
				std::vector<BYTE> data;
				if (enumRegistryValue(key, i, e.value, type, data) != ERROR_SUCCESS) break;
				e.source = source;
				e.kind = kind;
				e.keyLastWriteUtc = written;
				exclusions_.push_back(std::move(e));
			}
			ORCloseKey(key);
		}
		for (const wchar_t* sub : SETTINGS) {
			const std::wstring path = std::wstring(root) + (*sub ? L"\\" : L"") + sub;
			ORHKEY key = NULL;
			if (OROpenKey(conf.Software, path.c_str(), &key) != ERROR_SUCCESS) continue;
			DefenderSettings settings;
			settings.source = source;
			settings.key = path;
			settings.keyLastWriteUtc = lastWrite(key);
			readAllValues(key, settings.values);
			ORCloseKey(key);
			if (!settings.values.empty()) settings_.push_back(std::move(settings));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT DefenderConfiguration::toJson() {
	Json o = Json::obj();
	Json exclusions = Json::arr();
	for (const DefenderExclusion& e : exclusions_) exclusions.push(e.toJson());
	o.add(L"Exclusions", std::move(exclusions));
	Json settings = Json::arr();
	for (const DefenderSettings& s : settings_) settings.push(s.toJson());
	o.add(L"Settings", std::move(settings));
	return writeJsonFile("defender_configuration.json", o);
}

void DefenderConfiguration::clear() { exclusions_.clear(); settings_.clear(); }

// ------------------------------------------------------------ Explorer RecentDocs

namespace {

/*! Reads one RecentDocs list: the values named by MRUListEx, most recent
 *  first. A value is the file's name in UTF-16, then the shell item of the
 *  shortcut Explorer made in Recent.
 *  @param key the list's key
 *  @param sid,extension what the entries belong to
 *  @param out receives the entries */
void readRecentDocsList(ORHKEY key, const std::wstring& sid, const std::wstring& extension,
                        std::vector<ExplorerRecentDoc>& out) {
	std::vector<unsigned int> order;
	if (readMruListEx(key, order) != ERROR_SUCCESS) return;
	const FILETIME written = lastWrite(key);
	unsigned position = 0;
	for (unsigned int id : order) {
		std::vector<BYTE> data;
		if (getRegBinaryValue(key, nullptr, std::to_wstring(id).c_str(), data) != ERROR_SUCCESS) continue;
		ExplorerRecentDoc e;
		e.sid = sid;
		e.extension = extension;
		e.mruPosition = position++;
		e.name = readWideZ(data.data(), data.size(), 0);
		e.keyLastWriteUtc = written;
		// The shell item, bounded by its own size and by the value.
		const size_t at = (e.name.size() + 1) * sizeof(wchar_t);
		if (at + 2 <= data.size()) {
			const unsigned short itemSize = *reinterpret_cast<const unsigned short*>(data.data() + at);
			if (itemSize >= 3 && itemSize <= data.size() - at) {
				std::vector<BYTE> item(data.begin() + at, data.begin() + at + itemSize);
				e.shortcut = IdList(item.data(), 2).toJson();
			}
		}
		out.push_back(std::move(e));
	}
}

} // namespace

Json ExplorerRecentDoc::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	o.add(L"Extension", Json::str(extension));
	o.add(L"MruPosition", Json::num(mruPosition));
	o.add(L"Name", Json::str(name));
	o.add(L"Shortcut", shortcut);
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT ExplorerRecentDocs::getData() {
	const std::wstring RECENT_DOCS = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs";
	forEachProfileHive(L"\\ntuser.dat", [this, &RECENT_DOCS](ORHKEY root, const std::wstring& sid) {
		ORHKEY key = NULL;
		if (OROpenKey(root, RECENT_DOCS.c_str(), &key) != ERROR_SUCCESS) return;
		readRecentDocsList(key, sid, L"", entries_);
		ORCloseKey(key);
		for (const std::wstring& extension : subkeys(root, RECENT_DOCS)) {
			if (OROpenKey(root, (RECENT_DOCS + L"\\" + extension).c_str(), &key) != ERROR_SUCCESS) continue;
			readRecentDocsList(key, sid, extension, entries_);
			ORCloseKey(key);
		}
	});
	return ERROR_SUCCESS;
}

HRESULT ExplorerRecentDocs::toJson() { return writeList("explorer_recent_docs.json", entries_); }
void ExplorerRecentDocs::clear() { entries_.clear(); }

// ------------------------------------------------------------ MountPoints2

namespace {

/*! Every subkey below `path`, depth first, with its default value: an
 *  entry's commands (Shell\\AutoRun\\command) are in it.
 *  @param root the hive's root
 *  @param path the entry's key
 *  @param relative the path below the entry, "" at the start
 *  @param out receives "relative path" / default value
 *  @param depth guards against a forged hive's loop (a key is not its own
 *         descendant, but a corrupt cell can make it look so) */
void readSubkeys(ORHKEY root, const std::wstring& path, const std::wstring& relative, NameValues& out, int depth = 0) {
	const int MAX_DEPTH = 8;
	if (depth >= MAX_DEPTH) return;
	for (const std::wstring& name : subkeys(root, path)) {
		const std::wstring child = relative.empty() ? name : relative + L"\\" + name;
		ORHKEY key = NULL;
		std::wstring value;
		if (OROpenKey(root, (path + L"\\" + name).c_str(), &key) == ERROR_SUCCESS) {
			getRegSzValue(key, nullptr, L"", &value);
			ORCloseKey(key);
		}
		out.emplace_back(child, value);
		readSubkeys(root, path + L"\\" + name, child, out, depth + 1);
	}
}

/*! Reads the entries of one MountPoints2 key (or of its CPC\\Volume).
 *  @param root the hive's root
 *  @param path the key
 *  @param sid the user
 *  @param out receives the entries */
void readMountPoints(ORHKEY root, const std::wstring& path, const std::wstring& sid, std::vector<MountPoint>& out) {
	for (const std::wstring& name : subkeys(root, path)) {
		if (name == L"CPC") continue;          // a container, read on its own
		ORHKEY key = NULL;
		if (OROpenKey(root, (path + L"\\" + name).c_str(), &key) != ERROR_SUCCESS) continue;
		MountPoint m;
		m.sid = sid;
		m.name = name;
		if (name.size() > 2 && name.compare(0, 2, L"##") == 0) {
			// "##server#share": the share's path, # for each backslash.
			m.kind = L"NetworkShare";
			m.share = name;
			for (wchar_t& c : m.share) if (c == L'#') c = L'\\';
		}
		else if (name.size() == 38 && name.front() == L'{' && name.back() == L'}') m.kind = L"Volume";
		m.keyLastWriteUtc = lastWrite(key);
		readAllValues(key, m.values);
		ORCloseKey(key);
		readSubkeys(root, path + L"\\" + name, L"", m.subkeys);
		out.push_back(std::move(m));
	}
}

} // namespace

Json MountPoint::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	o.add(L"Name", Json::str(name));
	o.add(L"Kind", Json::str(kind));
	o.add(L"Share", Json::str(share));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	for (const auto& [n, v] : values) o.add(n, v);
	if (!subkeys.empty()) {
		Json list = Json::arr();
		for (const auto& [path, value] : subkeys) {
			Json k = Json::obj();
			k.add(L"Path", Json::str(path));
			k.add(L"DefaultValue", Json::str(value));
			list.push(std::move(k));
		}
		o.add(L"Subkeys", std::move(list));
	}
	return o;
}

HRESULT MountPoints::getData() {
	const std::wstring MOUNT_POINTS = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";
	forEachProfileHive(L"\\ntuser.dat", [this, &MOUNT_POINTS](ORHKEY root, const std::wstring& sid) {
		readMountPoints(root, MOUNT_POINTS, sid, entries_);
		// CPC\\Volume: its entries are volatile on Windows 11 (measured: reg save
		// keeps the key, empty), so absent from the hive's file; read in case
		// another version keeps them.
		readMountPoints(root, MOUNT_POINTS + L"\\CPC\\Volume", sid, entries_);
	});
	return ERROR_SUCCESS;
}

HRESULT MountPoints::toJson() { return writeList("mount_points.json", entries_); }
void MountPoints::clear() { entries_.clear(); }

// ------------------------------------------------------------ Known networks

namespace {

/*! A NetworkList date: a SYSTEMTIME in the machine's LOCAL time — measured on
 *  the test VM, DateLastConnected 23:46:44 is the 21:46:44 UTC of the
 *  NetworkProfile event 10000 of that connection (+2 h). Converted to UTC with
 *  the offset in force at that date.
 *  @param data the value's 16 bytes
 *  @return the instant in UTC, or a null FILETIME */
FILETIME networkListDate(const std::vector<BYTE>& data) {
	FILETIME local = { 0, 0 };
	if (data.size() < sizeof(SYSTEMTIME)) return local;
	SYSTEMTIME st;
	memcpy(&st, data.data(), sizeof(SYSTEMTIME));
	if (!SystemTimeToFileTime(&st, &local)) return FILETIME{ 0, 0 };
	return suspectLocalToUtc(local);
}

} // namespace

Json KnownNetwork::toJson() const {
	Json o = Json::obj();
	o.add(L"ProfileGuid", Json::str(profileGuid));
	for (const auto& [name, value] : values) o.add(name, value);
	addDate(o, L"DateCreated", createdUtc);
	addDate(o, L"DateLastConnected", lastConnectedUtc);
	addDate(o, L"KeyLastWrite", profileLastWriteUtc);
	if (!signatures.empty()) {
		Json list = Json::arr();
		for (const Signature& sig : signatures) {
			Json g = Json::obj();
			g.add(L"Kind", Json::str(sig.kind));
			for (const auto& [name, value] : sig.values) g.add(name, value);
			g.add(L"DefaultGatewayMac", Json::str(sig.gatewayMac));
			list.push(std::move(g));
		}
		o.add(L"Signatures", std::move(list));
	}
	return o;
}

HRESULT KnownNetworks::getData() {
	if (!conf.Software) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const std::wstring LIST = L"Microsoft\\Windows NT\\CurrentVersion\\NetworkList";
	for (const std::wstring& guid : subkeys(conf.Software, LIST + L"\\Profiles")) {
		ORHKEY key = NULL;
		if (OROpenKey(conf.Software, (LIST + L"\\Profiles\\" + guid).c_str(), &key) != ERROR_SUCCESS) continue;
		KnownNetwork n;
		n.profileGuid = guid;
		n.profileLastWriteUtc = lastWrite(key);
		for (DWORD i = 0;; ++i) {
			std::wstring name;
			DWORD type = 0;
			std::vector<BYTE> data;
			if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
			if (name == L"DateCreated") n.createdUtc = networkListDate(data);
			else if (name == L"DateLastConnected") n.lastConnectedUtc = networkListDate(data);
			else n.values.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
		}
		ORCloseKey(key);
		networks_.push_back(std::move(n));
	}
	// Signatures: one per network seen, pointing to its profile by ProfileGuid.
	for (const wchar_t* kind : { L"Managed", L"Unmanaged" }) {
		const std::wstring base = LIST + L"\\Signatures\\" + kind;
		for (const std::wstring& id : subkeys(conf.Software, base)) {
			ORHKEY key = NULL;
			if (OROpenKey(conf.Software, (base + L"\\" + id).c_str(), &key) != ERROR_SUCCESS) continue;
			KnownNetwork::Signature sig;
			sig.kind = kind;
			std::wstring profile;
			for (DWORD i = 0;; ++i) {
				std::wstring name;
				DWORD type = 0;
				std::vector<BYTE> data;
				if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
				if (name == L"ProfileGuid") profile = readWideZ(data.data(), data.size(), 0);
				else if (name == L"DefaultGatewayMac") sig.gatewayMac = HardwareAddressText(data.data(), data.size());
				else sig.values.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
			}
			ORCloseKey(key);
			auto owner = std::find_if(networks_.begin(), networks_.end(),
			                          [&](const KnownNetwork& n) { return _wcsicmp(n.profileGuid.c_str(), profile.c_str()) == 0; });
			if (owner != networks_.end()) owner->signatures.push_back(std::move(sig));
			else log(2, L"🔥NetworkList: signature " + id + L" points to no profile (" + profile + L")");
		}
	}
	return ERROR_SUCCESS;
}

HRESULT KnownNetworks::toJson() { return writeList("known_networks.json", networks_); }
void KnownNetworks::clear() { networks_.clear(); }

// ------------------------------------------------------------ Program usage

namespace {

//! A FILETIME stored as a QWORD (JumplistData, RADAR) as its two dates.
void addQwordDate(std::vector<std::pair<std::wstring, Json>>& values, const std::wstring& key,
                  const std::vector<BYTE>& data) {
	if (data.size() < sizeof(FILETIME)) return;
	FILETIME utc;
	memcpy(&utc, data.data(), sizeof(FILETIME));
	if (!utc.dwLowDateTime && !utc.dwHighDateTime) return;
	values.emplace_back(key + L"Utc", Json::str(timeToIso8601Utc(utc)));
	values.emplace_back(key, Json::str(utcTimeToIso8601Local(utc)));
}

/*! Reads one key whose values are programs: `convert` turns a value into the
 *  trace's fields.
 *  @param root,path the key
 *  @param source,sid what the traces belong to
 *  @param convert fills the values of one trace from the registry value
 *  @param out receives the traces */
void readUsageKey(ORHKEY root, const std::wstring& path, const std::wstring& source, const std::wstring& sid,
                  const std::function<void(DWORD, const std::vector<BYTE>&, std::vector<std::pair<std::wstring, Json>>&)>& convert,
                  std::vector<ProgramUsage>& out) {
	ORHKEY key = NULL;
	if (OROpenKey(root, path.c_str(), &key) != ERROR_SUCCESS) return;
	const FILETIME written = lastWrite(key);
	for (DWORD i = 0;; ++i) {
		ProgramUsage u;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, u.name, type, data) != ERROR_SUCCESS) break;
		u.source = source;
		u.sid = sid;
		u.keyLastWriteUtc = written;
		convert(type, data, u.values);
		out.push_back(std::move(u));
	}
	ORCloseKey(key);
}

//! The value as stored, under a fixed name.
auto asStored(const wchar_t* field) {
	return [field](DWORD type, const std::vector<BYTE>& data, std::vector<std::pair<std::wstring, Json>>& values) {
		values.emplace_back(field, registryValueToJson(type, data));
	};
}

/*! The taskbar's pinned items: FavoritesResolve is a sequence of whole
 *  shortcuts, each after its size (measured: four of 824, 1267, 1706 and
 *  1780 bytes fill its 5593 exactly). Each is decoded as a .lnk.
 *  @param root the user's hive
 *  @param sid the user
 *  @param out receives one trace per pinned item */
void readTaskband(ORHKEY root, const std::wstring& sid, std::vector<ProgramUsage>& out) {
	const std::wstring path = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband";
	ORHKEY key = NULL;
	if (OROpenKey(root, path.c_str(), &key) != ERROR_SUCCESS) return;
	const FILETIME written = lastWrite(key);
	std::vector<BYTE> data;
	const bool read = getRegBinaryValue(key, nullptr, L"FavoritesResolve", data) == ERROR_SUCCESS;
	ORCloseKey(key);
	if (!read) return;
	const size_t LNK_HEADER = 76;
	size_t at = 0;
	for (unsigned index = 0; at + 4 <= data.size(); ++index) {
		DWORD size;
		memcpy(&size, data.data() + at, 4);
		if (size < LNK_HEADER || size > data.size() - at - 4) {
			log(2, L"🔥Taskband: pinned item of " + std::to_wstring(size) + L" bytes at " + std::to_wstring(at) + L", walk stopped");
			break;
		}
		std::vector<BYTE> lnk(data.begin() + at + 4, data.begin() + at + 4 + size);
		RecentDoc shortcut(lnk.data(), lnk.size(), L"Taskband\\FavoritesResolve", sid);
		ProgramUsage u;
		u.source = L"Taskband";
		u.sid = sid;
		u.name = shortcut.target.empty() ? L"pinned item " + std::to_wstring(index) : shortcut.target;
		u.keyLastWriteUtc = written;
		u.values.emplace_back(L"Shortcut", shortcut.toJson());
		out.push_back(std::move(u));
		at += 4 + size;
	}
}

} // namespace

Json ProgramUsage::toJson() const {
	Json o = Json::obj();
	o.add(L"Source", Json::str(source));
	if (!sid.empty()) addUser(o, sid);
	o.add(L"Name", Json::str(name));
	for (const auto& [n, v] : values) o.add(n, v);
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT ProgramUsages::getData() {
	const std::wstring NT = L"Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\";
	auto lastUsed = [](DWORD, const std::vector<BYTE>& data, std::vector<std::pair<std::wstring, Json>>& values) {
		addQwordDate(values, L"LastUsed", data);
	};
	if (conf.Software) {
		readUsageKey(conf.Software, NT + L"Layers", L"AppCompatFlags\\Layers", L"", asStored(L"Layers"), usages_);
		// RADAR: one subkey per program diagnosed for a memory leak.
		const std::wstring radar = L"Microsoft\\RADAR\\HeapLeakDetection\\DiagnosedApplications";
		for (const std::wstring& program : subkeys(conf.Software, radar)) {
			ORHKEY key = NULL;
			if (OROpenKey(conf.Software, (radar + L"\\" + program).c_str(), &key) != ERROR_SUCCESS) continue;
			ProgramUsage u;
			u.source = L"RADAR";
			u.name = program;
			u.keyLastWriteUtc = lastWrite(key);
			for (DWORD i = 0;; ++i) {
				std::wstring name;
				DWORD type = 0;
				std::vector<BYTE> data;
				if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
				if (name == L"LastDetectionTime" && type == REG_QWORD) addQwordDate(u.values, L"LastDetectionTime", data);
				else u.values.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
			}
			ORCloseKey(key);
			usages_.push_back(std::move(u));
		}
	}
	forEachProfileHive(L"\\ntuser.dat", [&](ORHKEY root, const std::wstring& sid) {
		const std::wstring explorer = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage";
		for (const std::wstring& kind : subkeys(root, explorer))
			readUsageKey(root, explorer + L"\\" + kind, L"FeatureUsage\\" + kind, sid, asStored(L"Count"), usages_);
		readUsageKey(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData", L"JumplistData", sid, lastUsed, usages_);
		readUsageKey(root, L"Software\\" + NT + L"Compatibility Assistant\\Store", L"CompatibilityAssistant\\Store", sid, asStored(L"Data"), usages_);
		readUsageKey(root, L"Software\\" + NT + L"Layers", L"AppCompatFlags\\Layers", sid, asStored(L"Layers"), usages_);
		readTaskband(root, sid, usages_);
	});
	return ERROR_SUCCESS;
}

HRESULT ProgramUsages::toJson() { return writeList("program_usage.json", usages_); }
void ProgramUsages::clear() { usages_.clear(); }

// ------------------------------------------------------------ Devices

namespace {

/*! Reads the four dates of a device's properties: DEVPROP_TYPE_FILETIME
 *  values, UTC (the USBSTOR ones were confronted with Get-PnpDeviceProperty),
 *  under Properties\\{83da6326-97a6-4088-9453-a1923f573b29}.
 *  @param key the device instance's key
 *  @param d receives the dates */
void readDeviceDates(ORHKEY key, DeviceTrace& d) {
	const std::wstring PROPERTIES = L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\";
	const std::pair<const wchar_t*, FILETIME*> DATES[] = {
		{ L"0064", &d.installUtc }, { L"0065", &d.firstInstallUtc },
		{ L"0066", &d.lastArrivalUtc }, { L"0067", &d.lastRemovalUtc } };
	for (const auto& [id, date] : DATES)
		if (getRegFiletimeValue(key, (PROPERTIES + id).c_str(), L"", date) != ERROR_SUCCESS) *date = FILETIME{ 0, 0 };
}

/*! Reads every device of one enumerator: Enum\\<enumerator>\\<device>\\<instance>.
 *  @param enumerator "USB", "SCSI"
 *  @param out receives the devices */
void readEnumerator(const std::wstring& enumerator, std::vector<DeviceTrace>& out) {
	const std::wstring base = L"Enum\\" + enumerator;
	for (const std::wstring& device : subkeys(conf.CurrentControlSet, base))
		for (const std::wstring& instance : subkeys(conf.CurrentControlSet, base + L"\\" + device)) {
			ORHKEY key = NULL;
			if (OROpenKey(conf.CurrentControlSet, (base + L"\\" + device + L"\\" + instance).c_str(), &key) != ERROR_SUCCESS) continue;
			DeviceTrace d;
			d.source = base;
			d.name = device + L"\\" + instance;
			d.keyLastWriteUtc = lastWrite(key);
			readAllValues(key, d.values);
			readDeviceDates(key, d);
			ORCloseKey(key);
			out.push_back(std::move(d));
		}
}

/*! Reads the subkeys of `path` in `root` as traces of one source: each its
 *  values and its key's last write.
 *  @param root,path where
 *  @param source the traces' source
 *  @param out receives them */
void readKeysAsTraces(ORHKEY root, const std::wstring& path, const std::wstring& source, std::vector<DeviceTrace>& out) {
	for (const std::wstring& name : subkeys(root, path)) {
		ORHKEY key = NULL;
		if (OROpenKey(root, (path + L"\\" + name).c_str(), &key) != ERROR_SUCCESS) continue;
		DeviceTrace d;
		d.source = source;
		d.name = name;
		d.keyLastWriteUtc = lastWrite(key);
		readAllValues(key, d.values);
		ORCloseKey(key);
		out.push_back(std::move(d));
	}
}

} // namespace

Json DeviceTrace::toJson() const {
	Json o = Json::obj();
	o.add(L"Source", Json::str(source));
	o.add(L"Name", Json::str(name));
	for (const auto& [n, v] : values) o.add(n, v);
	addDate(o, L"Install", installUtc);
	addDate(o, L"FirstInstall", firstInstallUtc);
	addDate(o, L"LastArrival", lastArrivalUtc);
	addDate(o, L"LastRemoval", lastRemovalUtc);
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT Devices::getData() {
	if (!conf.CurrentControlSet) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	readEnumerator(L"USB", devices_);
	readEnumerator(L"SCSI", devices_);
	/* The disk, volume and portable-device interfaces: one subkey per device
	   that exposed one, written when it first did. */
	const wchar_t* INTERFACES[] = { L"{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",   // disks
	                                L"{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}",   // volumes
	                                L"{6ac27878-a6fa-4155-ba85-f98f491d4f33}" }; // portable devices
	for (const wchar_t* guid : INTERFACES)
		readKeysAsTraces(conf.CurrentControlSet, std::wstring(L"Control\\DeviceClasses\\") + guid,
		                 std::wstring(L"DeviceClasses\\") + guid, devices_);
	if (conf.Software) {
		readKeysAsTraces(conf.Software, L"Microsoft\\Windows Portable Devices\\Devices", L"WindowsPortableDevices", devices_);
		readKeysAsTraces(conf.Software, L"Microsoft\\Windows Search\\VolumeInfoCache", L"VolumeInfoCache", devices_);
	}
	return ERROR_SUCCESS;
}

HRESULT Devices::toJson() { return writeList("devices.json", devices_); }
void Devices::clear() { devices_.clear(); }

// ------------------------------------------------------------ Network shares

Json NetworkShare::toJson() const {
	Json o = Json::obj();
	o.add(L"Name", Json::str(name));
	for (const auto& [field, value] : fields) o.add(registryNameToJsonKey(field), Json::str(value));
	o.add(L"SecurityDescriptor", securityDescriptor);
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT NetworkShares::getData() {
	if (!conf.CurrentControlSet) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const std::wstring SHARES = L"Services\\LanmanServer\\Shares";
	ORHKEY key = NULL;
	if (OROpenKey(conf.CurrentControlSet, SHARES.c_str(), &key) != ERROR_SUCCESS) return ERROR_SUCCESS;
	const FILETIME written = lastWrite(key);
	for (DWORD i = 0;; ++i) {
		NetworkShare share;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, share.name, type, data) != ERROR_SUCCESS) break;
		share.keyLastWriteUtc = written;
		// A REG_MULTI_SZ of "Name=Value" lines.
		const Json lines = registryValueToJson(type, data);
		if (lines.kind() == Json::Kind::Arr)
			for (const auto& [unused, line] : lines.members()) {
				const std::wstring text = line.text();
				const size_t equal = text.find(L'=');
				if (equal != std::wstring::npos) share.fields.emplace_back(text.substr(0, equal), text.substr(equal + 1));
			}
		std::vector<BYTE> sd;
		if (getRegBinaryValue(conf.CurrentControlSet, (SHARES + L"\\Security").c_str(), share.name.c_str(), sd) == ERROR_SUCCESS)
			share.securityDescriptor = securityDescriptorToJson(sd.data(), sd.size());
		shares_.push_back(std::move(share));
	}
	ORCloseKey(key);
	return ERROR_SUCCESS;
}

HRESULT NetworkShares::toJson() { return writeList("network_shares.json", shares_); }
void NetworkShares::clear() { shares_.clear(); }

// ------------------------------------------------------------ Network configuration

namespace {

/*! Every value of a key, the DHCP lease times — Unix times, seconds since
 *  1970 UTC — as dates.
 *  @param root,path the key
 *  @param out receives the values
 *  @param written receives the key's last write, if asked */
void readInterfaceValues(ORHKEY root, const std::wstring& path, std::vector<std::pair<std::wstring, Json>>& out,
                         FILETIME* written = nullptr) {
	ORHKEY key = NULL;
	if (OROpenKey(root, path.c_str(), &key) != ERROR_SUCCESS) return;
	if (written) *written = lastWrite(key);
	const wchar_t* LEASE_TIMES[] = { L"LeaseObtainedTime", L"LeaseTerminatesTime", L"T1", L"T2" };
	for (DWORD i = 0;; ++i) {
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
		const bool leaseTime = std::any_of(std::begin(LEASE_TIMES), std::end(LEASE_TIMES),
		                                   [&](const wchar_t* t) { return name == t; });
		if (leaseTime && type == REG_DWORD && data.size() >= 4) {
			DWORD seconds;
			memcpy(&seconds, data.data(), 4);
			const FILETIME utc = unixToFiletime(seconds);
			out.emplace_back(name + L"Utc", Json::str(timeToIso8601Utc(utc, Precision::Second)));
			out.emplace_back(name, Json::str(utcTimeToIso8601Local(utc, Precision::Second)));
		}
		else if ((name == L"CurrentAddress" || name == L"PermanentAddress") && type == REG_BINARY)
			// The adapter's hardware address, in the form WAC gives every one.
			out.emplace_back(name, Json::str(HardwareAddressText(data.data(), data.size())));
		else out.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
	}
	ORCloseKey(key);
}

//! A list of name/value pairs as one JSON object; nothing for an empty list.
void addSection(Json& o, const wchar_t* key, const std::vector<std::pair<std::wstring, Json>>& values) {
	if (values.empty()) return;
	Json section = Json::obj();
	for (const auto& [n, v] : values) section.add(n, v);
	o.add(key, std::move(section));
}

} // namespace

Json NetworkAdapterConfiguration::toJson() const {
	Json o = Json::obj();
	o.add(L"InterfaceGuid", Json::str(guid));
	addSection(o, L"Adapter", adapter);
	addSection(o, L"Ipv4", ipv4);
	addDate(o, L"Ipv4KeyLastWrite", ipv4LastWriteUtc);
	addSection(o, L"Ipv6", ipv6);
	addSection(o, L"Kernel", kernel);
	return o;
}

HRESULT NetworkConfiguration::getData() {
	if (!conf.CurrentControlSet) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const std::wstring TCPIP = L"Services\\Tcpip\\Parameters";
	ORHKEY key = NULL;
	if (OROpenKey(conf.CurrentControlSet, TCPIP.c_str(), &key) == ERROR_SUCCESS) {
		for (const wchar_t* name : { L"Hostname", L"NV Hostname", L"Domain", L"NV Domain", L"SearchList", L"DhcpDomain", L"NameServer" }) {
			DWORD type = 0, size = 0;
			if (ORGetValue(key, nullptr, name, &type, nullptr, &size) != ERROR_SUCCESS) continue;
			std::vector<BYTE> data(size);
			if (ORGetValue(key, nullptr, name, &type, data.data(), &size) == ERROR_SUCCESS)
				global_.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
		}
		ORCloseKey(key);
	}
	// The adapters, by their GUID: the class entry names them, Tcpip holds their settings.
	const std::wstring CLASS = L"Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
	auto adapterFor = [&](const std::wstring& guid) -> NetworkAdapterConfiguration& {
		for (NetworkAdapterConfiguration& a : adapters_) if (_wcsicmp(a.guid.c_str(), guid.c_str()) == 0) return a;
		adapters_.push_back(NetworkAdapterConfiguration{});
		adapters_.back().guid = guid;
		return adapters_.back();
	};
	for (const std::wstring& index : subkeys(conf.CurrentControlSet, CLASS)) {
		std::wstring guid;
		if (getRegSzValue(conf.CurrentControlSet, (CLASS + L"\\" + index).c_str(), L"NetCfgInstanceId", &guid) != ERROR_SUCCESS || guid.empty()) continue;
		std::vector<std::pair<std::wstring, Json>> values;
		ORHKEY k = NULL;
		if (OROpenKey(conf.CurrentControlSet, (CLASS + L"\\" + index).c_str(), &k) == ERROR_SUCCESS) {
			readAllValues(k, values);
			ORCloseKey(k);
		}
		adapterFor(guid).adapter = std::move(values);
	}
	for (const std::wstring& guid : subkeys(conf.CurrentControlSet, TCPIP + L"\\Interfaces")) {
		NetworkAdapterConfiguration& a = adapterFor(guid);
		readInterfaceValues(conf.CurrentControlSet, TCPIP + L"\\Interfaces\\" + guid, a.ipv4, &a.ipv4LastWriteUtc);
	}
	for (NetworkAdapterConfiguration& a : adapters_) {
		readInterfaceValues(conf.CurrentControlSet, L"Services\\Tcpip6\\Parameters\\Interfaces\\" + a.guid, a.ipv6);
		readInterfaceValues(conf.CurrentControlSet, L"Control\\NetworkSetup2\\Interfaces\\" + a.guid + L"\\Kernel", a.kernel);
	}
	return ERROR_SUCCESS;
}

HRESULT NetworkConfiguration::toJson() {
	Json o = Json::obj();
	addSection(o, L"Global", global_);
	Json adapters = Json::arr();
	for (const NetworkAdapterConfiguration& a : adapters_) adapters.push(a.toJson());
	o.add(L"Adapters", std::move(adapters));
	return writeJsonFile("network_configuration.json", o);
}

void NetworkConfiguration::clear() { global_.clear(); adapters_.clear(); }

// ------------------------------------------------------------ Event log configuration

Json EventLogChannel::toJson() const {
	Json o = Json::obj();
	o.add(L"Source", Json::str(source));
	o.add(L"Name", Json::str(name));
	for (const auto& [n, v] : values) o.add(n, v);
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT EventLogConfiguration::getData() {
	auto read = [this](ORHKEY root, const std::wstring& base, const wchar_t* source) {
		for (const std::wstring& name : subkeys(root, base)) {
			// Under Services\\EventLog, "Parameters" and "State" are the service's
			// own keys, not logs: its DLL is in services.json.
			if (name == L"Parameters" || name == L"State") continue;
			ORHKEY key = NULL;
			if (OROpenKey(root, (base + L"\\" + name).c_str(), &key) != ERROR_SUCCESS) continue;
			EventLogChannel c;
			c.source = source;
			c.name = name;
			c.keyLastWriteUtc = lastWrite(key);
			readAllValues(key, c.values);
			ORCloseKey(key);
			channels_.push_back(std::move(c));
		}
	};
	if (conf.Software) read(conf.Software, L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels", L"WINEVT\\Channels");
	if (conf.CurrentControlSet) read(conf.CurrentControlSet, L"Services\\EventLog", L"Services\\EventLog");
	return ERROR_SUCCESS;
}

HRESULT EventLogConfiguration::toJson() { return writeList("event_log_configuration.json", channels_); }
void EventLogConfiguration::clear() { channels_.clear(); }
