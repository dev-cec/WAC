/*! \file
 *  \brief Registry artefacts of the third lot (see registry_lot3.h).
 */
#include "registry_lot3.h"
#include "idList.h"
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
