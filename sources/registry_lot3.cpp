/*! \file
 *  \brief Registry artefacts of the third lot (see registry_lot3.h).
 */
#include "registry_lot3.h"

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
