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
