/*! \file
 *  \brief Each user's shell folders (see user_shell_folders.h).
 */
#include "user_shell_folders.h"
#include "trans_id.h"
#include <map>

namespace {

//! The key, in a profile's NTUSER.DAT.
const wchar_t USER_SHELL_FOLDERS[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
const wchar_t USERPROFILE[] = L"%userprofile%";

} // namespace

std::wstring resolveUserShellFolder(const std::wstring& raw, const std::wstring& profilePath) {
	std::wstring path = raw;
	const size_t variable = sizeof(USERPROFILE) / sizeof(wchar_t) - 1;
	if (toLower(path.substr(0, variable)) == USERPROFILE) path = profilePath + path.substr(variable);
	return normalizeFilePath(path);
}

std::wstring redirectedDesktop(const std::wstring& sid, const std::wstring& profilePath) {
	// Collection and conversion both ask, for each profile: read once.
	static std::map<std::wstring, std::wstring> cache;
	const auto known = cache.find(sid);
	if (known != cache.end()) return known->second;
	std::wstring desktop;
	ORHKEY root = NULL;
	const std::wstring hive = extractedPath(profilePath) + L"\\ntuser.dat";
	if (OROpenHive(hive.c_str(), &root) == ERROR_SUCCESS) {
		std::wstring raw;
		if (getRegSzValue(root, USER_SHELL_FOLDERS, L"Desktop", &raw) == ERROR_SUCCESS) {
			const std::wstring resolved = resolveUserShellFolder(raw, profilePath);
			if (resolved.empty()) log(2, L"🔥Desktop of " + sid + L" not local, not followed: " + raw);
			else if (toLower(resolved) != toLower(profilePath + L"\\Desktop")) desktop = resolved;
		}
		ORCloseHive(root);
	}
	if (!desktop.empty()) log(2, L"❇️Desktop of " + sid + L" redirected to " + desktop);
	cache.emplace(sid, desktop);
	return desktop;
}

Json UserShellFolder::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	o.add(L"Name", Json::str(name));
	// The newer folders are named by their known folder GUID (Downloads, Saved Games…).
	if (!name.empty() && name.front() == L'{') o.add(L"FolderName", Json::str(trans_guid_to_wstring(name)));
	o.add(L"Value", Json::str(value));
	o.add(L"Path", Json::str(path));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT UserShellFolders::getData() {
	log(0, L"ℹ️User Shell Folders :");
	forEachProfileHive(L"\\ntuser.dat", [&](ORHKEY root, const std::wstring& sid) {
		std::wstring profilePath;
		for (const std::tuple<std::wstring, std::wstring>& p : conf.profiles)
			if (std::get<0>(p) == sid) profilePath = std::get<1>(p);
		ORHKEY key = NULL;
		if (OROpenKey(root, USER_SHELL_FOLDERS, &key) != ERROR_SUCCESS) return;
		DWORD values = 0;
		FILETIME written = { 0 };
		if (ORQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, &values, NULL, NULL, NULL, &written) == ERROR_SUCCESS)
			for (DWORD i = 0; i < values; ++i) {
				UserShellFolder f;
				DWORD type = 0;
				std::vector<BYTE> data;
				if (enumRegistryValue(key, i, f.name, type, data) != ERROR_SUCCESS
				    || (type != REG_SZ && type != REG_EXPAND_SZ)) continue;
				f.sid = sid;
				f.value = readWideZ(data.data(), data.size(), 0);
				f.path = resolveUserShellFolder(f.value, profilePath);
				f.keyLastWriteUtc = written;
				folders_.push_back(std::move(f));
			}
		ORCloseKey(key);
	});
	return ERROR_SUCCESS;
}

HRESULT UserShellFolders::toJson() {
	Json list = Json::arr();
	for (const UserShellFolder& f : folders_) list.push(f.toJson());
	return writeJsonFile("user_shell_folders.json", list);
}

void UserShellFolders::clear() {
	folders_.clear();
}
