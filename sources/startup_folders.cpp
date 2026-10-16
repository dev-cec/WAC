/*! \file
 *  \brief Startup folders (see startup_folders.h).
 */
#include "startup_folders.h"
#include "consigne.h"
#include <filesystem>

const wchar_t STARTUP_ALL_USERS[] = L"\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";
const wchar_t STARTUP_PROFILE[] = L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";

namespace {

/*! Every file of an extracted folder, desktop.ini aside.
 *  @param folder the folder, in the working copy
 *  @param sid the profile's SID, empty for all users
 *  @param items receives the files */
void readFolder(const std::filesystem::path& folder, const std::wstring& sid, std::vector<StartupItem>& items) {
	std::error_code ec;
	for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(folder, ec)) {
		if (!e.is_regular_file(ec)) continue;
		const std::wstring name = toLower(e.path().filename().wstring());
		if (name == L"desktop.ini") continue;
		StartupItem item;
		item.sid = sid;
		item.path = originalPath(e.path().wstring());
		ExhibitSourceTimes(e.path().wstring(), item.sourceCreatedUtc, item.sourceModifiedUtc, item.sourceAccessedUtc);
		const auto& index = ExhibitStoreIndex();
		const auto found = index.find(toLower(item.path));
		if (found != index.end()) {
			item.md5 = found->second.md5;
			item.sha1 = found->second.sha1;
			item.sha256 = found->second.sha256;
		}
		if (name.size() > 4 && name.compare(name.size() - 4, 4, L".lnk") == 0)
			item.shortcut = std::make_unique<RecentDoc>(e.path(), sid);
		items.push_back(std::move(item));
	}
}

} // namespace

Json StartupItem::toJson() const {
	Json o = Json::obj();
	o.add(L"Scope", Json::str(sid.empty() ? L"AllUsers" : L"User"));
	addUser(o, sid);
	o.add(L"Path", Json::str(path));
	addDate(o, L"SourceCreated", sourceCreatedUtc);
	addDate(o, L"SourceModified", sourceModifiedUtc);
	addDate(o, L"SourceAccessed", sourceAccessedUtc);
	o.add(L"MD5", Json::str(md5));
	o.add(L"SHA1", Json::str(sha1));
	o.add(L"SHA256", Json::str(sha256));
	if (shortcut) o.add(L"Shortcut", shortcut->toJson());
	return o;
}

HRESULT StartupFolders::getData() {
	log(0, L"ℹ️Startup folders :");
	readFolder(extractedPath(conf.systemDrive + STARTUP_ALL_USERS), L"", items_);
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
		readFolder(extractedPath(std::get<1>(profileEntry) + STARTUP_PROFILE), std::get<0>(profileEntry), items_);
	return ERROR_SUCCESS;
}

HRESULT StartupFolders::toJson() {
	Json list = Json::arr();
	for (const StartupItem& i : items_) list.push(i.toJson());
	return writeJsonFile("startup_folders.json", list);
}

void StartupFolders::clear() {
	items_.clear();
}
