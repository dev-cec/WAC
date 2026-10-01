/*! \file
 *  \brief Shortcuts outside the Recent folder (see shortcuts.h).
 */
#include "shortcuts.h"
#include "startup_folders.h"
#include "consigne.h"
#include "user_shell_folders.h"
#include <filesystem>

const ShortcutFolder SHORTCUT_FOLDERS[] = {
	{ L"\\ProgramData\\Microsoft\\Windows\\Start Menu",                     false, true,  L"StartMenu" },
	{ L"\\Users\\Public\\Desktop",                                          false, false, L"Desktop" },
	{ L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu",                true,  true,  L"StartMenu" },
	{ L"\\Desktop",                                                         true,  false, L"Desktop" },
	{ L"\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch",    true,  true,  L"QuickLaunch" },
};
const size_t SHORTCUT_FOLDER_COUNT = sizeof(SHORTCUT_FOLDERS) / sizeof(SHORTCUT_FOLDERS[0]);

namespace {

//! Under Quick Launch, the shortcuts pinned to the task bar.
const wchar_t PINNED_TASK_BAR[] = L"\\user pinned\\taskbar\\";

/*! Whether a path begins with a folder, case ignored.
 *  @param path the path
 *  @param folder the folder, without a final separator
 *  @return true if path is inside folder */
bool isInside(const std::wstring& path, const std::wstring& folder) {
	return path.size() > folder.size() && path[folder.size()] == L'\\'
	    && toLower(path.substr(0, folder.size())) == toLower(folder);
}

/*! Every .lnk and .url of an extracted folder, its subfolders too if asked.
 *  @param root the folder, in the working copy
 *  @param recursive true to descend, up to SHORTCUT_TREE_DEPTH
 *  @param skipped a subfolder not to descend into (the Startup folder), in the working copy; empty for none
 *  @return the files, in the order listed */
std::vector<std::filesystem::path> listShortcuts(const std::filesystem::path& root, bool recursive,
                                                 const std::wstring& skipped) {
	if (!recursive) return listFilesByExtension(root, { L".lnk", L".url" });
	std::vector<std::filesystem::path> files;
	std::error_code ec;
	std::filesystem::recursive_directory_iterator it(root, ec), end;
	for (; !ec && it != end; it.increment(ec)) {
		if (it->is_directory(ec)) {
			if ((unsigned)it.depth() >= SHORTCUT_TREE_DEPTH
			    || (!skipped.empty() && toLower(it->path().wstring()) == toLower(skipped)))
				it.disable_recursion_pending();
			continue;
		}
		const std::wstring extension = toLower(it->path().extension().wstring());
		if (it->is_regular_file(ec) && (extension == L".lnk" || extension == L".url"))
			files.push_back(it->path());
	}
	return files;
}

/*! Reads the shortcuts of one folder.
 *  @param where the folder
 *  @param items receives the shortcuts */
void readFolder(const ShortcutLocation& where, std::vector<ShortcutItem>& items) {
	const ShortcutFolder& folder = *where.folder;
	const std::wstring& sid = where.sid;
	const std::wstring root = extractedPath(where.absolute);
	const std::vector<std::filesystem::path> files =
		listShortcuts(root, folder.recursive, where.startup.empty() ? L"" : extractedPath(where.startup));
	size_t iFile = 0;
	for (const std::filesystem::path& file : files) {
		printProgress(L"Shortcut " + file.filename().wstring(), ++iFile, files.size(), L"lnk");
		ShortcutItem item;
		item.sid = sid;
		item.location = folder.location;
		// Below the folder, case ignored: Windows writes "User Pinned" or "user pinned".
		if (toLower(file.wstring()).find(PINNED_TASK_BAR, root.size()) != std::wstring::npos)
			item.location = L"TaskBar";
		item.shortcut = std::make_unique<RecentDoc>(file, sid);
		items.push_back(std::move(item));
	}
}

} // namespace

std::vector<ShortcutLocation> shortcutLocations() {
	std::vector<ShortcutLocation> locations;
	for (size_t i = 0; i < SHORTCUT_FOLDER_COUNT; ++i) {
		const ShortcutFolder& folder = SHORTCUT_FOLDERS[i];
		if (!folder.perProfile) {
			const std::wstring base = conf.systemDrive + folder.relative;
			const std::wstring startup = conf.systemDrive + STARTUP_ALL_USERS;
			locations.push_back({ &folder, base, L"", isInside(startup, base) ? startup : L"" });
			continue;
		}
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
			const std::wstring& sid = std::get<0>(profileEntry);
			const std::wstring& profile = std::get<1>(profileEntry);   // absolute, with its letter
			const std::wstring base = profile + folder.relative;
			const std::wstring startup = profile + STARTUP_PROFILE;
			locations.push_back({ &folder, base, sid, isInside(startup, base) ? startup : L"" });
			// A desktop moved elsewhere (OneDrive, another disk): its shortcuts are there.
			if (std::wstring(folder.location) == L"Desktop") {
				const std::wstring moved = redirectedDesktop(sid, profile);
				if (!moved.empty()) locations.push_back({ &folder, moved, sid, L"" });
			}
		}
	}
	return locations;
}

Json ShortcutItem::toJson() const {
	Json o = Json::obj();
	o.add(L"Location", Json::str(location));
	o.add(L"Scope", Json::str(sid.empty() ? L"AllUsers" : L"User"));
	addUser(o, sid);
	o.merge(shortcut->toJson());
	return o;
}

HRESULT Shortcuts::getData() {
	log(0, L"ℹ️Shortcuts :");
	for (const ShortcutLocation& where : shortcutLocations()) readFolder(where, items_);
	return ERROR_SUCCESS;
}

HRESULT Shortcuts::toJson() {
	Json list = Json::arr();
	for (const ShortcutItem& i : items_) list.push(i.toJson());
	return writeJsonFile("shortcuts.json", list);
}

void Shortcuts::clear() {
	items_.clear();
}
