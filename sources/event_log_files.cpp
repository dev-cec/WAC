/*! \file
 *  \brief The event logs kept outside their default folder (see event_log_files.h).
 */
#include "event_log_files.h"
#include "registry_common.h"
#include "tools.h"
#include <set>

namespace {

//! The folders Windows keeps its logs in: a file there is collected with them.
const wchar_t* const DEFAULT_FOLDERS[] = { L"\\windows\\system32\\winevt\\logs\\", L"\\windows\\system32\\config\\" };

/*! Whether a path lies in one of the default folders, any volume.
 *  @param path an absolute path */
bool inDefaultFolder(const std::wstring& path) {
	const std::wstring lower = toLower(path);
	if (lower.size() < 3 || lower[1] != L':') return false;
	for (const wchar_t* folder : DEFAULT_FOLDERS) {
		const std::wstring f = folder;
		if (lower.compare(2, f.size(), f) == 0 && lower.find(L'\\', 2 + f.size()) == std::wstring::npos) return true;
	}
	return false;
}

} // namespace

std::vector<MovedEventLog> movedEventLogFiles() {
	std::vector<MovedEventLog> files;
	std::set<std::wstring> seen;
	auto read = [&](ORHKEY root, const std::wstring& base) {
		if (!root) return;
		for (const std::wstring& name : subkeys(root, base)) {
			std::wstring file;
			if (getRegSzValue(root, (base + L"\\" + name).c_str(), L"File", &file) != ERROR_SUCCESS || file.empty()) continue;
			const std::wstring path = normalizeFilePath(file);
			if (path.empty() || inDefaultFolder(path) || !seen.insert(toLower(path)).second) continue;
			files.push_back({ name, path });
		}
	};
	read(conf.Software, L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels");
	read(conf.CurrentControlSet, L"Services\\EventLog");
	return files;
}
