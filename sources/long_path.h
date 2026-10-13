/*! \file
 *  \brief Paths longer than MAX_PATH: the extended form, and the operations
 *  on folders and files that hold with it.
 *
 *  WHY. An exhibit is stored under its original path, below the output
 *  folder: `<output>\exhibits\C\Users\…`. A path of 230 characters on the
 *  examined machine — a deep `node_modules`, an application's profile —
 *  passes MAX_PATH (260) once there, and Windows refuses it unless it is
 *  written in the extended form `\\?\C:\…`: 482 exhibits of a full kit were
 *  lost so (0x8007001d, backlog B-049). Declaring the program `longPathAware`
 *  is not enough: it also needs `LongPathsEnabled` in the registry, off by
 *  default, and WAC writes nothing on the examined machine.
 *
 *  WHY NOT std::filesystem. Measured in the test VM with g++ 13 (MinGW-w64):
 *  on an extended path, the streams and `file_size` work, but
 *  `create_directories` loops forever, `copy_file` fails ("File exists",
 *  overwrite asked), `relative` and `root_name` give nothing, and a
 *  directory iteration does not give the folder's files. Folders, copies,
 *  moves, walks and deletions therefore go through Win32 here; a stream is
 *  opened on `extendedPath(path)`.
 *
 *  Header-only and without WAC's other headers, as whole_file.h, which uses it.
 */
#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

/*! The form of `path` that Windows opens whatever its length.
 *
 *  A path whose ABSOLUTE form is shorter than the limit is returned AS IS:
 *  what is written, logged and recorded keeps its ordinary form, and the APIs
 *  that do not accept the extended one (some take a path from WAC: esent, the
 *  offline registry) never see it on a common path. The absolute form decides,
 *  not the path as given: Windows applies the limit after resolving it, and a
 *  relative "out\working\…" of 241 characters failed once under C:\wactest.
 *  A longer one is made absolute (GetFullPathNameW, which also turns `/` into
 *  `\` — the extended form takes no `/`, no `.`, no `..`) and prefixed:
 *  `\\?\C:\…`, or `\\?\UNC\server\share\…`.
 *  @param path a file or folder, absolute or relative to the current folder
 *  @return the path to give Windows */
inline std::wstring extendedPath(const std::wstring& path) {
	// MAX_PATH less the 12 characters CreateDirectoryW keeps for an 8.3 name.
	const size_t LIMIT = MAX_PATH - 12;
	if (path.empty() || path.compare(0, 4, L"\\\\?\\") == 0) return path;
	const DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
	if (size == 0) return path;
	std::wstring full(size, L'\0');
	const DWORD written = GetFullPathNameW(path.c_str(), size, full.data(), nullptr);
	if (written == 0 || written >= size) return path;
	full.resize(written);
	if (full.size() < LIMIT) return path;
	if (full.compare(0, 2, L"\\\\") == 0) return L"\\\\?\\UNC\\" + full.substr(2);
	return L"\\\\?\\" + full;
}

/*! Creates a folder and its parents, whatever the length of its path.
 *  @param folder the folder
 *  @return true if it exists afterwards */
inline bool createFolders(const std::wstring& folder) {
	const std::wstring path = extendedPath(folder);
	const DWORD attributes = GetFileAttributesW(path.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES) return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
	const size_t cut = path.find_last_of(L"\\/");
	// The parent first; a root ("C:", "\\?\C:") has none to create.
	if (cut != std::wstring::npos && cut > 0 && path[cut - 1] != L':' && path[cut - 1] != L'?')
		createFolders(path.substr(0, cut));
	return CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

/*! The folder of a file path: everything before its last separator.
 *  @param file the file
 *  @return its folder, empty if the path has no separator */
inline std::wstring parentFolder(const std::wstring& file) {
	const size_t cut = file.find_last_of(L"\\/");
	return cut == std::wstring::npos ? std::wstring() : file.substr(0, cut);
}

/*! Whether a file or folder exists, whatever the length of its path. */
inline bool pathExists(const std::wstring& path) {
	return GetFileAttributesW(extendedPath(path).c_str()) != INVALID_FILE_ATTRIBUTES;
}

/*! The size of a file, whatever the length of its path.
 *  @return false if it cannot be read */
inline bool fileSizeOf(const std::wstring& file, uint64_t& size) {
	WIN32_FILE_ATTRIBUTE_DATA data = {};
	if (!GetFileAttributesExW(extendedPath(file).c_str(), GetFileExInfoStandard, &data)) return false;
	size = ((uint64_t)data.nFileSizeHigh << 32) | data.nFileSizeLow;
	return true;
}

/*! Copies a file, its folder created, whatever the length of the paths.
 *  @param source the file
 *  @param target its copy
 *  @param overwrite whether an existing target is replaced
 *  @return true on success */
inline bool copyFileLong(const std::wstring& source, const std::wstring& target, bool overwrite) {
	createFolders(parentFolder(target));
	return CopyFileW(extendedPath(source).c_str(), extendedPath(target).c_str(), overwrite ? FALSE : TRUE) != 0;
}

/*! Moves a file on the same volume, its folder created, whatever the length
 *  of the paths. An existing target is not replaced.
 *  @return true on success */
inline bool moveFileLong(const std::wstring& source, const std::wstring& target) {
	createFolders(parentFolder(target));
	return MoveFileExW(extendedPath(source).c_str(), extendedPath(target).c_str(), 0) != 0;
}

/*! Every file below a folder, whatever the depth, with its path RELATIVE to
 *  the folder ("a\b.txt"): each folder's files, then its subfolders in the
 *  order Windows lists them. A subfolder that cannot be listed is skipped, the
 *  walk goes on: std::filesystem's iteration stopped at the first error, and
 *  a deep folder ended it before the system hives were reached (B-049).
 *  @param folder the folder
 *  @param visit called for each regular file
 *  @param enter decides, from its relative path, whether a subfolder is
 *         walked; empty: all of them
 *  @return false if the folder itself cannot be listed */
/*! Starts the listing of a folder, as each walk here wants it: names only,
 *  fetched in large batches. Both options came with Windows 7; XP and Vista
 *  refuse the call ("the parameter is incorrect") — the walk then listed
 *  nothing, and under XP the working copy of a collection stayed empty
 *  without a word. Refused, the listing is asked for the way XP knows.
 *  @param pattern the folder, extended, followed by `\*`
 *  @param found receives the first entry
 *  @return the search handle, INVALID_HANDLE_VALUE if the folder cannot be listed */
inline HANDLE firstFolderEntry(const std::wstring& pattern, WIN32_FIND_DATAW& found) {
	const HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &found, FindExSearchNameMatch, nullptr,
	                                  FIND_FIRST_EX_LARGE_FETCH);
	if (h != INVALID_HANDLE_VALUE || GetLastError() != ERROR_INVALID_PARAMETER) return h;
	return FindFirstFileExW(pattern.c_str(), FindExInfoStandard, &found, FindExSearchNameMatch, nullptr, 0);
}

inline bool forEachFileBelow(const std::wstring& folder, const std::function<void(const std::wstring&)>& visit,
                             const std::function<bool(const std::wstring&)>& enter = nullptr) {
	const std::wstring root = extendedPath(folder);
	std::vector<std::wstring> pending{ L"" };
	bool first = true;
	while (!pending.empty()) {
		const std::wstring relative = pending.back();
		pending.pop_back();
		// The folder joined to its relative part, and only then extended: the
		// sum may pass the limit where neither did.
		const std::wstring here = extendedPath(relative.empty() ? root : root + L"\\" + relative);
		WIN32_FIND_DATAW found = {};
		const HANDLE h = firstFolderEntry(here + L"\\*", found);
		if (h == INVALID_HANDLE_VALUE) {
			if (first) return false;
			continue;
		}
		first = false;
		std::vector<std::wstring> subfolders;
		do {
			const std::wstring name = found.cFileName;
			if (name == L"." || name == L"..") continue;
			const std::wstring child = relative.empty() ? name : relative + L"\\" + name;
			// A junction or a symbolic link is not followed: it can loop.
			if (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
			if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (!enter || enter(child)) subfolders.push_back(child);
			}
			else visit(child);
		} while (FindNextFileW(h, &found));
		FindClose(h);
		// Pushed in reverse: the first listed is walked first.
		pending.insert(pending.end(), subfolders.rbegin(), subfolders.rend());
	}
	return true;
}

/*! Deletes a folder and everything below it, whatever the depth.
 *  @param folder the folder
 *  @return true if it no longer exists afterwards */
inline bool removeFolderTree(const std::wstring& folder) {
	const std::wstring root = extendedPath(folder);
	if (GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
	std::vector<std::wstring> folders{ L"" };   // in the order found: parents first
	forEachFileBelow(folder, [&](const std::wstring& relative) {
		const std::wstring file = extendedPath(root + L"\\" + relative);
		SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);   // a read-only exhibit too
		DeleteFileW(file.c_str());
	});
	// The folders, listed parents first, removed children first.
	for (size_t i = 0; i < folders.size(); ++i) {
		const std::wstring here = extendedPath(folders[i].empty() ? root : root + L"\\" + folders[i]);
		WIN32_FIND_DATAW found = {};
		const HANDLE h = firstFolderEntry(here + L"\\*", found);
		if (h == INVALID_HANDLE_VALUE) continue;
		do {
			const std::wstring name = found.cFileName;
			if (name == L"." || name == L"..") continue;
			// A junction is removed as a folder, never entered: its target is not ours.
			if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
				folders.push_back(folders[i].empty() ? name : folders[i] + L"\\" + name);
			else if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				RemoveDirectoryW(extendedPath(here + L"\\" + name).c_str());
		} while (FindNextFileW(h, &found));
		FindClose(h);
	}
	for (size_t i = folders.size(); i-- > 0;)
		RemoveDirectoryW(extendedPath(folders[i].empty() ? root : root + L"\\" + folders[i]).c_str());
	return GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES;
}

/*! The part of `path` below `folder` ("a\b.txt"), compared without case.
 *  A string operation: std::filesystem::relative gives nothing on an extended
 *  path, and checks each parent on the disk where none needs checking.
 *  @param path a file below the folder
 *  @param folder the folder, without a trailing separator
 *  @return the relative part, empty if `path` is not below `folder` */
inline std::wstring pathBelow(const std::wstring& path, const std::wstring& folder) {
	if (folder.empty() || path.size() <= folder.size() + 1 || path[folder.size()] != L'\\') return std::wstring();
	if (CompareStringOrdinal(path.c_str(), (int)folder.size(), folder.c_str(), (int)folder.size(), TRUE) != CSTR_EQUAL)
		return std::wstring();
	return path.substr(folder.size() + 1);
}
