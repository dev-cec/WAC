/*! \file
 *  \brief removeFolderTree (long_path.h), which empties the previous working
 *         copy before a conversion: a tree past MAX_PATH with a read-only
 *         file goes entirely, and an entry that holds is named with its own
 *         error.
 *
 *  The second check holds the defect it was written for: a conversion
 *  refused on Server 2022 (2026-11-08) said only "access denied", a code its
 *  caller wrote whatever the cause, and the entry that held was lost.
 *
 *  Usage: long_path_test — built by `build-windows.sh --test`, runs under
 *  Wine. Exit code: 0 if all checks hold.
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include "long_path.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

static int failures = 0;

//! Prints a check and its verdict; counts a failure.
void check(bool ok, const char* what) {
	std::printf("%s %s\n", ok ? "OK  " : "FAIL", what);
	if (!ok) ++failures;
}

//! Creates a file holding a few bytes; true if it was written.
static bool makeFile(const std::wstring& path) {
	const HANDLE h = CreateFileW(extendedPath(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) return false;
	DWORD written = 0;
	const bool ok = WriteFile(h, "wac", 3, &written, nullptr) && written == 3;
	return CloseHandle(h) && ok;
}

//! True if nothing exists at `path`.
static bool absent(const std::wstring& path) {
	return GetFileAttributesW(extendedPath(path).c_str()) == INVALID_FILE_ATTRIBUTES;
}

int wmain() {
	wchar_t temp[MAX_PATH] = {};
	const DWORD length = GetTempPathW(MAX_PATH, temp);
	if (length == 0 || length >= MAX_PATH) { std::printf("FAIL no temporary folder\n"); return 1; }
	const std::wstring root = std::wstring(temp) + L"wac-long-path-test-" + std::to_wstring(GetCurrentProcessId());

	// 1. A tree past MAX_PATH, a read-only file at its bottom: removed entirely.
	std::wstring deep = root;
	bool made = CreateDirectoryW(extendedPath(root).c_str(), nullptr) != 0;
	for (int i = 0; made && i < 12; ++i) {
		deep += L"\\wac-long-path-segment-" + std::to_wstring(i);
		made = CreateDirectoryW(extendedPath(deep).c_str(), nullptr) != 0;
	}
	const std::wstring bottom = deep + L"\\read-only.txt";
	made = made && makeFile(bottom) && SetFileAttributesW(extendedPath(bottom).c_str(), FILE_ATTRIBUTE_READONLY);
	check(made && bottom.size() > MAX_PATH, "a tree past MAX_PATH with a read-only file is made");
	std::wstring blocked = L"untouched";
	check(removeFolderTree(root, &blocked) == S_OK && absent(root), "it is removed entirely");
	check(blocked == L"untouched", "nothing is named blocked when all goes");

	// 2. A file held open without FILE_SHARE_DELETE: its error and its path.
	const std::wstring held = root + L"\\sub\\held.txt";
	made = CreateDirectoryW(extendedPath(root).c_str(), nullptr) && CreateDirectoryW(extendedPath(root + L"\\sub").c_str(), nullptr)
	       && makeFile(held) && makeFile(root + L"\\free.txt");
	const HANDLE h = CreateFileW(extendedPath(held).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	check(made && h != INVALID_HANDLE_VALUE, "a file is held open, without sharing its deletion");
	const HRESULT hr = removeFolderTree(root, &blocked);
	check(hr == HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION), "the error is the file's own, a sharing violation, not a code of the caller");
	check(blocked == held, "the entry that held is named");
	check(absent(root + L"\\free.txt") && !absent(held), "the rest is removed, the held file kept");
	if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
	check(removeFolderTree(root, &blocked) == S_OK && absent(root), "once closed, the folder goes");

	// 3. A folder that does not exist: nothing to do, no failure.
	check(removeFolderTree(root) == S_OK, "an absent folder is no failure");

	std::printf(failures ? "%d failure(s)\n" : "all checks hold\n", failures);
	return failures ? 1 : 0;
}
