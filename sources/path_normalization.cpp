/*! \file
 *  \brief THE normalisation of a file path (path_normalization.h).
 */
#include "path_normalization.h"

#include <map>

namespace {

/*! \a s with its ASCII letters in lower case, the others kept. */
std::wstring asciiLower(std::wstring s) {
	for (wchar_t& c : s)
		if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
	return s;
}

}  // namespace

std::wstring normalizeFilePath(std::wstring path, const std::wstring& systemDrive) {
	// Surrounding spaces and quotes: present in Shimcache and Amcache.
	while (!path.empty() && (path.front() == L' ' || path.front() == L'"')) path.erase(0, 1);
	while (!path.empty() && (path.back() == L' ' || path.back() == L'"')) path.pop_back();
	if (path.empty()) return L"";

	std::wstring low = asciiLower(path);
	// NT object prefixes: "\??\C:\…" (Shimcache, ImagePath), "\\?\C:\…".
	if (low.compare(0, 4, L"\\??\\") == 0 || low.compare(0, 4, L"\\\\?\\") == 0) {
		if (low.compare(4, 4, L"unc\\") == 0) return L"";   // network share
		path.erase(0, 4);
		low.erase(0, 4);
	}
	// Kernel prefix.
	if (low.compare(0, 12, L"\\systemroot\\") == 0)
		return systemDrive + L"\\Windows\\" + path.substr(12);
	// "SYSVOL\": the system volume, as the ShimCache of Windows 8 and 8.1 names it.
	if (low.compare(0, 7, L"sysvol\\") == 0)
		return systemDrive + L"\\" + path.substr(7);

	/* VARIABLES, expanded from the DETECTED system drive and never from the
	   process's environment: the value belongs to the examined installation, not
	   to the one running WAC (and WAC runs as SYSTEM, whose environment says
	   nothing about the users).
	   `%windir%` is a synonym of `%systemroot%`; not handling it gave paths of
	   the kind "C:\Windows\%windir%\system32\ncsi.dll".
	   The variables SPECIFIC TO A USER (%APPDATA%, %LOCALAPPDATA%,
	   %USERPROFILE%…) are not expanded: the account is not known here, and
	   guessing would return the fingerprint of another file than the one
	   named. */
	if (!path.empty() && path.front() == L'%') {
		const size_t end = path.find(L'%', 1);
		if (end == std::wstring::npos) return L"";
		const std::wstring var = low.substr(1, end - 1);
		static const std::map<std::wstring, std::wstring> known = {
			{ L"systemroot", L"\\Windows" },               { L"windir", L"\\Windows" },
			{ L"systemdrive", L"" },
			{ L"programfiles", L"\\Program Files" },       { L"programw6432", L"\\Program Files" },
			{ L"programfiles(x86)", L"\\Program Files (x86)" },
			{ L"commonprogramfiles", L"\\Program Files\\Common Files" },
			{ L"commonprogramw6432", L"\\Program Files\\Common Files" },
			{ L"commonprogramfiles(x86)", L"\\Program Files (x86)\\Common Files" },
			{ L"programdata", L"\\ProgramData" },          { L"allusersprofile", L"\\ProgramData" },
			{ L"public", L"\\Users\\Public" },
		};
		const auto it = known.find(var);
		if (it == known.end()) return L"";
		path = systemDrive + it->second + path.substr(end + 1);
	}
	if (path.size() < 3 || path[1] != L':' || path[2] != L'\\') return L"";
	if (path[0] >= L'a' && path[0] <= L'z') path[0] = static_cast<wchar_t>(path[0] - L'a' + L'A');
	return path;
}
