/*! \file
 *  \brief A Windows library loaded at run time, from System32 only, and its
 *         functions resolved — for the libraries WAC must not import.
 *
 *  WinHTTP (--update-trust, http_client.cpp), iphlpapi (the network state,
 *  network.cpp) and esent.dll (the replay of ESE logs, ese_recovery.cpp) are
 *  each needed in one mode only: imported, they would be loaded at every start
 *  of WAC.exe on the examined machine, and stand in its import table, which
 *  the harmlessness file describes. Loaded from System32 only: never a DLL of
 *  the current folder or of the collection medium.
 */
#pragma once

#include <windows.h>
#include <string>

/*! Loads a system library from System32.
 *  @param name its file name ("winhttp.dll")
 *  @return the module, or nullptr (GetLastError says why) */
inline HMODULE loadSystemLibrary(const wchar_t* name) {
	HMODULE module = LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (module || GetLastError() != ERROR_INVALID_PARAMETER) return module;
	/* A Windows 7 or Vista without update KB2533623 does not know that flag
	   and refuses the call ("the parameter is incorrect": the network state
	   was not collected under Windows 7 SP1). The library is then named by
	   its full path in System32 — as safe: neither the current folder nor
	   the program's is searched, for it or for what it loads in turn. */
	wchar_t folder[MAX_PATH] = L"";
	const UINT length = GetSystemDirectoryW(folder, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) return nullptr;
	return LoadLibraryExW((std::wstring(folder, length) + L"\\" + name).c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
}

/*! Resolves one export of a loaded library into a function pointer.
 *  @param module the library
 *  @param name the export's name
 *  @param target receives the function, typed by the caller (decltype(&Function))
 *  @return false if the library does not export it */
template <typename F>
bool resolveExport(HMODULE module, const char* name, F& target) {
	target = reinterpret_cast<F>(reinterpret_cast<void*>(GetProcAddress(module, name)));
	return target != nullptr;
}
