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

/*! Loads a system library from System32.
 *  @param name its file name ("winhttp.dll")
 *  @return the module, or nullptr (GetLastError says why) */
inline HMODULE loadSystemLibrary(const wchar_t* name) {
	return LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
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
