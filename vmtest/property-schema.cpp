/*! \file
 *  \brief Dumps the property schema of a Windows machine: the source of WAC's
 *         table of property names (trans_id.cpp, TABLE_PROPERTY).
 *
 *  WHY. WAC named the properties of shortcuts, shell items and jump lists with
 *  PSGetNameFromPropertyKey, from propsys.dll — a library of the EXAMINED
 *  machine, whose answer depends on its Windows version, on the software
 *  installed there, and even on the state of the process (a key resolved in
 *  one phase of a collection and not in the next). The names are now a static
 *  table in WAC, generated from the schema of a reference Windows by this
 *  program, run in the test VM.
 *
 *  Output, one line per property: `{fmtid-in-lower-case}<TAB>pid<TAB>name`,
 *  sorted, in UTF-8.
 *
 *  Build: x86_64-w64-mingw32-g++ -std=c++17 -municode -static property-schema.cpp
 *         -o property-schema.exe -lpropsys -lole32 -luuid
 *  Run (in the VM): property-schema.exe > schema.tsv
 */
#include <windows.h>
#include <propsys.h>
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

int wmain() {
	if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 1;
	IPropertyDescriptionList* list = nullptr;
	if (FAILED(PSEnumeratePropertyDescriptions(PDEF_ALL, IID_IPropertyDescriptionList,
	                                           reinterpret_cast<void**>(&list)))) return 1;
	UINT count = 0;
	list->GetCount(&count);
	std::vector<std::string> lines;
	for (UINT i = 0; i < count; ++i) {
		IPropertyDescription* d = nullptr;
		if (FAILED(list->GetAt(i, IID_IPropertyDescription, reinterpret_cast<void**>(&d)))) continue;
		PROPERTYKEY key;
		PWSTR name = nullptr;
		if (SUCCEEDED(d->GetPropertyKey(&key)) && SUCCEEDED(d->GetCanonicalName(&name)) && name) {
			wchar_t guid[64];
			StringFromGUID2(key.fmtid, guid, 64);
			std::wstring line = std::wstring(guid) + L"\t" + std::to_wstring(key.pid) + L"\t" + name;
			std::transform(line.begin(), line.begin() + 38, line.begin(), ::towlower);
			const int n = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, nullptr, 0, nullptr, nullptr);
			std::string utf8((size_t)(n > 0 ? n - 1 : 0), '\0');
			if (n > 1) WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, &utf8[0], n, nullptr, nullptr);
			lines.push_back(utf8);
			CoTaskMemFree(name);
		}
		d->Release();
	}
	list->Release();
	std::sort(lines.begin(), lines.end());
	for (const std::string& l : lines) std::printf("%s\n", l.c_str());
	CoUninitialize();
	return 0;
}
