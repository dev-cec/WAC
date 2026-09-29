/*! \file
 *  \brief Confronts WAC's offline registry reader with Microsoft's offreg.dll
 *         on whole hives.
 *
 *  WHY THIS TEST. offline_registry.cpp replaces Microsoft's DLL for every
 *  registry artefact WAC collects. A reader that is slightly wrong still
 *  returns plausible keys and values: only a comparison with the reference,
 *  key by key and byte by byte, shows it. Microsoft's DLL is loaded here
 *  DYNAMICALLY, from the path given: this program is the only one that still
 *  uses it.
 *
 *  For each hive: both readers walk every key; for each key the name, last
 *  write time, class, subkey and value counts, the ORQueryInfoKey maxima and
 *  the security descriptor size are compared; for each value its name, type
 *  and bytes, through OREnumValue and ORGetValue. The contract's edge cases
 *  are compared on every key too: a zero-size buffer, a null data buffer, the
 *  default value, a missing value, a missing subkey.
 *
 *  Usage: offline_registry_test `<offreg.dll>` `<hive>` [hive ...]
 *  Built by `build-windows.sh --test`; runs on Windows (Microsoft's DLL needs
 *  it), e.g. in the test VM.
 */
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include "offline_registry.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

/*! Microsoft's functions, loaded from its DLL. */
struct Reference {
	DWORD (WINAPI* openHive)(PCWSTR, PORHKEY) = nullptr;
	DWORD (WINAPI* closeHive)(ORHKEY) = nullptr;
	DWORD (WINAPI* openKey)(ORHKEY, PCWSTR, PORHKEY) = nullptr;
	DWORD (WINAPI* closeKey)(ORHKEY) = nullptr;
	DWORD (WINAPI* enumKey)(ORHKEY, DWORD, PWSTR, PDWORD, PWSTR, PDWORD, PFILETIME) = nullptr;
	DWORD (WINAPI* enumValue)(ORHKEY, DWORD, PWSTR, PDWORD, PDWORD, PBYTE, PDWORD) = nullptr;
	DWORD (WINAPI* getValue)(ORHKEY, PCWSTR, PCWSTR, PDWORD, PVOID, PDWORD) = nullptr;
	DWORD (WINAPI* queryInfo)(ORHKEY, PWSTR, PDWORD, PDWORD, PDWORD, PDWORD, PDWORD,
	                          PDWORD, PDWORD, PDWORD, PFILETIME) = nullptr;

	bool load(const wchar_t* path) {
		HMODULE m = LoadLibraryW(path);
		if (!m) return false;
		auto get = [&](auto& f, const char* name) {
			f = reinterpret_cast<std::remove_reference_t<decltype(f)>>(
				reinterpret_cast<void*>(GetProcAddress(m, name)));
			return f != nullptr;
		};
		return get(openHive, "OROpenHive") && get(closeHive, "ORCloseHive") && get(openKey, "OROpenKey")
		    && get(closeKey, "ORCloseKey") && get(enumKey, "OREnumKey") && get(enumValue, "OREnumValue")
		    && get(getValue, "ORGetValue") && get(queryInfo, "ORQueryInfoKey");
	}
};

Reference ms;
unsigned long long g_keys = 0, g_values = 0, g_differences = 0;

std::map<std::wstring, std::pair<unsigned long long, std::wstring>> g_kinds;   //!< per kind: count, first example

/*! Records a difference: counted by kind (the words before its first
 *  number), the first example of each kind kept for the report. */
void differ(const std::wstring& where, const std::wstring& what) {
	++g_differences;
	const std::wstring kind = what.substr(0, what.find_first_of(L"0123456789\"#"));
	auto& k = g_kinds[kind];
	if (k.first++ == 0) k.second = where + L": " + what;
}

/*! Everything ORQueryInfoKey says about a key, and the call's result. */
struct Info {
	DWORD result = 0, subkeys = 0, maxSubkey = 0, maxClass = 0, values = 0;
	DWORD maxValueName = 0, maxValue = 0, security = 0, classLength = 0;
	FILETIME lastWrite = { 0, 0 };
	std::wstring cls;
};

template <typename QueryInfo>
Info query(QueryInfo fn, ORHKEY k) {
	Info i;
	wchar_t cls[1024] = L"";
	i.classLength = 1024;
	i.result = fn(k, cls, &i.classLength, &i.subkeys, &i.maxSubkey, &i.maxClass, &i.values,
	              &i.maxValueName, &i.maxValue, &i.security, &i.lastWrite);
	i.cls = cls;
	return i;
}

std::wstring num(unsigned long long v) { return std::to_wstring(v); }

/*! Compares one key under both readers, then recurses into its subkeys. */
void compare(ORHKEY mine, ORHKEY ref, const std::wstring& path, int depth) {
	++g_keys;
	const Info a = query(ORQueryInfoKey, mine), b = query(ms.queryInfo, ref);
	if (a.result != b.result) { differ(path, L"ORQueryInfoKey " + num(a.result) + L" vs " + num(b.result)); return; }
	if (a.subkeys != b.subkeys) differ(path, L"subkeys " + num(a.subkeys) + L" vs " + num(b.subkeys));
	if (a.values != b.values) differ(path, L"values " + num(a.values) + L" vs " + num(b.values));
	if (a.maxSubkey != b.maxSubkey) differ(path, L"max subkey name " + num(a.maxSubkey) + L" vs " + num(b.maxSubkey));
	if (a.maxClass != b.maxClass) differ(path, L"max class " + num(a.maxClass) + L" vs " + num(b.maxClass));
	if (a.maxValueName != b.maxValueName) differ(path, L"max value name " + num(a.maxValueName) + L" vs " + num(b.maxValueName));
	if (a.maxValue != b.maxValue) differ(path, L"max value data " + num(a.maxValue) + L" vs " + num(b.maxValue));
	if (a.security != b.security) differ(path, L"security size " + num(a.security) + L" vs " + num(b.security));
	if (CompareFileTime(&a.lastWrite, &b.lastWrite) != 0) differ(path, L"last write time");
	if (a.cls != b.cls || a.classLength != b.classLength) differ(path, L"class \"" + a.cls + L"\" vs \"" + b.cls + L"\"");

	// Values: a size probe (null data buffer) compared as such, then a real
	// read with a buffer large enough for both, then ORGetValue.
	for (DWORD i = 0;; ++i) {
		wchar_t na[16384], nb[16384];
		DWORD la = 16384, lb = 16384, ta = 0, tb = 0, sa = 0, sb = 0;
		const DWORD pa = OREnumValue(mine, i, na, &la, &ta, nullptr, &sa);
		const DWORD pb = ms.enumValue(ref, i, nb, &lb, &tb, nullptr, &sb);
		if ((pa == ERROR_NO_MORE_ITEMS) != (pb == ERROR_NO_MORE_ITEMS)) {
			differ(path, L"OREnumValue end #" + num(i) + L" " + num(pa) + L" vs " + num(pb));
			break;
		}
		if (pb == ERROR_NO_MORE_ITEMS) break;
		++g_values;
		if (pa != pb || sa != sb) differ(path, L"size probe " + num(pa) + L"/" + num(sa) + L" vs " + num(pb) + L"/" + num(sb));
		const DWORD room = std::max(sa, sb) + 16;
		std::vector<BYTE> da(room), db(room);
		DWORD ca = room, cb = room;
		la = lb = 16384;
		const DWORD ra = OREnumValue(mine, i, na, &la, &ta, da.data(), &ca);
		const DWORD rb = ms.enumValue(ref, i, nb, &lb, &tb, db.data(), &cb);
		const std::wstring name(nb, lb);
		const std::wstring where = path + L" : " + name;
		if (ra != rb) { differ(where, L"OREnumValue " + num(ra) + L" vs " + num(rb)); continue; }
		if (ra != ERROR_SUCCESS) continue;
		if (std::wstring(na, la) != name) differ(where, L"value name");
		if (ta != tb) differ(where, L"type " + num(ta) + L" vs " + num(tb));
		if (ca != cb || std::memcmp(da.data(), db.data(), ca) != 0) differ(where, L"OREnumValue data " + num(ca) + L" vs " + num(cb));
		DWORD ga = room, gb = room;
		const DWORD xa = ORGetValue(mine, nullptr, nb, nullptr, da.data(), &ga);
		const DWORD xb = ms.getValue(ref, nullptr, nb, nullptr, db.data(), &gb);
		if (xa != xb || ga != gb || std::memcmp(da.data(), db.data(), ga) != 0)
			differ(where, L"ORGetValue data " + num(xa) + L"/" + num(ga) + L" vs " + num(xb) + L"/" + num(gb));
		// ORGetValue size probe: null buffer, size 0.
		DWORD za = 0, zb = 0;
		const DWORD ea = ORGetValue(mine, nullptr, nb, nullptr, nullptr, &za);
		const DWORD eb = ms.getValue(ref, nullptr, nb, nullptr, nullptr, &zb);
		if (ea != eb || za != zb) differ(where, L"ORGetValue null buffer " + num(ea) + L"/" + num(za) + L" vs " + num(eb) + L"/" + num(zb));
		// A zero-size buffer.
		BYTE dummy = 0;
		za = zb = 0;
		const DWORD fa = ORGetValue(mine, nullptr, nb, nullptr, &dummy, &za);
		const DWORD fb = ms.getValue(ref, nullptr, nb, nullptr, &dummy, &zb);
		if (fa != fb || za != zb) differ(where, L"zero-size buffer " + num(fa) + L"/" + num(za) + L" vs " + num(fb) + L"/" + num(zb));
		// A name buffer too small by one.
		if (lb > 0) {
			DWORD sa2 = lb, sb2 = lb;
			const DWORD sa3 = OREnumValue(mine, i, na, &sa2, nullptr, nullptr, nullptr);
			const DWORD sb3 = ms.enumValue(ref, i, nb, &sb2, nullptr, nullptr, nullptr);
			if (sa3 != sb3 || sa2 != sb2) differ(where, L"short value name buffer " + num(sa3) + L"/" + num(sa2) + L" vs " + num(sb3) + L"/" + num(sb2));
		}
	}
	// Default value and a value that cannot exist.
	{
		DWORD ta = 0, tb = 0, sa = 0, sb = 0;
		const DWORD ra = ORGetValue(mine, nullptr, nullptr, &ta, nullptr, &sa);
		const DWORD rb = ms.getValue(ref, nullptr, nullptr, &tb, nullptr, &sb);
		if (ra != rb || (ra == ERROR_SUCCESS && (ta != tb || sa != sb))) differ(path, L"default value " + num(ra) + L" vs " + num(rb));
		const DWORD ma = ORGetValue(mine, nullptr, L"¤ no such value ¤", nullptr, nullptr, &sa);
		const DWORD mb = ms.getValue(ref, nullptr, L"¤ no such value ¤", nullptr, nullptr, &sb);
		if (ma != mb) differ(path, L"missing value " + num(ma) + L" vs " + num(mb));
		ORHKEY xa = nullptr, xb = nullptr;
		const DWORD ka = OROpenKey(mine, L"¤ no such key ¤", &xa);
		const DWORD kb = ms.openKey(ref, L"¤ no such key ¤", &xb);
		if (ka != kb) differ(path, L"missing key " + num(ka) + L" vs " + num(kb));
	}

	// Subkeys, in order; each opened by name through both readers.
	if (depth > 512) { differ(path, L"depth over 512"); return; }
	for (DWORD i = 0;; ++i) {
		wchar_t na[512], nb[512], ca[512], cb[512];
		DWORD la = 512, lb = 512, cla = 512, clb = 512;
		FILETIME fa = { 0, 0 }, fb = { 0, 0 };
		const DWORD ra = OREnumKey(mine, i, na, &la, ca, &cla, &fa);
		const DWORD rb = ms.enumKey(ref, i, nb, &lb, cb, &clb, &fb);
		if (ra != rb) { differ(path, L"OREnumKey #" + num(i) + L" " + num(ra) + L" vs " + num(rb)); break; }
		if (ra != ERROR_SUCCESS) break;
		const std::wstring name(na, la);
		if (name != std::wstring(nb, lb)) { differ(path, L"subkey #" + num(i) + L" \"" + name + L"\" vs \"" + std::wstring(nb, lb) + L"\""); continue; }
		if (CompareFileTime(&fa, &fb) != 0) differ(path + L"\\" + name, L"OREnumKey last write time");
		// A name buffer too small by one.
		DWORD sa = la, sb = lb;
		const DWORD sa3 = OREnumKey(mine, i, na, &sa, nullptr, nullptr, nullptr);
		const DWORD sb3 = ms.enumKey(ref, i, nb, &sb, nullptr, nullptr, nullptr);
		if (sa3 != sb3 || sa != sb) differ(path + L"\\" + name, L"short key name buffer " + num(sa3) + L"/" + num(sa) + L" vs " + num(sb3) + L"/" + num(sb));
		ORHKEY ka = nullptr, kb = nullptr;
		const DWORD oa = OROpenKey(mine, name.c_str(), &ka);
		const DWORD ob = ms.openKey(ref, name.c_str(), &kb);
		if (oa != ob) { differ(path + L"\\" + name, L"OROpenKey " + num(oa) + L" vs " + num(ob)); }
		else if (oa == ERROR_SUCCESS) compare(ka, kb, path + L"\\" + name, depth + 1);
		if (ka) ORCloseKey(ka);
		if (kb) ms.closeKey(kb);
	}
}

/*! True if the hive's two sequence numbers differ: its last write was not
 *  completed, and its transaction logs have not been replayed into it. */
bool dirty(const wchar_t* path) {
	HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
	                       OPEN_EXISTING, 0, nullptr);
	if (f == INVALID_HANDLE_VALUE) return false;
	DWORD header[3] = { 0, 0, 0 }, got = 0;
	const BOOL ok = ReadFile(f, header, sizeof(header), &got, nullptr);
	CloseHandle(f);
	return ok && got == sizeof(header) && header[1] != header[2];
}

} // namespace

/*! Runs the comparison.
 * @param argc,argv `<offreg.dll> <hive> [hive ...]`
 * @return 0 if both readers agree on every hive */
int wmain(int argc, wchar_t** argv) {
	if (argc < 3) {
		std::wprintf(L"usage: offline_registry_test <offreg.dll> <hive> [hive ...]\n");
		return 2;
	}
	if (!ms.load(argv[1])) {
		std::wprintf(L"  FAILED  cannot load Microsoft's offreg.dll from %ls\n", argv[1]);
		return 1;
	}
	for (int a = 2; a < argc; ++a) {
		const unsigned long long before = g_differences, keysBefore = g_keys, valuesBefore = g_values;
		ORHKEY mine = nullptr, ref = nullptr;
		const DWORD ra = OROpenHive(argv[a], &mine);
		const DWORD rb = ms.openHive(argv[a], &ref);
		if (ra == ERROR_BADDB && rb == ERROR_SUCCESS && dirty(argv[a])) {
			/* The one intended difference: a hive whose last write was not
			   completed is refused (see OROpenHive), where recent versions of
			   Microsoft's DLL read it as is — stale keys, without an error. */
			std::wprintf(L"  ok      %ls: not replayed, refused as intended\n", argv[a]);
			continue;
		}
		if (ra != rb) {
			differ(argv[a], L"OROpenHive " + num(ra) + L" vs " + num(rb));
		}
		else if (ra == ERROR_SUCCESS) {
			compare(mine, ref, L"", 0);
		}
		if (mine) ORCloseHive(mine);
		if (ref) ms.closeHive(ref);
		std::wprintf(L"  %ls  %ls: %llu key(s), %llu value(s), %llu difference(s)\n",
		             g_differences == before ? L"ok    " : L"FAILED", argv[a],
		             g_keys - keysBefore, g_values - valuesBefore, g_differences - before);
	}
	for (const auto& k : g_kinds)
		std::wprintf(L"  DIFF  %llu x [%ls] e.g. %ls\n", k.second.first, k.first.c_str(), k.second.second.c_str());
	std::wprintf(L"%ls: %llu key(s), %llu value(s) compared, %llu difference(s)\n",
	             g_differences ? L"FAILED" : L"all identical", g_keys, g_values, g_differences);
	return g_differences ? 1 : 0;
}
