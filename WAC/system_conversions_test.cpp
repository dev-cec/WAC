/*! \file
 *  \brief Confronts WAC's own conversions with the Windows functions they
 *         replaced, which WAC no longer imports.
 *
 *  WHY THIS TEST. To depend only on what querying the running system requires,
 *  WAC stopped importing ole32, oleaut32, propsys and shell32, and the SID
 *  conversions of advapi32: GUIDs, SIDs, OLE dates and property names are now
 *  formatted and parsed by WAC itself (tools.cpp, trans_id.cpp). A conversion
 *  that is slightly off still produces well-formed output; only a comparison
 *  with the functions replaced, on many inputs, shows it. This program is the
 *  only one that still calls them.
 *
 *  Compared:
 *  - guid_to_wstring / StringFromGUID2, on random GUIDs;
 *  - sidToText / ConvertSidToStringSidW and textToSid / ConvertStringSidToSidW,
 *    on random SIDs (0 to 15 sub-authorities, authorities of 2^32 and more)
 *    and on malformed texts, which both must refuse;
 *  - oleDateToSystemTime / VariantTimeToSystemTime, on random dates, the ends
 *    of the range, times close to midnight, negative dates and NaN;
 *  - to_FriendlyName / PSGetNameFromPropertyKey, on every property of the
 *    table: a name WAC gives must be the one Windows gives.
 *
 *  Usage: system_conversions_test
 *  Built by `build-windows.sh --test`; runs on Windows (the test VM).
 */
#include <windows.h>
#include <sddl.h>
#include <oleauto.h>
#include <propsys.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <random>
#include <string>
#include <vector>
#include "tools.h"
#include "trans_id.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned long long g_checks = 0, g_failures = 0;

/*! Records one comparison, printing the first failures. */
void check(bool same, const std::wstring& what) {
	++g_checks;
	if (!same && ++g_failures <= 20) std::wprintf(L"  DIFF  %ls\n", what.c_str());
}

void guids(std::mt19937_64& rng) {
	for (int i = 0; i < 100000; ++i) {
		GUID g;
		const unsigned long long a = rng(), b = rng();
		std::memcpy(&g, &a, 8);
		std::memcpy(reinterpret_cast<BYTE*>(&g) + 8, &b, 8);
		wchar_t ref[64];
		StringFromGUID2(g, ref, 64);
		check(guid_to_wstring(g) == ref, L"GUID " + std::wstring(ref) + L" -> " + guid_to_wstring(g));
	}
}

void sids(std::mt19937_64& rng) {
	for (int i = 0; i < 100000; ++i) {
		const unsigned count = (unsigned)(rng() % 16);
		std::vector<BYTE> sid(8 + 4 * count);
		sid[0] = 1;
		sid[1] = (BYTE)count;
		// An authority below 2^32 most of the time, above it sometimes.
		const unsigned long long authority = (rng() % 4 == 0) ? (rng() & 0xFFFFFFFFFFFFULL) : (rng() & 0xFFFFFFFFULL);
		for (int k = 0; k < 6; ++k) sid[2 + k] = (BYTE)(authority >> (8 * (5 - k)));
		for (unsigned k = 0; k < count; ++k) {
			const uint32_t v = (uint32_t)rng();
			std::memcpy(&sid[8 + 4 * k], &v, 4);
		}
		LPWSTR ref = nullptr;
		if (!ConvertSidToStringSidW(sid.data(), &ref)) { check(false, L"ConvertSidToStringSidW refused a SID"); continue; }
		const std::wstring mine = sidToText(sid.data(), sid.size());
		check(mine == ref, L"SID " + std::wstring(ref) + L" -> " + mine);
		// And back: the same bytes as ConvertStringSidToSidW.
		PSID back = nullptr;
		const std::vector<BYTE> parsed = textToSid(ref);
		if (ConvertStringSidToSidW(ref, &back)) {
			const DWORD length = GetLengthSid(back);
			check(parsed.size() == length && std::memcmp(parsed.data(), back, length) == 0,
			      L"textToSid(" + std::wstring(ref) + L")");
			LocalFree(back);
		}
		LocalFree(ref);
	}
	// Malformed texts: both must refuse.
	for (const wchar_t* bad : { L"", L"S", L"S-", L"S-1", L"S-1-", L"X-1-5-21", L"S-1-5--7", L"S-1-5-x", L"S-256-5" }) {
		PSID back = nullptr;
		const bool windows = ConvertStringSidToSidW(bad, &back) != 0;
		if (back) LocalFree(back);
		check(windows == !textToSid(bad).empty(), L"malformed SID \"" + std::wstring(bad) + L"\" accepted differently");
	}
	/* Intended differences: Windows accepts a sub-authority of 2^32 or more
	   (truncated) and a 16th sub-authority; WAC refuses them — the SID looked
	   up would not be the one read. */
	for (const wchar_t* refused : { L"S-1-5-21-4294967296", L"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16" })
		check(textToSid(refused).empty(), L"SID \"" + std::wstring(refused) + L"\" should be refused");
}

void dates(std::mt19937_64& rng) {
	std::vector<double> inputs = { 0.0, 1.0, -1.0, -1.25, -0.5, 0.5, 2958465.0, 2958465.99999, 2958466.0,
	                               -657434.0, -657434.5, -657435.0, 36526.999994213, 36526.99999421, 1e12,
	                               -1e12, std::numeric_limits<double>::quiet_NaN(),
	                               std::numeric_limits<double>::infinity() };
	std::uniform_real_distribution<double> any(-657434.0, 2958466.0);
	for (int i = 0; i < 200000; ++i) inputs.push_back(any(rng));
	// Just before and after midnight, where rounding decides the day — on
	// negative dates too, where the time counts forward from the integer part.
	for (int d = -1000; d < 1000; ++d)
		for (double e : { -0.999994, -0.9999942, -0.9999943, -0.000005, -0.0000058 }) inputs.push_back(-(double)(d + 1000) + e);
	for (int d = -1000; d < 1000; ++d)
		for (double e : { -0.000005, -0.0000058, 0.000005, 0.0000058 }) inputs.push_back(45000.0 + d + e);
	for (double date : inputs) {
		SYSTEMTIME a = {}, b = {};
		const bool ra = oleDateToSystemTime(date, a);
		if (std::isnan(date)) {   // intended difference: Windows returns a meaningless time
			check(!ra, L"OLE date NaN should be refused");
			continue;
		}
		const bool rb = VariantTimeToSystemTime(date, &b) != 0;
		const bool same = ra == rb && (!ra || (a.wYear == b.wYear && a.wMonth == b.wMonth && a.wDay == b.wDay
		                  && a.wDayOfWeek == b.wDayOfWeek && a.wHour == b.wHour && a.wMinute == b.wMinute
		                  && a.wSecond == b.wSecond && a.wMilliseconds == b.wMilliseconds));
		wchar_t text[160];
		swprintf(text, 160, L"OLE date %.17g: %d %04u-%02u-%02u %02u:%02u:%02u vs %d %04u-%02u-%02u %02u:%02u:%02u.%03u",
		         date, ra, a.wYear, a.wMonth, a.wDay, a.wHour, a.wMinute, a.wSecond,
		         rb, b.wYear, b.wMonth, b.wDay, b.wHour, b.wMinute, b.wSecond, b.wMilliseconds);
		check(same, text);
	}
}

void properties() {
	// Every property Windows knows: WAC's name must be Windows' name.
	IPropertyDescriptionList* list = nullptr;
	if (FAILED(PSEnumeratePropertyDescriptions(PDEF_ALL, IID_IPropertyDescriptionList,
	                                           reinterpret_cast<void**>(&list)))) {
		check(false, L"PSEnumeratePropertyDescriptions failed");
		return;
	}
	UINT count = 0;
	list->GetCount(&count);
	for (UINT i = 0; i < count; ++i) {
		IPropertyDescription* d = nullptr;
		if (FAILED(list->GetAt(i, IID_IPropertyDescription, reinterpret_cast<void**>(&d)))) continue;
		PROPERTYKEY key;
		PWSTR name = nullptr;
		if (SUCCEEDED(d->GetPropertyKey(&key)) && SUCCEEDED(PSGetNameFromPropertyKey(key, &name)) && name) {
			const std::wstring mine = to_FriendlyName(guid_to_wstring(key.fmtid), key.pid);
			check(mine == name, L"property " + guid_to_wstring(key.fmtid) + L"/" + std::to_wstring(key.pid)
			                    + L": \"" + mine + L"\" vs \"" + name + L"\"");
			CoTaskMemFree(name);
		}
		d->Release();
	}
	list->Release();
}

} // namespace

/*! Runs every comparison.
 * @return 0 if WAC's conversions agree with Windows everywhere */
int wmain() {
	if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return 1;
	std::mt19937_64 rng(20260924);
	guids(rng);
	sids(rng);
	dates(rng);
	properties();
	CoUninitialize();
	std::wprintf(L"%ls: %llu comparison(s), %llu difference(s)\n",
	             g_failures ? L"FAILED" : L"all identical", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
