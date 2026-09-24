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
 *    table: a name WAC gives must be the one Windows gives;
 *  - FatDateTime::toFileTime / DosDateTimeToFileTime, on every date with a
 *    sample of times and every time with a sample of dates: an impossible
 *    date (month 13, hour 25...) must give a null FILETIME, not whatever the
 *    stack held;
 *  - wstring_to_filetime / SystemTimeToFileTime, valid and impossible dates;
 *  - utcToSuspectLocal and suspectLocalToUtc: the SUSPECT's offset, not the
 *    running machine's, in both directions (LocalFileTimeToFileTime, used
 *    before, applied the machine's), and a null result out of range.
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

//! A FILETIME as one 64-bit number.
ULONGLONG value(const FILETIME& ft) {
	return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

//! A FILETIME from one 64-bit number.
FILETIME filetime(ULONGLONG v) {
	return FILETIME{ (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) };
}

//! Compares one FAT date and time with DosDateTimeToFileTime.
void fatDate(WORD date, WORD time) {
	FILETIME windows = { 0, 0 };
	const bool accepted = DosDateTimeToFileTime(date, time, &windows) != 0;
	const FILETIME mine = FatDateTime((unsigned)date | ((unsigned)time << 16)).toFileTime();
	wchar_t text[120];
	swprintf(text, 120, L"FAT date %04X time %04X: Windows %d %llu, WAC %llu",
	         date, time, accepted, value(windows), value(mine));
	check(accepted ? value(mine) == value(windows) : value(mine) == 0, text);
}

void fatDates(std::mt19937_64& rng) {
	for (unsigned date = 0; date < 0x10000; ++date)
		for (int k = 0; k < 8; ++k) fatDate((WORD)date, (WORD)rng());
	for (unsigned time = 0; time < 0x10000; ++time)
		for (int k = 0; k < 8; ++k) fatDate((WORD)rng(), (WORD)time);
}

void textDates() {
	const struct { const wchar_t* text; WORD year, month, day, hour, minute, second; } valid[] = {
		{ L"9/24/2026 7:06:32", 2026, 9, 24, 7, 6, 32 },
		{ L"2/29/2024 23:59:59", 2024, 2, 29, 23, 59, 59 },
		{ L"1/1/1601 0:00:01", 1601, 1, 1, 0, 0, 1 },
	};
	for (const auto& v : valid) {
		SYSTEMTIME st = {};
		st.wYear = v.year; st.wMonth = v.month; st.wDay = v.day;
		st.wHour = v.hour; st.wMinute = v.minute; st.wSecond = v.second;
		FILETIME windows = { 0, 0 };
		SystemTimeToFileTime(&st, &windows);
		check(value(wstring_to_filetime(v.text)) == value(windows), L"text date \"" + std::wstring(v.text) + L"\"");
	}
	for (const wchar_t* impossible : { L"13/1/2026 0:00:00", L"2/30/2026 0:00:00", L"1/1/2026 25:00:00",
	                                   L"1/1/2026 0:60:00", L"", L"garbage", L"1/1/1600 0:00:00" })
		check(value(wstring_to_filetime(impossible)) == 0, L"text date \"" + std::wstring(impossible) + L"\" should give a null date");
}

void suspectOffset(std::mt19937_64& rng) {
	/* A suspect at UTC-05:00 while the test runs at another offset (the VM is
	   at UTC+01:00 or +02:00): a conversion that used the running machine's
	   time zone gives another hour. */
	conf.timeZone.valid = true;
	conf.timeZone.activeBiasMinutes = 300;
	const ULONGLONG hour = 36000000000ULL;
	for (int i = 0; i < 100000; ++i) {
		const ULONGLONG utc = 5 * hour + rng() % (0x7FFFFFFFFFFFFFFFULL - 10 * hour);
		const FILETIME local = utcToSuspectLocal(filetime(utc));
		check(value(local) == utc - 5 * hour, L"utcToSuspectLocal: not UTC-05:00");
		check(value(suspectLocalToUtc(local)) == utc, L"suspectLocalToUtc: not the reverse of utcToSuspectLocal");
	}
	// The formatted UTC version of a local date (Amcache, BAM, UserAssist...).
	SYSTEMTIME noon = {};
	noon.wYear = 2026; noon.wMonth = 1; noon.wDay = 15; noon.wHour = 12;
	FILETIME localNoon = { 0, 0 };
	SystemTimeToFileTime(&noon, &localNoon);
	check(localTimeToIso8601Utc(localNoon) == L"2026-01-15T17:00:00.0000000Z",
	      L"localTimeToIso8601Utc(12:00 at UTC-05:00) = " + localTimeToIso8601Utc(localNoon));
	// Null in, out of range: a null date, never a shifted one.
	check(value(utcToSuspectLocal(filetime(0))) == 0, L"utcToSuspectLocal(null) should be null");
	check(value(suspectLocalToUtc(filetime(0))) == 0, L"suspectLocalToUtc(null) should be null");
	check(value(utcToSuspectLocal(filetime(hour))) == 0, L"utcToSuspectLocal before 1601 should be null");
	check(value(suspectLocalToUtc(filetime(0x7FFFFFFFFFFFFFFFULL))) == 0, L"suspectLocalToUtc beyond the range should be null");
	check(value(utcToSuspectLocal(filetime(0x8000000000000000ULL + hour * 10))) == 0, L"utcToSuspectLocal of a negative FILETIME should be null");
	conf.timeZone = TimeZoneInfo{};
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
	fatDates(rng);
	textDates();
	suspectOffset(rng);
	CoUninitialize();
	std::wprintf(L"%ls: %llu comparison(s), %llu difference(s)\n",
	             g_failures ? L"FAILED" : L"all identical", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
