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
 *    before, applied the machine's), and a null result out of range;
 *  - biasAtUtc / SystemTimeToTzSpecificLocalTimeEx and biasAtLocal /
 *    TzSpecificLocalTimeToSystemTimeEx, on EVERY time zone of Windows, with
 *    the rules read in the registry as WAC reads them in the suspect's
 *    hives: random instants from 1970 to 2040, and every transition (the
 *    hour skipped, the hour repeated) from 1980 to 2035;
 *  - the rule read in `SYSTEM\...\TimeZoneInformation` (transition dates in
 *    the kernel's TIME_FIELDS layout) against GetTimeZoneInformation;
 *  - the formatting of WAC end to end: a winter date collected in summer is
 *    labelled with its own offset, not the collection day's;
 *  - random (forged) rules: offsets within bounds, no overflow;
 *  - the precision written: seven, three or no digits of fraction, as the
 *    source holds; a FAT date comes out to the second, never ".0000000";
 *  - serviceSid / LookupAccountNameW("NT SERVICE\\<name>"), on every service
 *    of the machine: the SIDs WAC names offline are those Windows gives.
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
#include "time_zone.h"
#include "account_names.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned long long g_checks = 0, g_failures = 0;

/*! Records one comparison, printing the first failures. */
void check(bool same, const std::wstring& what) {
	++g_checks;
	if (same) return;
	++g_failures;
	// At most three differences per subject (the text before the first comma), 60 in all.
	static std::wstring subject;
	static unsigned shown = 0, forSubject = 0;
	const std::wstring s = what.substr(0, what.find(L','));
	if (s != subject) { subject = s; forSubject = 0; }
	if (++forSubject <= 3 && ++shown <= 60) std::wprintf(L"  DIFF  %ls\n", what.c_str());
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
	conf.timeZone.rules = TimeZoneRules{};
	conf.timeZone.rules.current.biasMinutes = 300;
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

//! One registry value of a time zone, read live: the bytes WAC reads in the hive.
std::vector<BYTE> zoneValue(const std::wstring& key, const wchar_t* name) {
	DWORD size = 0;
	if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), name, RRF_RT_ANY, nullptr, nullptr, &size) != ERROR_SUCCESS)
		return {};
	std::vector<BYTE> data(size);
	if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), name, RRF_RT_ANY, nullptr, data.data(), &size) != ERROR_SUCCESS)
		return {};
	data.resize(size);
	return data;
}

//! The rules of a time zone, from the registry, as loadSuspectTimeZone builds them.
bool zoneRules(const std::wstring& keyName, TimeZoneRules& rules) {
	const std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\" + keyName;
	const std::vector<BYTE> tzi = zoneValue(key, L"TZI");
	if (!parseTimeZoneRule(tzi.data(), tzi.size(), rules.current)) return false;
	const std::wstring dynamic = key + L"\\Dynamic DST";
	const std::vector<BYTE> first = zoneValue(dynamic, L"FirstEntry"), last = zoneValue(dynamic, L"LastEntry");
	if (first.size() != 4 || last.size() != 4) return true;
	DWORD firstYear = 0, lastYear = 0;
	std::memcpy(&firstYear, first.data(), 4);
	std::memcpy(&lastYear, last.data(), 4);
	for (DWORD year = firstYear; year <= lastYear && year - firstYear < 1000; ++year) {
		const std::vector<BYTE> rule = zoneValue(dynamic, std::to_wstring(year).c_str());
		TimeZoneRule r;
		if (parseTimeZoneRule(rule.data(), rule.size(), r)) rules.byYear[(int)year] = r;
	}
	return true;
}

//! SYSTEMTIME of a 100 ns count.
SYSTEMTIME systemTime(ULONGLONG ticks) {
	const FILETIME ft = filetime(ticks);
	SYSTEMTIME st = {};
	FileTimeToSystemTime(&ft, &st);
	return st;
}

//! 100 ns count of a SYSTEMTIME.
long long ticksOf(const SYSTEMTIME& st) {
	FILETIME ft = { 0, 0 };
	SystemTimeToFileTime(&st, &ft);
	return (long long)value(ft);
}

//! Compares both directions at one instant, taken as UTC then as a local time.
void zoneInstant(const DYNAMIC_TIME_ZONE_INFORMATION& zone, const TimeZoneRules& rules, long long instant) {
	const long long minute = 600000000LL;
	// A SYSTEMTIME stops at the millisecond: both sides compare that instant.
	const SYSTEMTIME st = systemTime((ULONGLONG)instant);
	const long long ticks = ticksOf(st);
	SYSTEMTIME other = {};
	if (SystemTimeToTzSpecificLocalTimeEx(&zone, &st, &other)) {
		const long windows = (long)((ticks - ticksOf(other)) / minute);
		const long mine = biasAtUtc(rules, ticks);
		check(windows == mine, std::wstring(zone.TimeZoneKeyName) + L", UTC "
		      + timeToIso8601Utc(filetime((ULONGLONG)ticks)) + L": Windows bias " + std::to_wstring(windows)
		      + L", WAC " + std::to_wstring(mine));
	}
	if (TzSpecificLocalTimeToSystemTimeEx(&zone, &st, &other)) {
		const long windows = (long)((ticksOf(other) - ticks) / minute);
		const long mine = biasAtLocal(rules, ticks);
		check(windows == mine, std::wstring(zone.TimeZoneKeyName) + L", local "
		      + timeToIso8601Utc(filetime((ULONGLONG)ticks)).substr(0, 19) + L": Windows bias " + std::to_wstring(windows)
		      + L", WAC " + std::to_wstring(mine));
	}
}

void timeZones(std::mt19937_64& rng) {
	const long long minute = 600000000LL;
	SYSTEMTIME from = {}, to = {};
	from.wYear = 1970; from.wMonth = 1; from.wDay = 1;
	to.wYear = 2040; to.wMonth = 1; to.wDay = 1;
	const long long start = ticksOf(from), span = ticksOf(to) - start;
	DYNAMIC_TIME_ZONE_INFORMATION zone = {};
	unsigned zones = 0;
	for (DWORD i = 0; EnumDynamicTimeZoneInformation(i, &zone) == ERROR_SUCCESS; ++i) {
		TimeZoneRules rules;
		if (!zoneRules(zone.TimeZoneKeyName, rules)) {
			check(false, L"time zone " + std::wstring(zone.TimeZoneKeyName) + L": TZI unreadable");
			continue;
		}
		++zones;
		for (int k = 0; k < 2000; ++k) zoneInstant(zone, rules, start + (long long)(rng() % (ULONGLONG)span));
		// Around every transition: the edges are where a rule read wrong shows.
		for (int year = 1980; year <= 2035; ++year) {
			const TimeZoneRule& r = rules.forYear(year);
			for (const SYSTEMTIME* date : { &r.daylightDate, &r.standardDate }) {
				if (date->wMonth == 0) continue;
				for (int week = 0; week < 5; ++week) {
					SYSTEMTIME day = {};
					day.wYear = (WORD)year; day.wMonth = date->wMonth; day.wDay = (WORD)(1 + 7 * week);
					if (week == 4) day.wDay = 28;
					const long long base = ticksOf(day) + (date->wHour * 60LL + date->wMinute) * minute;
					for (int d = 0; d < 7; ++d)
						for (long long m : { -121LL, -61LL, -60LL, -59LL, -1LL, 0LL, 1LL, 30LL, 59LL, 60LL, 61LL, 121LL })
							zoneInstant(zone, rules, base + d * 1440LL * minute + m * minute);
				}
			}
		}
		// Around 1 January, where a change of rule takes effect: every half hour of a day and a half.
		for (int year = 1980; year <= 2035; ++year) {
			SYSTEMTIME newYear = {};
			newYear.wYear = (WORD)year; newYear.wMonth = 1; newYear.wDay = 1;
			for (long long m = -18 * 60; m <= 18 * 60; m += 30)
				zoneInstant(zone, rules, ticksOf(newYear) + m * minute);
		}
	}
	check(zones > 100, L"only " + std::to_wstring(zones) + L" time zone(s) enumerated");
	std::wprintf(L"  %u time zones compared\n", zones);
}

/*! The rule WAC builds from `SYSTEM\...\TimeZoneInformation`, read as it reads
 *  it in the suspect's hive, must be the one GetTimeZoneInformation gives:
 *  the transition dates are stored there as TIME_FIELDS, not SYSTEMTIMEs. */
void systemTimeZoneKey() {
	const std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation";
	const std::vector<BYTE> bias = zoneValue(key, L"Bias"), standardBias = zoneValue(key, L"StandardBias"),
	    daylightBias = zoneValue(key, L"DaylightBias"), standardStart = zoneValue(key, L"StandardStart"),
	    daylightStart = zoneValue(key, L"DaylightStart");
	if (bias.size() != 4 || standardBias.size() != 4 || daylightBias.size() != 4
	    || standardStart.size() != 16 || daylightStart.size() != 16) {
		check(false, L"TimeZoneInformation: values missing");
		return;
	}
	int32_t b[3];
	std::memcpy(&b[0], bias.data(), 4);
	std::memcpy(&b[1], standardBias.data(), 4);
	std::memcpy(&b[2], daylightBias.data(), 4);
	BYTE standard[16], daylight[16];
	std::memcpy(standard, standardStart.data(), 16);
	std::memcpy(daylight, daylightStart.data(), 16);
	TimeZoneRule rule;
	TIME_ZONE_INFORMATION windows = {};
	if (!parseTimeZoneInformation(b[0], b[1], b[2], standard, daylight, rule)
	    || GetTimeZoneInformation(&windows) == TIME_ZONE_ID_INVALID) {
		check(false, L"TimeZoneInformation: rule refused");
		return;
	}
	const auto same = [](const SYSTEMTIME& a, const SYSTEMTIME& c) {
		return a.wYear == c.wYear && a.wMonth == c.wMonth && a.wDayOfWeek == c.wDayOfWeek && a.wDay == c.wDay
		    && a.wHour == c.wHour && a.wMinute == c.wMinute && a.wSecond == c.wSecond && a.wMilliseconds == c.wMilliseconds;
	};
	check(rule.biasMinutes == windows.Bias && rule.standardBiasMinutes == windows.StandardBias
	      && rule.daylightBiasMinutes == windows.DaylightBias, L"TimeZoneInformation: offsets differ from Windows'");
	check(same(rule.standardDate, windows.StandardDate), L"TimeZoneInformation: StandardStart read differently from Windows");
	check(same(rule.daylightDate, windows.DaylightDate), L"TimeZoneInformation: DaylightStart read differently from Windows");
}

/*! End to end, through the formatting of WAC: a collection made in SUMMER in
 *  Paris (offset of the day +02:00) must still date a winter instant at
 *  +01:00. The offset of the collection day, applied to every date before,
 *  gave "+02:00" and a local time one hour off. */
void seasonalOffsets() {
	TimeZoneRules paris;
	if (!zoneRules(L"Romance Standard Time", paris)) { check(false, L"Romance Standard Time unreadable"); return; }
	conf.timeZone = TimeZoneInfo{};
	conf.timeZone.valid = true;
	conf.timeZone.activeBiasMinutes = -120;      // collected in summer
	conf.timeZone.rules = paris;
	SYSTEMTIME winter = {}, summer = {};
	winter.wYear = 2026; winter.wMonth = 1; winter.wDay = 15; winter.wHour = 12;
	summer.wYear = 2026; summer.wMonth = 7; summer.wDay = 15; summer.wHour = 12;
	const FILETIME winterFt = filetime((ULONGLONG)ticksOf(winter)), summerFt = filetime((ULONGLONG)ticksOf(summer));
	check(utcTimeToIso8601Local(winterFt) == L"2026-01-15T13:00:00.0000000+01:00",
	      L"winter UTC -> local: " + utcTimeToIso8601Local(winterFt));
	check(utcTimeToIso8601Local(summerFt) == L"2026-07-15T14:00:00.0000000+02:00",
	      L"summer UTC -> local: " + utcTimeToIso8601Local(summerFt));
	// A local date stored by the artefact (Amcache, FAT date): its UTC and its label.
	check(localTimeToIso8601Utc(winterFt) == L"2026-01-15T11:00:00.0000000Z",
	      L"winter local -> UTC: " + localTimeToIso8601Utc(winterFt));
	check(timeToIso8601Local(winterFt) == L"2026-01-15T12:00:00.0000000+01:00",
	      L"winter local label: " + timeToIso8601Local(winterFt));
	// The hour repeated on 25 October 2026 (03:00 -> 02:00): two UTC instants, two labels.
	SYSTEMTIME first = {};
	first.wYear = 2026; first.wMonth = 10; first.wDay = 25; first.wHour = 0; first.wMinute = 30;
	const long long hour = 36000000000LL;
	check(utcTimeToIso8601Local(filetime((ULONGLONG)ticksOf(first))) == L"2026-10-25T02:30:00.0000000+02:00"
	      && utcTimeToIso8601Local(filetime((ULONGLONG)(ticksOf(first) + hour))) == L"2026-10-25T02:30:00.0000000+01:00",
	      L"repeated hour: the two occurrences must carry their own offsets");
	conf.timeZone = TimeZoneInfo{};
}

/*! Rules read from a forged hive: random bytes must give a refused rule or
 *  offsets within their bounds — never a crash or an overflow, even at the
 *  ends of the FILETIME range. */
void hostileRules(std::mt19937_64& rng) {
	const long long ends[] = { 0, 1, 36000000000LL, 0x7FFFFFFFFFFFFFFFLL, 0x7FFFFFFFFFFFFFFFLL - 36000000000LL,
	                           0x0240000000000000LL };
	for (int i = 0; i < 20000; ++i) {
		BYTE bytes[44];
		for (BYTE& b : bytes) b = (BYTE)rng();
		// Plausible offsets half of the time, so that the transitions get exercised.
		if (i % 2) for (int k = 0; k < 3; ++k) { const int32_t v = (int32_t)(rng() % 1441) - 720; std::memcpy(bytes + 4 * k, &v, 4); }
		TimeZoneRules rules;
		if (!parseTimeZoneRule(bytes, sizeof(bytes), rules.current)) continue;
		if (i % 3 == 0) rules.byYear[2000 + (int)(rng() % 50)] = rules.current;
		for (int k = 0; k < 20; ++k) {
			const long long instant = k < 6 ? ends[k] : (long long)(rng() >> 1);
			const long a = biasAtUtc(rules, instant), b = biasAtLocal(rules, instant);
			check(a >= -2880 && a <= 2880 && b >= -2880 && b <= 2880, L"hostile rule: offset out of bounds");
		}
	}
}

/*! Every service of the machine: WAC's service SID against Windows'. */
void serviceSids() {
	HKEY services = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &services) != ERROR_SUCCESS) {
		check(false, L"Services key unreadable");
		return;
	}
	unsigned compared = 0;
	wchar_t name[256];
	for (DWORD i = 0; ; ++i) {
		DWORD length = 256;
		const LONG r = RegEnumKeyExW(services, i, name, &length, nullptr, nullptr, nullptr, nullptr);
		if (r == ERROR_NO_MORE_ITEMS) break;
		if (r != ERROR_SUCCESS) continue;
		BYTE sid[SECURITY_MAX_SID_SIZE];
		DWORD sidSize = sizeof(sid), domainSize = 256;
		wchar_t domain[256];
		SID_NAME_USE use;
		const std::wstring account = std::wstring(L"NT SERVICE\\") + name;
		if (!LookupAccountNameW(nullptr, account.c_str(), sid, &sidSize, domain, &domainSize, &use)) continue;
		++compared;
		check(sidToText(sid, sidSize) == serviceSid(name),
		      L"service SID of " + std::wstring(name) + L": Windows " + sidToText(sid, sidSize) + L", WAC " + serviceSid(name));
	}
	RegCloseKey(services);
	check(compared > 100, L"only " + std::to_wstring(compared) + L" service SID(s) compared");
	std::wprintf(L"  %u service SIDs compared\n", compared);
}

/*! The fraction written says no more than the source holds. */
void precisions() {
	SYSTEMTIME st = {};
	st.wYear = 2026; st.wMonth = 3; st.wDay = 6; st.wHour = 4; st.wMinute = 7; st.wSecond = 44;
	const FILETIME base = filetime((ULONGLONG)ticksOf(st) + 1234567);   // + 0.1234567 s
	check(timeToIso8601Utc(base) == L"2026-03-06T04:07:44.1234567Z",
	      L"precision 100 ns: " + timeToIso8601Utc(base));
	check(timeToIso8601Utc(base, Precision::Millisecond) == L"2026-03-06T04:07:44.123Z",
	      L"precision millisecond: " + timeToIso8601Utc(base, Precision::Millisecond));
	check(timeToIso8601Utc(base, Precision::Second) == L"2026-03-06T04:07:44Z",
	      L"precision second: " + timeToIso8601Utc(base, Precision::Second));
	// A FAT date: 6 March 2026, 04:07:44 — date (year-1980, month, day), time (h, min, s/2).
	const unsigned date = ((2026 - 1980) << 9) | (3 << 5) | 6, time = (4 << 11) | (7 << 5) | 22;
	const FILETIME fat = FatDateTime(date | (time << 16)).toFileTime();
	check(timeToIso8601Utc(fat, Precision::Second) == L"2026-03-06T04:07:44Z",
	      L"FAT date: " + timeToIso8601Utc(fat, Precision::Second));
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
	timeZones(rng);
	precisions();
	serviceSids();
	seasonalOffsets();
	systemTimeZoneKey();
	hostileRules(rng);
	CoUninitialize();
	std::wprintf(L"%ls: %llu comparison(s), %llu difference(s)\n",
	             g_failures ? L"FAILED" : L"all identical", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
