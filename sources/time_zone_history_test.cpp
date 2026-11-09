/*! \file
 *  \brief The offset in force when a local time was written, from the System
 *         log (time_zone.h: timeZoneHistoryFrom, biasAtLocalLogged).
 *
 *  WHY THIS TEST. A local time read with the current zone's offset, when the
 *  zone was another when it was written, gives a valid date hours off: the
 *  NetSetup.LOG of Server 2025, written in the Pacific time of its
 *  installation, came out 8 h off. The cases here are those the test VMs
 *  showed, 2026-11-09, and those of a zone set back or forward.
 *
 *  Usage: time_zone_history_test — built by `build-windows.sh --test`, runs
 *  under Wine. Exit code: 0 if all checks hold.
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include "time_zone.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

int failures = 0, checks = 0;

//! Records one check, printing a failure.
void check(bool ok, const wchar_t* what) {
	++checks;
	if (!ok) { ++failures; std::wprintf(L"FAIL %ls\n", what); }
}

/*! The rules of a European zone as Windows stores them: daylight saving
 *  time from the last Sunday of March at 01:00 UTC to the last Sunday of
 *  October at 01:00 UTC.
 *  @param bias the standard offset: -60 for Paris, 0 for London */
TimeZoneRules europeanRules(long bias) {
	TimeZoneRules rules;
	rules.current.biasMinutes = bias;
	rules.current.daylightBiasMinutes = -60;
	const WORD local = (WORD)(-bias / 60);   // 01:00 UTC, in the zone's clock
	rules.current.standardDate = SYSTEMTIME{ 0, 10, 0, 5, (WORD)(local + 2), 0, 0, 0 };
	rules.current.daylightDate = SYSTEMTIME{ 0, 3, 0, 5, (WORD)(local + 1), 0, 0, 0 };
	return rules;
}

//! 100 ns count of a date, its fraction in hundreds of nanoseconds.
long long instant(WORD year, WORD month, WORD day, WORD hour, WORD minute, WORD second, long long hundredNs = 0) {
	SYSTEMTIME st = {};
	st.wYear = year; st.wMonth = month; st.wDay = day; st.wHour = hour; st.wMinute = minute; st.wSecond = second;
	FILETIME ft = {};
	SystemTimeToFileTime(&st, &ft);
	return (long long)(((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime) + hundredNs;
}

/*! The offset in force when a local time was written, from the System log
 *  (biasAtLocalLogged): the cases measured in the test VMs, 2026-11-09. */
void loggedOffsets() {
	const TimeZoneRules paris = europeanRules(-60), london = europeanRules(0);
	const long long minute = 600000000LL;
	auto utcOf = [&](const TimeZoneRules& rules, const TimeZoneHistory& h, long long local, bool& fromHistory) {
		const LocalBias b = biasAtLocalLogged(rules, h, local);
		fromHistory = b.fromHistory;
		return local + b.biasMinutes * minute;
	};
	bool fromHistory = false;
	/* Server 2025, its installation: Pacific time (420) until 08:05:11.6933122Z,
	   then Paris; between two records of 08:05, two dated 00:05:11Z, the clock
	   set 8 h back — here with a forged offset, which must not count. */
	const TimeZoneHistory installed = timeZoneHistoryFrom({
		{ 5, instant(2026, 10, 31, 0, 5, 11, 6910663), 300 },
		{ 1, instant(2026, 10, 31, 8, 4, 5, 7113518), 420 },
		{ 2, instant(2026, 10, 31, 8, 5, 4, 9054467), 420 },
		{ 3, instant(2026, 10, 31, 8, 5, 11, 6933122), -60 },
		{ 4, instant(2026, 10, 31, 8, 5, 11, 6933356), -60 },
		{ 6, instant(2026, 10, 31, 8, 5, 13, 9607396), -60 } }, instant(2026, 11, 7, 10, 8, 46));
	check(installed.changes.size() == 2, L"history: the clock set back left out, the repeated offsets merged");
	check(utcOf(paris, installed, instant(2026, 10, 31, 1, 4, 24, 140000), fromHistory) == instant(2026, 10, 31, 8, 4, 24, 140000) && fromHistory,
	      L"NetSetup.LOG of Server 2025: 01:04:24.014 written at UTC-7 is 08:04:24.014Z, the last write of the file");
	check(utcOf(paris, installed, instant(2026, 11, 5, 10, 0, 0), fromHistory) == instant(2026, 11, 5, 9, 0, 0) && !fromHistory,
	      L"after the change, the current zone: its rules");
	check(utcOf(paris, installed, instant(2026, 10, 30, 19, 5, 11), fromHistory) == instant(2026, 10, 30, 18, 5, 11) && !fromHistory,
	      L"before the first offset logged: the rules, not the offset of a clock set back");
	check(utcOf(paris, installed, instant(2026, 12, 1, 12, 0, 0), fromHistory) == instant(2026, 12, 1, 11, 0, 0) && !fromHistory,
	      L"past the end of the log: the rules");
	/* Spring: Windows 11 logs its change 0.68 ms after making it. The first
	   local times after 03:00 are the new offset's, not an hour skipped. */
	const TimeZoneHistory spring = timeZoneHistoryFrom({
		{ 1, instant(2026, 3, 20, 12, 0, 0), -60 },
		{ 2, instant(2026, 3, 29, 1, 0, 0, 6783), -120 } }, instant(2026, 4, 10, 0, 0, 0));
	check(utcOf(paris, spring, instant(2026, 3, 29, 3, 0, 0, 3000), fromHistory) == instant(2026, 3, 29, 1, 0, 0, 3000) && !fromHistory,
	      L"spring: 03:00:00.0003 local, before the change is logged, is 01:00:00.0003Z");
	check(utcOf(paris, spring, instant(2026, 3, 29, 1, 59, 59), fromHistory) == instant(2026, 3, 29, 0, 59, 59) && !fromHistory,
	      L"spring: the last second before the change");
	/* A time zone set back an hour: Paris to London at 12:00Z — the local
	   hour 12:00-13:00 lived twice; its first occurrence, as Windows in autumn. */
	const TimeZoneHistory moved = timeZoneHistoryFrom({
		{ 1, instant(2026, 11, 1, 0, 0, 0), -60 },
		{ 2, instant(2026, 11, 2, 12, 0, 0), 0 } }, instant(2026, 11, 9, 0, 0, 0));
	check(utcOf(london, moved, instant(2026, 11, 2, 12, 30, 0), fromHistory) == instant(2026, 11, 2, 11, 30, 0) && fromHistory,
	      L"an hour lived twice by a change of zone: its first occurrence");
	check(utcOf(london, moved, instant(2026, 11, 1, 18, 0, 0), fromHistory) == instant(2026, 11, 1, 17, 0, 0) && fromHistory,
	      L"before a change of zone: the former zone's offset");
	check(utcOf(london, moved, instant(2026, 11, 3, 18, 0, 0), fromHistory) == instant(2026, 11, 3, 18, 0, 0) && !fromHistory,
	      L"after a change of zone: the new one");
	/* A time zone set forward: London to Paris at 12:00Z — 12:00-13:00 local
	   skipped; the offset before the change, as Windows in spring. */
	const TimeZoneHistory forward = timeZoneHistoryFrom({
		{ 1, instant(2026, 11, 1, 0, 0, 0), 0 },
		{ 2, instant(2026, 11, 2, 12, 0, 0), -60 } }, instant(2026, 11, 9, 0, 0, 0));
	check(utcOf(paris, forward, instant(2026, 11, 2, 12, 30, 0), fromHistory) == instant(2026, 11, 2, 12, 30, 0) && fromHistory,
	      L"an hour skipped by a change of zone: the offset before it");
	check(utcOf(paris, forward, instant(2027, 7, 1, 12, 0, 0), fromHistory) == instant(2027, 7, 1, 10, 0, 0) && !fromHistory,
	      L"past the end of the log, in summer: the rules' daylight saving time, not the last offset logged");
	check(timeZoneHistoryFrom({ { 1, instant(2026, 1, 1, 0, 0, 0), 5000 } }, instant(2026, 2, 1, 0, 0, 0)).changes.empty(),
	      L"a forged offset past 24 h is no offset");
	check(biasAtLocalLogged(paris, TimeZoneHistory{}, instant(2026, 1, 15, 12, 0, 0)).biasMinutes == -60, L"no history: the rules");
}

} // namespace

int wmain() {
	loggedOffsets();
	std::printf("%d check(s), %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
