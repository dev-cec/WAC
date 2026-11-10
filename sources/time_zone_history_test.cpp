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
#include <memory>
#include <vector>
#include "time_zone.h"
#include "time_zone_history.h"
#include "xml_light.h"
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

/*! The rules of Pacific time as Windows stores them: daylight saving time from
 *  the second Sunday of March at 02:00 to the first Sunday of November at 02:00. */
TimeZoneRules pacificRules() {
	TimeZoneRules rules;
	rules.current.biasMinutes = 480;
	rules.current.daylightBiasMinutes = -60;
	rules.current.standardDate = SYSTEMTIME{ 0, 11, 0, 1, 2, 0, 0, 0 };
	rules.current.daylightDate = SYSTEMTIME{ 0, 3, 0, 2, 2, 0, 0, 0 };
	return rules;
}

/*! What a Windows before 10 logs of its zone (timeZoneHistoryFromObservations):
 *  the cases measured on Server 2008 R2, 2026-11-10, and those of a change
 *  whose instant the log does not give. */
void observedZones() {
	using Kind = ZoneObservation::Kind;
	TimeZoneRules india;
	india.current.biasMinutes = -330;
	const std::vector<TimeZoneRules> zones = { europeanRules(-60), pacificRules(), india };
	const std::vector<std::wstring> names = { L"Romance Standard Time", L"Pacific Standard Time", L"India Standard Time" };
	const TimeZoneRules& paris = zones[0];
	const long long minute = 600000000LL;
	auto build = [&](std::vector<ZoneObservation> o, long long end) {
		return timeZoneHistoryFromObservations(zones, names, 0, std::move(o), end);
	};
	auto read = [&](const TimeZoneHistory& h, long long local, long long& utc) {
		const LocalBias b = biasAtLocalLogged(paris, h, local);
		utc = local + b.biasMinutes * minute;
		return b;
	};
	long long utc = 0;
	/* The witness of Server 2008 R2: tzutil to India, then back to Paris —
	   20001 at each, and Kernel-General 1 at the same instant; 6013 at the
	   boot before and after. In the order WAC reads them: TZUtil's log before
	   System.evtx, as their names sort — at an equal instant, 20001 first. */
	const TimeZoneHistory witness = build({
		{ Kind::NamedChange, instant(2026, 11, 9, 21, 19, 35, 5311250), 2 },
		{ Kind::NamedChange, instant(2026, 11, 9, 21, 19, 39, 5467500), 0 },
		{ Kind::InForce, instant(2026, 11, 9, 20, 57, 42), 0 },
		{ Kind::UnnamedChange, instant(2026, 11, 9, 21, 19, 35, 5311250), -1 },
		{ Kind::UnnamedChange, instant(2026, 11, 9, 21, 19, 39, 5467500), -1 },
		{ Kind::InForce, instant(2026, 11, 10, 8, 56, 11), 0 } }, instant(2026, 11, 10, 9, 20, 40));
	check(witness.uncertain.empty(), L"Server 2008 R2: tzutil's Kernel-General 1 is its 20001's change, not another");
	LocalBias b = read(witness, instant(2026, 11, 10, 2, 49, 37, 5310000), utc);
	check(utc == instant(2026, 11, 9, 21, 19, 37, 5310000) && b.fromHistory && b.biasMinutes == -330 && !b.uncertain,
	      L"Server 2008 R2: a line written under India's zone, set by tzutil (20001), at its UTC");
	b = read(witness, instant(2026, 11, 9, 22, 19, 41, 5460000), utc);
	check(utc == instant(2026, 11, 9, 21, 19, 41, 5460000) && !b.fromHistory && !b.uncertain,
	      L"Server 2008 R2: the line after the zone came back, by the current rules");
	/* Installed in Pacific time, set to Paris through the API: 6013 before and
	   after, the change at the one unnamed Kernel-General 1 between them. In
	   October, Pacific daylight time: UTC-7, from its rules — 6013 gives 480. */
	const TimeZoneHistory installed = build({
		{ Kind::InForce, instant(2026, 10, 31, 7, 0, 0), 1 },
		{ Kind::UnnamedChange, instant(2026, 10, 31, 8, 5, 11, 6933122), -1 },
		{ Kind::InForce, instant(2026, 10, 31, 9, 0, 0), 0 } }, instant(2026, 11, 7, 0, 0, 0));
	b = read(installed, instant(2026, 10, 31, 1, 4, 24, 140000), utc);
	check(utc == instant(2026, 10, 31, 8, 4, 24, 140000) && b.biasMinutes == 420 && !b.uncertain,
	      L"installed in Pacific time: UTC-7 in October by its rules, the change at the unnamed event");
	check(installed.uncertain.empty() && installed.changes.size() == 2 && installed.changes[0].zone == names[1],
	      L"installed in Pacific time: two stretches, each named by its zone");
	// The same without the unnamed event: the instant of the change unknown.
	const TimeZoneHistory unknown = build({
		{ Kind::InForce, instant(2026, 10, 31, 7, 0, 0), 1 },
		{ Kind::InForce, instant(2026, 10, 31, 9, 0, 0), 0 } }, instant(2026, 11, 7, 0, 0, 0));
	b = read(unknown, instant(2026, 10, 31, 1, 4, 24, 140000), utc);
	check(unknown.uncertain.size() == 1 && b.uncertain && b.biasMinutes == -60 && !b.fromHistory
	      && b.uncertain->fromUtc100ns == instant(2026, 10, 31, 7, 0, 0) && b.uncertain->toUtc100ns == instant(2026, 10, 31, 9, 0, 0),
	      L"a change between two 6013 with no event of its own: the current rules, the interval said");
	b = read(unknown, instant(2026, 10, 30, 12, 0, 0), utc);
	check(utc == instant(2026, 10, 30, 11, 0, 0) && !b.fromHistory && !b.uncertain,
	      L"before the first observation: the current rules, as before the first offset logged");
	// Away and back through the API between two 6013 of Paris: between the two changes, unknown.
	const TimeZoneHistory away = build({
		{ Kind::InForce, instant(2026, 11, 2, 8, 0, 0), 0 },
		{ Kind::UnnamedChange, instant(2026, 11, 2, 10, 0, 0), -1 },
		{ Kind::UnnamedChange, instant(2026, 11, 2, 11, 0, 0), -1 },
		{ Kind::InForce, instant(2026, 11, 3, 8, 0, 0), 0 } }, instant(2026, 11, 4, 0, 0, 0));
	check(away.uncertain.size() == 1 && read(away, instant(2026, 11, 2, 11, 30, 0), utc).uncertain
	      && !read(away, instant(2026, 11, 2, 14, 0, 0), utc).uncertain,
	      L"away and back between two 6013 of one zone: the interval between the two changes said, not after");
	// One change alone between two 6013 of one zone: the same zone set again.
	check(build({ { Kind::InForce, instant(2026, 11, 2, 8, 0, 0), 0 },
	              { Kind::UnnamedChange, instant(2026, 11, 2, 10, 0, 0), -1 },
	              { Kind::InForce, instant(2026, 11, 3, 8, 0, 0), 0 } }, instant(2026, 11, 4, 0, 0, 0)).uncertain.empty(),
	      L"a single change between two 6013 of one zone: no interval");
	/* An unnamed event at Paris's return to winter time is that transition:
	   the change of zone is the other one. */
	const TimeZoneHistory transition = build({
		{ Kind::InForce, instant(2026, 10, 20, 0, 0, 0), 1 },
		{ Kind::UnnamedChange, instant(2026, 10, 25, 1, 0, 0, 6783), -1 },
		{ Kind::UnnamedChange, instant(2026, 10, 26, 10, 0, 0), -1 },
		{ Kind::InForce, instant(2026, 10, 27, 0, 0, 0), 0 } }, instant(2026, 11, 4, 0, 0, 0));
	b = read(transition, instant(2026, 10, 26, 2, 0, 0), utc);
	check(transition.uncertain.empty() && utc == instant(2026, 10, 26, 9, 0, 0) && b.biasMinutes == 420,
	      L"an unnamed event at a daylight saving transition is not the change of zone");
	// Paris over its return to winter time: the transition from its rules.
	const TimeZoneHistory autumn = build({ { Kind::InForce, instant(2026, 10, 20, 0, 0, 0), 0 } }, instant(2026, 10, 30, 0, 0, 0));
	check(autumn.changes.size() == 2 && autumn.changes[1].utc100ns == instant(2026, 10, 25, 1, 0, 0)
	      && autumn.changes[0].biasMinutes == -120 && autumn.changes[1].biasMinutes == -60,
	      L"a stretch over a daylight saving transition: the offset changes at the transition, to 100 ns");
	check(build({ { Kind::InForce, instant(2026, 10, 20, 0, 0, 0), 7 },
	              { Kind::UnnamedChange, instant(2026, 10, 21, 0, 0, 0), -1 } }, instant(2026, 10, 30, 0, 0, 0)).changes.empty(),
	      L"no zone known: no history, the rules");
}

/*! The zone in force an EventLog 6013 gives (zoneInForceOf): the event as
 *  Server 2008 R2 wrote it, its Binary after the last datum. */
void eventLog6013() {
	const std::wstring head = L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
		L"<Provider Name='EventLog'/><EventID Qualifiers='32768'>6013</EventID><Level>4</Level>"
		L"<TimeCreated SystemTime='2026-11-10T08:56:11.000000000Z'/><EventRecordID>1316</EventRecordID>"
		L"<Channel>System</Channel></System><EventData><Data></Data><Data></Data><Data></Data><Data></Data>"
		L"<Data>2</Data><Data>60</Data>";
	long bias = 0;
	std::wstring name;
	auto read = [&](const std::wstring& xml) {
		const std::unique_ptr<XmlNode> event = xmlParse(xml, true);
		return event && zoneInForceOf(*event, bias, name);
	};
	check(read(head + L"<Data>-60 Romance Standard Time</Data><Binary>31002E00</Binary></EventData></Event>")
	      && bias == -60 && name == L"Romance Standard Time",
	      L"6013 of Server 2008 R2: the last datum, not the Binary after it");
	check(read(head + L"<Data>-60 Paris, Madrid</Data></EventData></Event>") && name == L"Paris, Madrid",
	      L"6013 of a French Windows: the standard name, with its comma");
	check(!read(head + L"<Data>-6x0 Paris</Data></EventData></Event>") && !read(head + L"<Data>-60</Data></EventData></Event>"),
	      L"6013 with a forged datum: no zone");
}

} // namespace

int wmain() {
	eventLog6013();
	loggedOffsets();
	observedZones();
	std::printf("%d check(s), %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
