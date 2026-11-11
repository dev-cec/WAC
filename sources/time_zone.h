/*! \file
 *  \brief The daylight saving rules of a Windows time zone, and the offset
 *         they give at a given instant — in UTC or in local time.
 *
 *  WHY. A local date is only right with the offset in force AT THAT DATE. WAC
 *  applied to every date the offset of the collection day (ActiveTimeBias):
 *  collected in summer, a winter date came out one hour off in local time and
 *  labelled "+02:00" instead of "+01:00" — a well-formed, wrong value, and in
 *  the other direction (a local time stored by the artefact, converted to UTC)
 *  a wrong UTC instant.
 *
 *  THE RULES, AS WINDOWS STORES THEM. A rule is the REG_TZI_FORMAT structure:
 *  the base offset, the standard and daylight adjustments, and the two
 *  transition dates, most often "the n-th <weekday> of <month> at <time>".
 *  Windows keeps one rule per year where the rules changed (the "Dynamic DST"
 *  key: the United States in 2007, Russia in 2011 and 2014...); a year before
 *  the first entry takes the first, after the last takes the last.
 *
 *  SAME ANSWERS AS WINDOWS. biasAtUtc follows SystemTimeToTzSpecificLocalTimeEx
 *  and biasAtLocal TzSpecificLocalTimeToSystemTimeEx, including for the local
 *  hour that does not exist (spring) or occurs twice (autumn); checked on every
 *  time zone of Windows by system_conversions_test.cpp.
 *
 *  The functions are pure: the rules come in as parameters, read from the
 *  suspect's hives by loadSuspectTimeZone (tools.cpp). The bytes of a rule come
 *  from the examined machine and are hostile input: an impossible transition
 *  date (month 13, 6th week) makes the rule one without daylight saving time,
 *  never an out-of-range computation.
 */
#pragma once
#include <windows.h>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

//! One rule: the REG_TZI_FORMAT structure of the registry.
struct TimeZoneRule {
	long biasMinutes = 0;          //!< minutes to ADD to the local time to obtain UTC, before adjustment
	long standardBiasMinutes = 0;  //!< added to biasMinutes outside daylight saving time
	long daylightBiasMinutes = 0;  //!< added to biasMinutes during daylight saving time
	SYSTEMTIME standardDate = {};  //!< return to standard time (local daylight time); wMonth 0: none
	SYSTEMTIME daylightDate = {};  //!< start of daylight saving time (local standard time); wMonth 0: none
};

//! The rules of a time zone over the years.
struct TimeZoneRules {
	TimeZoneRule current;               //!< the rule in force, used for every year without its own
	std::map<int, TimeZoneRule> byYear; //!< one rule per year ("Dynamic DST"), possibly empty

	/*! The rule of a year: its own, the first one before the first year, the
	 *  last one after the last year, `current` if there are none.
	 *  @param year the calendar year
	 *  @return the rule that applies */
	const TimeZoneRule& forYear(int year) const;
};

/*! Reads a rule in the REG_TZI_FORMAT form (44 bytes).
 *  @param data the bytes of the registry value
 *  @param size their number
 *  @param rule receives the rule
 *  @return false if the value is not 44 bytes long, or carries an offset
 *          beyond ±24 hours (a forged value) */
bool parseTimeZoneRule(const BYTE* data, size_t size, TimeZoneRule& rule);

/*! Builds a rule from the values of `SYSTEM\...\Control\TimeZoneInformation`.
 *
 *  THE TRAP. There, StandardStart and DaylightStart are NOT SYSTEMTIMEs, as in
 *  the TZI values of the Time Zones key, but the kernel's TIME_FIELDS: Year,
 *  Month, Day, Hour, Minute, Second, Milliseconds, Weekday — the weekday LAST.
 *  Read as SYSTEMTIMEs, "last Sunday of October at 03:00" became "3rd Friday
 *  of October at 00:00", and every date between the two was dated one hour
 *  off: caught by check-json.py, which confronts the offsets with the tz
 *  database.
 *  @param bias the Bias value (minutes)
 *  @param standardBias the StandardBias value
 *  @param daylightBias the DaylightBias value
 *  @param standardStart the 16 bytes of StandardStart
 *  @param daylightStart the 16 bytes of DaylightStart
 *  @param rule receives the rule
 *  @return false if an offset is out of bounds (see parseTimeZoneRule) */
bool parseTimeZoneInformation(int32_t bias, int32_t standardBias, int32_t daylightBias,
                              const BYTE (&standardStart)[16], const BYTE (&daylightStart)[16],
                              TimeZoneRule& rule);

/*! Offset in force at a UTC instant.
 *  @param rules the time zone's rules
 *  @param utc100ns the instant, in hundreds of nanoseconds since 1601 (UTC)
 *  @return the bias in minutes: local = UTC - bias */
long biasAtUtc(const TimeZoneRules& rules, long long utc100ns);

/*! Offset in force at a local wall-clock time, resolved as Windows does for
 *  the hour that does not exist or occurs twice.
 *  @param rules the time zone's rules
 *  @param local100ns the local time, in hundreds of nanoseconds since 1601
 *  @return the bias in minutes: UTC = local + bias */
long biasAtLocal(const TimeZoneRules& rules, long long local100ns);

/*! The other offsets a local wall-clock time has by the zone's rules: in the
 *  hour repeated in autumn, the second occurrence's (biasAtLocal gives the
 *  first) — each its own UTC instant, as possible. Empty for a time lived
 *  once, or skipped.
 *  @param rules the time zone's rules
 *  @param local100ns the local time, in hundreds of nanoseconds since 1601
 *  @return the biases in minutes, ascending: UTC = local + bias */
std::vector<long> otherBiasesAtLocal(const TimeZoneRules& rules, long long local100ns);

/*! An offset the examined machine wrote in its System log, at an instant:
 *  Kernel-General 22 (NewBias, on every change of offset — a time zone set,
 *  a daylight saving transition — while the machine runs), 24 (CurrentBias,
 *  at each boot and each refresh) or 1 (TimeZoneBias, each time the clock is
 *  set). Measured on Windows 11 and Server 2025, 2026-11-09: a time zone set
 *  by tzutil writes 22, 24 and 1 at the same instant. */
struct LoggedBias {
	unsigned long long recordId = 0; //!< the record's number: the order Windows wrote them in; 0 for an offset a zone's rules gave
	long long utc100ns = 0;          //!< the record's time, UTC
	long biasMinutes = 0;            //!< the offset in force from then on: UTC = local + bias
	std::wstring zone;               //!< the zone whose rules gave the offset (timeZoneHistoryFromObservations); empty when logged as such
};

/*! An interval where the zone in force is not known: it changed somewhere
 *  inside, and nothing tells when (timeZoneHistoryFromObservations). */
struct UncertainZone {
	long long fromUtc100ns = 0;  //!< the last instant the zone before is known in force
	long long toUtc100ns = 0;    //!< the first instant the zone after is known in force
	long biasBefore = 0;         //!< the offset of the zone before, at fromUtc100ns
	long biasAfter = 0;          //!< the offset of the zone after, at toUtc100ns
};

/*! The offset in force over the period the System log covers.
 *
 *  WHY. A local time is right only with the offset of the zone in force WHEN
 *  IT WAS WRITTEN. The rules of the current zone know the daylight saving
 *  time of each date, not that the zone itself changed: an installation in
 *  the default Pacific time, set to Paris afterwards (measured, Server 2025:
 *  NetSetup.LOG written at UTC−7, read at UTC+1, 8 h off), a laptop that
 *  travelled. Windows writes each change while it runs, and the offset at
 *  each boot: within the log, the offset at any instant the machine ran is
 *  known exactly. */
struct TimeZoneHistory {
	/*! From each instant on, its offset, until the next: ascending, no two
	 *  consecutive alike. Empty: nothing logged, the rules alone apply. */
	std::vector<LoggedBias> changes;
	long long endUtc100ns = 0; //!< last instant the log covers: past it, the rules alone
	/*! Where a change happened at an unknown instant: the current zone's rules
	 *  hold there in `changes`, and a time read there says so. Ascending. */
	std::vector<UncertainZone> uncertain;
};

/*! What a Windows before Windows 10 logs of its time zone — it writes no
 *  Kernel-General 22 nor 24. Measured on Server 2008 R2, 2026-11-10:
 *  - EventLog 6013, at each boot and once a day: the zone in force, as its
 *    STANDARD offset and standard name (the last datum, "-60 Paris, Madrid",
 *    localized: Windows 11 in French). The standard offset, not the one in
 *    force: -60 for Paris in October, in summer time — daylight saving comes
 *    from the zone's rules. Server 2003 writes none, but the same datum in
 *    EventLog 6005 and 6006, at each boot and each shutdown (measured);
 *  - TZUtil/Operational 20001: a zone set by tzutil, its key name, at the
 *    instant of the change;
 *  - Kernel-General 1 with NewTime equal to OldTime: a zone set through the
 *    API (SetDynamicTimeZoneInformation, as the Control Panel does), at the
 *    instant of the change, without its name. A clock really set, or adjusted
 *    at boot (by 0.125 ms, measured), changes the time: not one. tzutil
 *    writes one too, with its 20001: within a second of a 20001, the same change. */
struct ZoneObservation {
	enum class Kind {
		InForce,        //!< 6013, 6005, 6006: zone in force at that instant
		NamedChange,    //!< 20001: zone set at that instant
		UnnamedChange   //!< Kernel-General 1, times equal: a zone set at that instant, which one unknown
	};
	Kind kind = Kind::InForce;
	long long utc100ns = 0;  //!< the record's time, UTC
	int zone = -1;           //!< InForce and NamedChange: index of its rules in the zones given
};

/*! Builds the history from what a Windows before Windows 10 logs.
 *
 *  Between two observations of the same zone, it was in force — two unnamed
 *  changes between them (one away, one back) leave the interval between those
 *  two unknown. A named change starts its zone at its instant. Between two
 *  observations of different zones, the change happened in between: at the
 *  unnamed change if a single one lies there (one within a second of a
 *  daylight saving transition of either zone is that transition, not a change
 *  of zone); otherwise its instant is unknown — the interval goes to
 *  `uncertain`, and the current zone's rules hold in it, never an invented
 *  instant (decision of the user, 2026-11-10). The end of the log observes the
 *  current zone. Each stretch takes its zone's rules: an offset at its start,
 *  one at each daylight saving transition within it.
 *  @param zones the rules of each zone observed, read in the examined SOFTWARE hive
 *  @param zoneNames the key name of each, written with its offsets
 *  @param currentZone index of the current zone in `zones`
 *  @param observations as read, in the order Windows wrote each log
 *  @param endUtc100ns the time of the last record of the log
 *  @return the history */
TimeZoneHistory timeZoneHistoryFromObservations(const std::vector<TimeZoneRules>& zones,
                                                const std::vector<std::wstring>& zoneNames, int currentZone,
                                                std::vector<ZoneObservation> observations, long long endUtc100ns);

/*! Builds the history from the offsets read, in any order.
 *
 *  THE CLOCK SET BACK. Taken in the order Windows wrote them (recordId), an
 *  offset dated before one written earlier is left out: its clock was wrong.
 *  Measured on Server 2025 during its installation: records dated 00:05:11Z
 *  between two of 08:05, the clock set 8 h back for two seconds — taken, the
 *  offset of 00:05 would have been the one of 08:05.
 *  @param logged the offsets, as read
 *  @param endUtc100ns the time of the last record of the log
 *  @return the history */
TimeZoneHistory timeZoneHistoryFrom(std::vector<LoggedBias> logged, long long endUtc100ns);

//! The offset of a local time, and where it comes from.
struct LocalBias {
	long biasMinutes = 0;       //!< UTC = local + bias
	bool fromHistory = false;   //!< the System log's offset, not the one the current zone's rules give
	/*! The time may have been written in an interval where the zone changed at
	 *  an unknown instant (TimeZoneHistory::uncertain): that interval, else null. */
	const UncertainZone* uncertain = nullptr;
	/*! The other offsets whose stretch of the history also holds the time: a
	 *  local time lived twice — the zone set back (measured, Server 2025 from
	 *  Paris to New York: 16:45 local lived at 15:45Z, then at 21:45Z) or the
	 *  hour of autumn. Each its own UTC instant, as likely as the one chosen:
	 *  said, never dropped. Empty when the time was lived once. */
	std::vector<long> otherBiasesMinutes;
};

/*! The offset of a local time on the examined machine: the one in force WHEN
 *  it was written, as its System log shows it, else the current zone's rules
 *  (biasAtLocal).
 *
 *  A local time L belongs to a stretch of the history when L + its offset
 *  falls within it. Several do (a clock set back: an hour lived twice): the
 *  smallest offset, its first occurrence, as Windows chooses in autumn — the
 *  others in otherBiasesMinutes, each a UTC instant as possible. None
 *  does: the rules' offset if the log shows it within a second of that instant
 *  (Windows logs a change a moment after making it); else, L within the log (a
 *  clock set forward: an hour skipped), the offset in force before the change,
 *  as Windows does in spring. L before the first offset logged, or after the
 *  end of the log: the rules. L read in an interval of `uncertain` — by its
 *  offset, or by the zone before or after it —: that interval, said.
 *  @param rules the current zone's rules
 *  @param history what the System log shows
 *  @param local100ns the local time, in hundreds of nanoseconds since 1601
 *  @return the offset, and its source */
LocalBias biasAtLocalLogged(const TimeZoneRules& rules, const TimeZoneHistory& history, long long local100ns);

/*! Local times the history shows lived twice: the offset grew from one
 *  stretch to a later one (the zone, or daylight saving, set back), and the
 *  local times of the two overlap. */
struct LivedTwice {
	long long localFrom100ns = 0;  //!< first local time lived twice
	long long localTo100ns = 0;    //!< end of them, excluded
	long firstBiasMinutes = 0;     //!< the offset of their first occurrence: UTC = local + bias
	long againBiasMinutes = 0;     //!< the offset of the second
};

/*! The local times lived twice within the history (LivedTwice), ascending by
 *  their first occurrence. Every time converted from local within one is
 *  ambiguous: the conversion says them all (conversion.json, SuspectTimeZone).
 *  Outside the history, the hour repeated each autumn by the rules is not
 *  listed — every year has one —, each time read there says it all the same.
 *  @param history what the System log shows
 *  @param limit at most this many returned: a forged log costs no more
 *  @return the intervals */
std::vector<LivedTwice> localTimesLivedTwice(const TimeZoneHistory& history, size_t limit = 10000);
