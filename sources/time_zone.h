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
