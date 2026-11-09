/*! \file
 *  \brief Implementation of the daylight saving rules (see time_zone.h).
 *
 *  The calendar arithmetic (day of the week, length of a month) is done by
 *  SystemTimeToFileTime and FileTimeToSystemTime: pure computations of
 *  kernel32, which consult no time zone.
 */
#include "time_zone.h"
#include "conversions.h"
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <climits>
#include <iterator>

namespace {

const long long MINUTE_100NS = 600000000LL;   //!< one minute, in hundreds of nanoseconds
const size_t TZI_SIZE = 44;                   //!< size of REG_TZI_FORMAT: 3 LONG + 2 SYSTEMTIME
/*! Largest offset accepted, in minutes: real zones stay within ±14 h. A
 *  larger one comes from a forged hive, and would make the tick arithmetic
 *  overflow. */
const long MAX_OFFSET_MINUTES = 24 * 60;
//! Instants beyond this margin of the range are not adjusted: the sums could overflow.
const long long SAFE_MARGIN_100NS = 4LL * MAX_OFFSET_MINUTES * MINUTE_100NS;
//! Longest delay between a change of offset and the record that logs it, accepted as the same change.
const long long LOGGED_CHANGE_DELAY_100NS = 10000000LL;

//! 100 ns count of a SYSTEMTIME, or false if it is not a valid date.
bool toTicks(const SYSTEMTIME& st, long long& ticks) {
	FILETIME ft = { 0, 0 };
	if (!SystemTimeToFileTime(&st, &ft)) return false;
	ticks = (long long)(ticksFromFiletime(ft));
	return true;
}

//! Calendar year of a 100 ns count, or 0 if it is out of range.
int yearOf(long long ticks) {
	if (ticks < 0) return 0;
	const FILETIME ft = filetimeFromTicks(ticks);
	SYSTEMTIME st = {};
	if (!FileTimeToSystemTime(&ft, &st)) return 0;
	return st.wYear;
}

//! True for the transition "January, first week, 00:00": a change of rule at the new year.
bool newYearMarker(const SYSTEMTIME& rule) {
	return rule.wYear == 0 && rule.wMonth == 1 && rule.wDay == 1 && rule.wHour == 0
	    && rule.wMinute == 0 && rule.wSecond == 0 && rule.wMilliseconds == 0;
}

/*! Local wall-clock time of a transition in a given year.
 *  A transition is either "the n-th <weekday> of <month>" (wYear 0; wDay 5
 *  means the last), or a fixed day of the month (wYear set). The new-year
 *  marker is 1 January at 00:00 whatever its weekday: Windows' Dynamic DST
 *  entries write it with the weekday of 1 January of THEIR year, and Windows
 *  applies it to 1 January of every year the entry covers (measured: the
 *  2004 entry of "Central Brazilian Standard Time", "first Thursday of
 *  January", ends daylight time on Friday 1 January 1993).
 *  @param rule the transition date of the rule
 *  @param year the year wanted
 *  @param ticks receives the local wall-clock time
 *  @return false if the transition is impossible (hostile or empty rule) */
bool transition(const SYSTEMTIME& rule, int year, long long& ticks) {
	if (rule.wMonth < 1 || rule.wMonth > 12 || rule.wHour > 23 || rule.wMinute > 59
	    || rule.wSecond > 59 || rule.wMilliseconds > 999) return false;
	SYSTEMTIME st = {};
	st.wYear = (WORD)year;
	st.wMonth = rule.wMonth;
	st.wHour = rule.wHour;
	st.wMinute = rule.wMinute;
	st.wSecond = rule.wSecond;
	st.wMilliseconds = rule.wMilliseconds;
	if (rule.wYear != 0 || newYearMarker(rule)) {
		st.wDay = newYearMarker(rule) ? 1 : rule.wDay;
		return toTicks(st, ticks);
	}
	if (rule.wDayOfWeek > 6 || rule.wDay < 1 || rule.wDay > 5) return false;
	// Day of the week of the 1st of the month, then the n-th occurrence.
	st.wDay = 1;
	long long first = 0;
	if (!toTicks(st, first)) return false;
	const FILETIME ft = filetimeFromTicks(first);
	SYSTEMTIME firstDay = {};
	if (!FileTimeToSystemTime(&ft, &firstDay)) return false;
	st.wDay = (WORD)(1 + (rule.wDayOfWeek + 7 - firstDay.wDayOfWeek) % 7 + (rule.wDay - 1) * 7);
	// The 5th occurrence may not exist: "the last" is then the 4th.
	if (toTicks(st, ticks)) return true;
	st.wDay -= 7;
	return toTicks(st, ticks);
}

//! The two transitions of a rule in a year, local; false if the rule has no daylight saving time.
bool transitions(const TimeZoneRule& r, int year, long long& daylightStart, long long& standardStart) {
	if (r.standardDate.wMonth == 0 || r.daylightDate.wMonth == 0) return false;
	return transition(r.daylightDate, year, daylightStart)
	    && transition(r.standardDate, year, standardStart);
}

//! Bias in force at the end of a year: daylight time if its last transition starts it.
long endOfYearBias(const TimeZoneRules& rules, int year) {
	const TimeZoneRule& r = rules.forYear(year);
	long long daylightStart = 0, standardStart = 0;
	if (!transitions(r, year, daylightStart, standardStart) || daylightStart <= standardStart)
		return r.biasMinutes + r.standardBiasMinutes;
	return r.biasMinutes + r.daylightBiasMinutes;
}

/*! UTC instant at which a year begins in the zone: 1 January 00:00 on the
 *  clock of the previous year, whose offset may differ from this year's rule. */
long long yearStartUtc(const TimeZoneRules& rules, int year) {
	SYSTEMTIME st = {};
	st.wYear = (WORD)year; st.wMonth = 1; st.wDay = 1;
	long long ticks = 0;
	if (!toTicks(st, ticks)) return year < 1601 ? LLONG_MIN : LLONG_MAX;
	return ticks + endOfYearBias(rules, year - 1) * MINUTE_100NS;
}

/*! Bias of a year's rule at a UTC instant of that year.
 *  A transition happens at its wall-clock time, read at the offset in force
 *  just BEFORE it: standard time for the start of daylight time, daylight time
 *  for its end — and, for the new-year marker, the previous year's offset
 *  (a zone at UTC+3 until 31 December moving to "UTC+2 with daylight time from
 *  1 January" changes nothing at midnight). */
long biasInYear(const TimeZoneRules& rules, int year, long long utc100ns) {
	const TimeZoneRule& r = rules.forYear(year);
	const long standard = r.biasMinutes + r.standardBiasMinutes;
	const long daylight = r.biasMinutes + r.daylightBiasMinutes;
	long long daylightStart = 0, standardStart = 0;
	if (!transitions(r, year, daylightStart, standardStart)) return standard;
	const long long start = yearStartUtc(rules, year);
	const long long daylightStartUtc = newYearMarker(r.daylightDate) ? start : daylightStart + standard * MINUTE_100NS;
	const long long standardStartUtc = newYearMarker(r.standardDate) ? start : standardStart + daylight * MINUTE_100NS;
	const bool inDaylight = daylightStartUtc < standardStartUtc
		? utc100ns >= daylightStartUtc && utc100ns < standardStartUtc      // northern hemisphere
		: !(utc100ns >= standardStartUtc && utc100ns < daylightStartUtc);  // southern: over the new year
	return inDaylight ? daylight : standard;
}

} // namespace

const TimeZoneRule& TimeZoneRules::forYear(int year) const {
	if (byYear.empty()) return current;
	if (year <= byYear.begin()->first) return byYear.begin()->second;
	if (year >= byYear.rbegin()->first) return byYear.rbegin()->second;
	// A gap in the years takes the rule of the closest earlier year.
	return std::prev(byYear.upper_bound(year))->second;
}

bool parseTimeZoneRule(const BYTE* data, size_t size, TimeZoneRule& rule) {
	if (!data || size != TZI_SIZE) return false;
	int32_t bias[3];
	std::memcpy(bias, data, sizeof(bias));
	for (int32_t b : { bias[0], bias[1], bias[2], bias[0] + bias[1], bias[0] + bias[2] })
		if (b > MAX_OFFSET_MINUTES || b < -MAX_OFFSET_MINUTES) return false;
	rule.biasMinutes = bias[0];
	rule.standardBiasMinutes = bias[1];
	rule.daylightBiasMinutes = bias[2];
	std::memcpy(&rule.standardDate, data + 12, sizeof(SYSTEMTIME));
	std::memcpy(&rule.daylightDate, data + 28, sizeof(SYSTEMTIME));
	return true;
}

namespace {

//! SYSTEMTIME of the kernel's TIME_FIELDS: the same fields, the weekday last instead of third.
SYSTEMTIME fromTimeFields(const BYTE (&bytes)[16]) {
	WORD f[8];
	std::memcpy(f, bytes, sizeof(f));
	SYSTEMTIME st = {};
	st.wYear = f[0];
	st.wMonth = f[1];
	st.wDay = f[2];
	st.wHour = f[3];
	st.wMinute = f[4];
	st.wSecond = f[5];
	st.wMilliseconds = f[6];
	st.wDayOfWeek = f[7];
	return st;
}

} // namespace

bool parseTimeZoneInformation(int32_t bias, int32_t standardBias, int32_t daylightBias,
                              const BYTE (&standardStart)[16], const BYTE (&daylightStart)[16],
                              TimeZoneRule& rule) {
	// Through the registry layout of a rule, to share its validation.
	BYTE tzi[TZI_SIZE] = {};
	const int32_t biases[3] = { bias, standardBias, daylightBias };
	const SYSTEMTIME standardDate = fromTimeFields(standardStart), daylightDate = fromTimeFields(daylightStart);
	std::memcpy(tzi, biases, sizeof(biases));
	std::memcpy(tzi + 12, &standardDate, sizeof(SYSTEMTIME));
	std::memcpy(tzi + 28, &daylightDate, sizeof(SYSTEMTIME));
	return parseTimeZoneRule(tzi, sizeof(tzi), rule);
}

long biasAtUtc(const TimeZoneRules& rules, long long utc100ns) {
	/* The year is the one the zone's clock shows: it begins at 1 January
	   00:00 local, read at the offset of the end of the previous year. */
	int year = yearOf(utc100ns);
	if (year == 0 || utc100ns > LLONG_MAX - SAFE_MARGIN_100NS)
		return rules.current.biasMinutes + rules.current.standardBiasMinutes;
	if (utc100ns < yearStartUtc(rules, year)) --year;
	else if (utc100ns >= yearStartUtc(rules, year + 1)) ++year;
	return biasInYear(rules, year, utc100ns);
}

long biasAtLocal(const TimeZoneRules& rules, long long local100ns) {
	/* A local time L is the UTC instant L + b for a bias b that the zone has
	   at that instant. The candidates are the offsets of the year's rule and
	   the offset of the end of the previous year; Windows keeps:
	   - the consistent one if there is only one (an ordinary time);
	   - the smallest if several are (the hour repeated in autumn: its first
	     occurrence);
	   - if none is (the hour skipped in spring), the offset in force BEFORE
	     the change, which is the bias at L + the smallest candidate — except
	     for an hour skipped by a new-year marker, where the local time
	     belongs to the new year and takes its rule (measured on "Volgograd
	     Standard Time", 1 January 2020). A change of rule WITHOUT a marker
	     keeps the old offset ("Samoa Standard Time", 1 January 2012). */
	const int year = yearOf(local100ns);
	if (year == 0 || local100ns > LLONG_MAX - SAFE_MARGIN_100NS)
		return rules.current.biasMinutes + rules.current.standardBiasMinutes;
	const TimeZoneRule& r = rules.forYear(year);
	long candidates[3] = { r.biasMinutes + r.standardBiasMinutes, r.biasMinutes + r.daylightBiasMinutes,
	                       endOfYearBias(rules, year - 1) };
	std::sort(candidates, candidates + 3);
	for (long b : candidates)
		if (biasAtUtc(rules, local100ns + b * MINUTE_100NS) == b) return b;
	const long long start = yearStartUtc(rules, year);
	if ((newYearMarker(r.daylightDate) || newYearMarker(r.standardDate))
	    && start > local100ns + candidates[0] * MINUTE_100NS && start <= local100ns + candidates[2] * MINUTE_100NS)
		return biasInYear(rules, year, start);
	return biasAtUtc(rules, local100ns + candidates[0] * MINUTE_100NS);
}

TimeZoneHistory timeZoneHistoryFrom(std::vector<LoggedBias> logged, long long endUtc100ns) {
	std::sort(logged.begin(), logged.end(),
	          [](const LoggedBias& a, const LoggedBias& b) { return a.recordId < b.recordId; });
	TimeZoneHistory history;
	history.endUtc100ns = endUtc100ns;
	long long latest = LLONG_MIN;
	for (const LoggedBias& b : logged) {
		// A forged offset is no offset; a time set back is no instant (see time_zone.h).
		if (b.biasMinutes > MAX_OFFSET_MINUTES || b.biasMinutes < -MAX_OFFSET_MINUTES) continue;
		if (b.utc100ns < latest || b.utc100ns > endUtc100ns) continue;
		latest = b.utc100ns;
		if (!history.changes.empty() && history.changes.back().biasMinutes == b.biasMinutes) continue;
		history.changes.push_back(b);
	}
	return history;
}

LocalBias biasAtLocalLogged(const TimeZoneRules& rules, const TimeZoneHistory& history, long long local100ns) {
	const LocalBias byRules{ biasAtLocal(rules, local100ns), false };
	const std::vector<LoggedBias>& changes = history.changes;
	if (changes.empty() || local100ns < LLONG_MIN + SAFE_MARGIN_100NS || local100ns > LLONG_MAX - SAFE_MARGIN_100NS)
		return byRules;
	// Stretch i: from changes[i] to changes[i + 1], the last one to the end of the log.
	auto end = [&](size_t i) { return i + 1 < changes.size() ? changes[i + 1].utc100ns : history.endUtc100ns; };
	auto utcIn = [&](size_t i) { return local100ns + changes[i].biasMinutes * MINUTE_100NS; };
	// The offset the log shows at a UTC instant, false outside the log.
	auto loggedAt = [&](long long utc, long& bias) {
		if (utc < changes.front().utc100ns || utc >= history.endUtc100ns) return false;
		const auto next = std::upper_bound(changes.begin(), changes.end(), utc,
		                                   [](long long u, const LoggedBias& b) { return u < b.utc100ns; });
		bias = std::prev(next)->biasMinutes;
		return true;
	};
	bool found = false;
	long chosen = 0;
	for (size_t i = 0; i < changes.size(); ++i) {
		const long long utc = utcIn(i);
		if (utc >= changes[i].utc100ns && utc < end(i) && (!found || changes[i].biasMinutes < chosen)) {
			chosen = changes[i].biasMinutes;
			found = true;
		}
	}
	if (found) return LocalBias{ chosen, chosen != byRules.biasMinutes };
	/* No stretch holds L. The rules confirmed by the log within a second: Windows
	   writes its change a moment after making it (0.68 ms measured at the return
	   to winter time), and in spring the first local times after the change
	   would otherwise read as skipped. */
	const long long byRulesUtc = local100ns + byRules.biasMinutes * MINUTE_100NS;
	long logged = 0;
	if ((loggedAt(byRulesUtc - LOGGED_CHANGE_DELAY_100NS, logged) && logged == byRules.biasMinutes)
	    || (loggedAt(byRulesUtc + LOGGED_CHANGE_DELAY_100NS, logged) && logged == byRules.biasMinutes))
		return byRules;
	// An hour skipped between two stretches: L is past the first, before the second.
	for (size_t i = 0; !found && i + 1 < changes.size(); ++i)
		if (utcIn(i) >= end(i) && utcIn(i + 1) < changes[i + 1].utc100ns) { chosen = changes[i].biasMinutes; found = true; }
	// Before the first offset logged, or past the end of the log: nothing known, the rules.
	if (!found) return byRules;
	return LocalBias{ chosen, chosen != byRules.biasMinutes };
}
