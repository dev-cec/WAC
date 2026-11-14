/*! \file
 *  \brief The ISO 8601 writing of dates at the edges of the format
 *         (tools.h: timeToIso8601Utc, addDate) — backlog B-080.
 *
 *  WHY THIS TEST. The largest FILETIME, Windows' "never" (an IE cache entry
 *  that does not expire), is year 30828: the four-digit writing kept "0828",
 *  a date valid in appearance and 29 000 years off, which web_client.json
 *  carried on Windows 11 (2026-11-14). The last instant of 9999 is still a
 *  date; the first of 10000 is not one ISO 8601 can say.
 *
 *  Usage: iso8601_dates_test — built by `build-windows.sh --test`, runs
 *  under Wine. Exit code: 0 if all checks hold.
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include "json.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

int failures = 0;

void check(bool condition, const char* what) {
	if (!condition) {
		std::printf("FAILED: %s\n", what);
		++failures;
	}
}

FILETIME fromTicks(unsigned long long ticks) {
	return FILETIME{ (DWORD)ticks, (DWORD)(ticks >> 32) };
}

//! 9999-12-31T23:59:59Z and the second after it, in 100-ns ticks since 1601.
const unsigned long long LAST_SECOND_OF_9999 = 2650467743990000000ULL;
const unsigned long long FIRST_SECOND_OF_10000 = LAST_SECOND_OF_9999 + 10000000ULL;
const unsigned long long NEVER = 0x7FFFFFFFFFFFFFFFULL;

}  // namespace

int wmain() {
	check(timeToIso8601Utc(fromTicks(LAST_SECOND_OF_9999), Precision::Second) == L"9999-12-31T23:59:59Z",
	      "the last second of 9999 is written");
	check(timeToIso8601Utc(fromTicks(FIRST_SECOND_OF_10000)).empty(), "the first second of 10000 is not written");
	check(timeToIso8601Utc(fromTicks(NEVER)).empty(), "the largest FILETIME is not written as year 0828");

	Json never = Json::obj();
	addDate(never, L"Expiry", fromTicks(NEVER));
	check(never.dump().find(L"\"ExpiryNever\": true") != std::wstring::npos, "never is said");
	check(never.dump().find(L"0828") == std::wstring::npos && never.dump().find(L"ExpiryUtc") == std::wstring::npos,
	      "no date is written for never");

	Json real = Json::obj();
	addDate(real, L"Expiry", fromTicks(LAST_SECOND_OF_9999));
	check(real.dump().find(L"\"ExpiryUtc\": \"9999-12-31T23:59:59") != std::wstring::npos, "a real date stays a date");

	std::printf(failures ? "%d check(s) failed\n" : "all checks hold\n", failures);
	return failures ? 1 : 0;
}
