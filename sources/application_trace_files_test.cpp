/*! \file
 *  \brief The generic conversion of the applications' traces
 *         (application_trace_files.h): the time a log line starts with, the
 *         records of a text, the format of a file, structured content with its
 *         secrets left out.
 *
 *  WHY THIS TEST. A time read wrong still gives a valid JSON: a day-first date
 *  taken for month-first, or a local time written as UTC, sends an event to
 *  another day of the timeline. Each case here has its expected result: the
 *  forms products write, and those that must NOT be read as a time.
 *
 *  Usage: application_trace_files_test — built by `build-windows.sh --test`,
 *  runs under Wine. Exit code: 0 if all checks hold.
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include "application_trace_files.h"
#include "conversions.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

int failures = 0, checks = 0;

//! Records one check, printing a failure.
void check(bool ok, const char* what) {
	++checks;
	if (!ok) { ++failures; std::printf("FAIL %s\n", what); }
}

//! The time read at the head of a line: "asWritten|clock|offset", the clock in
//! ISO 8601 (no zone applied, written with a Z by timeToIso8601Utc), "-" when none.
std::wstring timeOf(const std::wstring& line, const LineLayout& layout = {}) {
	WrittenTime time;
	if (!leadingTime(line, time, layout)) return L"-";
	return time.asWritten + L"|" + timeToIso8601Utc(filetimeFromTicks(time.ticks)) + L"|"
	       + (time.hasOffset ? std::to_wstring(time.offsetMinutes) : std::wstring(L"none"));
}

//! The TimeUtc addRecordTimes writes for a line.
std::wstring utcOf(const std::wstring& line, bool writesUtc) {
	WrittenTime time;
	leadingTime(line, time);
	Json row = Json::obj();
	addRecordTimes(row, time, writesUtc);
	const Json* utc = row.find(L"TimeUtc");
	const Json* assumed = row.find(L"TimeZoneAssumed");
	return (utc ? utc->text() : L"") + L"|" + (assumed ? assumed->text() : L"");
}

void testTimes() {
	check(timeOf(L"2026-11-08 14:03:21.457 Connection from 10.0.0.5") == L"2026-11-08 14:03:21.457|2026-11-08T14:03:21.4570000Z|none",
	      "ISO without offset: its clock, no offset");
	check(timeOf(L"2026-11-08T14:03:21Z sshd started") == L"2026-11-08T14:03:21Z|2026-11-08T14:03:21.0000000Z|0", "ISO in UTC");
	check(timeOf(L"2026-11-08T14:03:21+01:00 x") == L"2026-11-08T14:03:21+01:00|2026-11-08T14:03:21.0000000Z|60", "an offset east");
	check(timeOf(L"2026-01-01 00:30:00-0130 x") == L"2026-01-01 00:30:00-0130|2026-01-01T00:30:00.0000000Z|-90", "a negative offset without colon");
	check(timeOf(L"2026/11/08 14:03:21 [error] 123#456: open() failed") == L"2026/11/08 14:03:21|2026-11-08T14:03:21.0000000Z|none", "nginx's slashes");
	check(timeOf(L"[2026-11-08 14:03:21,123] INFO x") == L"2026-11-08 14:03:21,123|2026-11-08T14:03:21.1230000Z|none", "a bracket and a comma before the fraction");
	check(timeOf(L"  <2026.11.08 14:03:21> x") == L"2026.11.08 14:03:21|2026-11-08T14:03:21.0000000Z|none", "blanks, an angle bracket, dots");
	check(timeOf(L"2026-11-08 14:03:21.123456789 x") == L"2026-11-08 14:03:21.123456789|2026-11-08T14:03:21.1234567Z|none", "nine digits kept to 100 ns");
	check(timeOf(L"10/31/2026 01:04:23:981 NetpDoDomainJoin", { true }) == L"10/31/2026 01:04:23:981|2026-10-31T01:04:23.9810000Z|none",
	      "month first, for a product that declares it, its fraction after a colon");
	check(timeOf(L"10/31/2026 01:04:23:981 NetpDoDomainJoin") == L"-", "month first, for any other product, is not read");
	check(timeOf(L"2026-11-08 14:03:21 x", { true }) == L"-", "a product month first reads no other form");
	// Win32-OpenSSH's sshd.log: the process's identifier, then the local time (measured on Server 2025).
	const LineLayout sshd = { false, true };
	check(timeOf(L"4464 2026-11-10 21:59:57.158 Invalid user wacnobody from 127.0.0.1 port 49802", sshd)
	      == L"2026-11-10 21:59:57.158|2026-11-10T21:59:57.1580000Z|none",
	      "sshd.log: the time after the process's identifier, to the millisecond");
	check(timeOf(L"4464 2026-11-10 21:59:57.158 Invalid user", {}) == L"-",
	      "a process's identifier first is read for the product that writes one only");
	check(timeOf(L"2026-11-08T14:03:21.123+01:00 sshd[42]: x", sshd) == L"2026-11-08T14:03:21.123+01:00|2026-11-08T14:03:21.1230000Z|60",
	      "a product with an identifier first still reads a line that starts with its time");
	check(timeOf(L"4464 started", sshd) == L"-" && timeOf(L"12345678901 2026-11-10 21:59:57 x", sshd) == L"-",
	      "an identifier not followed by a time, or longer than ten digits: no time");
	check(timeOf(L"08/11/2026 14:03:21 x") == L"-", "a day-first or month-first date is not read");
	check(timeOf(L"2026-02-30 10:00:00 x") == L"-", "an impossible day is not a time");
	check(timeOf(L"2026-11-08 24:00:00 x") == L"-", "an impossible hour is not a time");
	check(timeOf(L"2026-11-08 x") == L"-", "a date without a time is not read");
	check(timeOf(L"2026-11-08 14:03:21 -connect") == L"2026-11-08 14:03:21|2026-11-08T14:03:21.0000000Z|none", "a sign that is no offset ends the time");
	check(timeOf(L"2026-11-08 14:03:21+25:00") == L"2026-11-08 14:03:21|2026-11-08T14:03:21.0000000Z|none", "an impossible offset is not applied");
	check(timeOf(L"Connection from 10.0.0.5") == L"-", "no time");
	check(timeOf(L"") == L"-", "an empty line");
	// The instant written: an offset applied, a product writing UTC taken as is.
	check(utcOf(L"2026-11-08T14:03:21.123+01:00 x", false) == L"2026-11-08T13:03:21.123Z|", "an offset east, applied, nothing assumed");
	check(utcOf(L"2026-03-01 00:15:00.5+02:00 x", false) == L"2026-02-28T22:15:00.5Z|", "an offset across a month, the one digit written, none invented");
	check(utcOf(L"2026-01-01 00:30:00-0130 x", false) == L"2026-01-01T02:00:00Z|", "an offset west");
	check(utcOf(L"2026-11-08 14:03:21 x", true) == L"2026-11-08T14:03:21Z|UTC", "a product writing UTC: its clock, said so");
	{
		WrittenTime time;
		leadingTime(L"2026-11-08T14:03:21.123456789Z x", time);
		Json row = Json::obj();
		addRecordTimes(row, time, false);
		const Json* utc = row.find(L"TimeUtc");
		check(utc && utc->text() == L"2026-11-08T14:03:21.1234567Z" && row.find(L"TimePrecisionCut") && row.find(L"TimeAsWritten")
		      && row.find(L"TimeAsWritten")->text() == L"2026-11-08T14:03:21.123456789Z", "past 100 ns: cut, said, the text kept");
		WrittenTime exact;
		leadingTime(L"2026-11-08T14:03:21.1234567Z x", exact);
		Json kept = Json::obj();
		addRecordTimes(kept, exact, false);
		check(!kept.find(L"TimePrecisionCut") && kept.find(L"TimeUtc") && kept.find(L"TimeUtc")->text() == L"2026-11-08T14:03:21.1234567Z",
		      "seven digits: all kept, nothing said");
	}
}

void testRecords() {
	const std::vector<TextRecord> records = textRecords(
		L"header without a time\r\n"
		L"2026-11-08 10:00:00 first\r\n"
		L"   at Module.Function()\r\n"
		L"\r\n"
		L"2026-11-08 10:00:01 second\n"
		L"2026-11-08 10:00:02 third");
	check(records.size() == 4, "four records");
	check(records.size() == 4 && records[0].line == 1 && records[0].time.asWritten.empty() && records[0].text == L"header without a time",
	      "a line before any time is a record of its own");
	check(records.size() == 4 && records[1].line == 2 && records[1].text == L"2026-11-08 10:00:00 first\n   at Module.Function()",
	      "a line without a time continues the dated record before it");
	check(records.size() == 4 && records[2].line == 5 && records[3].line == 6, "blank lines are left out, the numbers kept");
	const std::vector<TextRecord> undated = textRecords(L"a\nb\n");
	check(undated.size() == 2, "lines without any time are records of their own");
	const std::vector<TextRecord> huge = textRecords(std::wstring(TEXT_RECORD_MAX + 10, L'x'));
	check(huge.size() == 1 && huge[0].truncated && huge[0].text.size() == TEXT_RECORD_MAX, "a line past the limit is cut and says so");
	check(textRecords(L"").empty(), "an empty text has no record");
}

void testFormats() {
	check(traceFormatOf(L"Connections_incoming.txt", "2026-11-08 x\r\n") == TraceFormat::Text, "a text log");
	check(traceFormatOf(L"main.db", "SQLite format 3") == TraceFormat::Database, "a database by its extension");
	check(traceFormatOf(L"log.bin", "x") == TraceFormat::Binary, "a binary by its extension");
	check(traceFormatOf(L"ad.trace", std::string("ab\0cd", 5)) == TraceFormat::Binary, "a null byte makes a binary");
	check(traceFormatOf(L"ERRORLOG", std::string("\xFF\xFE" "2\0" "0\0", 6)) == TraceFormat::Text, "UTF-16 with its mark is text");
	check(traceFormatOf(L"sitemanager.xml", "<a/>") == TraceFormat::Xml && traceFormatOf(L"config.json", "{}") == TraceFormat::Json
	      && traceFormatOf(L"WinSCP.ini", "[a]") == TraceFormat::Ini, "structured files by their extension");
	check(traceFormatOf(L"settings.xml", std::string("<a>\0</a>", 8)) == TraceFormat::Binary, "a binary named .xml stays a binary");
}

void testStructured() {
	bool secret = false;
	const Json xml = structuredContent(TraceFormat::Xml,
		L"<FileZilla3><Servers><Server><Host>ftp.example</Host><User>bob</User><Pass encoding=\"base64\">c2VjcmV0</Pass></Server></Servers></FileZilla3>", secret);
	const std::wstring xmlText = xml.dump();
	check(xml.kind() == Json::Kind::Obj && xmlText.find(L"ftp.example") != std::wstring::npos && xmlText.find(L"bob") != std::wstring::npos,
	      "XML: elements and their text");
	check(secret && xmlText.find(L"c2VjcmV0") == std::wstring::npos && xmlText.find(L"\"Pass\"") == std::wstring::npos, "XML: <Pass> left out, said");
	secret = false;
	const Json json = structuredContent(TraceFormat::Json, L"{\"server\":\"h\",\"auth\":{\"password\":\"p\",\"user\":\"u\"},\"list\":[{\"token_secret\":\"t\"}]}", secret);
	const std::wstring jsonText = json.dump();
	check(secret && jsonText.find(L"\"p\"") == std::wstring::npos && jsonText.find(L"\"t\"") == std::wstring::npos
	      && jsonText.find(L"\"u\"") != std::wstring::npos, "JSON: secrets left out at any depth, the rest kept");
	secret = false;
	const Json ini = structuredContent(TraceFormat::Ini, L"[Sessions\\bob]\r\nHostName=h\r\nPassword=enc\r\nPortNumber=22\r\n", secret);
	const std::wstring iniText = ini.dump();
	check(secret && iniText.find(L"enc") == std::wstring::npos && iniText.find(L"PortNumber") != std::wstring::npos, "INI: a password value left out");
	secret = false;
	check(structuredContent(TraceFormat::Json, L"{\"a\":", secret).kind() == Json::Kind::Null, "a malformed JSON is no content");
	check(structuredContent(TraceFormat::Xml, L"<a><b></a>", secret).kind() == Json::Kind::Null
	      || structuredContent(TraceFormat::Xml, L"<a><b></a>", secret).kind() == Json::Kind::Obj, "a malformed XML is refused or read, never thrown");
}

/*! End to end: a log line written in the zone of the installation (Pacific,
 *  UTC-7), read on a machine set to Paris since — the NetSetup.LOG of
 *  Server 2025. Its System log shows the change; the line takes the offset in
 *  force when it was written, and says it. */
void testZoneInForce() {
	TimeZoneRules paris;
	paris.current.biasMinutes = -60;
	paris.current.daylightBiasMinutes = -60;
	paris.current.standardDate = SYSTEMTIME{ 0, 10, 0, 5, 3, 0, 0, 0 };
	paris.current.daylightDate = SYSTEMTIME{ 0, 3, 0, 5, 2, 0, 0, 0 };
	auto at = [](WORD day, WORD hour, WORD minute, WORD second) {
		SYSTEMTIME st = { 2026, 10, 0, day, hour, minute, second, 0 };
		FILETIME ft = {};
		SystemTimeToFileTime(&st, &ft);
		return (long long)ticksFromFiletime(ft);
	};
	conf.timeZone = TimeZoneInfo{};
	conf.timeZone.valid = true;
	conf.timeZone.rules = paris;
	conf.timeZone.history = timeZoneHistoryFrom({ { 1, at(31, 8, 4, 5), 420 }, { 2, at(31, 8, 5, 11), -60 } }, at(31, 23, 0, 0));
	WrittenTime time;
	leadingTime(L"2026-10-31 01:04:24.014 NetpDoDomainJoin", time);
	Json row = Json::obj();
	addRecordTimes(row, time, false);
	const Json* utc = row.find(L"TimeUtc");
	const Json* local = row.find(L"Time");
	const Json* inForce = row.find(L"TimeZoneInForce");
	check(utc && utc->text() == L"2026-10-31T08:04:24.014Z", "a line written at UTC-7, the zone then: its instant");
	check(local && local->text() == L"2026-10-31T09:04:24.014+01:00", "its Time in the current zone, as every date");
	check(inForce && inForce->text() == L"-07:00", "the offset of the zone in force then, said");
	WrittenTime later;
	leadingTime(L"2026-10-31 12:00:00 x", later);
	Json now = Json::obj();
	addRecordTimes(now, later, false);
	check(!now.find(L"TimeZoneInForce") && now.find(L"TimeUtc") && now.find(L"TimeUtc")->text() == L"2026-10-31T11:00:00Z",
	      "after the change: the current zone, nothing said");
	conf.timeZone = TimeZoneInfo{};
}

} // namespace

int wmain() {
	testTimes();
	testRecords();
	testFormats();
	testStructured();
	testZoneInForce();
	std::printf("%d check(s), %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
