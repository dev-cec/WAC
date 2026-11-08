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
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

int failures = 0, checks = 0;

//! Records one check, printing a failure.
void check(bool ok, const char* what) {
	++checks;
	if (!ok) { ++failures; std::printf("FAIL %s\n", what); }
}

//! The time read at the head of a line: "asWritten|utc", or "-" when none.
std::wstring timeOf(const std::wstring& line) {
	WrittenTime time;
	return leadingTime(line, time) ? time.asWritten + L"|" + time.utc : L"-";
}

void testTimes() {
	check(timeOf(L"2026-11-08 14:03:21.457 Connection from 10.0.0.5") == L"2026-11-08 14:03:21.457|", "ISO without offset: as written, no UTC");
	check(timeOf(L"2026-11-08T14:03:21Z sshd started") == L"2026-11-08T14:03:21Z|2026-11-08T14:03:21Z", "ISO in UTC");
	check(timeOf(L"2026-11-08T14:03:21+01:00 x") == L"2026-11-08T14:03:21+01:00|2026-11-08T13:03:21Z", "an offset is applied");
	check(timeOf(L"2026-01-01 00:30:00-0130 x") == L"2026-01-01 00:30:00-0130|2026-01-01T02:00:00Z", "a negative offset without colon");
	check(timeOf(L"2026-03-01 00:15:00.5+02:00 x") == L"2026-03-01 00:15:00.5+02:00|2026-02-28T22:15:00.5Z", "a day back across a month");
	check(timeOf(L"2026/11/08 14:03:21 [error] 123#456: open() failed") == L"2026/11/08 14:03:21|", "nginx's slashes");
	check(timeOf(L"[2026-11-08 14:03:21,123] INFO x") == L"2026-11-08 14:03:21,123|", "a bracket and a comma before the fraction");
	check(timeOf(L"  <2026.11.08 14:03:21> x") == L"2026.11.08 14:03:21|", "blanks, an angle bracket, dots");
	check(timeOf(L"08/11/2026 14:03:21 x") == L"-", "a day-first or month-first date is not read");
	check(timeOf(L"2026-02-30 10:00:00 x") == L"-", "an impossible day is not a time");
	check(timeOf(L"2026-11-08 24:00:00 x") == L"-", "an impossible hour is not a time");
	check(timeOf(L"2026-11-08 x") == L"-", "a date without a time is not read");
	check(timeOf(L"2026-11-08 14:03:21 -connect") == L"2026-11-08 14:03:21|", "a sign that is no offset ends the time");
	check(timeOf(L"2026-11-08 14:03:21+25:00") == L"2026-11-08 14:03:21|", "an impossible offset is not applied");
	check(timeOf(L"Connection from 10.0.0.5") == L"-", "no time");
	check(timeOf(L"") == L"-", "an empty line");
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

} // namespace

int wmain() {
	testTimes();
	testRecords();
	testFormats();
	testStructured();
	std::printf("%d check(s), %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
