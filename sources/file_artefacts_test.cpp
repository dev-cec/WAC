/*! \file
 *  \brief Checks the decoders of the small file artefacts on inputs whose
 *  result is known: PowerShell history, setupapi.dev.log, recycle bin `$I`,
 *  hosts, Report.wer, Defender's MPLog, Zone.Identifier.
 *
 *  WHY THIS TEST. These formats are text or a few bytes, and a decoder that
 *  misses a case still gives valid JSON: a multi-line command cut in two, a
 *  section without its end, a `$I` path read past the file. Each case is
 *  written here from the format's description, with what must come out, and
 *  the hostile ones — a `$I` truncated, a length that lies — must be refused
 *  or bounded, never read beyond the bytes given.
 *
 *  Usage (runs under wine): file_artefacts_test.exe
 */
#include "powershell_history.h"
#include "setupapi_log.h"
#include "recycle_bin.h"
#include "hosts_file.h"
#include "error_reports.h"
#include "defender_log.h"
#include "zone_identifiers.h"
#include <cstdio>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const char* what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::printf("  FAILED  %s\n", what);
}

//! A FILETIME as one 64-bit number.
unsigned long long value(const FILETIME& f) { return ((unsigned long long)f.dwHighDateTime << 32) | f.dwLowDateTime; }

//! Appends a 64-bit little-endian value.
void put64(std::vector<uint8_t>& b, uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back((uint8_t)(v >> (8 * i))); }

//! Appends a UTF-16LE text, without its terminating zero.
void putWide(std::vector<uint8_t>& b, const std::wstring& s) {
	for (wchar_t c : s) { b.push_back((uint8_t)(c & 0xFF)); b.push_back((uint8_t)(c >> 8)); }
}

void powershell() {
	const std::vector<PowerShellCommand> c = parsePowerShellHistory(
		L"whoami\r\n\r\nGet-Process |`\r\n  Where-Object CPU -gt 10\r\nInvoke-WebRequest http://x/a.ps1`");
	check(c.size() == 3, "powershell: 3 commands, the blank line not one");
	check(c.size() == 3 && c[0].command == L"whoami" && c[0].number == 1 && c[0].line == 1, "powershell: first command");
	check(c.size() == 3 && c[1].command == L"Get-Process |`\n  Where-Object CPU -gt 10" && c[1].line == 3,
	      "powershell: a command continued by a backtick joined, its first line kept");
	check(c.size() == 3 && c[2].command == L"Invoke-WebRequest http://x/a.ps1`" && c[2].number == 3,
	      "powershell: a last command left open is still a command");
	check(parsePowerShellHistory(L"").empty(), "powershell: an empty file has no command");
}

void setupapi() {
	const std::vector<SetupApiSection> s = parseSetupApiLog(
		L"[Device Install Log]\r\n"
		L">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5567\\4C530001]\r\n"
		L">>>  Section start 2023/05/12 10:11:12.345\r\n"
		L"     dvi: ...\r\n"
		L"<<<  Section end 2023/05/12 10:11:13.456\r\n"
		L"<<<  [Exit status: SUCCESS]\r\n"
		L">>>  [Setup Import Driver Package]\r\n"
		L">>>  Section start 2023/02/31 00:00:00.000\r\n", L"C:\\Windows\\INF\\setupapi.dev.log");
	check(s.size() == 2, "setupapi: 2 sections");
	if (s.size() == 2) {
		check(s[0].operation == L"Device Install (Hardware initiated)" && s[0].subject == L"USB\\VID_0781&PID_5567\\4C530001",
		      "setupapi: operation and subject split at \" - \"");
		check(s[0].line == 2 && s[0].exitStatus == L"SUCCESS", "setupapi: line and exit status");
		FILETIME expected;
		check(parseSetupApiDate(L"2023/05/12 10:11:12.345", expected) && value(s[0].startLocal) == value(expected),
		      "setupapi: start date read");
		check(value(s[0].endLocal) - value(s[0].startLocal) == 11110000ULL, "setupapi: end 1.111 s after the start");
		check(s[1].operation == L"Setup Import Driver Package" && s[1].subject.empty(), "setupapi: a title without a subject");
		check(value(s[1].startLocal) == 0, "setupapi: 31 February is not a date");
	}
	FILETIME f;
	check(!parseSetupApiDate(L"2023-05-12 10:11:12", f) && !parseSetupApiDate(L"2023/05/1", f), "setupapi: malformed dates refused");
}

void recycleBin() {
	const uint64_t deleted = 133280000000000000ULL;
	// Version 2, "C:\Users\a\evil.exe" (19 characters + the zero).
	std::vector<uint8_t> v2;
	put64(v2, 2); put64(v2, 12345); put64(v2, deleted);
	v2.push_back(20); v2.push_back(0); v2.push_back(0); v2.push_back(0);
	putWide(v2, L"C:\\Users\\a\\evil.exe"); v2.push_back(0); v2.push_back(0);
	RecycledFile r;
	check(parseRecycleBinIndex(v2, r) && r.version == 2 && r.size == 12345 && value(r.deletedUtc) == deleted
	      && r.originalPath == L"C:\\Users\\a\\evil.exe", "recycle bin: version 2 read");
	// A length that lies: 10,000 characters announced, the file holds 19. Bounded by the file.
	std::vector<uint8_t> lying = v2;
	lying[24] = 0x10; lying[25] = 0x27;
	RecycledFile l;
	check(parseRecycleBinIndex(lying, l) && l.originalPath == L"C:\\Users\\a\\evil.exe", "recycle bin: announced length bounded by the file");
	// Version 1: 520 bytes of path, zero-padded.
	std::vector<uint8_t> v1;
	put64(v1, 1); put64(v1, 7); put64(v1, deleted);
	putWide(v1, L"D:\\doc.txt");
	v1.resize(24 + 520, 0);
	RecycledFile o;
	check(parseRecycleBinIndex(v1, o) && o.version == 1 && o.originalPath == L"D:\\doc.txt", "recycle bin: version 1 read");
	// Truncated, unknown version: refused.
	RecycledFile t;
	check(!parseRecycleBinIndex(std::vector<uint8_t>(v1.begin(), v1.begin() + 100), t), "recycle bin: truncated version 1 refused");
	check(!parseRecycleBinIndex(std::vector<uint8_t>(v2.begin(), v2.begin() + 20), t), "recycle bin: truncated header refused");
	std::vector<uint8_t> v3 = v2; v3[0] = 3;
	check(!parseRecycleBinIndex(v3, t), "recycle bin: unknown version refused");
}

void hosts() {
	const std::vector<HostsEntry> e = parseHostsFile(
		L"# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n\r\n"
		L"127.0.0.1\tupdate.vendor.com   av.vendor.com # blocked\r\n"
		L"  10.1.2.3 intranet\r\n   # 1.2.3.4 commented\r\n");
	check(e.size() == 2, "hosts: 2 entries, comments and blank lines left out");
	check(e.size() == 2 && e[0].address == L"127.0.0.1" && e[0].names.size() == 2 && e[0].names[1] == L"av.vendor.com"
	      && e[0].line == 4, "hosts: address, names separated by tabs and spaces, the comment cut");
	check(e.size() == 2 && e[1].address == L"10.1.2.3" && e[1].line == 5, "hosts: leading blanks");
}

void errorReport() {
	ErrorReport r;
	check(parseErrorReport(L"Version=1\r\nEventType=APPCRASH\r\nEventTime=133280000000000000\r\n"
	                       L"Sig[1].Name=Application Version\r\nSig[0].Name=Application Name\r\n"
	                       L"Sig[0].Value=evil.exe\r\nSig[1].Value=1.0.0.0\r\nAppPath=C:\\Temp\\evil.exe\r\n", r),
	      "error report: read");
	check(value(r.eventTimeUtc) == 133280000000000000ULL, "error report: EventTime, a decimal FILETIME");
	check(r.signature.size() == 2 && r.signature[0].first == L"Application Name" && r.signature[0].second == L"evil.exe"
	      && r.signature[1].second == L"1.0.0.0", "error report: signature ordered by index, whatever the file's order");
	check(r.values.size() == 8, "error report: every value kept");
	ErrorReport bad;
	check(!parseErrorReport(L"not a report\r\n", bad), "error report: no Key=Value refused");
	ErrorReport date;
	parseErrorReport(L"EventTime=12x4\r\n", date);
	check(value(date.eventTimeUtc) == 0, "error report: a non-numeric EventTime is not a date");
}

void defender() {
	const std::vector<DefenderLogLine> l = parseDefenderLog(
		L"2023-05-12T10:11:12.345Z Engine:Detected threat\r\n\r\nno date here  \r\n2023-05-12T10:11:13Z done\r\n");
	check(l.size() == 3, "defender: 3 lines, the blank one left out");
	FILETIME expected;
	check(l.size() == 3 && iso8601UtcToFiletime(L"2023-05-12T10:11:12.345Z", expected) && value(l[0].timeUtc) == value(expected),
	      "defender: date with milliseconds read");
	check(l.size() == 3 && value(l[1].timeUtc) == 0 && l[1].text == L"no date here" && l[1].line == 3,
	      "defender: a line without a date kept, trailing blanks removed");
	check(l.size() == 3 && value(l[2].timeUtc) != 0, "defender: date without fraction read");
	FILETIME f;
	check(!parseDefenderDate(L"2023-05-12T10:11:12.345 local", f), "defender: a date without Z is not taken");
}

void zoneIdentifier() {
	ZoneIdentifier z;
	check(parseZoneIdentifier("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a.invalid/\r\nHostUrl=https://a.invalid/x.exe\r\n", z)
	      && z.values.size() == 3 && z.values[0].first == L"ZoneId" && z.values[0].second == L"3"
	      && z.values[2].second == L"https://a.invalid/x.exe", "zone identifier: section header skipped, three values");
	ZoneIdentifier w;
	std::string wide("\xFF\xFE", 2);
	for (char c : std::string("[ZoneTransfer]\r\nZoneId=4\r\n")) { wide += c; wide += '\0'; }
	check(parseZoneIdentifier(wide, w) && w.values.size() == 1 && w.values[0].second == L"4", "zone identifier: UTF-16 content read");
	ZoneIdentifier e;
	check(!parseZoneIdentifier("[ZoneTransfer]\r\n", e), "zone identifier: a header alone is refused");
	check(zoneName(L"3") == L"Internet" && zoneName(L"0") == L"Local machine" && zoneName(L"7").empty() && zoneName(L"31").empty(),
	      "zone identifier: zone names, unknown ones empty");
}

} // namespace

int wmain() {
	powershell();
	setupapi();
	recycleBin();
	hosts();
	errorReport();
	defender();
	zoneIdentifier();
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
