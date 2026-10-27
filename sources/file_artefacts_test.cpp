/*! \file
 *  \brief Checks the decoders of the small file artefacts on inputs whose
 *  result is known: PowerShell history, setupapi.dev.log, recycle bin `$I`,
 *  hosts, Report.wer, Defender's MPLog, DetectionHistory and quarantine,
 *  Zone.Identifier, and the registry values of the second lot (TrustRecords,
 *  firewall rules, certificate Blob), the NTFS security descriptors of
 *  $Secure:$SDS, the NTFS boot sector and change journal header, and the
 *  volume serial of a shortcut, the DPAPI master key header and Preferred,
 *  the paths of User Shell Folders, and the reading of an SQLite database
 *  on a private copy, its write-ahead log replayed, a Chromium History and
 *  Firefox's places and form history.
 *
 *  Usage (runs under wine): file_artefacts_test.exe — every check;
 *  file_artefacts_test.exe --bmc <bcache22.bmc> [folder] — the tiles WAC
 *  decodes in a bitmap cache of the test VM, for bmc-tools to be confronted
 *  with, and written as images in the folder if one is given.
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
#include "firewall_log.h"
#include "boot_records.h"
#include "intune_logs.h"
#include "recycle_bin.h"
#include "hosts_file.h"
#include "reg_shimcache.h"
#include "error_reports.h"
#include "defender_history.h"
#include "defender_log.h"
#include "zone_identifiers.h"
#include "registry_lot2.h"
#include "security_descriptors.h"
#include "ntfs_volumes.h"
#include "recent_docs.h"
#include "dpapi_master_keys.h"
#include "user_shell_folders.h"
#include "sqlite_reader.h"
#include "web_client.h"
#include "search_index.h"
#include "rdp_client.h"
#include "rdp_server.h"
#include "thumbcache.h"
#include "reg_amcache.h"
#include "events.h"
#include "evt.h"
#include "scheduledTasks.h"
#include "reg_userassists.h"
#include "xml_light.h"
#include "oleparser.h"
#include "emails.h"
#include "mbox_mail.h"
#include "wevt.h"
#include "conversions.h"
#include "prefetchs.h"
#include "conversions.h"
#include "registry_common.h"
#include "sqlite3.h"
#include "sha.h"
#include <filesystem>
#include <fstream>
#include "guard_page.h"
#include <cstdio>
#include <cstring>
#include <cwchar>

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

void firewallLog() {
	/* The header Windows 11 writes (pid added since Windows 10), a dropped
	   inbound connection behind the zeros Windows leaves where it reopened
	   the file, and an allowed outbound one; a line before the header, and a
	   field without value. The zeros go in by length: a literal stops at them. */
	const std::wstring text = std::wstring(
		L"stray line\r\n"
		L"#Version: 1.5\r\n#Software: Microsoft Windows Firewall\r\n#Time Format: Local\r\n"
		L"#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid\r\n"
		L"\r\n") + std::wstring(4, L'\0') +
		L"2026-10-24 15:01:02 DROP TCP 192.168.1.20 192.168.1.10 51234 445 52 S 1234567 0 64240 - - - RECEIVE 4\r\n"
		L"2026-10-24 15:01:03 ALLOW UDP 192.168.1.10 8.8.8.8 60000 53 0 - - - - - - - SEND 1312\r\n"
		L"2026-02-31 00:00:00 ALLOW TCP 10.0.0.1 10.0.0.2 1 2 0 - - - - - - - SEND 1\r\n";
	const std::vector<FirewallLogEntry> e = parseFirewallLog(text,
		L"C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log");
	check(e.size() == 3, "firewall log: 3 lines after the header, the line before it skipped");
	if (e.size() != 3) return;
	auto field = [](const FirewallLogEntry& x, const wchar_t* key) {
		for (const auto& [k, v] : x.fields) if (k == key) return v;
		return std::wstring();
	};
	FILETIME expected;
	check(iso8601UtcToFiletime(L"2026-10-24T15:01:02Z", expected) && value(e[0].timeLocal) == value(expected) && e[0].timeAsStored.empty(),
	      "firewall log: local date and time read, behind the zeros Windows left before them");
	check(e[0].line == 7 && e[1].line == 8, "firewall log: lines counted from 1, the empty one included");
	check(field(e[0], L"Action") == L"DROP" && field(e[0], L"SourceAddress") == L"192.168.1.20"
	      && field(e[0], L"DestinationPort") == L"445" && field(e[0], L"Direction") == L"RECEIVE" && field(e[0], L"ProcessId") == L"4",
	      "firewall log: the fields named by #Fields:");
	check(field(e[1], L"TcpFlags").empty() && e[1].fields.size() == 9, "firewall log: a \"-\" left out");
	check(value(e[2].timeLocal) == 0 && e[2].timeAsStored == L"2026-02-31 00:00:00", "firewall log: an impossible date given as stored");
	check(parseFirewallLog(L"2026-10-24 15:01:02 DROP TCP\r\n", L"x").empty(), "firewall log: no line without a #Fields: header");
}

void partitionTables() {
	auto put32 = [](std::vector<uint8_t>& b, size_t at, uint32_t v) { for (int i = 0; i < 4; ++i) b[at + i] = (uint8_t)(v >> (8 * i)); };
	auto put64 = [](std::vector<uint8_t>& b, size_t at, uint64_t v) { for (int i = 0; i < 8; ++i) b[at + i] = (uint8_t)(v >> (8 * i)); };
	// An MBR as Windows 7 writes it: a 100 MB active NTFS partition, then the system.
	std::vector<uint8_t> mbr(512);
	mbr[510] = 0x55; mbr[511] = 0xAA;
	put32(mbr, 440, 0x1A2B3C4D);
	mbr[446] = 0x80; mbr[446 + 4] = 0x07; put32(mbr, 446 + 8, 2048); put32(mbr, 446 + 12, 204800);
	mbr[462 + 4] = 0x07; put32(mbr, 462 + 8, 206848); put32(mbr, 462 + 12, 1000000);
	PartitionTable t = parsePartitionTable(mbr.data(), mbr.size());
	check(t.style == L"MBR" && t.diskId == L"1A2B3C4D" && t.sectorSize == 0 && t.partitions.size() == 2,
	      "partition table: an MBR, its signature, its two primary partitions");
	check(t.partitions.size() == 2 && t.partitions[0].active && !t.partitions[1].active && t.partitions[0].type == L"0x07"
	      && t.partitions[1].firstSector == 206848 && t.partitions[1].sectors == 1000000 && t.partitions[1].index == 2,
	      "partition table: an MBR entry's type, boot flag, first sector and length");
	// A GPT at 512 bytes per sector: an EFI system partition and a basic data one, 128 entries of 128 bytes.
	std::vector<uint8_t> gpt(34 * 512);
	gpt[510] = 0x55; gpt[511] = 0xAA; gpt[446 + 4] = 0xEE;
	memcpy(gpt.data() + 512, "EFI PART", 8);
	for (int i = 0; i < 16; ++i) gpt[512 + 56 + i] = (uint8_t)(0x10 + i);
	put64(gpt, 512 + 72, 2); put32(gpt, 512 + 80, 128); put32(gpt, 512 + 84, 128);
	const uint8_t esp[16] = { 0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B };
	memcpy(gpt.data() + 1024, esp, 16); gpt[1024 + 16] = 1;
	put64(gpt, 1024 + 32, 2048); put64(gpt, 1024 + 40, 206847);
	const std::wstring name = L"EFI system partition";
	for (size_t i = 0; i < name.size(); ++i) gpt[1024 + 56 + 2 * i] = (uint8_t)name[i];
	gpt[1152] = 0xA2; gpt[1152 + 16] = 2;
	put64(gpt, 1152 + 32, 239616); put64(gpt, 1152 + 40, 239615 + 5000000);
	t = parsePartitionTable(gpt.data(), gpt.size());
	check(t.style == L"GPT" && t.sectorSize == 512 && t.diskId == L"{13121110-1514-1716-1819-1A1B1C1D1E1F}" && t.partitions.size() == 2,
	      "partition table: a GPT behind its protective MBR, its disk GUID, its used entries only");
	check(t.partitions.size() == 2 && t.partitions[0].efiSystem && t.partitions[0].name == name && t.partitions[0].sectors == 204800
	      && !t.partitions[1].efiSystem && t.partitions[1].index == 2 && t.partitions[1].firstSector == 239616,
	      "partition table: the EFI system partition told by its type GUID, its name and length");
	std::vector<uint8_t> forged = gpt;
	put32(forged, 512 + 84, 64);
	check(parsePartitionTable(forged.data(), forged.size()).partitions.empty(), "partition table: an entry size under 128 refused");
	forged = gpt;
	put64(forged, 512 + 72, 1000000);
	check(parsePartitionTable(forged.data(), forged.size()).partitions.empty(), "partition table: entries said past the bytes refused");
	/* A USB key formatted whole in FAT32, as the harness's: its boot sector at
	   sector 0, whose BPB bytes read as entries gave partitions at random. */
	std::vector<uint8_t> key(512);
	key[0] = 0xEB; key[1] = 0x58; key[2] = 0x90;
	memcpy(key.data() + 3, "MSDOS5.0", 8);
	memcpy(key.data() + 82, "FAT32   ", 8);
	for (size_t i = 446; i < 510; ++i) key[i] = (uint8_t)(0x41 + i % 26);
	key[510] = 0x55; key[511] = 0xAA;
	t = parsePartitionTable(key.data(), key.size());
	check(t.style == L"Volume" && t.partitions.empty() && t.diskId.empty(), "partition table: a disk formatted whole, no partition made up");
	key[82] = 'X';
	check(parsePartitionTable(key.data(), key.size()).style.empty(), "partition table: neither a table nor a volume, nothing");
	check(parsePartitionTable(gpt.data(), 1100).partitions.empty() && parsePartitionTable(gpt.data(), 300).style.empty(),
	      "partition table: an entry cut by the end of the bytes not read; fewer than a sector, no table");
}

void cmTraceLog() {
	/* Two messages as the Intune Management Extension writes them, the first
	   on two lines; one with a bias after its time; one cut short. */
	const std::vector<IntuneLogEntry> e = parseCmTraceLog(
		L"<![LOG[[Win32App] Downloading app\r\nsecond line]LOG]!><time=\"15:01:02.1234567\" date=\"10-24-2026\" "
		L"component=\"IntuneManagementExtension\" context=\"\" type=\"1\" thread=\"12\" file=\"\">\r\n"
		L"<![LOG[Script ran]LOG]!><time=\"09:00:00.000+300\" date=\"1-2-2026\" component=\"AgentExecutor\" context=\"\" type=\"3\" thread=\"7\" file=\"x.cs\">\r\n"
		L"<![LOG[cut short", L"C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log");
	check(e.size() == 2, "CMTrace: two whole messages, the one cut short left out");
	if (e.size() != 2) return;
	FILETIME expected;
	check(e[0].message == L"[Win32App] Downloading app\r\nsecond line" && e[0].component == L"IntuneManagementExtension"
	      && e[0].thread == L"12" && e[0].type == L"1" && e[0].context.empty() && e[0].line == 1,
	      "CMTrace: a message on two lines, its attributes, its first line");
	check(iso8601UtcToFiletime(L"2026-10-24T15:01:02.1234567Z", expected) && value(e[0].timeLocal) == value(expected) && !e[0].hasBias,
	      "CMTrace: the local date read, month first, to the 100 ns");
	check(e[1].line == 3 && e[1].hasBias && e[1].biasMinutes == 300 && e[1].sourceFile == L"x.cs"
	      && iso8601UtcToFiletime(L"2026-01-02T09:00:00.000Z", expected) && value(e[1].timeLocal) == value(expected),
	      "CMTrace: a bias after the time read apart, a one-digit month and day");
}

void internetShortcut() {
	// As Internet Explorer writes it: a property section, then [InternetShortcut].
	check(internetShortcutUrl("[{000214A0-0000-0000-C000-000000000046}]\r\nProp3=19,11\r\n[InternetShortcut]\r\nIDList=\r\nURL=https://example.com/a%20b\r\n")
	      == "https://example.com/a%20b", "url: the URL= of [InternetShortcut], wherever the section lies");
	check(internetShortcutUrl("[InternetShortcut]\nURL=http://x/\n") == "http://x/", "url: the plain form, LF line ends");
	check(internetShortcutUrl("[Other]\r\nURL=http://not-this/\r\n").empty() && internetShortcutUrl("").empty(),
	      "url: a URL= outside [InternetShortcut], or none, gives nothing");
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
	RecycledFile unknown;
	check(parseRecycleBinIndex(v3, unknown) && unknown.unsupportedFormat && unknown.version == 3 && unknown.originalPath.empty()
	      && unknown.size == 0, "recycle bin: a version without decoder is declared unsupported, and nothing of it is read");
	std::vector<uint8_t> wide = v2; wide[4] = 1;   // version 0x1'00000002: not version 2
	RecycledFile aliased;
	check(parseRecycleBinIndex(wide, aliased) && aliased.unsupportedFormat, "recycle bin: a 64-bit version taken for its low half");
	check(!o.unsupportedFormat && !r.unsupportedFormat, "recycle bin: version 1 or 2 declared unsupported");
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

//! Appends a DetectionHistory field: size, type, value, aligned on 8 bytes.
void putField(std::vector<uint8_t>& b, uint32_t type, const std::vector<uint8_t>& value) {
	const uint32_t size = (uint32_t)value.size();
	for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(size >> (8 * i)));
	for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(type >> (8 * i)));
	b.insert(b.end(), value.begin(), value.end());
	while (b.size() % 8) b.push_back(0);
}
std::vector<uint8_t> wide(const std::wstring& s) { std::vector<uint8_t> v; putWide(v, s); v.push_back(0); v.push_back(0); return v; }
std::vector<uint8_t> number32(uint32_t n) { std::vector<uint8_t> v; for (int i = 0; i < 4; ++i) v.push_back((uint8_t)(n >> (8 * i))); return v; }
std::vector<uint8_t> number64(uint64_t n) { std::vector<uint8_t> v; put64(v, n); return v; }

/*! Defender: the quarantine key against an entry header Defender wrote in the
 *  test VM (its lengths come out), then a DetectionHistory and an entry built
 *  as the reference showed them, and their hostile variants. */
void defenderHistory() {
	// First 0x3C bytes of Entries\{80008A1B-0000-0000-9243-05FA81693319}, EICAR, 2026-09-30.
	const uint8_t header[0x3C] = {
		0xD3, 0x45, 0xC5, 0x99, 0x92, 0xFD, 0xDF, 0x68, 0xC2, 0xF9, 0x91, 0xC7, 0x81, 0xFA, 0xFC, 0x90,
		0x8A, 0xA2, 0xAD, 0xB3, 0x68, 0x34, 0x03, 0x9C, 0x16, 0x61, 0xBC, 0xC2, 0xF0, 0xE8, 0xCA, 0xE7,
		0xF1, 0xFF, 0xA3, 0x02, 0x72, 0x58, 0x32, 0xB2, 0x7E, 0xDB, 0xEF, 0xE0, 0x84, 0xBC, 0xBB, 0x0F,
		0xED, 0x84, 0x08, 0xFD, 0x11, 0x35, 0xA6, 0xAC, 0x3E, 0x10, 0xD3, 0x5E };
	const std::vector<uint8_t> clear = defenderDecrypt(header, sizeof header);
	check(clear[0x28] == 0x4E && clear[0x2C] == 0xF8 && clear[0x29] == 0 && clear[0x2D] == 0,
	      "quarantine key: the lengths Defender wrote (0x4E, 0xF8) do not come out");

	// DetectionHistory, Magic.Version 1.2, one file resource.
	const uint8_t guid[16] = { 0xD4, 0xF3, 0x7F, 0xC6, 0x8C, 0xCF, 0x6E, 0x49, 0x82, 0x78, 0x4E, 0x6C, 0x68, 0x2A, 0xAA, 0x69 };
	const uint8_t entry[16] = { 0x1B, 0x8A, 0x00, 0x80, 0, 0, 0, 0, 0x92, 0x43, 0x05, 0xFA, 0x81, 0x69, 0x33, 0x19 };
	std::vector<uint8_t> dh;
	putField(dh, 0x08, number64(0x80008A1B));
	putField(dh, 0x1E, std::vector<uint8_t>(guid, guid + 16));
	putField(dh, 0x15, wide(L"Magic.Version:1.2"));
	putField(dh, 0x15, wide(L"Virus:DOS/EICAR_Test_File"));
	for (uint32_t n : { 0u, 5u, 42u, 110u }) putField(dh, 0x06, number32(n));
	putField(dh, 0x15, wide(L"Magic.Version:1.2"));
	putField(dh, 0x15, wide(L"file"));
	putField(dh, 0x15, wide(L"C:\\wactest\\eicar\\wac-eicar.com"));
	std::vector<uint8_t> bag(24, 0);
	const std::wstring name = L"ThreatTrackingStartTime";
	const std::vector<uint8_t> nameBytes = wide(name);
	for (uint8_t b : number32((uint32_t)nameBytes.size())) bag.push_back(b);
	bag.insert(bag.end(), nameBytes.begin(), nameBytes.end());
	for (uint8_t b : number32(4)) bag.push_back(b);
	put64(bag, 0x01DD50978AB992EBULL);
	putField(dh, 0x28, bag);
	putField(dh, 0x0A, number64(0x01DD5097915F0F1AULL));
	putField(dh, 0x1E, std::vector<uint8_t>(entry, entry + 16));
	putField(dh, 0x06, number32(1));
	putField(dh, 0x06, number32(2));
	putField(dh, 0x15, wide(L"NT AUTHORITY\\SYSTEM"));
	putField(dh, 0x06, number32(3));
	putField(dh, 0x15, wide(L"C:\\Windows\\System32\\cmd.exe"));
	for (uint32_t n : { 3u, 1u, 0u }) putField(dh, 0x06, number32(n));
	putField(dh, 0x0A, number64(0x01DD50978ABA0B12ULL));
	DefenderDetection d;
	check(parseDetectionHistory(dh, d), "DetectionHistory: a well-formed file refused");
	check(d.threatId == 0x80008A1B && d.detectionId == L"{C67FF3D4-CF8C-496E-8278-4E6C682AAA69}"
	      && d.threatName == L"Virus:DOS/EICAR_Test_File", "DetectionHistory: threat and detection identifiers");
	check(d.severityKnown && d.severityId == 5 && d.categoryKnown && d.categoryId == 42, "DetectionHistory: severity and category");
	check(d.resources.size() == 1 && d.resources[0].type == L"file" && d.resources[0].path == L"C:\\wactest\\eicar\\wac-eicar.com",
	      "DetectionHistory: the resource");
	check(d.quarantineEntryId == L"{80008A1B-0000-0000-9243-05FA81693319}" && d.executionStatusKnown && d.executionStatusId == 1
	      && d.domainUser == L"NT AUTHORITY\\SYSTEM" && d.processName == L"C:\\Windows\\System32\\cmd.exe",
	      "DetectionHistory: quarantine entry, execution status, account and process by their position");
	check(value(d.initialDetectionUtc) == 0x01DD50978ABA0B12ULL, "DetectionHistory: InitialDetectionTime at +9");
	check(d.threatTracking.size() == 1 && d.threatTracking[0].name == name, "DetectionHistory: the named bag");
	// The date before the entry, and the numbers not confirmed, stay unnamed — as read.
	size_t dates = 0;
	for (const DetectionField& f : d.unnamed) dates += f.type == 0x0A;
	check(dates == 1 && d.unnamed.size() == 8, "DetectionHistory: the fields not confirmed are given unnamed");
	// A length that lies: what precedes is kept, nothing is read beyond.
	std::vector<uint8_t> lying(dh.begin(), dh.begin() + 200);
	lying[152] = 0xFF; lying[153] = 0xFF;
	DefenderDetection partial;
	check(parseDetectionHistory(lying, partial) && partial.threatName == L"Virus:DOS/EICAR_Test_File",
	      "DetectionHistory: a lying length stops the reading");
	std::vector<uint8_t> other = dh;
	other[4] = 0x06;
	DefenderDetection refused;
	check(!parseDetectionHistory(other, refused), "DetectionHistory: another header accepted");

	/* DetectionHistory of Defender on Windows 8.1, field by field as it wrote
	   DetectionHistory\00\08344BE3-… in the test VM (2026-10-13): no
	   Magic.Version marker, the name right after the detection's GUID. */
	const uint8_t detection81[16] = { 0xE3, 0x4B, 0x34, 0x08, 0x28, 0x32, 0xE0, 0x47, 0x8F, 0xF1, 0xCD, 0x41, 0x62, 0x9E, 0x5E, 0x02 };
	std::vector<uint8_t> dh81;
	putField(dh81, 0x08, number64(0x80008A1B));
	putField(dh81, 0x1E, std::vector<uint8_t>(detection81, detection81 + 16));
	putField(dh81, 0x15, wide(L"Virus:DOS/EICAR_Test_File"));
	for (uint32_t n : { 0u, 5u, 42u, 110u, 4u, 3u, 3u, 3u, 2u, 6u, 1u }) putField(dh81, 0x06, number32(n));
	putField(dh81, 0x15, wide(L"file"));
	putField(dh81, 0x15, wide(L"C:\\wactest\\eicar-held\\wac-eicar-220958.txt"));
	putField(dh81, 0x06, number32(0));
	putField(dh81, 0x0A, number64(0x01DD5B4EDAC61327ULL));
	putField(dh81, 0x05, number32(0));
	putField(dh81, 0x06, number32(0));
	putField(dh81, 0x1E, std::vector<uint8_t>(16, 0));
	putField(dh81, 0x06, number32(0));
	putField(dh81, 0x06, number32(2));
	putField(dh81, 0x15, wide(L"NT AUTHORITY\\LOCAL SERVICE"));
	putField(dh81, 0x06, number32(2));
	putField(dh81, 0x15, wide(L"Unknown"));
	for (uint32_t n : { 2u, 1u, 0u }) putField(dh81, 0x06, number32(n));
	putField(dh81, 0x0A, number64(0x01DD5B4ED62FD7A3ULL));
	putField(dh81, 0x15, wide(L"NT AUTHORITY\\SYSTEM"));
	DefenderDetection d81;
	check(parseDetectionHistory(dh81, d81) && d81.magicVersion.empty() && d81.threatId == 0x80008A1B
	      && d81.detectionId == L"{08344BE3-3228-47E0-8FF1-CD41629E5E02}" && d81.threatName == L"Virus:DOS/EICAR_Test_File",
	      "DetectionHistory of Windows 8.1: no marker, threat and detection identifiers");
	check(d81.severityKnown && d81.severityId == 5 && d81.categoryKnown && d81.categoryId == 42,
	      "DetectionHistory of Windows 8.1: severity and category two and three fields after the name");
	check(d81.resources.size() == 1 && d81.resources[0].type == L"file"
	      && d81.resources[0].path == L"C:\\wactest\\eicar-held\\wac-eicar-220958.txt",
	      "DetectionHistory of Windows 8.1: the resource, its type and path alone; account and process are not resources");
	check(d81.quarantineEntryId.empty() && d81.executionStatusKnown && d81.executionStatusId == 0
	      && d81.domainUser == L"NT AUTHORITY\\LOCAL SERVICE" && d81.processName == L"Unknown"
	      && value(d81.initialDetectionUtc) == 0x01DD5B4ED62FD7A3ULL,
	      "DetectionHistory of Windows 8.1: no quarantine, execution status, account, process and InitialDetectionTime by their position");

	// A quarantine entry: threat, then one resource with its fields.
	std::vector<uint8_t> threat;
	put64(threat, 0x80008A1B);
	threat.resize(0x20, 0);
	put64(threat, 0x01DD5097915D8EC9ULL);
	put64(threat, 0x80008A1B);
	for (uint8_t b : number32(1)) threat.push_back(b);
	for (char c : std::string("Virus:DOS/EICAR_Test_File")) threat.push_back((uint8_t)c);
	threat.push_back(0);
	std::vector<uint8_t> resources = number32(1);
	for (uint8_t b : number32(8)) resources.push_back(b);
	putWide(resources, L"\\\\?\\C:\\wactest\\wac-eicar.com");
	resources.push_back(0); resources.push_back(0);
	resources.push_back(5); resources.push_back(0);                     // five fields
	for (char c : std::string("file")) resources.push_back((uint8_t)c);
	resources.push_back(0);
	while ((resources.size() - 8) % 4) resources.push_back(0);
	auto putTagged = [&](uint16_t tag, const std::vector<uint8_t>& v) {
		resources.push_back((uint8_t)v.size()); resources.push_back((uint8_t)(v.size() >> 8));
		resources.push_back((uint8_t)tag); resources.push_back((uint8_t)(tag >> 8));
		resources.insert(resources.end(), v.begin(), v.end());
		while ((resources.size() - 8) % 4) resources.push_back(0);
	};
	putTagged(0x4002, std::vector<uint8_t>(20, 0xAB));
	putTagged(0x6012, number64(68));
	putTagged(0x6011, number64(0x01D82F8A0B72A780ULL));
	putTagged(0x600F, number64(0x01D6E0B5C9A5D680ULL));
	putTagged(0x300A, number32(0x20));
	std::vector<uint8_t> head(0x3C, 0);
	for (int i = 0; i < 4; ++i) head[0x28 + i] = (uint8_t)(threat.size() >> (8 * i));
	for (int i = 0; i < 4; ++i) head[0x2C + i] = (uint8_t)(resources.size() >> (8 * i));
	std::vector<uint8_t> file = defenderDecrypt(head.data(), head.size());
	for (const std::vector<uint8_t>* part : { &threat, &resources }) {
		const std::vector<uint8_t> encrypted = defenderDecrypt(part->data(), part->size());
		file.insert(file.end(), encrypted.begin(), encrypted.end());
	}
	QuarantineEntry q;
	check(parseQuarantineEntry(file, q), "quarantine entry: a well-formed entry refused");
	check(q.threatId == 0x80008A1B && q.threatName == L"Virus:DOS/EICAR_Test_File" && value(q.quarantinedUtc) == 0x01DD5097915D8EC9ULL,
	      "quarantine entry: threat and instant");
	check(q.resources.size() == 1 && q.resources[0].path == L"C:\\wactest\\wac-eicar.com" && q.resources[0].type == L"file"
	      && q.resources[0].fields.size() == 5, "quarantine entry: the resource, its \\\\?\\ prefix removed, its fields");
	if (q.resources.size() == 1)
		check(q.resources[0].resourceDataSha1() == L"ABABABABABABABABABABABABABABABABABABABAB", "quarantine entry: the ResourceData name");
	// An entry whose announced length exceeds the file.
	std::vector<uint8_t> shortFile(file.begin(), file.end() - 1);
	QuarantineEntry truncated;
	check(!parseQuarantineEntry(shortFile, truncated), "quarantine entry: a part beyond the file accepted");

	// ResourceData: a 0x10-byte descriptor, then the length, then the content.
	std::vector<uint8_t> data(0x38 + 5, 0);
	data[8] = 0x10;
	data[0x10 + 0x1C] = 5;
	size_t offset = 0;
	uint64_t size = 0;
	check(quarantinedContent(data, data.size(), offset, size) && offset == 0x38 && size == 5, "ResourceData: content located");
	check(!quarantinedContent(data, data.size() - 1, offset, size), "ResourceData: a content beyond the file accepted");
	data[8] = 0xF0;
	check(!quarantinedContent(data, data.size(), offset, size), "ResourceData: a descriptor beyond the data accepted");
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

void registryLot2() {
	// TrustRecords: a FILETIME, then the flag at the very end.
	std::vector<uint8_t> record;
	put64(record, 133280000000000000ULL);
	record.resize(20, 0);
	record.push_back(0xFF); record.push_back(0xFF); record.push_back(0xFF); record.push_back(0x7F);
	FILETIME t; bool macros = false;
	check(parseTrustRecord(record, t, macros) && macros && value(t) == 133280000000000000ULL, "trust record: macros enabled, date read");
	record[23] = 0x00;
	check(parseTrustRecord(record, t, macros) && !macros, "trust record: editing only, no macros");
	check(!parseTrustRecord(std::vector<uint8_t>(8, 0), t, macros), "trust record: too short refused");
	// Firewall rule: version, fields, a repeated field, empty trailing field.
	std::wstring version;
	const NameValues f = parseFirewallRule(L"v2.33|Action=Block|Active=TRUE|Dir=In|RA4=10.0.0.1|RA4=10.0.0.2|Name=WAC test|", version);
	check(version == L"v2.33" && f.size() == 6 && f[1].second == L"TRUE" && f[3].first == L"RA4" && f[4].first == L"RA4"
	      && f[5].second == L"WAC test", "firewall rule: version, six fields, the repeated one kept twice");
	// Certificate Blob: a first property, then 0x20; a length that lies.
	std::vector<uint8_t> blob;
	auto put32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) blob.push_back((uint8_t)(v >> (8 * i))); };
	put32(0x03); put32(1); put32(4); put32(0xDEADBEEF);
	put32(0x20); put32(1); put32(3); blob.push_back(0x30); blob.push_back(0x01); blob.push_back(0x00);
	size_t der = 0, size = 0;
	check(certificateInBlob(blob, der, size) && der == 28 && size == 3, "certificate blob: property 0x20 found after another");
	std::vector<uint8_t> lying = blob;
	lying[8] = 0xFF; lying[9] = 0xFF;
	check(!certificateInBlob(lying, der, size), "certificate blob: a length beyond the value refused");
}

/*! A self-relative descriptor: owner S-1-5-21-1-2-3-1001, a DACL of one ACE
 *  granting Everyone (S-1-1-0) full control, 0x001F01FF. */
std::vector<uint8_t> testDescriptor() {
	std::vector<uint8_t> d;
	auto put16 = [&](uint16_t v) { d.push_back((uint8_t)v); d.push_back((uint8_t)(v >> 8)); };
	auto put32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) d.push_back((uint8_t)(v >> (8 * i))); };
	d.push_back(1); d.push_back(0); put16(0x8004);         // revision, self-relative + DACL present
	put32(20); put32(0); put32(0); put32(48);               // owner, group, SACL, DACL offsets
	for (uint8_t c : { 1, 5, 0, 0, 0, 0, 0, 5 }) d.push_back(c);  // S-1-5-…, five sub-authorities
	for (uint32_t sub : { 21u, 1u, 2u, 3u, 1001u }) put32(sub);
	d.push_back(2); d.push_back(0); put16(28); put16(1); put16(0);  // ACL: revision, size, one ACE
	d.push_back(0); d.push_back(0); put16(20); put32(0x001F01FF);   // ACCESS_ALLOWED, size, mask
	for (uint8_t c : { 1, 1, 0, 0, 0, 0, 0, 1 }) d.push_back(c);  // S-1-1-0
	put32(0);
	return d;
}

/*! Writes an $SDS entry at `at`: hash, SecurityId, its offset, its length, the descriptor.
 *  @return the offset of the next entry, aligned on 16 bytes */
size_t putSdsEntry(std::vector<uint8_t>& sds, size_t at, uint32_t securityId, const std::vector<uint8_t>& sd) {
	std::vector<uint8_t> e;
	put64(e, 0);   // room for hash and SecurityId
	put64(e, at);
	const uint32_t length = (uint32_t)(20 + sd.size());
	for (int i = 0; i < 4; ++i) e.push_back((uint8_t)(length >> (8 * i)));
	const uint32_t hash = securityDescriptorHash(sd.data(), sd.size());
	for (int i = 0; i < 4; ++i) { e[i] = (uint8_t)(hash >> (8 * i)); e[4 + i] = (uint8_t)(securityId >> (8 * i)); }
	e.insert(e.end(), sd.begin(), sd.end());
	std::copy(e.begin(), e.end(), sds.begin() + at);
	return (at + e.size() + 15) / 16 * 16;
}

void securityDescriptors() {
	const size_t BLOCK = 0x40000;
	const std::vector<uint8_t> sd = testDescriptor();
	std::vector<uint8_t> sds(3 * BLOCK, 0);
	size_t next = putSdsEntry(sds, 0, 0x100, sd);
	next = putSdsEntry(sds, next, 0x101, sd);
	std::copy(sds.begin(), sds.begin() + BLOCK, sds.begin() + BLOCK);   // the mirror of block 0
	// A mirror holds copies whose recorded offset is their original's; this one
	// is consistent with its own place, and must be skipped all the same.
	putSdsEntry(sds, BLOCK, 0x999, sd);
	next = putSdsEntry(sds, 2 * BLOCK, 0x102, sd);
	next = putSdsEntry(sds, next, 0x100, sd);          // a SecurityId met again: kept once
	const size_t lying = next;
	putSdsEntry(sds, lying, 0x103, sd);
	sds[lying + 16] = 0xF0; sds[lying + 17] = 0xFF; sds[lying + 18] = 0xFF; sds[lying + 19] = 0xFF;  // a length past the block
	sds[0x60] ^= 1;                                    // entry 0x101: its stored hash damaged

	for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
		GuardedCopy copy(sds, side);
		const std::vector<SecurityDescriptorEntry> e = parseSds(copy.data(), copy.size(), L"C:");
		check(e.size() == 3 && e[0].securityId == 0x100 && e[1].securityId == 0x101 && e[2].securityId == 0x102,
		      "sds: three descriptors, the mirror skipped, a repeated SecurityId kept once, the lying entry refused");
		check(e.size() == 3 && e[0].hashMatches && !e[1].hashMatches && e[2].hashMatches,
		      "sds: the stored hash checked against the descriptor's bytes");
		if (e.size() == 3) {
			const Json first = e[0].toJson();
			const Json* owner = first.find(L"Owner");
			const Json* dacl = first.find(L"Dacl");
			const Json* ace = dacl && dacl->members().size() == 1 ? &dacl->members()[0].second : nullptr;
			check(owner && owner->text() == L"S-1-5-21-1-2-3-1001" && ace && ace->find(L"Sid")
			      && ace->find(L"Sid")->text() == L"S-1-1-0" && ace->find(L"Mask")
			      && ace->find(L"Mask")->text() == L"0x001f01ff",
			      "sds: owner, ACE SID and mask decoded");
			const Json* mismatch = e[1].toJson().find(L"HashMismatch");
			check(!first.find(L"HashMismatch") && mismatch && mismatch->text() == L"true",
			      "sds: HashMismatch emitted only for the damaged descriptor");
		}
	}
	// Truncated streams: never read past the bytes given.
	for (size_t size : { (size_t)0, (size_t)19, (size_t)0x70, BLOCK + 3 }) {
		GuardedCopy copy(std::vector<uint8_t>(sds.begin(), sds.begin() + size), GuardSide::After);
		const std::vector<SecurityDescriptorEntry> e = parseSds(copy.data(), copy.size(), L"C:");
		check(e.size() <= 2, "sds: a truncated stream read within its bytes");
	}
}

/*! An NTFS boot sector: 512-byte sectors, 8 per cluster, 1 KiB records
 *  (0xF6 = -10), one-cluster index blocks, serial 0x1122334455667788. */
std::vector<uint8_t> testBootSector() {
	std::vector<uint8_t> b(512, 0);
	std::memcpy(b.data() + 3, "NTFS    ", 8);
	b[0x0B] = 0x00; b[0x0C] = 0x02;   // 512
	b[0x0D] = 8;
	auto at64 = [&](size_t at, uint64_t v) { for (int i = 0; i < 8; ++i) b[at + i] = (uint8_t)(v >> (8 * i)); };
	at64(0x28, 125829119);
	at64(0x30, 786432);
	at64(0x38, 2);
	b[0x40] = 0xF6;
	b[0x44] = 1;
	at64(0x48, 0x1122334455667788ULL);
	b[0x1FE] = 0x55; b[0x1FF] = 0xAA;
	return b;
}

void ntfsVolumes() {
	const std::vector<uint8_t> sector = testBootSector();
	for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
		GuardedCopy copy(sector, side);
		NtfsBootSector boot;
		check(parseNtfsBootSector(copy.data(), copy.size(), boot) && boot.bytesPerSector == 512
		      && boot.bytesPerCluster == 4096 && boot.totalSectors == 125829119 && boot.mftCluster == 786432
		      && boot.mftMirrorCluster == 2 && boot.bytesPerRecord == 1024 && boot.bytesPerIndexBlock == 4096
		      && boot.serialNumber == 0x1122334455667788ULL, "boot sector: geometry and serial read");
	}
	NtfsBootSector boot;
	std::vector<uint8_t> big = sector;
	big[0x0D] = 0xF8;                                   // 2^8 sectors: 128 KiB clusters
	check(parseNtfsBootSector(big.data(), big.size(), boot) && boot.bytesPerCluster == 131072,
	      "boot sector: a cluster count above 0x80 is a power of two");
	std::vector<uint8_t> unsigned_ = sector;
	unsigned_[0x1FF] = 0;
	check(!parseNtfsBootSector(unsigned_.data(), unsigned_.size(), boot), "boot sector: without 0x55AA refused");
	std::vector<uint8_t> fat = sector;
	std::memcpy(fat.data() + 3, "MSDOS5.0", 8);
	check(!parseNtfsBootSector(fat.data(), fat.size(), boot), "boot sector: another file system refused");
	std::vector<uint8_t> odd = sector;
	odd[0x0B] = 100; odd[0x0C] = 0;
	check(!parseNtfsBootSector(odd.data(), odd.size(), boot), "boot sector: a 100-byte sector refused");
	GuardedCopy truncated(std::vector<uint8_t>(sector.begin(), sector.begin() + 511), GuardSide::After);
	check(!parseNtfsBootSector(truncated.data(), truncated.size(), boot), "boot sector: 511 bytes refused, not read past");

	// $Max: maximum size, allocation delta, journal identifier (a FILETIME), lowest valid USN.
	std::vector<uint8_t> max;
	for (uint64_t v : { 33554432ULL, 8388608ULL, 0x01DB1C2D3E4F5061ULL, 1234567ULL }) put64(max, v);
	UsnJournalHeader header;
	check(parseUsnJournalHeader(max.data(), max.size(), header) && header.maximumSize == 33554432
	      && header.allocationDelta == 8388608 && header.journalId == 0x01DB1C2D3E4F5061ULL
	      && header.lowestValidUsn == 1234567, "usn $Max: the four fields read");
	check(!parseUsnJournalHeader(max.data(), 31, header), "usn $Max: 31 bytes refused");

	NtfsVolumeInfo info;
	info.volume = L"C:";
	parseNtfsBootSector(sector.data(), sector.size(), boot);
	info.boot = boot;
	parseUsnJournalHeader(max.data(), max.size(), header);
	info.journal = header;
	const Json o = info.toJson();
	const Json* serial = o.find(L"VolumeSerial");
	const Json* serial64 = o.find(L"VolumeSerial64");
	const Json* journal = o.find(L"UsnJournal");
	check(serial && serial->text() == L"55667788" && serial64 && serial64->text() == L"1122334455667788",
	      "ntfs volume: serial as Windows shows it (low 32 bits), and whole");
	check(journal && journal->find(L"UsnJournalId") && journal->find(L"UsnJournalId")->text() == L"01DB1C2D3E4F5061"
	      && journal->find(L"CreatedUtc"), "ntfs volume: journal identifier, and its date");
}

/*! A shortcut with a LinkInfo only: its target on a fixed volume of serial
 *  0x0A1B2C3D — a leading zero that must be kept, as Prefetch and
 *  ntfs_volumes.json write it. */
void shortcutVolumeSerial() {
	std::vector<uint8_t> lnk(76, 0);
	lnk[0] = 0x4C;
	const uint8_t CLSID[16] = { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
	std::memcpy(lnk.data() + 4, CLSID, 16);
	lnk[20] = 0x02;                                    // HasLinkInfo
	auto put32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) lnk.push_back((uint8_t)(v >> (8 * i))); };
	const std::string path = "C:\\a.txt";
	const uint32_t volumeIdSize = 0x11, basePath = 0x1C + volumeIdSize;
	const uint32_t suffix = basePath + (uint32_t)path.size() + 1;
	put32(suffix + 1);                                 // LinkInfoSize
	put32(0x1C);                                       // LinkInfoHeaderSize
	put32(1);                                          // VolumeIDAndLocalBasePath
	put32(0x1C);                                       // VolumeIDOffset
	put32(basePath);                                   // LocalBasePathOffset
	put32(0);                                          // CommonNetworkRelativeLinkOffset
	put32(suffix);                                     // CommonPathSuffixOffset
	put32(volumeIdSize); put32(3); put32(0x0A1B2C3D); put32(0x10);   // VolumeID: size, fixed, serial, label offset
	lnk.push_back(0);                                  // empty label
	for (char c : path) lnk.push_back((uint8_t)c);
	lnk.push_back(0);
	lnk.push_back(0);                                  // empty suffix
	put32(0);                                          // terminal block
	RecentDoc doc(lnk.data(), lnk.size(), L"C:\\test.lnk", L"");
	check(doc.volumeSerial == L"0A1B2C3D", "shortcut: volume serial on eight digits, the leading zero kept");
}

/*! A master key file: version 2, its GUID, policy 5, blocks of 0xB0, 0x90,
 *  0x14 and no domain copy — zeros standing for the encrypted blocks. */
std::vector<uint8_t> testMasterKey(const std::wstring& guid) {
	std::vector<uint8_t> k;
	auto put32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) k.push_back((uint8_t)(v >> (8 * i))); };
	put32(2); put32(0); put32(0);
	for (wchar_t c : guid) { k.push_back((uint8_t)c); k.push_back((uint8_t)(c >> 8)); }
	put32(0); put32(0); put32(5);
	for (uint64_t length : { 0xB0ULL, 0x90ULL, 0x14ULL, 0ULL }) put64(k, length);
	k.resize(k.size() + 0xB0 + 0x90 + 0x14, 0);
	return k;
}

void dpapiMasterKeys() {
	const std::wstring guid = L"1b9c8e2a-4d3f-4a5b-9c6d-7e8f90a1b2c3";
	const std::vector<uint8_t> key = testMasterKey(guid);
	for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
		GuardedCopy copy(key, side);
		DpapiMasterKeyHeader h;
		check(parseDpapiMasterKeyHeader(copy.data(), copy.size(), h) && h.version == 2 && h.guid == guid
		      && h.policy == 5 && h.masterKeyLength == 0xB0 && h.backupKeyLength == 0x90
		      && h.credHistLength == 0x14 && h.domainKeyLength == 0, "dpapi: header of a master key read");
	}
	DpapiMasterKeyHeader h;
	std::vector<uint8_t> lying = key;
	lying[0x78] = 0xFF;                                // a domain block beyond the file
	check(!parseDpapiMasterKeyHeader(lying.data(), lying.size(), h), "dpapi: block sizes beyond the file refused");
	std::vector<uint8_t> huge = key;
	for (int i = 0; i < 8; ++i) huge[0x60 + i] = 0xFF;  // a length near 2^64, which an addition would wrap
	check(!parseDpapiMasterKeyHeader(huge.data(), huge.size(), h), "dpapi: a wrapping block size refused");
	GuardedCopy truncated(std::vector<uint8_t>(key.begin(), key.begin() + 0x7F), GuardSide::After);
	check(!parseDpapiMasterKeyHeader(truncated.data(), truncated.size(), h), "dpapi: a header of 127 bytes refused");

	// Preferred: the GUID in binary form (mixed endianness), then the expiry.
	std::vector<uint8_t> preferred = { 0x2a, 0x8e, 0x9c, 0x1b, 0x3f, 0x4d, 0x5b, 0x4a,
	                                   0x9c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3 };
	put64(preferred, 0x01DB000000000000ULL);
	std::wstring named;
	FILETIME expires = { 0 };
	check(parseDpapiPreferred(preferred.data(), preferred.size(), named, expires) && named == guid
	      && value(expires) == 0x01DB000000000000ULL, "dpapi: Preferred names the key as its file is named, with its expiry");
	check(!parseDpapiPreferred(preferred.data(), 23, named, expires), "dpapi: a Preferred of 23 bytes refused");
}

void userShellFolders() {
	const std::wstring profile = L"C:\\Users\\wac";
	check(resolveUserShellFolder(L"%USERPROFILE%\\OneDrive\\Desktop", profile) == L"C:\\Users\\wac\\OneDrive\\Desktop",
	      "user shell folders: %USERPROFILE% is the profile's path");
	check(resolveUserShellFolder(L"%userprofile%\\Desktop", profile) == L"C:\\Users\\wac\\Desktop",
	      "user shell folders: the variable's case ignored");
	check(resolveUserShellFolder(L"D:\\Data\\Desktop", profile) == L"D:\\Data\\Desktop",
	      "user shell folders: a path on another disk kept");
	check(resolveUserShellFolder(L"\\\\server\\share\\Desktop", profile).empty(),
	      "user shell folders: a share is not a local path");
	check(resolveUserShellFolder(L"%APPDATA%\\Desktop", profile).empty(),
	      "user shell folders: another user variable is not guessed");
}

/*! A browser's database as a running browser leaves it: write-ahead log
 *  mode, the last rows only in the -wal, the writer still open. Read through
 *  SqliteDatabase, the rows of the log must come back, and neither the
 *  database nor its log may change. */
void sqliteReader() {
	const std::filesystem::path root = std::filesystem::temp_directory_path() / L"wac-sqlite-test";
	std::error_code ec;
	std::filesystem::remove_all(root, ec);
	std::filesystem::create_directories(root / L"exhibit", ec);
	conf._outputDir = (root / L"output").wstring();
	const std::filesystem::path db = root / L"exhibit" / L"History";

	sqlite3* writer = nullptr;
	check(sqlite3_open_v2(encodeText(db.wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK,
	      "sqlite: the test database created");
	sqlite3_exec(writer, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
	                     "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER, favicon BLOB);"
	                     "INSERT INTO urls VALUES(1, 'https://example.org/', 'Exemple été', 13370000000000000, x'00FF10');"
	                     "INSERT INTO urls VALUES(2, 'https://wac.invalid/a', NULL, 13380000000000000, NULL);",
	             nullptr, nullptr, nullptr);
	check(std::filesystem::exists(db.wstring() + L"-wal") && std::filesystem::file_size(db.wstring() + L"-wal") > 0,
	      "sqlite: the rows are in the write-ahead log, as a running browser leaves them");
	const std::wstring dbBefore = sha256OfFile(db.wstring()), walBefore = sha256OfFile(db.wstring() + L"-wal");
	{
		SqliteDatabase reader;
		check(reader.open(db.wstring()) == ERROR_SUCCESS, "sqlite: opened on its private copy");
		check(reader.hasTable("urls") && !reader.hasTable("visits"), "sqlite: tables told apart");
		std::vector<std::wstring> urls, titles;
		std::vector<int64_t> times;
		std::vector<std::vector<uint8_t>> blobs;
		std::vector<bool> nullTitles;
		check(reader.query("SELECT url, title, last_visit_time, favicon FROM urls ORDER BY id", [&](const SqliteRow& r) {
			urls.push_back(r.text(0)); titles.push_back(r.text(1)); nullTitles.push_back(r.isNull(1));
			times.push_back(r.integer(2)); blobs.push_back(r.blob(3)); }) == ERROR_SUCCESS,
		      "sqlite: query run");
		check(urls.size() == 2 && urls[0] == L"https://example.org/" && titles[0] == L"Exemple \u00e9t\u00e9"
		      && times[1] == 13380000000000000LL && nullTitles[1] && !nullTitles[0]
		      && blobs[0] == std::vector<uint8_t>({ 0x00, 0xFF, 0x10 }) && blobs[1].empty(),
		      "sqlite: the log's rows read, UTF-8 text, integer, NULL and BLOB");
		check(reader.query("SELECT missing_column FROM urls", [](const SqliteRow&) {}) == HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
		      "sqlite: a query on another schema refused, not crashing");
	}
	check(sha256OfFile(db.wstring()) == dbBefore && sha256OfFile(db.wstring() + L"-wal") == walBefore,
	      "sqlite: the database and its log unchanged by the reading");
	check(!std::filesystem::exists(std::filesystem::path(conf._outputDir) / L"working" / L"sqlite-copies" / L"1"),
	      "sqlite: the private copy deleted when closed");
	sqlite3_close(writer);   // only now: closing it checkpoints the log into the database

	std::ofstream(root / L"exhibit" / L"notadb") << "this is not an SQLite database, only text";
	SqliteDatabase notDatabase;
	check(notDatabase.open((root / L"exhibit" / L"notadb").wstring()) == HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
	      "sqlite: a file that is no database refused at the opening");
	std::filesystem::remove_all(root, ec);
}

//! @return the record of a type whose field `key` is `value`, or nullptr
const WebClientRecord* findRecord(const std::vector<WebClientRecord>& records, const wchar_t* type,
                                  const wchar_t* key, const std::wstring& value) {
	for (const WebClientRecord& r : records)
		if (r.type == type && r.fields.find(key) && r.fields.find(key)->text() == value) return &r;
	return nullptr;
}

//! @return a field's text, "" if absent
std::wstring field(const WebClientRecord* r, const wchar_t* key) {
	return r && r->fields.find(key) ? r->fields.find(key)->text() : L"";
}

/*! A Chromium History built here with Chromium's tables: a typed visit, a
 *  link from it, a download through a redirection, a search. */
void chromiumHistory() {
	check(transitionCore(1) == L"typed" && transitionCore(0x30000000 | 0) == L"link" && transitionCore(0x20) == L"32",
	      "chromium: transition core types, an unknown one as its number");
	check(transitionQualifiers(0x02000001 | 0x10000000 | 0x20000000) == L"from_address_bar, chain_start, chain_end"
	      && transitionQualifiers(0x00000100) == L"0x00000100" && transitionQualifiers(1).empty(),
	      "chromium: transition qualifiers, an unknown bit in hexadecimal");
	const FILETIME t = chromiumTime(13370000000000000LL);
	check(value(t) == 133700000000000000ULL && value(chromiumTime(0)) == 0 && value(chromiumTime(-5)) == 0,
	      "chromium: microseconds since 1601 made a FILETIME, 0 and negative are none");

	const std::filesystem::path root = std::filesystem::temp_directory_path() / L"wac-history-test";
	std::error_code ec;
	std::filesystem::remove_all(root, ec);
	std::filesystem::create_directories(root, ec);
	conf._outputDir = (root / L"output").wstring();
	const std::filesystem::path db = root / L"History";
	sqlite3* writer = nullptr;
	sqlite3_open_v2(encodeText(db.wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
	sqlite3_exec(writer,
		"CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);"
		"CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, segment_id INTEGER, visit_duration INTEGER);"
		"CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT, start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,"
		" state INTEGER, danger_type INTEGER, interrupt_reason INTEGER, hash BLOB, end_time INTEGER, opened INTEGER, last_access_time INTEGER, transient INTEGER,"
		" referrer TEXT, site_url TEXT, tab_url TEXT, tab_referrer_url TEXT, mime_type TEXT, original_mime_type TEXT);"
		"CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);"
		"CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT);"
		"INSERT INTO urls VALUES(1, 'https://search.invalid/?q=mimikatz', 'mimikatz - Recherche', 1, 0, 13370000000000000, 0);"
		"INSERT INTO urls VALUES(2, 'https://tools.invalid/get', 'Téléchargement', 1, 1, 13370000060000000, 0);"
		"INSERT INTO visits VALUES(10, 1, 13370000000000000, 0, 33554433, 0, 5000000);"   /* typed | from_address_bar */
		"INSERT INTO visits VALUES(11, 2, 13370000060000000, 10, 805306368, 0, 0);"        /* link | chain_start | chain_end */
		"INSERT INTO downloads VALUES(1, 'g-1', 'C:\\Users\\wac\\Downloads\\m.zip.crdownload', 'C:\\Users\\wac\\Downloads\\m.zip',"
		" 13370000070000000, 1024, 1024, 1, 0, 0, x'00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF', 13370000080000000, 1, 0, 0,"
		" 'https://tools.invalid/get', 'https://tools.invalid/', 'https://tools.invalid/get', '', 'application/zip', 'application/zip');"
		"INSERT INTO downloads_url_chains VALUES(1, 1, 'https://cdn.invalid/m.zip');"
		"INSERT INTO downloads_url_chains VALUES(1, 0, 'https://tools.invalid/dl?id=7');"
		"INSERT INTO keyword_search_terms VALUES(2, 1, 'mimikatz', 'mimikatz');",
		nullptr, nullptr, nullptr);
	sqlite3_close(writer);

	WebClientRecord base;
	base.browser = L"Edge";
	base.browserProfile = L"Default";
	base.sid = L"S-1-5-21-1-2-3-1001";
	base.source = L"C:\\Users\\wac\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History";
	std::vector<WebClientRecord> records;
	check(readChromiumHistory(db.wstring(), base, records) == ERROR_SUCCESS && records.size() == 6,
	      "chromium: 2 URLs, 2 visits, 1 download, 1 search term read");
	const WebClientRecord* typed = findRecord(records, L"Visit", L"Url", L"https://search.invalid/?q=mimikatz");
	check(field(typed, L"Transition") == L"typed" && field(typed, L"TransitionQualifiers") == L"from_address_bar"
	      && field(typed, L"VisitUtc") == timeToIso8601Utc(chromiumTime(13370000000000000LL)) && field(typed, L"DurationMicroseconds") == L"5000000"
	      && typed && !typed->fields.find(L"FromVisitId"), "chromium: the typed visit, its instant and duration");
	const WebClientRecord* link = findRecord(records, L"Visit", L"Url", L"https://tools.invalid/get");
	check(field(link, L"Transition") == L"link" && field(link, L"FromVisitId") == L"10"
	      && field(link, L"FromUrl") == L"https://search.invalid/?q=mimikatz" && field(link, L"Title") == L"T\u00e9l\u00e9chargement",
	      "chromium: the link visit names the visit it came from");
	const WebClientRecord* download = findRecord(records, L"Download", L"Guid", L"g-1");
	const Json* chain = download ? download->fields.find(L"UrlChain") : nullptr;
	check(field(download, L"Url") == L"https://cdn.invalid/m.zip" && chain && chain->members().size() == 2
	      && chain->members()[0].second.text() == L"https://tools.invalid/dl?id=7",
	      "chromium: the download's chain in its order, the final URL last");
	check(field(download, L"State") == L"complete" && field(download, L"Opened") == L"true" && field(download, L"DangerType") == L"0"
	      && field(download, L"CurrentPath") == L"C:\\Users\\wac\\Downloads\\m.zip.crdownload"
	      && field(download, L"SHA256") == L"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
	      && download && !download->fields.find(L"OriginalMimeType") && !download->fields.find(L"InterruptReason"),
	      "chromium: the download's state, paths, hash; equal or zero fields not emitted");
	check(findRecord(records, L"SearchTerm", L"Term", L"mimikatz") && !findRecord(records, L"SearchTerm", L"Term", L"mimikatz")->fields.find(L"NormalizedTerm"),
	      "chromium: the search term, its normalized form only when it differs");
	const Json whole = records[0].toJson();
	check(whole.find(L"Browser") && whole.find(L"Browser")->text() == L"Edge" && whole.find(L"SID") && whole.find(L"Source"),
	      "chromium: each record carries its browser, profile, SID and source");
	std::filesystem::remove_all(root, ec);
}

/*! Firefox's places.sqlite and formhistory.sqlite built here with Firefox's
 *  tables: a typed visit, a link from it, a download whose destination is a
 *  percent-encoded file URI, an address bar input, a search bar entry. */
void firefoxHistory() {
	check(firefoxVisitType(2) == L"typed" && firefoxVisitType(7) == L"download" && firefoxVisitType(0) == L"0"
	      && firefoxVisitType(10) == L"10", "firefox: visit types, an unknown one as its number");
	check(value(firefoxTime(1700000000000000LL)) == 133444736000000000ULL && value(firefoxTime(0)) == 0,
	      "firefox: microseconds since 1970 made a FILETIME");
	check(fileUriToPath(L"file:///C:/Users/wac/T%C3%A9l%C3%A9chargements/m%20k.zip") == L"C:\\Users\\wac\\T\u00e9l\u00e9chargements\\m k.zip"
	      && fileUriToPath(L"https://x.invalid/a") == L"https://x.invalid/a", "firefox: a file URI made a path, UTF-8 decoded");

	const std::filesystem::path root = std::filesystem::temp_directory_path() / L"wac-firefox-test";
	std::error_code ec;
	std::filesystem::remove_all(root, ec);
	std::filesystem::create_directories(root, ec);
	conf._outputDir = (root / L"output").wstring();
	sqlite3* writer = nullptr;
	sqlite3_open_v2(encodeText((root / L"places.sqlite").wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
	sqlite3_exec(writer,
		"CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, rev_host TEXT, visit_count INTEGER, hidden INTEGER, typed INTEGER, frecency INTEGER, last_visit_date INTEGER);"
		"CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER);"
		"CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);"
		"CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, flags INTEGER, expiration INTEGER, type INTEGER, dateAdded INTEGER, lastModified INTEGER);"
		"CREATE TABLE moz_inputhistory(place_id INTEGER, input TEXT, use_count REAL);"
		"INSERT INTO moz_places VALUES(1, 'https://search.invalid/?q=psexec', 'psexec', '', 1, 0, 1, 0, 1700000000000000);"
		"INSERT INTO moz_places VALUES(2, 'https://tools.invalid/m.zip', NULL, '', 1, 0, 0, 0, 1700000060000000);"
		"INSERT INTO moz_historyvisits VALUES(20, 0, 1, 1700000000000000, 2, 0);"
		"INSERT INTO moz_historyvisits VALUES(21, 20, 2, 1700000060000000, 7, 0);"
		"INSERT INTO moz_anno_attributes VALUES(1, 'downloads/destinationFileURI');"
		"INSERT INTO moz_anno_attributes VALUES(2, 'downloads/metaData');"
		"INSERT INTO moz_annos VALUES(1, 2, 1, 'file:///C:/Users/wac/Downloads/m%20k.zip', 0, 4, 3, 1700000061000000, 0);"
		"INSERT INTO moz_annos VALUES(2, 2, 2, '{\"state\":1,\"deleted\":false,\"endTime\":1700000065000,\"fileSize\":4096}', 0, 4, 3, 1700000065000000, 0);"
		"INSERT INTO moz_inputhistory VALUES(1, 'psex', 1.0);",
		nullptr, nullptr, nullptr);
	sqlite3_close(writer);
	sqlite3_open_v2(encodeText((root / L"formhistory.sqlite").wstring()).c_str(), &writer, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
	sqlite3_exec(writer,
		"CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER, guid TEXT);"
		"INSERT INTO moz_formhistory VALUES(1, 'searchbar-history', 'dump lsass', 3, 1700000000000000, 1700000300000000, 'x');",
		nullptr, nullptr, nullptr);
	sqlite3_close(writer);

	WebClientRecord base;
	base.browser = L"Firefox";
	base.browserProfile = L"abcd.default-release";
	std::vector<WebClientRecord> records;
	check(readFirefoxPlaces((root / L"places.sqlite").wstring(), base, records) == ERROR_SUCCESS && records.size() == 6,
	      "firefox: 2 places, 2 visits, 1 download, 1 typed input read");
	const WebClientRecord* visit = findRecord(records, L"Visit", L"Url", L"https://tools.invalid/m.zip");
	check(field(visit, L"Transition") == L"download" && field(visit, L"FromUrl") == L"https://search.invalid/?q=psexec"
	      && field(visit, L"VisitUtc") == timeToIso8601Utc(firefoxTime(1700000060000000LL)),
	      "firefox: the download visit, its instant, the visit it came from");
	const WebClientRecord* download = findRecord(records, L"Download", L"Url", L"https://tools.invalid/m.zip");
	check(field(download, L"TargetPath") == L"C:\\Users\\wac\\Downloads\\m k.zip" && field(download, L"State") == L"1"
	      && field(download, L"ReceivedBytes") == L"4096" && field(download, L"EndUtc") == timeToIso8601Utc(firefoxTime(1700000065000000LL))
	      && download && !download->fields.find(L"Deleted"),
	      "firefox: the download's destination, state, size, end in milliseconds");
	check(field(findRecord(records, L"TypedInput", L"Input", L"psex"), L"Url") == L"https://search.invalid/?q=psexec",
	      "firefox: what was typed in the address bar, and where it led");
	std::vector<WebClientRecord> forms;
	check(readFirefoxFormHistory((root / L"formhistory.sqlite").wstring(), base, forms) == ERROR_SUCCESS && forms.size() == 1
	      && field(&forms[0], L"FieldName") == L"searchbar-history" && field(&forms[0], L"Value") == L"dump lsass"
	      && field(&forms[0], L"TimesUsed") == L"3", "firefox: a search bar entry of the form history");
	std::filesystem::remove_all(root, ec);
}

/*! Saved logins and cookies, Chromium's and Firefox's, built here: what
 *  they say is read, their secrets — password, cookie value — never. */
void loginsAndCookies() {
	const std::filesystem::path root = std::filesystem::temp_directory_path() / L"wac-logins-test";
	std::error_code ec;
	std::filesystem::remove_all(root, ec);
	std::filesystem::create_directories(root, ec);
	conf._outputDir = (root / L"output").wstring();
	auto make = [&](const wchar_t* name, const char* sql) {
		sqlite3* w = nullptr;
		sqlite3_open_v2(encodeText((root / name).wstring()).c_str(), &w, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
		sqlite3_exec(w, sql, nullptr, nullptr, nullptr);
		sqlite3_close(w);
	};
	make(L"Login Data",
		"CREATE TABLE logins(origin_url TEXT, action_url TEXT, username_element TEXT, username_value TEXT, password_element TEXT,"
		" password_value BLOB, signon_realm TEXT, date_created INTEGER, blacklisted_by_user INTEGER, times_used INTEGER,"
		" date_last_used INTEGER, date_password_modified INTEGER);"
		"INSERT INTO logins VALUES('https://mail.invalid/', 'https://mail.invalid/login', 'u', 'alice', 'p', x'763130DEADBEEF', 'https://mail.invalid/',"
		" 13370000000000000, 0, 4, 13380000000000000, 13370000000000000);");
	make(L"Cookies",
		"CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, path TEXT, expires_utc INTEGER, is_secure INTEGER,"
		" is_httponly INTEGER, last_access_utc INTEGER, has_expires INTEGER, is_persistent INTEGER, encrypted_value BLOB);"
		"INSERT INTO cookies VALUES(13370000000000000, '.mail.invalid', 'SID', 'secret-token', '/', 13400000000000000, 1, 1, 13380000000000000, 1, 0, x'763130AA');");
	make(L"cookies.sqlite",
		"CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER,"
		" creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER);"
		"INSERT INTO moz_cookies VALUES(1, 'sess', 'secret-token', '.forum.invalid', '/', 1800000000, 1700000300000000, 1700000000000000, 0, 1);");
	WebClientRecord base;
	base.browser = L"Edge";
	std::vector<WebClientRecord> records;
	check(readChromiumLogins((root / L"Login Data").wstring(), base, records) == ERROR_SUCCESS
	      && readChromiumCookies((root / L"Cookies").wstring(), base, records) == ERROR_SUCCESS && records.size() == 2,
	      "logins: Chromium's saved login and cookie read");
	const WebClientRecord* login = findRecord(records, L"SavedLogin", L"UserName", L"alice");
	check(field(login, L"Origin") == L"https://mail.invalid/" && field(login, L"Action") == L"https://mail.invalid/login"
	      && field(login, L"TimesUsed") == L"4" && field(login, L"LastUsedUtc") == timeToIso8601Utc(chromiumTime(13380000000000000LL)),
	      "logins: Chromium's login: site, account, uses, last use");
	const WebClientRecord* cookie = findRecord(records, L"Cookie", L"Name", L"SID");
	check(field(cookie, L"Host") == L".mail.invalid" && field(cookie, L"Session") == L"true" && field(cookie, L"Secure") == L"true",
	      "logins: Chromium's cookie: site, name, flags");
	records.clear();
	base.browser = L"Firefox";
	check(readFirefoxLogins(L"{\"nextId\":2,\"logins\":[{\"id\":1,\"hostname\":\"https://bank.invalid\",\"httpRealm\":null,"
	                        L"\"formSubmitURL\":\"https://bank.invalid\",\"encryptedUsername\":\"MDoEEPgAAA\",\"encryptedPassword\":\"MDoEEPgBBB\","
	                        L"\"timeCreated\":1700000000000,\"timeLastUsed\":1700000100000,\"timePasswordChanged\":1700000000000,\"timesUsed\":2}]}",
	                        base, records) == ERROR_SUCCESS
	      && readFirefoxCookies((root / L"cookies.sqlite").wstring(), base, records) == ERROR_SUCCESS && records.size() == 2,
	      "logins: Firefox's saved login and cookie read");
	const WebClientRecord* firefoxLogin = findRecord(records, L"SavedLogin", L"Origin", L"https://bank.invalid");
	check(field(firefoxLogin, L"TimesUsed") == L"2" && field(firefoxLogin, L"LastUsedUtc") == timeToIso8601Utc(firefoxTime(1700000100000000LL))
	      && firefoxLogin && !firefoxLogin->fields.find(L"Realm") && !firefoxLogin->fields.find(L"UserName"),
	      "logins: Firefox's login: site, uses, last use; its encrypted account not given");
	const WebClientRecord* firefoxCookie = findRecord(records, L"Cookie", L"Name", L"sess");
	check(field(firefoxCookie, L"ExpiresUtc") == timeToIso8601Utc(firefoxTime(1800000000000000LL)) && field(firefoxCookie, L"HttpOnly") == L"true",
	      "logins: Firefox's cookie: its expiry in seconds converted");
	check(readFirefoxLogins(L"not json", base, records) == HRESULT_FROM_WIN32(ERROR_INVALID_DATA), "logins: a logins.json that is no JSON refused");
	// No secret in any record: neither the passwords nor the cookie values.
	bool clean = true;
	std::vector<WebClientRecord> all;
	readChromiumLogins((root / L"Login Data").wstring(), base, all);
	readChromiumCookies((root / L"Cookies").wstring(), base, all);
	readFirefoxCookies((root / L"cookies.sqlite").wstring(), base, all);
	for (const WebClientRecord& r : all) {
		const std::wstring text = r.toJson().dump();
		if (text.find(L"secret-token") != std::wstring::npos || text.find(L"763130") != std::wstring::npos
		    || text.find(L"MDoEEPg") != std::wstring::npos) clean = false;
	}
	check(clean, "logins: no password and no cookie value in the JSON");
	std::filesystem::remove_all(root, ec);
}

/*! A Prefetch metric entry's $MFT reference: eight bytes, 48 of entry and 16
 *  of sequence, followed by the next entry. The split by hand read the
 *  sequence on four bytes — taking two from what follows — and lost the
 *  entry's high 16 bits; both are given values that show it. */
void prefetchReference() {
	const uint8_t bytes[10] = { 0x44, 0x19, 0x00, 0x00, 0x01, 0x00,   // entry 0x1_0000_1944
	                            0x02, 0x00,                           // sequence 2
	                            0xEF, 0x2D };                         // the next entry's first bytes
	const MFTInformation reference(const_cast<LPBYTE>(bytes));
	check(reference.entryIndex == 0x100001944ULL, "prefetch: $MFT reference entry on 48 bits");
	check(reference.sequenceNumber == 2, "prefetch: sequence on 16 bits, nothing read beyond the 8 bytes");
	const NtfsReference split = splitNtfsReference(0xFFFF800000000005ULL);
	check(split.entry == 0x800000000005ULL && split.sequence == 0xFFFF, "ntfs reference: high bits to the sequence only");
}

/*! Explorer's caches (CMMM). The reference is Windows itself: the 48 bytes of
 *  an entry header of the test VM's iconcache_48.db and the checksum Windows
 *  wrote after them. Then a cache built here: decoded, its checksums found
 *  valid, a byte the data checksum samples caught when changed, one it skips
 *  not — the format's own choice —, and forged lengths stopping the reading. */
void thumbcache() {
	const uint8_t header[48] = { 0x43, 0x4D, 0x4D, 0x4D, 0xF0, 0x24, 0x00, 0x00, 0xB2, 0xB4, 0x6B, 0xFD, 0xC4, 0x35, 0x14, 0x59,
	                             0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x96, 0x24, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
	                             0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x4F, 0x4E, 0x58, 0xC0, 0x36, 0x67, 0xE7 };
	check(thumbcacheCrc64(header, sizeof header, ~0ULL) == 0x209DE6BD12D112A4ULL, "thumbcache: header checksum as Windows wrote it");
	// A cache of one entry: identifier "0123456789abcdef", 2 bytes of padding, a 2,000-byte PNG.
	const std::wstring identifier = L"0123456789abcdef";
	std::vector<uint8_t> data(2000);
	for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i * 7 + 3);
	const uint8_t png[4] = { 0x89, 'P', 'N', 'G' };
	memcpy(data.data(), png, 4);
	auto build = [&](const std::vector<uint8_t>& image, uint32_t identifierBytes) {
		std::vector<uint8_t> f(24 + 56 + identifier.size() * 2 + 2 + image.size());
		memcpy(f.data(), "CMMM", 4);
		writeLittleEndian<uint32_t>(f.data() + 4, 0x20);
		writeLittleEndian<uint32_t>(f.data() + 8, 4);                   // 256 pixels
		writeLittleEndian<uint32_t>(f.data() + 16, 24);
		writeLittleEndian<uint32_t>(f.data() + 20, (uint32_t)f.size());
		uint8_t* e = f.data() + 24;
		memcpy(e, "CMMM", 4);
		writeLittleEndian<uint32_t>(e + 4, (uint32_t)(f.size() - 24));
		writeLittleEndian<uint64_t>(e + 8, 0x0123456789ABCDEFULL);
		writeLittleEndian<uint32_t>(e + 16, identifierBytes);
		writeLittleEndian<uint32_t>(e + 20, 2);
		writeLittleEndian<uint32_t>(e + 24, (uint32_t)image.size());
		writeLittleEndian<uint32_t>(e + 28, 256);
		writeLittleEndian<uint32_t>(e + 32, 192);
		for (size_t i = 0; i < identifier.size(); ++i) writeLittleEndian<uint16_t>(e + 56 + 2 * i, (uint16_t)identifier[i]);
		memcpy(e + 56 + identifier.size() * 2 + 2, data.data(), image.size());
		writeLittleEndian<uint64_t>(e + 40, thumbcacheDataChecksum(data.data(), data.size()));
		writeLittleEndian<uint64_t>(e + 48, thumbcacheCrc64(e, 48, ~0ULL));
		return f;
	};
	std::vector<uint8_t> file = build(data, (uint32_t)identifier.size() * 2);
	ThumbcacheFile cache;
	check(decodeThumbcache(file, cache) && cache.entries.size() == 1 && cache.entries[0].hash == 0x0123456789ABCDEFULL
	      && cache.entries[0].identifier == identifier && cache.entries[0].width == 256 && cache.entries[0].height == 192
	      && cache.entries[0].dataSize == 2000 && cache.entries[0].headerChecksumValid && cache.entries[0].dataChecksumValid
	      && thumbcacheSize(cache.version, cache.type) == L"256", "thumbcache: an entry decoded, both checksums valid");
	const size_t at = cache.entries.empty() ? 0 : cache.entries[0].dataOffset;
	std::vector<uint8_t> sampled = file, skipped = file;
	sampled[at + 1024] ^= 0xFF;   // the first of the four bytes taken every 400
	skipped[at + 1030] ^= 0xFF;   // between two samples
	ThumbcacheFile a, b;
	check(decodeThumbcache(sampled, a) && a.entries.size() == 1 && !a.entries[0].dataChecksumValid,
	      "thumbcache: a byte the data checksum covers, changed, is caught");
	check(decodeThumbcache(skipped, b) && b.entries.size() == 1 && b.entries[0].dataChecksumValid,
	      "thumbcache: a byte between the samples is not — as Windows computes it");
	std::vector<uint8_t> forged = build(data, 0x7FFFFFFE);   // identifier longer than the entry
	ThumbcacheFile c;
	check(decodeThumbcache(forged, c) && c.entries.empty(), "thumbcache: a forged length stops the reading");
	std::vector<uint8_t> cut(file.begin(), file.begin() + 100);
	writeLittleEndian<uint32_t>(cut.data() + 20, 0xFFFFFFFF);   // first free place beyond the file
	ThumbcacheFile d;
	check(decodeThumbcache(cut, d) && d.entries.empty(), "thumbcache: a cut file read no further than its end");
	/* REMNANTS: an entry past the first free place, whole, is read and
	   flagged; one whose header was rewritten is not, and the walk stops
	   there; one whose image was rewritten keeps its header, not its image. */
	std::vector<uint8_t> withRemnant = file;
	withRemnant.insert(withRemnant.end(), file.begin() + 24, file.end());   // the same entry again, past the free place
	ThumbcacheFile r;
	check(decodeThumbcache(withRemnant, r) && r.entries.size() == 2 && !r.entries[0].remnant && r.entries[1].remnant
	      && r.entries[1].headerChecksumValid && r.entries[1].dataChecksumValid && r.entries[1].offset == file.size(),
	      "thumbcache: a whole entry past the first free place read as a remnant");
	std::vector<uint8_t> rewrittenHeader = withRemnant;
	rewrittenHeader[file.size() + 8] ^= 0xFF;   // its hash, which its header checksum covers
	check(decodeThumbcache(rewrittenHeader, r) && r.entries.size() == 1, "thumbcache: a remnant whose header was rewritten kept");
	std::vector<uint8_t> rewrittenImage = withRemnant;
	rewrittenImage[file.size() + (cache.entries.empty() ? 0 : cache.entries[0].dataOffset - 24)] ^= 0xFF;   // the remnant's first image byte
	check(decodeThumbcache(rewrittenImage, r) && r.entries.size() == 2 && r.entries[1].remnant && !r.entries[1].dataChecksumValid,
	      "thumbcache: a remnant whose image was rewritten lost, or its image taken as valid");
	/* VISTA (0x14): the first entry header of the Vista VM's thumbcache_96.db
	   and the checksum Windows wrote after its first 48 bytes; then a Vista
	   cache built here, the source's extension after the hash and every later
	   field eight bytes further than on Windows 7. */
	const uint8_t vistaHeader[56] = {
	                                 0x43, 0x4D, 0x4D, 0x4D, 0x90, 0x6C, 0x00, 0x00, 0x7E, 0x5A, 0x2D, 0x8B, 0xB0, 0x2B, 0x25, 0x36,
	                                 0x6A, 0x00, 0x70, 0x00, 0x67, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	                                 0x36, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x89, 0xD6, 0x65, 0x0C, 0xFF, 0xF4, 0xE5, 0x5A,
	                                 0x0A, 0x5E, 0x8F, 0x93, 0x32, 0xE3, 0xB8, 0xA4 };
	check(thumbcacheCrc64(vistaHeader, 48, ~0ULL) == readLittleEndian<uint64_t>(vistaHeader + 48),
	      "thumbcache of Vista: header checksum as Windows wrote it");
	std::vector<uint8_t> vista(24 + 56 + identifier.size() * 2 + 2 + data.size());
	memcpy(vista.data(), "CMMM", 4);
	writeLittleEndian<uint32_t>(vista.data() + 4, 0x14);
	writeLittleEndian<uint32_t>(vista.data() + 8, 1);                   // 96 pixels
	writeLittleEndian<uint32_t>(vista.data() + 12, 24);
	writeLittleEndian<uint32_t>(vista.data() + 16, (uint32_t)vista.size());
	writeLittleEndian<uint32_t>(vista.data() + 20, 1);
	uint8_t* v = vista.data() + 24;
	memcpy(v, "CMMM", 4);
	writeLittleEndian<uint32_t>(v + 4, (uint32_t)(vista.size() - 24));
	writeLittleEndian<uint64_t>(v + 8, 0x36252BB08B2D5A7EULL);
	for (size_t i = 0; i < 3; ++i) writeLittleEndian<uint16_t>(v + 16 + 2 * i, (uint16_t)"png"[i]);
	writeLittleEndian<uint32_t>(v + 24, (uint32_t)identifier.size() * 2);
	writeLittleEndian<uint32_t>(v + 28, 2);
	writeLittleEndian<uint32_t>(v + 32, (uint32_t)data.size());
	for (size_t i = 0; i < identifier.size(); ++i) writeLittleEndian<uint16_t>(v + 56 + 2 * i, (uint16_t)identifier[i]);
	memcpy(v + 56 + identifier.size() * 2 + 2, data.data(), data.size());
	writeLittleEndian<uint64_t>(v + 40, thumbcacheDataChecksum(data.data(), data.size()));
	writeLittleEndian<uint64_t>(v + 48, thumbcacheCrc64(v, 48, ~0ULL));
	ThumbcacheFile g;
	check(decodeThumbcache(vista, g) && !g.unsupportedFormat && g.entries.size() == 1 && g.entries[0].hash == 0x36252BB08B2D5A7EULL
	      && g.entries[0].extension == L"png" && g.entries[0].identifier == identifier && g.entries[0].dataSize == 2000
	      && g.entries[0].width == 0 && g.entries[0].headerChecksumValid && g.entries[0].dataChecksumValid
	      && thumbcacheSize(g.version, g.type) == L"96",
	      "thumbcache of Vista: extension, identifier, image and both checksums at their places");
	writeLittleEndian<uint32_t>(vista.data() + 4, 0x21);   // a version nobody has seen yet
	check(decodeThumbcache(vista, g) && g.unsupportedFormat && g.entries.empty(), "thumbcache: an unknown version decoded");
	check(!cache.unsupportedFormat, "thumbcache: the Windows 10 layout declared unsupported");
}

/*! Windows 7's layout (version 0x15): first the 48 bytes of an entry of the
 *  test VM's thumbcache_256.db, whose header checksum, over its first 40
 *  bytes, is the one Windows wrote after them. Then a cache of that version
 *  built here — offsets at 12 and 16 in the file header, an entry of 48
 *  bytes, checksums at 32 and 40, no width nor height — decoded with both
 *  checksums valid, its type named by Windows 7's sizes. */
void thumbcacheWindows7() {
	const uint8_t header[48] = { 0x43, 0x4D, 0x4D, 0x4D, 0x80, 0x00, 0x00, 0x00, 0xE8, 0x4E, 0xB8, 0xF9, 0x51, 0xBC, 0x24, 0x09,
	                             0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D, 0xFE, 0x28, 0x91, 0x9F, 0x41, 0x8B, 0x4D };
	check(thumbcacheCrc64(header, 40, ~0ULL) == readLittleEndian<uint64_t>(header + 40),
	      "thumbcache: Windows 7 header checksum as Windows wrote it");
	const std::wstring identifier = L"a5c4cc8a55cc40e9";
	std::vector<uint8_t> data(1500);
	for (size_t i = 0; i < data.size(); ++i) data[i] = (uint8_t)(i * 11 + 5);
	data[0] = 'B';
	data[1] = 'M';
	std::vector<uint8_t> file(24 + 48 + identifier.size() * 2 + data.size());
	memcpy(file.data(), "CMMM", 4);
	writeLittleEndian<uint32_t>(file.data() + 4, 0x15);
	writeLittleEndian<uint32_t>(file.data() + 8, 1);                      // 96 pixels on Windows 7
	writeLittleEndian<uint32_t>(file.data() + 12, 24);                    // first entry
	writeLittleEndian<uint32_t>(file.data() + 16, (uint32_t)file.size()); // first free place
	writeLittleEndian<uint32_t>(file.data() + 20, 1);                     // entries
	uint8_t* e = file.data() + 24;
	memcpy(e, "CMMM", 4);
	writeLittleEndian<uint32_t>(e + 4, (uint32_t)(file.size() - 24));
	writeLittleEndian<uint64_t>(e + 8, 0xA5C4CC8A55CC40E9ULL);
	writeLittleEndian<uint32_t>(e + 16, (uint32_t)identifier.size() * 2);
	writeLittleEndian<uint32_t>(e + 24, (uint32_t)data.size());
	for (size_t i = 0; i < identifier.size(); ++i) writeLittleEndian<uint16_t>(e + 48 + 2 * i, (uint16_t)identifier[i]);
	memcpy(e + 48 + identifier.size() * 2, data.data(), data.size());
	writeLittleEndian<uint64_t>(e + 32, thumbcacheDataChecksum(data.data(), data.size()));
	writeLittleEndian<uint64_t>(e + 40, thumbcacheCrc64(e, 40, ~0ULL));
	ThumbcacheFile cache;
	check(decodeThumbcache(file, cache) && !cache.unsupportedFormat && cache.entries.size() == 1
	      && cache.entries[0].hash == 0xA5C4CC8A55CC40E9ULL && cache.entries[0].identifier == identifier
	      && cache.entries[0].dataSize == data.size() && cache.entries[0].width == 0 && cache.entries[0].height == 0
	      && cache.entries[0].headerChecksumValid && cache.entries[0].dataChecksumValid
	      && thumbcacheSize(cache.version, cache.type) == L"96",
	      "thumbcache: a Windows 7 entry decoded, both checksums valid, its size named as Windows 7 numbers them");
	std::vector<uint8_t> later = file;
	writeLittleEndian<uint32_t>(later.data() + 4, 0x20);   // the same bytes read as Windows 10's
	ThumbcacheFile other;
	check(decodeThumbcache(later, other) && (other.entries.empty() || !other.entries[0].headerChecksumValid),
	      "thumbcache: a Windows 7 entry read with Windows 10's layout and found valid");
}

/*! Thunderbird's mail: an mbox of two messages written here, decoded. What a
 *  sender controls is all there: encoded words (B and Q), a quoted-printable
 *  body, a base64 attachment with an RFC 2231 name, a nested multipart, a
 *  multipart without its boundary, a ">From" line in a body, a Date with its
 *  offset. The VM cycle confronts the real thing with Python's mailbox. */
void mboxMail() {
	check(decodeEncodedWords("=?UTF-8?B?VMOpbW9pbg==?= =?ISO-8859-1?Q?caf=E9_cr=E8me?= fin") == L"T\u00e9moincaf\u00e9 cr\u00e8me fin",
	      "mail: encoded words B and Q, the space between two of them dropped");
	FILETIME t{};
	check(parseMailDate("Wed, 07 Oct 2026 21:05:09 +0200", t) && timeToIso8601Utc(t) == L"2026-10-07T19:05:09.0000000Z",
	      "mail: a Date with its offset, in UTC");
	check(!parseMailDate("not a date", t), "mail: a Date that is none refused");
	const std::string first =
		"From - Wed Oct 07 19:05:09 2026\r\n"
		"From: =?UTF-8?Q?T=C3=A9moin?= <temoin@wac-test.invalid>\r\n"
		"To: WAC <wac@wac-test.invalid>\r\n"
		"Subject: =?UTF-8?B?VMOpbW9pbiBXQUM=?=\r\n"
		"Date: Wed, 07 Oct 2026 19:05:09 +0000\r\n"
		"Message-ID: <one@wac-test.invalid>\r\n"
		"Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n"
		"--outer\r\n"
		"Content-Type: multipart/alternative; boundary=inner\r\n\r\n"
		"--inner\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
		"Corps du t=C3=A9moin, ligne =\r\ncoup=C3=A9e\r\n"
		"--inner\r\nContent-Type: text/html\r\n\r\n<p>t</p>\r\n--inner--\r\n"
		"--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n"
		"Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.bin\r\n\r\nV0FD\r\n"
		"--outer--\r\n\r\n";
	const std::string second =
		"From - Wed Oct 07 19:06:00 2026\r\n"
		"Subject: plain\r\nContent-Type: multipart/mixed\r\n\r\n"   // no boundary: no part read, no failure
		">From the start of a line\r\n";
	const std::filesystem::path box = std::filesystem::temp_directory_path() / "wac-mbox-test";
	{ std::ofstream(box, std::ios::binary) << first << second; }
	std::vector<MimeMessage> messages;
	size_t skipped = 0;
	const bool read = forEachMboxMessage(box.wstring(), [&](MimeMessage& m) { messages.push_back(m); }, skipped);
	check(read && messages.size() == 2 && skipped == 0, "mail: an mbox of two messages split at its From lines");
	if (messages.size() == 2) {
		const MimeMessage& m = messages[0];
		check(m.subject == L"T\u00e9moin WAC" && m.from == L"T\u00e9moin <temoin@wac-test.invalid>" && m.messageId == L"<one@wac-test.invalid>"
		      && timeToIso8601Utc(m.dateUtc) == L"2026-10-07T19:05:09.0000000Z", "mail: headers decoded");
		// The line break before a boundary belongs to the boundary (RFC 2046 §5.1.1), not to the part.
		check(m.body == L"Corps du t\u00e9moin, ligne coup\u00e9e" && std::string(m.html.begin(), m.html.end()) == "<p>t</p>",
		      "mail: quoted-printable body with a soft break, and the HTML part, out of a nested multipart");
		check(m.attachments.size() == 1 && m.attachments[0].fileName == L"r\u00e9sum\u00e9.bin"
		      && std::string(m.attachments[0].data.begin(), m.attachments[0].data.end()) == "WAC",
		      "mail: a base64 attachment with its RFC 2231 name");
		check(messages[1].subject == L"plain" && messages[1].attachments.empty() && messages[0].offset == first.find('\n') + 1,
		      "mail: a multipart without boundary read without parts; the offset after the From line");
	}
	std::error_code ec;
	std::filesystem::remove(box, ec);
	const std::filesystem::path other = std::filesystem::temp_directory_path() / "wac-not-mbox";
	{ std::ofstream(other, std::ios::binary) << "SQLite format 3"; }
	size_t none = 0;
	check(!forEachMboxMessage(other.wstring(), [](MimeMessage&) {}, none), "mail: a file that is not an mbox refused");
	std::filesystem::remove(other, ec);
}

} // namespace

/*! A DestList of a version without decoder, presented to the decoder: 5 and
 *  7, which nobody has seen, with one entry announced — declared unsupported,
 *  no entry read; 6, the version of Windows 11, is read. */
void destListVersion() {
	std::vector<uint8_t> stream(32 + 130 + 8, 0);
	writeLittleEndian<uint32_t>(stream.data() + 4, 1);     // one entry announced
	for (uint32_t version : { 5u, 7u, 2u }) {
		writeLittleEndian<uint32_t>(stream.data(), version);
		const DestFileDirectory list(stream.data(), stream.size());
		check(list.unsupportedFormat && list.destfiles.empty() && list.formatVersion == (int)version,
		      "jump list: a DestList version without decoder read, or not declared unsupported");
	}
	writeLittleEndian<uint32_t>(stream.data(), 6);
	const DestFileDirectory eleven(stream.data(), stream.size());
	check(!eleven.unsupportedFormat && eleven.destfiles.size() == 1, "jump list: the DestList version of Windows 11 not read");
}

/*! ShimCache of Windows 7 (0xBADC0FEE), 64-bit and 32-bit layouts, as the
 *  format lays them out: two entries, their paths stored after the table. */
std::vector<BYTE> windows7Cache(bool wide, bool lyingOffset) {
	const size_t header = 0x80, entry = wide ? 48 : 32;
	const std::wstring paths[2] = { L"\\??\\C:\\Windows\\a.exe", L"\\??\\C:\\b.dll" };
	std::vector<BYTE> v(header + 2 * entry, 0);
	const uint32_t magic = 0xBADC0FEE, count = 2;
	memcpy(v.data(), &magic, 4);
	memcpy(v.data() + 4, &count, 4);
	for (int i = 0; i < 2; ++i) {
		BYTE* e = v.data() + header + i * entry;
		const uint16_t length = (uint16_t)(paths[i].size() * 2);
		const uint64_t offset = v.size() + (lyingOffset && i == 1 ? 4096 : 0);
		memcpy(e, &length, 2);
		memcpy(e + 2, &length, 2);
		if (wide) memcpy(e + 8, &offset, 8); else { const uint32_t o = (uint32_t)offset; memcpy(e + 4, &o, 4); }
		const uint64_t modified = 0x01D8A0A0B0C0D0E0ULL + i;
		memcpy(e + (wide ? 16 : 8), &modified, 8);
		const size_t at = v.size();
		v.resize(at + length);
		memcpy(v.data() + at, paths[i].data(), length);
	}
	return v;
}

void shimcacheWindows7() {
	for (const bool wide : { true, false }) {
		Shimcaches s;
		check(s.parse(windows7Cache(wide, false)) == S_OK && s.shimcaches.size() == 2
		      && s.shimcaches[0].path == L"\\??\\C:\\Windows\\a.exe" && s.shimcaches[1].path == L"\\??\\C:\\b.dll"
		      && s.shimcaches[1].position == 1 && !s.shimcaches[0].lastModificationUtc.empty(),
		      wide ? "ShimCache of Windows 7, 64-bit: paths, order, dates" : "ShimCache of Windows 7, 32-bit: paths, order, dates");
	}
	Shimcaches lying;
	check(lying.parse(windows7Cache(true, true)) == S_OK && lying.shimcaches.size() == 1,
	      "ShimCache of Windows 7: a path beyond the value read");
	std::vector<BYTE> outside = windows7Cache(true, false);
	outside[0x80 + 9] = 0xFF;                                       // the first path beyond the value, in both readings
	Shimcaches none;
	check(none.parse(outside) == ERROR_INVALID_DATA && none.shimcaches.empty(), "ShimCache of Windows 7: a layout guessed");
	const std::vector<BYTE> whole = windows7Cache(true, false);
	Shimcaches cut;
	check(cut.parse(std::vector<BYTE>(whole.begin(), whole.begin() + 0x40)) == ERROR_INVALID_DATA,
	      "ShimCache of Windows 7: a value shorter than its header read");
}

/*! ShimCache of Vista (0xBADC0FFE): three real entries of the Vista VM's
 *  value (SP2 x86), their paths moved next to them — as Windows stores
 *  them, the first entry's last. Paths and dates as dissect.target reads
 *  them. Server 2003 writes the same magic: its form, not measured, stays
 *  undecoded — the examined version tells them apart. */
void shimcacheVista() {
	const std::vector<BYTE> value = {
		0xFE, 0x0F, 0xDC, 0xBA, 0x03, 0x00, 0x00, 0x00, 0x46, 0x00, 0x48, 0x00, 0xE4, 0x00, 0x00, 0x00,
		0x04, 0x41, 0x3D, 0xCB, 0xD4, 0x5B, 0xC8, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x00, 0x4A, 0x00, 0x9A, 0x00, 0x00, 0x00, 0x60, 0xCD, 0xB0, 0xA6, 0x63, 0xFE, 0xC6, 0x01,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x4A, 0x00, 0x50, 0x00, 0x00, 0x00,
		0x10, 0x5F, 0x5D, 0xAE, 0x63, 0xFE, 0xC6, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x5C, 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00,
		0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x73, 0x00,
		0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00,
		0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x63, 0x00, 0x6C, 0x00, 0x73, 0x00, 0x69, 0x00, 0x64, 0x00,
		0x2E, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00, 0x00, 0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00,
		0x5C, 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00,
		0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00,
		0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00, 0x72, 0x00, 0x75, 0x00, 0x6E, 0x00,
		0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x33, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00,
		0x65, 0x00, 0x00, 0x00, 0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x5C, 0x00, 0x43, 0x00, 0x3A, 0x00,
		0x5C, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00,
		0x5C, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00,
		0x32, 0x00, 0x5C, 0x00, 0x4C, 0x00, 0x6F, 0x00, 0x67, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x55, 0x00,
		0x49, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00, 0x00,
	};
	const WindowsVersion examined = conf.examinedVersion;
	conf.examinedVersion = WindowsVersion{ 6002, false, false };
	Shimcaches s;
	check(s.parse(value) == S_OK && !s.unsupportedFormat && s.shimcaches.size() == 3
	      && s.shimcaches[0].path == L"\\??\\C:\\Windows\\system32\\LogonUI.exe" && s.shimcaches[0].lastModificationUtc == L"2008-01-21T02:24:48.1042692Z"
	      && s.shimcaches[1].path == L"\\??\\C:\\Windows\\system32\\rundll32.exe" && s.shimcaches[1].lastModificationUtc == L"2006-11-02T09:45:37.8460000Z"
	      && s.shimcaches[2].path == L"\\??\\C:\\Windows\\system32\\verclsid.exe" && s.shimcaches[2].lastModificationUtc == L"2006-11-02T09:45:50.7210000Z",
	      "ShimCache of Vista: paths, order and dates as dissect.target reads them");
	conf.examinedVersion = WindowsVersion{ 3790, true, false };
	Shimcaches server2003;
	check(server2003.parse(value) == S_OK && server2003.unsupportedFormat && server2003.shimcaches.empty(),
	      "ShimCache 0xBADC0FFE of Server 2003 decoded with Vista's layout");
	conf.examinedVersion = examined;
}

/*! ShimCache of Windows 8 ("00ts" entries): the header and first entry of
 *  the Windows 8 VM's value, as Windows wrote them — the layout of Windows
 *  8.1 under another tag, its package size 0. */
void shimcacheWindows8() {
	const std::vector<BYTE> value = {
		0x00, 0x00, 0x00, 0x00, 0xB2, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8D, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x03, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00,
		0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC4, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x30, 0x30, 0x74, 0x73, 0xB1, 0xC5, 0x4E, 0x1D, 0x70, 0x00, 0x00, 0x00, 0x58, 0x00, 0x53, 0x00,
		0x59, 0x00, 0x53, 0x00, 0x56, 0x00, 0x4F, 0x00, 0x4C, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x69, 0x00,
		0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x53, 0x00, 0x79, 0x00,
		0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00, 0x53, 0x00,
		0x65, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x68, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6C, 0x00,
		0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x48, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x74, 0x00, 0x2E, 0x00,
		0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xF0, 0x9C, 0x32, 0xAB, 0xDD, 0x6A, 0xCD, 0x01, 0x00, 0x00, 0x00, 0x00
	};
	Shimcaches s;
	check(s.parse(value) == S_OK && !s.unsupportedFormat && s.shimcaches.size() == 1
	      && s.shimcaches[0].path == L"SYSVOL\\Windows\\System32\\SearchFilterHost.exe"
	      && s.shimcaches[0].lastModificationUtc.compare(0, 10, L"2012-07-26") == 0,
	      "ShimCache of Windows 8: the \"00ts\" entry read, path and date");
}

/*! A Prefetch of version 17, as Windows XP wrote it on the test VM
 *  (SPOOLSV.EXE, 780 bytes): its run count, its last run, its volume and its
 *  two files as libscca reads them. */
void prefetchVersion17() {
	std::vector<BYTE> file = {
		0x11, 0x00, 0x00, 0x00, 0x53, 0x43, 0x43, 0x41, 0x0F, 0x00, 0x00, 0x00, 0x0C, 0x03, 0x00, 0x00,
		0x53, 0x00, 0x50, 0x00, 0x4F, 0x00, 0x4F, 0x00, 0x4C, 0x00, 0x53, 0x00, 0x56, 0x00, 0x2E, 0x00,
		0x45, 0x00, 0x58, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x0A, 0x9B, 0x19, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x40, 0x9D, 0xF1, 0xF6, 0x00, 0x00, 0x00, 0x00, 0xA7, 0x76, 0x2F, 0x28,
		0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0xD8, 0x00, 0x00, 0x00, 0xCE, 0x00, 0x00, 0x00, 0xA8, 0x01, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00, 0xBE, 0xB5, 0xD4, 0x53, 0x29, 0x5B, 0xDD, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x54, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x90, 0x06, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x5C, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00,
		0x49, 0x00, 0x43, 0x00, 0x45, 0x00, 0x5C, 0x00, 0x48, 0x00, 0x41, 0x00, 0x52, 0x00, 0x44, 0x00,
		0x44, 0x00, 0x49, 0x00, 0x53, 0x00, 0x4B, 0x00, 0x56, 0x00, 0x4F, 0x00, 0x4C, 0x00, 0x55, 0x00,
		0x4D, 0x00, 0x45, 0x00, 0x31, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x44, 0x00,
		0x4F, 0x00, 0x57, 0x00, 0x53, 0x00, 0x5C, 0x00, 0x53, 0x00, 0x59, 0x00, 0x53, 0x00, 0x54, 0x00,
		0x45, 0x00, 0x4D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00, 0x47, 0x00, 0x44, 0x00, 0x49, 0x00,
		0x33, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x44, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x00, 0x00, 0x5C, 0x00,
		0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x49, 0x00, 0x43, 0x00, 0x45, 0x00, 0x5C, 0x00, 0x48, 0x00,
		0x41, 0x00, 0x52, 0x00, 0x44, 0x00, 0x44, 0x00, 0x49, 0x00, 0x53, 0x00, 0x4B, 0x00, 0x56, 0x00,
		0x4F, 0x00, 0x4C, 0x00, 0x55, 0x00, 0x4D, 0x00, 0x45, 0x00, 0x31, 0x00, 0x5C, 0x00, 0x57, 0x00,
		0x49, 0x00, 0x4E, 0x00, 0x44, 0x00, 0x4F, 0x00, 0x57, 0x00, 0x53, 0x00, 0x5C, 0x00, 0x53, 0x00,
		0x59, 0x00, 0x53, 0x00, 0x54, 0x00, 0x45, 0x00, 0x4D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00,
		0x57, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x33, 0x00, 0x32, 0x00, 0x4B, 0x00, 0x2E, 0x00, 0x53, 0x00,
		0x59, 0x00, 0x53, 0x00, 0x00, 0x00, 0x00, 0x13, 0x28, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
		0x00, 0xD4, 0xA6, 0x7A, 0x39, 0x5B, 0xDD, 0x01, 0xB2, 0xF5, 0x7A, 0xE4, 0x58, 0x00, 0x00, 0x00,
		0x30, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x77, 0x7A, 0x63, 0x73,
		0x5C, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x49, 0x00, 0x43, 0x00, 0x45, 0x00, 0x5C, 0x00,
		0x48, 0x00, 0x41, 0x00, 0x52, 0x00, 0x44, 0x00, 0x44, 0x00, 0x49, 0x00, 0x53, 0x00, 0x4B, 0x00,
		0x56, 0x00, 0x4F, 0x00, 0x4C, 0x00, 0x55, 0x00, 0x4D, 0x00, 0x45, 0x00, 0x31, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x28, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x3B, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
		0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x18, 0x00, 0x5C, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x49, 0x00, 0x43, 0x00, 0x45, 0x00,
		0x5C, 0x00, 0x48, 0x00, 0x41, 0x00, 0x52, 0x00, 0x44, 0x00, 0x44, 0x00, 0x49, 0x00, 0x53, 0x00,
		0x4B, 0x00, 0x56, 0x00, 0x4F, 0x00, 0x4C, 0x00, 0x55, 0x00, 0x4D, 0x00, 0x45, 0x00, 0x31, 0x00,
		0x5C, 0x00, 0x00, 0x00, 0x20, 0x00, 0x5C, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x49, 0x00,
		0x43, 0x00, 0x45, 0x00, 0x5C, 0x00, 0x48, 0x00, 0x41, 0x00, 0x52, 0x00, 0x44, 0x00, 0x44, 0x00,
		0x49, 0x00, 0x53, 0x00, 0x4B, 0x00, 0x56, 0x00, 0x4F, 0x00, 0x4C, 0x00, 0x55, 0x00, 0x4D, 0x00,
		0x45, 0x00, 0x31, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x44, 0x00, 0x4F, 0x00,
		0x57, 0x00, 0x53, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x29, 0x00, 0x5C, 0x00, 0x44, 0x00, 0x45, 0x00,
		0x56, 0x00, 0x49, 0x00, 0x43, 0x00, 0x45, 0x00, 0x5C, 0x00, 0x48, 0x00, 0x41, 0x00, 0x52, 0x00,
		0x44, 0x00, 0x44, 0x00, 0x49, 0x00, 0x53, 0x00, 0x4B, 0x00, 0x56, 0x00, 0x4F, 0x00, 0x4C, 0x00,
		0x55, 0x00, 0x4D, 0x00, 0x45, 0x00, 0x31, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4E, 0x00,
		0x44, 0x00, 0x4F, 0x00, 0x57, 0x00, 0x53, 0x00, 0x5C, 0x00, 0x53, 0x00, 0x59, 0x00, 0x53, 0x00,
		0x54, 0x00, 0x45, 0x00, 0x4D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00
	};
	Prefetch p(L"SPOOLSV.EXE-282F76A7.pf");
	const ULONGLONG lastRun = p.parse(file.data(), file.size()) == ERROR_SUCCESS && p.last_runsUtc.size() == 1
		? ((ULONGLONG)p.last_runsUtc[0].dwHighDateTime << 32) | p.last_runsUtc[0].dwLowDateTime : 0;
	check(!p.unsupportedFormat && p.version == 17 && p.run_count == 1 && lastRun == 134363796949218750ULL
	      && p.hash_string == L"282F76A7" && p.volumes.size() == 1 && p.volumes[0].serialNumber == L"E47AF5B2"
	      && p.filenames.size() == 2 && p.filenames[0].filename == L"\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\GDI32.DLL"
	      && !p.filenames[0].referenceKnown,
	      "Prefetch 17: run count, last run, volume and files as libscca reads them, no $MFT reference");
}

/*! A classic .evt log built here: a header of 0x30 bytes and a circular
 *  area of 0x100, its oldest record at 0xF0 reaching the end and going on
 *  after the header, a second record, then the end-of-file record. Both are
 *  read, in order, as the XML of a classic source; a forged length ends the
 *  walk without a read past the file. */
void classicEventLog() {
	auto record = [](uint32_t number, uint32_t eventId, const std::wstring& text) {
		std::vector<uint8_t> r(0x38, 0);
		auto put = [&](const std::wstring& w) { for (wchar_t c : w) { r.push_back((uint8_t)c); r.push_back(0); } r.push_back(0); r.push_back(0); };
		put(L"Src");
		put(L"PC");
		const size_t strings = r.size();
		put(text);
		r.resize((r.size() + 3) / 4 * 4 + 4);   // aligned on 4 bytes, as Windows writes them, then the trailing length
		const uint32_t length = (uint32_t)r.size();
		writeLittleEndian<uint32_t>(r.data(), length);
		memcpy(r.data() + 4, "LfLe", 4);
		writeLittleEndian<uint32_t>(r.data() + 8, number);
		writeLittleEndian<uint32_t>(r.data() + 12, 1700000000);   // 2023-11-14T22:13:20Z
		writeLittleEndian<uint32_t>(r.data() + 16, 1700000000);
		writeLittleEndian<uint32_t>(r.data() + 20, eventId);
		writeLittleEndian<uint16_t>(r.data() + 24, 1);            // error
		writeLittleEndian<uint16_t>(r.data() + 26, 1);
		writeLittleEndian<uint32_t>(r.data() + 36, (uint32_t)strings);
		writeLittleEndian<uint32_t>(r.data() + 44, (uint32_t)strings);
		writeLittleEndian<uint32_t>(r.data() + 52, (uint32_t)strings);
		writeLittleEndian<uint32_t>(r.data() + length - 4, length);
		return r;
	};
	std::vector<uint8_t> log(0x130, 0);
	writeLittleEndian<uint32_t>(log.data(), 0x30);
	memcpy(log.data() + 4, "LfLe", 4);
	writeLittleEndian<uint32_t>(log.data() + 0x10, 0xF0);   // the oldest record
	auto place = [&](size_t at, const std::vector<uint8_t>& r) {
		for (size_t i = 0; i < r.size(); ++i) log[0x30 + (at - 0x30 + i) % 0x100] = r[i];
	};
	const std::vector<uint8_t> first = record(1, 0xC0000005, L"first"), second = record(2, 7, L"second");
	place(0xF0, first);                                     // 0x40 bytes before the end, the rest after the header
	const size_t next = 0x30 + (0xF0 - 0x30 + first.size()) % 0x100;
	place(next, second);
	const size_t eof = next + second.size();
	writeLittleEndian<uint32_t>(log.data() + eof, 0x28);
	writeLittleEndian<uint32_t>(log.data() + eof + 4, 0x11111111);
	const std::wstring file = (std::filesystem::temp_directory_path() / L"wac-classic-test.evt").wstring();
	{ std::ofstream(std::filesystem::path(file), std::ios::binary).write((const char*)log.data(), (std::streamsize)log.size()); }
	std::vector<std::wstring> xml;
	const HRESULT hr = EvtReadFile(file, L"System", [&](const EvtxRecord& e) { xml.push_back(e.xml); return true; });
	check(hr == ERROR_SUCCESS && xml.size() == 2 && xml[0].find(L"<EventID Qualifiers='49152'>5</EventID>") != std::wstring::npos
	      && xml[0].find(L"<Data>first</Data>") != std::wstring::npos && xml[0].find(L"<Level>2</Level>") != std::wstring::npos
	      && xml[0].find(L"SystemTime='2023-11-14T22:13:20") != std::wstring::npos && xml[1].find(L"<Data>second</Data>") != std::wstring::npos
	      && xml[1].find(L"<Channel>System</Channel>") != std::wstring::npos,
	      "evt: a record across the end of the area read whole, then the next, as the XML of a classic source");
	writeLittleEndian<uint32_t>(log.data() + next, 0x7FFFFFF0);   // the second record's length forged
	{ std::ofstream(std::filesystem::path(file), std::ios::binary).write((const char*)log.data(), (std::streamsize)log.size()); }
	xml.clear();
	check(EvtReadFile(file, L"System", [&](const EvtxRecord& e) { xml.push_back(e.xml); return true; }) == S_FALSE && xml.size() == 1,
	      "evt: a forged length read past the file, or the records before it lost");
	std::filesystem::remove(std::filesystem::path(file));
}

/*! UserAssist of Windows XP: the value Explorer wrote on the XP VM for
 *  Notepad, started twice from the Run box — a counter of 7 from its base of
 *  5, the last run after it; no focus fields given. */
void userAssistXp() {
	const std::vector<BYTE> value = { 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x10, 0x84, 0xD2, 0x17, 0x1D, 0x5D, 0xDD, 0x01 };
	UserAssist u(L"{75048700-EF1F-11D0-9888-006097DEACF9}", L"HRZR_EHACNGU:P:\\JVAQBJF\\Flfgrz32\\abgrcnq.rkr", value, L"S-1-5-18");
	const Json o = u.toJson();
	const Json* count = o.find(L"Count");
	check(u.Name == L"UEME_RUNPATH:C:\\WINDOWS\\System32\\notepad.exe" && count && count->text() == L"2"
	      && !o.find(L"FocusCount") && !o.find(L"FocusTimeMs")
	      && u.lastRunUtc.dwLowDateTime == 0x17D28410 && u.lastRunUtc.dwHighDateTime == 0x01DD5D1D,
	      "UserAssist XP: 2 runs from a counter of 7, the last run, no focus fields");
}

/*! ShimCache of Windows XP (0xDEADBEEF): a value built around the first
 *  entry of the XP VM's cache (services.exe, as Windows wrote it), stored
 *  second, and a made-up entry stored first; the LRU table puts them the
 *  other way round, which the cache positions must follow. */
void shimcacheWindowsXp() {
	const std::vector<BYTE> servicesPath = { 0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x5C, 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4E, 0x00, 0x44, 0x00, 0x4F, 0x00, 0x57, 0x00, 0x53, 0x00, 0x5C, 0x00, 0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00 };
	const std::vector<BYTE> servicesTail = { 0x00, 0x20, 0x7C, 0x22, 0xCB, 0x2B, 0xC1, 0x01, 0x00, 0x8C, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0xB3, 0x45, 0xDC, 0x20, 0x5D, 0xDD, 0x01 };   // modified, size, updated
	std::vector<BYTE> value(0x190 + 2 * 552, 0);
	writeLittleEndian<uint32_t>(value.data(), 0xDEADBEEF);
	writeLittleEndian<uint32_t>(value.data() + 4, 96);
	writeLittleEndian<uint32_t>(value.data() + 8, 2);
	writeLittleEndian<uint32_t>(value.data() + 0x10, 1);   // position 0: the entry stored second
	writeLittleEndian<uint32_t>(value.data() + 0x14, 0);
	const std::wstring other = L"\\??\\C:\\other.exe";
	for (size_t i = 0; i < other.size(); ++i) writeLittleEndian<uint16_t>(value.data() + 0x190 + 2 * i, (uint16_t)other[i]);
	std::copy(servicesPath.begin(), servicesPath.end(), value.begin() + 0x190 + 552);
	std::copy(servicesTail.begin(), servicesTail.end(), value.begin() + 0x190 + 552 + 528);
	Shimcaches s;
	check(s.parse(value) == S_OK && !s.unsupportedFormat && s.shimcaches.size() == 2
	      && s.shimcaches[0].path == L"\\??\\C:\\WINDOWS\\system32\\services.exe" && s.shimcaches[0].position == 0
	      && s.shimcaches[0].fileSizeKnown && s.shimcaches[0].fileSize == 101376
	      && s.shimcaches[0].lastModificationUtc.compare(0, 10, L"2001-08-23") == 0
	      && s.shimcaches[1].path == L"\\??\\C:\\other.exe" && s.shimcaches[1].position == 1,
	      "ShimCache of Windows XP: entries in the LRU table's order, path, size, last modification");
	std::vector<BYTE> forged = value;
	writeLittleEndian<uint32_t>(forged.data() + 8, 0x7FFFFFFF);   // a count beyond the value
	Shimcaches f;
	check(f.parse(forged) == S_OK && f.shimcaches.size() == 2, "ShimCache of Windows XP: a forged count read past the value");
}

/*! Windows XP's setupapi.log: lines of the XP VM's log, a class install
 *  and a device install, each its section with its start, its operation,
 *  the device's instance and the outcome #I121 states. */
void setupApiXp() {
	const std::wstring log =
		L"[SetupAPI Log]\r\nOS Version = 5.1.2600 Service Pack 1\r\n"
		L"[2026/10/13 17:38:19 280.16]\r\n"
		L"#-199 Executing \"C:\\WINDOWS\\system32\\setup.exe\" with command line: setup -newsetup\r\n"
		L"#I140 Installing device class: \"1394\" {6BDD1FC1-810F-11D0-BEC7-08002BE2092F}.\r\n"
		L"[2026/10/13 17:39:02 280.41]\r\n"
		L"#-198 Command line processed: C:\\WINDOWS\\system32\\services.exe\r\n"
		L"#I121 Device install of \"ROOT\\LEGACY_BEEP\\0000\" finished successfully.\r\n";
	const std::vector<SetupApiSection> s = parseSetupApiLog(log, L"C:\\WINDOWS\\setupapi.log");
	FILETIME first = {};
	parseSetupApiDate(L"2026/10/13 17:38:19", first);
	check(s.size() == 2 && s[0].line == 3 && CompareFileTime(&s[0].startLocal, &first) == 0
	      && s[0].operation.compare(0, 9, L"Executing") == 0 && s[0].subject.empty() && s[0].exitStatus.empty()
	      && s[1].subject == L"ROOT\\LEGACY_BEEP\\0000" && s[1].exitStatus == L"SUCCESS",
	      "setupapi XP: sections by their date line, operation, device instance and outcome");
}

/*! INFO2 of Windows XP: the header and the record of the XP VM's bin
 *  (C:\\wac-recycle.txt, sent to the bin from Explorer), rebuilt with the
 *  values measured; then a record cut short, which is not read. */
void recycleBinInfo2() {
	std::vector<uint8_t> info2(20 + 800, 0);
	const uint32_t header[] = { 5, 1, 1, 800, 6 };
	for (size_t i = 0; i < 5; ++i) writeLittleEndian<uint32_t>(info2.data() + 4 * i, header[i]);
	uint8_t* r = info2.data() + 20;
	const std::string ansi = "C:\\wac-recycle.txt";
	std::copy(ansi.begin(), ansi.end(), r);
	writeLittleEndian<uint32_t>(r + 260, 1);                       // Dc1
	writeLittleEndian<uint32_t>(r + 264, 2);                       // C:
	writeLittleEndian<uint64_t>(r + 268, 134365983773430000ULL);   // 2026-10-16T04:26:17.343Z
	writeLittleEndian<uint32_t>(r + 276, 4096);
	for (size_t i = 0; i < ansi.size(); ++i) writeLittleEndian<uint16_t>(r + 280 + 2 * i, (uint16_t)ansi[i]);
	std::vector<RecycledFile> files;
	check(parseInfo2(info2, L"C:\\RECYCLER\\S-1-5-21-1-2-3-500\\INFO2", L"S-1-5-21-1-2-3-500", files) && files.size() == 1
	      && files[0].originalPath == L"C:\\wac-recycle.txt" && files[0].recycledName == L"Dc1.txt" && files[0].size == 4096
	      && timeToIso8601Utc(files[0].deletedUtc).compare(0, 23, L"2026-10-16T04:26:17.343") == 0,
	      "INFO2: the XP record read — path, Dc copy, size, deletion");
	std::vector<uint8_t> cut(info2.begin(), info2.end() - 1);
	files.clear();
	check(parseInfo2(cut, L"x", L"s", files) && files.empty(), "INFO2: a record cut short read past the file");
}

/*! A .job of Windows XP: the task the XP VM's schtasks created (notepad.exe,
 *  once on 2026-10-16 at 23:59, never run), read as a task; cut short, it
 *  is refused. */
void jobFile() {
	const std::vector<uint8_t> job = {
		0x01, 0x05, 0x01, 0x00, 0xC8, 0x36, 0xEF, 0x58, 0x45, 0x45, 0x4E, 0x4D, 0x9F, 0x98, 0x4B, 0xEE,
		0xCF, 0x9A, 0xD3, 0x93, 0x46, 0x00, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x0A, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x14, 0x73, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x03, 0x13, 0x04, 0x00,
		0x02, 0x00, 0x80, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00,
		0x49, 0x00, 0x4E, 0x00, 0x44, 0x00, 0x4F, 0x00, 0x57, 0x00, 0x53, 0x00, 0x5C, 0x00, 0x73, 0x00,
		0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00,
		0x6E, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x65, 0x00, 0x70, 0x00, 0x61, 0x00, 0x64, 0x00, 0x2E, 0x00,
		0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x6E, 0x00, 0x6F, 0x00,
		0x74, 0x00, 0x65, 0x00, 0x70, 0x00, 0x61, 0x00, 0x64, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00,
		0x65, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x6E, 0x00,
		0x69, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x61, 0x00, 0x74, 0x00, 0x6F, 0x00, 0x72, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x13, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0xEA, 0x07, 0x0A, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x17, 0x00, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00
	};
	ScheduledTask t;
	check(parseJobFile(job, t) && t.actions.size() == 1 && t.actions[0].command == L"C:\\WINDOWS\\system32\\notepad.exe"
	      && t.author == L"Administrator" && t.jobStatus == L"HasNotRun" && t.enabled && t.triggers.size() == 1
	      && t.triggers[0].type == L"TimeTrigger" && t.triggers[0].start == L"2026-10-16T23:59:00"
	      && !t.lastRunTimeUtc.dwHighDateTime,
	      ".job: program, author, status, trigger of the XP task, no last run");
	ScheduledTask cut;
	check(!parseJobFile(std::vector<uint8_t>(job.begin(), job.begin() + 0x60), cut), ".job: a file cut in its strings read");
}

/*! The firewall exceptions of Windows XP SP3, as the test VM's Standard
 *  profile holds them: an application whose path has its own colon, one
 *  whose state is written in lower case, a port; and a value of another
 *  layout, left out. */
void firewallXp() {
	const std::vector<FirewallRule> apps = parseXpFirewallList(L"StandardProfile", false, {
		{ L"C:\\WINDOWS\\system32\\notepad.exe", L"C:\\WINDOWS\\system32\\notepad.exe:*:Enabled:WacNotepad" },
		{ L"%windir%\\system32\\sessmgr.exe", L"%windir%\\system32\\sessmgr.exe:*:enabled:@xpsp2res.dll,-22019" },
		{ L"odd", L"no colon" } });
	const std::vector<FirewallRule> ports = parseXpFirewallList(L"StandardProfile", true, { { L"8765:TCP", L"8765:TCP:*:Enabled:WacPort" } });
	auto field = [](const FirewallRule& r, const wchar_t* k) {
		for (const auto& [n, v] : r.fields) if (n == k) return v;
		return std::wstring();
	};
	check(apps.size() == 2 && field(apps[0], L"App") == L"C:\\WINDOWS\\system32\\notepad.exe" && field(apps[0], L"Name") == L"WacNotepad"
	      && field(apps[0], L"Active") == L"TRUE" && field(apps[1], L"Active") == L"TRUE" && field(apps[0], L"Scope") == L"*"
	      && ports.size() == 1 && field(ports[0], L"LPort") == L"8765" && field(ports[0], L"Protocol") == L"TCP"
	      && field(ports[0], L"Name") == L"WacPort" && field(ports[0], L"Profile") == L"StandardProfile",
	      "firewall XP: applications and ports of a profile, as netsh shows them");
}

/*! A Thumbs.db of Windows XP: the one the XP VM wrote for C:\\wacthumb shown as
 *  thumbnails (two JPEG images), its catalogue and both thumbnails as olefile
 *  reads them; cut short, it is not read. */
void thumbsDb() {
	const std::vector<uint8_t> file = {
		0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x03, 0x00, 0xFE, 0xFF, 0x09, 0x00,
		0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFD, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00,
		0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x52, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x20, 0x00, 0x45, 0x00, 0x6E, 0x00, 0x74, 0x00,
		0x72, 0x00, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x16, 0x00, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xF0, 0xF1, 0x7A,
		0x61, 0x5D, 0xDD, 0x01, 0x03, 0x00, 0x00, 0x00, 0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x69, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x6C, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x43, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x67, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x00, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
		0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
		0x09, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
		0x0D, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x11, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
		0x15, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
		0x19, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00,
		0x1D, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0x1F, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
		0x21, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF,
		0x25, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x5D, 0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x4D, 0x07, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0xFF, 0xD8, 0xFF, 0xC0,
		0x00, 0x14, 0x08, 0x00, 0x48, 0x00, 0x60, 0x04, 0x52, 0x11, 0x00, 0x47, 0x11, 0x00, 0x42, 0x11,
		0x00, 0x41, 0x11, 0x00, 0xFF, 0xDA, 0x00, 0x0E, 0x04, 0x52, 0x00, 0x47, 0x00, 0x42, 0x00, 0x41,
		0x00, 0x00, 0x3F, 0x00, 0xF4, 0x7A, 0xAF, 0x5E, 0x39, 0x5F, 0x3F, 0xD1, 0x45, 0x14, 0x51, 0x45,
		0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14,
		0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x57,
		0x2B, 0xE3, 0x3F, 0x17, 0xC9, 0xE1, 0x5F, 0xB0, 0xF9, 0x76, 0x69, 0x71, 0xF6, 0x9D, 0xF9, 0xDC,
		0xE5, 0x76, 0xED, 0xDB, 0xEC, 0x7F, 0xBD, 0xFA, 0x56, 0xB6, 0x8B, 0xA3, 0xAE, 0xAB, 0xE7, 0xEE,
		0x98, 0xC7, 0xE5, 0xED, 0xE8, 0xB9, 0xCE, 0x73, 0xFE, 0x15, 0xDD, 0xFC, 0x37, 0xF8, 0x7D, 0x0F,
		0x8E, 0xFF, 0x00, 0xB4, 0xFC, 0xED, 0x42, 0x4B, 0x3F, 0xB1, 0x79, 0x58, 0xD9, 0x18, 0x7D, 0xDB,
		0xF7, 0xFB, 0x8C, 0x63, 0x67, 0xEB, 0x45, 0x72, 0x9F, 0xF0, 0xB7, 0x6E, 0x7F, 0xE8, 0x11, 0x0F,
		0xFD, 0xFE, 0x3F, 0xE1, 0x5A, 0xBF, 0xF0, 0x88, 0x45, 0xFF, 0x00, 0x3F, 0x8F, 0xFF, 0x00, 0x7C,
		0x0F, 0xF1, 0xAE, 0xF3, 0xFE, 0x19, 0xF6, 0xCF, 0xFE, 0x86, 0x19, 0xFF, 0x00, 0xF0, 0x18, 0x7F,
		0xF1, 0x54, 0x51, 0xFF, 0x00, 0x0B, 0x76, 0xE7, 0xFE, 0x81, 0x10, 0xFF, 0x00, 0xDF, 0xE3, 0xFE,
		0x14, 0x7F, 0xC2, 0x21, 0x17, 0xFC, 0xFE, 0x3F, 0xFD, 0xF0, 0x3F, 0xC6, 0x8F, 0xF8, 0x67, 0xDB,
		0x3F, 0xFA, 0x18, 0x67, 0xFF, 0x00, 0xC0, 0x61, 0xFF, 0x00, 0xC5, 0x51, 0x47, 0xFC, 0x2D, 0xDB,
		0x9F, 0xFA, 0x04, 0x43, 0xFF, 0x00, 0x7F, 0x8F, 0xF8, 0x51, 0xFF, 0x00, 0x08, 0x84, 0x5F, 0xF3,
		0xF8, 0xFF, 0x00, 0xF7, 0xC0, 0xFF, 0x00, 0x1A, 0x3F, 0xE1, 0x9F, 0x6C, 0xFF, 0x00, 0xE8, 0x61,
		0x9F, 0xFF, 0x00, 0x01, 0x87, 0xFF, 0x00, 0x15, 0x45, 0x1F, 0xF0, 0xB7, 0x6E, 0x7F, 0xE8, 0x11,
		0x0F, 0xFD, 0xFE, 0x3F, 0xE1, 0x47, 0xFC, 0x22, 0x11, 0x7F, 0xCF, 0xE3, 0xFF, 0x00, 0xDF, 0x03,
		0xFC, 0x68, 0xFF, 0x00, 0x86, 0x7D, 0xB3, 0xFF, 0x00, 0xA1, 0x86, 0x7F, 0xFC, 0x06, 0x1F, 0xFC,
		0x55, 0x14, 0x7F, 0xC2, 0xDD, 0xB9, 0xFF, 0x00, 0xA0, 0x44, 0x3F, 0xF7, 0xF8, 0xFF, 0x00, 0x85,
		0x1F, 0xF0, 0x88, 0x45, 0xFF, 0x00, 0x3F, 0x8F, 0xFF, 0x00, 0x7C, 0x0F, 0xF1, 0xA3, 0xFE, 0x19,
		0xF6, 0xCF, 0xFE, 0x86, 0x19, 0xFF, 0x00, 0xF0, 0x18, 0x7F, 0xF1, 0x54, 0x51, 0xFF, 0x00, 0x0B,
		0x76, 0xE7, 0xFE, 0x81, 0x10, 0xFF, 0x00, 0xDF, 0xE3, 0xFE, 0x14, 0x7F, 0xC2, 0x21, 0x17, 0xFC,
		0xFE, 0x3F, 0xFD, 0xF0, 0x3F, 0xC6, 0x8F, 0xF8, 0x67, 0xDB, 0x3F, 0xFA, 0x18, 0x67, 0xFF, 0x00,
		0xC0, 0x61, 0xFF, 0x00, 0xC5, 0x51, 0x47, 0xFC, 0x2D, 0xDB, 0x9F, 0xFA, 0x04, 0x43, 0xFF, 0x00,
		0x7F, 0x8F, 0xF8, 0x51, 0xFF, 0x00, 0x08, 0x84, 0x5F, 0xF3, 0xF8, 0xFF, 0x00, 0xF7, 0xC0, 0xFF,
		0x00, 0x1A, 0x3F, 0xE1, 0x9F, 0x6C, 0xFF, 0x00, 0xE8, 0x61, 0x9F, 0xFF, 0x00, 0x01, 0x87, 0xFF,
		0x00, 0x15, 0x45, 0x1F, 0xF0, 0xB7, 0x6E, 0x7F, 0xE8, 0x11, 0x0F, 0xFD, 0xFE, 0x3F, 0xE1, 0x47,
		0xFC, 0x22, 0x11, 0x7F, 0xCF, 0xE3, 0xFF, 0x00, 0xDF, 0x03, 0xFC, 0x68, 0xFF, 0x00, 0x86, 0x7D,
		0xB3, 0xFF, 0x00, 0xA1, 0x86, 0x7F, 0xFC, 0x06, 0x1F, 0xFC, 0x55, 0x15, 0xD3, 0xF8, 0x37, 0xC6,
		0x52, 0xF8, 0xA6, 0x7B, 0xB8, 0xE4, 0xB2, 0x4B, 0x71, 0x02, 0xAB, 0x02, 0xB2, 0x16, 0xCE, 0x49,
		0xF6, 0x1E, 0x95, 0x97, 0xAC, 0xE8, 0xCB, 0xA5, 0x47, 0x0B, 0x2C, 0xC6, 0x4F, 0x30, 0x91, 0xCA,
		0xE3, 0x18, 0xAE, 0x23, 0xE2, 0x37, 0xC3, 0x98, 0x3C, 0x0B, 0x6B, 0x61, 0x2C, 0x5A, 0x8C, 0x97,
		0x66, 0xE9, 0xDD, 0x48, 0x78, 0x82, 0x6D, 0xDA, 0x07, 0xB9, 0xF5, 0xA2, 0xBA, 0xEA, 0xC8, 0xAF,
		0x3F, 0xA2, 0x8A, 0x28, 0xA2, 0xBC, 0xC3, 0xE3, 0x07, 0xFC, 0xC1, 0xBF, 0xED, 0xB7, 0xFE, 0xD3,
		0xAE, 0xA3, 0xC1, 0xFF, 0x00, 0xF2, 0xFB, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0xD9, 0xAB, 0xDB, 0xFF,
		0x00, 0x67, 0x9F, 0xF9, 0x98, 0xFF, 0x00, 0xED, 0xD7, 0xFF, 0x00, 0x6A, 0xD1, 0x5E, 0x61, 0x5D,
		0x45, 0x7B, 0x75, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14,
		0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x15, 0xE9, 0x3F, 0x08, 0x7F, 0xE3, 0xF3, 0x55,
		0xFF, 0x00, 0xAE, 0x71, 0xFF, 0x00, 0x36, 0xAE, 0x6B, 0xC5, 0xFF, 0x00, 0xEA, 0x2D, 0x7F, 0xDE,
		0x6F, 0xE4, 0x2B, 0xC6, 0x7F, 0x68, 0x2F, 0xF9, 0x07, 0x68, 0x7F, 0xF5, 0xDA, 0x5F, 0xE4, 0xB4,
		0x57, 0xAA, 0xD7, 0x29, 0x5E, 0x11, 0x45, 0x14, 0x51, 0x45, 0x79, 0x87, 0xC6, 0x0F, 0xF9, 0x83,
		0x7F, 0xDB, 0x6F, 0xFD, 0xA7, 0x5D, 0x47, 0x83, 0xFF, 0x00, 0xE5, 0xF7, 0xFE, 0x01, 0xFF, 0x00,
		0xB3, 0x57, 0xB7, 0xFE, 0xCF, 0x3F, 0xF3, 0x31, 0xFF, 0x00, 0xDB, 0xAF, 0xFE, 0xD5, 0xA2, 0xBC,
		0xC2, 0xBA, 0x8A, 0xF6, 0xEA, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2,
		0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x2B, 0xD2, 0x7E, 0x10, 0xFF, 0x00,
		0xC7, 0xE6, 0xAB, 0xFF, 0x00, 0x5C, 0xE3, 0xFE, 0x6D, 0x5C, 0xD7, 0x8B, 0xFF, 0x00, 0xD4, 0x5A,
		0xFF, 0x00, 0xBC, 0xDF, 0xC8, 0x57, 0x8C, 0xFE, 0xD0, 0x5F, 0xF2, 0x0E, 0xD0, 0xFF, 0x00, 0xEB,
		0xB4, 0xBF, 0xC9, 0x68, 0xAF, 0x55, 0xAE, 0x52, 0xBC, 0x22, 0x8A, 0x28, 0xA2, 0x8A, 0xF3, 0x0F,
		0x8C, 0x1F, 0xF3, 0x06, 0xFF, 0x00, 0xB6, 0xDF, 0xFB, 0x4E, 0xBA, 0x8F, 0x07, 0xFF, 0x00, 0xCB,
		0xEF, 0xFC, 0x03, 0xFF, 0x00, 0x66, 0xAF, 0x6E, 0xFD, 0x9E, 0xBF, 0xE6, 0x63, 0xFF, 0x00, 0xB7,
		0x5F, 0xFD, 0xAB, 0x45, 0x79, 0x79, 0x65, 0x1D, 0x58, 0x0F, 0xC6, 0xBA, 0x29, 0x2E, 0xED, 0xA2,
		0x62, 0xB2, 0x5C, 0x44, 0x8C, 0x3A, 0x86, 0x70, 0x08, 0xAF, 0x67, 0x96, 0xFA, 0xD2, 0x07, 0x29,
		0x2D, 0xD4, 0x11, 0xB0, 0xE0, 0xAB, 0x48, 0x01, 0x14, 0x50, 0x59, 0x47, 0x52, 0x28, 0x7B, 0xBB,
		0x68, 0xFE, 0xFD, 0xC4, 0x4B, 0xDF, 0x97, 0x03, 0xFC, 0xF5, 0x14, 0x3D, 0xF5, 0x9C, 0x5F, 0xEB,
		0x2E, 0xE0, 0x4E, 0x9F, 0x7A, 0x40, 0x3A, 0xFF, 0x00, 0xFA, 0xC7, 0xE7, 0x45, 0x01, 0x95, 0xBA,
		0x10, 0x7E, 0x86, 0x88, 0x6E, 0xAD, 0xEE, 0x18, 0xAC, 0x37, 0x11, 0x48, 0xC0, 0x64, 0x84, 0x70,
		0x48, 0x19, 0xC7, 0x6F, 0x70, 0x7F, 0x2A, 0x58, 0x2F, 0x6D, 0x6E, 0x98, 0xAD, 0xBD, 0xCC, 0x32,
		0xB0, 0x19, 0x22, 0x39, 0x03, 0x10, 0x33, 0x8E, 0xDE, 0xE0, 0xFE, 0x54, 0x52, 0xD4, 0xD5, 0x3D,
		0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x15, 0xE9, 0x3F, 0x08,
		0x7F, 0xE3, 0xF3, 0x55, 0xFF, 0x00, 0xAE, 0x71, 0xFF, 0x00, 0x36, 0xAE, 0x6B, 0xC5, 0xFF, 0x00,
		0xEA, 0x2D, 0x7F, 0xDE, 0x6F, 0xE4, 0x2B, 0xC6, 0x7F, 0x68, 0x2F, 0xF9, 0x07, 0x68, 0x7F, 0xF5,
		0xDA, 0x5F, 0xE4, 0xB4, 0x57, 0xAA, 0xD7, 0x29, 0x5E, 0x11, 0x45, 0x14, 0x51, 0x45, 0x79, 0x87,
		0xC6, 0x0F, 0xF9, 0x83, 0x7F, 0xDB, 0x6F, 0xFD, 0xA7, 0x5D, 0x47, 0x83, 0xFF, 0x00, 0xE5, 0xF7,
		0xFE, 0x01, 0xFF, 0x00, 0xB3, 0x57, 0xB7, 0xFE, 0xCF, 0x3F, 0xF3, 0x31, 0xFF, 0x00, 0xDB, 0xB7,
		0xFE, 0xD5, 0xA2, 0xBC, 0xB8, 0xA2, 0x92, 0x49, 0x5E, 0x4D, 0x74, 0x12, 0x58, 0xDA, 0xCB, 0x2B,
		0x49, 0x24, 0x08, 0xCE, 0xD8, 0xCB, 0x11, 0xC9, 0xC7, 0x4A, 0xF6, 0x49, 0x74, 0xDB, 0x29, 0xE6,
		0x69, 0x65, 0xB6, 0x8D, 0xA4, 0x6C, 0x6E, 0x62, 0x39, 0x38, 0xE9, 0x45, 0x1B, 0x14, 0xF5, 0x51,
		0x48, 0xD6, 0x16, 0xAE, 0x58, 0xB4, 0x08, 0xC5, 0xBA, 0xE7, 0x9C, 0xF6, 0xFE, 0x94, 0x8F, 0xA6,
		0x59, 0x49, 0xBF, 0x7D, 0xBA, 0x36, 0xFC, 0x06, 0xDD, 0xCE, 0x78, 0xC7, 0xF4, 0xA2, 0x80, 0x8A,
		0xBC, 0x80, 0x07, 0xD2, 0x9D, 0x6F, 0x65, 0x6D, 0x6A, 0x49, 0x82, 0x14, 0x8F, 0x23, 0x1F, 0x28,
		0xED, 0x4E, 0xB6, 0xD3, 0xED, 0x2C, 0xD8, 0x9B, 0x6B, 0x74, 0x88, 0x91, 0xB7, 0xE5, 0x18, 0xE3,
		0xAD, 0x14, 0xEA, 0x9E, 0xAC, 0xD1, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45,
		0x14, 0x51, 0x5E, 0x93, 0xF0, 0x87, 0xFE, 0x3F, 0x35, 0x5F, 0xFA, 0xE7, 0x1F, 0xF3, 0x6A, 0xE6,
		0xBC, 0x5F, 0xFE, 0xA2, 0xD7, 0xFD, 0xE6, 0xFE, 0x42, 0xBC, 0x67, 0xF6, 0x82, 0xFF, 0x00, 0x90,
		0x76, 0x87, 0xFF, 0x00, 0x5D, 0xA5, 0xFE, 0x4B, 0x45, 0x7A, 0xAD, 0x72, 0x95, 0xE1, 0x14, 0x51,
		0x45, 0x14, 0x57, 0x98, 0x7C, 0x60, 0xFF, 0x00, 0x98, 0x37, 0xFD, 0xB6, 0xFF, 0x00, 0xDA, 0x75,
		0xD4, 0x78, 0x3F, 0xFE, 0x5F, 0x7F, 0xE0, 0x1F, 0xFB, 0x35, 0x7B, 0x7F, 0xEC, 0xF3, 0xFF, 0x00,
		0x33, 0x1F, 0xFD, 0xBA, 0xFF, 0x00, 0xED, 0x5A, 0x2B, 0xCC, 0x2B, 0xA8, 0xAF, 0x6E, 0xA2, 0x8A,
		0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28,
		0xA2, 0x8A, 0x28, 0xA2, 0xBD, 0x27, 0xE1, 0x0F, 0xFC, 0x7E, 0x6A, 0xBF, 0xF5, 0xCE, 0x3F, 0xE6,
		0xD5, 0xCD, 0x78, 0xBF, 0xFD, 0x45, 0xAF, 0xFB, 0xCD, 0xFC, 0x85, 0x78, 0xCF, 0xED, 0x05, 0xFF,
		0x00, 0x20, 0xED, 0x0F, 0xFE, 0xBB, 0x4B, 0xFC, 0x96, 0x8A, 0xF5, 0x5A, 0xE5, 0x2B, 0xC2, 0x28,
		0xA2, 0x8A, 0x28, 0xAE, 0x63, 0xC6, 0x1E, 0x0F, 0xFF, 0x00, 0x84, 0xB3, 0xEC, 0x5F, 0xE9, 0xFF,
		0x00, 0x65, 0xFB, 0x36, 0xFF, 0x00, 0xF9, 0x63, 0xBF, 0x76, 0xED, 0xBF, 0xED, 0x0C, 0x7D, 0xDF,
		0xD6, 0xB5, 0x34, 0x7D, 0x63, 0xFB, 0x27, 0xCE, 0xFD, 0xC7, 0x9B, 0xE6, 0xED, 0xFE, 0x3D, 0xB8,
		0xC6, 0x7D, 0x8F, 0xAD, 0x76, 0xFF, 0x00, 0x0F, 0x3E, 0x21, 0xFF, 0x00, 0xC2, 0x07, 0xFD, 0xA5,
		0xFF, 0x00, 0x12, 0xBF, 0xB7, 0x7D, 0xB7, 0xCA, 0xFF, 0x00, 0x97, 0x8F, 0x2B, 0x66, 0xCD, 0xFF,
		0x00, 0xEC, 0xB6, 0x73, 0xBF, 0xDB, 0xA5, 0x15, 0xCB, 0xFF, 0x00, 0xC2, 0x9F, 0xFF, 0x00, 0xA8,
		0xEF, 0xFE, 0x4A, 0x7F, 0xF6, 0x75, 0xA9, 0xFF, 0x00, 0x09, 0x87, 0xFD, 0x38, 0xFF, 0x00, 0xE4,
		0x6F, 0xFE, 0xC6, 0xBB, 0x8F, 0xF8, 0x68, 0x6F, 0xFA, 0x95, 0xFF, 0x00, 0xF2, 0xA1, 0xFF, 0x00,
		0xDA, 0xA8, 0xA3, 0xFE, 0x14, 0xFF, 0x00, 0xFD, 0x47, 0x7F, 0xF2, 0x53, 0xFF, 0x00, 0xB3, 0xA3,
		0xFE, 0x13, 0x0F, 0xFA, 0x71, 0xFF, 0x00, 0xC8, 0xDF, 0xFD, 0x8D, 0x1F, 0xF0, 0xD0, 0xDF, 0xF5,
		0x2B, 0xFF, 0x00, 0xE5, 0x43, 0xFF, 0x00, 0xB5, 0x51, 0x47, 0xFC, 0x29, 0xFF, 0x00, 0xFA, 0x8E,
		0xFF, 0x00, 0xE4, 0xA7, 0xFF, 0x00, 0x67, 0x47, 0xFC, 0x26, 0x1F, 0xF4, 0xE3, 0xFF, 0x00, 0x91,
		0xBF, 0xFB, 0x1A, 0x3F, 0xE1, 0xA1, 0xBF, 0xEA, 0x57, 0xFF, 0x00, 0xCA, 0x87, 0xFF, 0x00, 0x6A,
		0xA2, 0x8F, 0xF8, 0x53, 0xFF, 0x00, 0xF5, 0x1D, 0xFF, 0x00, 0xC9, 0x4F, 0xFE, 0xCE, 0x8F, 0xF8,
		0x4C, 0x3F, 0xE9, 0xC7, 0xFF, 0x00, 0x23, 0x7F, 0xF6, 0x34, 0x7F, 0xC3, 0x43, 0x7F, 0xD4, 0xAF,
		0xFF, 0x00, 0x95, 0x0F, 0xFE, 0xD5, 0x45, 0x1F, 0xF0, 0xA7, 0xFF, 0x00, 0xEA, 0x3B, 0xFF, 0x00,
		0x92, 0x9F, 0xFD, 0x9D, 0x1F, 0xF0, 0x98, 0x7F, 0xD3, 0x8F, 0xFE, 0x46, 0xFF, 0x00, 0xEC, 0x68,
		0xFF, 0x00, 0x86, 0x86, 0xFF, 0x00, 0xA9, 0x5F, 0xFF, 0x00, 0x2A, 0x1F, 0xFD, 0xAA, 0x8A, 0x3F,
		0xE1, 0x4F, 0xFF, 0x00, 0xD4, 0x77, 0xFF, 0x00, 0x25, 0x3F, 0xFB, 0x3A, 0x3F, 0xE1, 0x30, 0xFF,
		0x00, 0xA7, 0x1F, 0xFC, 0x8D, 0xFF, 0x00, 0xD8, 0xD1, 0xFF, 0x00, 0x0D, 0x0D, 0xFF, 0x00, 0x52,
		0xBF, 0xFE, 0x54, 0x3F, 0xFB, 0x55, 0x14, 0x7F, 0xC2, 0x9F, 0xFF, 0x00, 0xA8, 0xEF, 0xFE, 0x4A,
		0x7F, 0xF6, 0x74, 0x7F, 0xC2, 0x61, 0xFF, 0x00, 0x4E, 0x3F, 0xF9, 0x1B, 0xFF, 0x00, 0xB1, 0xA3,
		0xFE, 0x1A, 0x1B, 0xFE, 0xA5, 0x7F, 0xFC, 0xA8, 0x7F, 0xF6, 0xAA, 0x28, 0xFF, 0x00, 0x85, 0x3F,
		0xFF, 0x00, 0x51, 0xDF, 0xFC, 0x94, 0xFF, 0x00, 0xEC, 0xE8, 0xFF, 0x00, 0x84, 0xC3, 0xFE, 0x9C,
		0x7F, 0xF2, 0x37, 0xFF, 0x00, 0x63, 0x47, 0xFC, 0x34, 0x37, 0xFD, 0x4A, 0xFF, 0x00, 0xF9, 0x50,
		0xFF, 0x00, 0xED, 0x54, 0x57, 0x4B, 0xE1, 0x0F, 0x06, 0x7F, 0xC2, 0x2B, 0x35, 0xD4, 0x9F, 0x6F,
		0xFB, 0x57, 0x9E, 0xAA, 0xB8, 0xF2, 0x76, 0x6D, 0xC1, 0x3F, 0xED, 0x1C, 0xF5, 0xAC, 0xDD, 0x63,
		0x5A, 0xFE, 0xD5, 0x48, 0x97, 0xEC, 0xFE, 0x57, 0x96, 0x49, 0xFB, 0xFB, 0xB3, 0x9F, 0xC0, 0x57,
		0x17, 0xF1, 0x07, 0xE2, 0x47, 0xFC, 0x27, 0x76, 0xD6, 0x30, 0xFF, 0x00, 0x64, 0xFD, 0x87, 0xEC,
		0xAE, 0xED, 0x9F, 0xB4, 0x79, 0xBB, 0xB7, 0x01, 0xFE, 0xCA, 0xE3, 0xA5, 0x15, 0xD5, 0x56, 0x4D,
		0x70, 0x94, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45,
		0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x51, 0x45, 0x14,
		0x51, 0x45, 0x14, 0x51, 0x45, 0x14, 0x57, 0xFF, 0xD9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x50, 0x01, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0xFF, 0xD8, 0xFF, 0xC0,
		0x00, 0x14, 0x08, 0x00, 0x60, 0x00, 0x40, 0x04, 0x52, 0x11, 0x00, 0x47, 0x11, 0x00, 0x42, 0x11,
		0x00, 0x41, 0x11, 0x00, 0xFF, 0xDA, 0x00, 0x0E, 0x04, 0x52, 0x00, 0x47, 0x00, 0x42, 0x00, 0x41,
		0x00, 0x00, 0x3F, 0x00, 0xF2, 0x7A, 0xF2, 0x7A, 0xF4, 0x8A, 0xF9, 0xFE, 0x8A, 0x28, 0xA2, 0x8A,
		0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28,
		0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2,
		0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A,
		0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28,
		0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2,
		0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A,
		0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28,
		0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2,
		0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A,
		0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28,
		0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2,
		0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A,
		0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28,
		0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2,
		0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A,
		0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28,
		0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2,
		0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0x8A, 0x28, 0xA2, 0xBF, 0xFF, 0xD9, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
		0x2C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x4B, 0x3F, 0x0F, 0x61, 0x5D, 0xDD, 0x01,
		0x57, 0x00, 0x41, 0x00, 0x43, 0x00, 0x54, 0x00, 0x48, 0x00, 0x55, 0x00, 0x4D, 0x00, 0x42, 0x00,
		0x2E, 0x00, 0x4A, 0x00, 0x50, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x4B, 0x3F, 0x0F, 0x61, 0x5D, 0xDD, 0x01, 0x57, 0x00, 0x41, 0x00,
		0x43, 0x00, 0x52, 0x00, 0x45, 0x00, 0x44, 0x00, 0x2E, 0x00, 0x4A, 0x00, 0x50, 0x00, 0x47, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	std::vector<ThumbsDbEntry> t;
	check(decodeThumbsDb(file, t) && t.size() == 2 && t[0].index == 1 && t[0].name == L"WACTHUMB.JPG"
	      && t[0].width == 96 && t[0].height == 72 && t[0].image.size() == 1869 && t[0].image[0] == 0xFF && t[0].image[1] == 0xD8
	      && t[1].name == L"WACRED.JPG" && t[1].width == 64 && t[1].height == 96 && t[1].image.size() == 336
	      && (((ULONGLONG)t[0].sourceModifiedUtc.dwHighDateTime << 32) | t[0].sourceModifiedUtc.dwLowDateTime) == 134366235340000000ULL,
	      "Thumbs.db: catalogue and thumbnails as olefile reads them");
	std::vector<uint8_t> cut(file.begin(), file.begin() + 1024);
	std::vector<ThumbsDbEntry> none;
	check(!decodeThumbsDb(cut, none) || none.empty(), "Thumbs.db: a file cut short read past its end");
}

/* A bcache22.bmc of the client of Windows XP SP1 (test VM, session to
   Windows Server 2012 R2): two real tiles of it — a 64 × 64 one with text
   (its first slot, padded as the client pads it) and a 32 × 64 one, last of
   the file. The first is confronted with bmc-tools (ANSSI), the second, whose
   rows are 32 pixels long where bmc-tools assumes 64, with what it shows:
   the uniform blue of the logon screen. */
void rdpBmcCache() {
	const std::vector<uint8_t> textTile = {
		0x7A, 0xC7, 0x0C, 0x9C, 0xB4, 0x61, 0xB2, 0x1D, 0x40, 0x00, 0x40, 0x00, 0x6F, 0x04, 0x00, 0x00,
		0x19, 0x00, 0x00, 0x00, 0xC0, 0x2C, 0xC8, 0x08, 0x84, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8,
		0x08, 0xF0, 0x4F, 0x05, 0x8B, 0x09, 0x11, 0x4D, 0x3A, 0x50, 0x63, 0x13, 0x7C, 0x54, 0x84, 0xC8,
		0x08, 0xC8, 0x08, 0x4D, 0x3A, 0x0C, 0x32, 0x6D, 0x42, 0x4D, 0x3A, 0x00, 0x0E, 0x92, 0x6A, 0x19,
		0x4D, 0x3A, 0xB2, 0x6B, 0x74, 0x84, 0x57, 0xA5, 0x9B, 0xCE, 0x7E, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xBB, 0xD6, 0xC8, 0x08, 0xC8, 0x08, 0x50, 0x63, 0x30, 0x5B, 0x54, 0x84,
		0x74, 0x84, 0x00, 0x08, 0x86, 0x8E, 0x42, 0xB2, 0x6B, 0xD5, 0x94, 0x98, 0xAD, 0x9B, 0xCE, 0xDF,
		0xFF, 0x6B, 0xFF, 0xFF, 0x02, 0x85, 0x2D, 0x32, 0x33, 0x7C, 0x91, 0x63, 0xE9, 0x08, 0x10, 0x53,
		0x00, 0x06, 0x82, 0xFF, 0xFF, 0xC8, 0x08, 0x71, 0xFF, 0xFF, 0x02, 0x60, 0x0B, 0xC8, 0x08, 0x00,
		0x83, 0x83, 0x0C, 0x32, 0x4D, 0x3A, 0x0C, 0x32, 0x08, 0x84, 0x6A, 0x19, 0x4D, 0x3A, 0x4D, 0x3A,
		0x2A, 0x11, 0x06, 0x88, 0x6A, 0x19, 0x4D, 0x3A, 0x0C, 0x32, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08,
		0x0C, 0x32, 0x4D, 0x3A, 0x00, 0x02, 0x85, 0x09, 0x11, 0xBF, 0xF7, 0xFF, 0xFF, 0xFF, 0xFF, 0x4A,
		0x19, 0x07, 0x84, 0x16, 0x9D, 0xFF, 0xFF, 0xFF, 0xFF, 0x33, 0x7C, 0x06, 0x88, 0xD2, 0x6B, 0xFF,
		0xFF, 0xBB, 0xD6, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xBB, 0xD6, 0xFF, 0xFF, 0x00, 0x02, 0x85,
		0xEF, 0x52, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x53, 0x07, 0x83, 0x3D, 0xE7, 0xFF, 0xFF,
		0xFF, 0xFF, 0xD0, 0x30, 0xCA, 0xC9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x16, 0x9D,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x16, 0x9D, 0x06, 0x85, 0x0C, 0x32, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xBF, 0xF7, 0xD6, 0xC1, 0x19, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x3D, 0xE7,
		0xFF, 0xFF, 0x77, 0xAD, 0xFF, 0xFF, 0x3D, 0xE7, 0x06, 0x86, 0x33, 0x7C, 0xFF, 0xFF, 0x5A, 0xC6,
		0x7E, 0xEF, 0xFF, 0xFF, 0xEF, 0x52, 0x00, 0x0E, 0x92, 0x0C, 0x32, 0xFF, 0xFF, 0xFF, 0xFF, 0xCC,
		0x29, 0xBF, 0xF7, 0xFF, 0xFF, 0x0C, 0x32, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8,
		0x08, 0xF9, 0xB5, 0xFF, 0xFF, 0x33, 0x7C, 0x77, 0xAD, 0xFF, 0xFF, 0x16, 0x9D, 0x00, 0x0E, 0x92,
		0x33, 0x7C, 0xFF, 0xFF, 0xBB, 0xD6, 0xC8, 0x08, 0xF9, 0xB5, 0xFF, 0xFF, 0x33, 0x7C, 0xC8, 0x08,
		0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x09, 0x11, 0xBF, 0xF7, 0xFF, 0xFF, 0x6D, 0x42, 0x91, 0x6B,
		0xFF, 0xFF, 0x3D, 0xE7, 0x00, 0x0E, 0x93, 0x5A, 0xC6, 0xFF, 0xFF, 0x95, 0x8C, 0xC8, 0x08, 0xD2,
		0x6B, 0xFF, 0xFF, 0xF9, 0xB5, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xEF, 0x52, 0xFF,
		0xFF, 0x7E, 0xEF, 0xE9, 0x08, 0xAB, 0x21, 0xFF, 0xFF, 0xFF, 0xFF, 0xCB, 0x29, 0x00, 0x0C, 0x94,
		0x4A, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0x8E, 0x42, 0xC8, 0x08, 0xAB, 0x21, 0xFF, 0xFF, 0xBF, 0xF7,
		0x09, 0x11, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x16, 0x9D, 0xFF, 0xFF, 0x77, 0xAD, 0xC8, 0x08,
		0xC8, 0x08, 0xFC, 0xDE, 0xFF, 0xFF, 0xD2, 0x6B, 0x00, 0x0C, 0x94, 0x50, 0x63, 0xFF, 0xFF, 0xBF,
		0xF7, 0x09, 0x11, 0xC8, 0x08, 0xC8, 0x08, 0x3D, 0xE7, 0xFF, 0xFF, 0xEF, 0x52, 0xC8, 0x08, 0xC8,
		0x08, 0xC8, 0x08, 0x1C, 0xDF, 0xFF, 0xFF, 0xB2, 0x6B, 0xC8, 0x08, 0xC8, 0x08, 0x16, 0x9D, 0xFF,
		0xFF, 0xF9, 0xB5, 0x0C, 0x60, 0x00, 0xC8, 0x08, 0x95, 0x77, 0xAD, 0xFF, 0xFF, 0xF9, 0xB5, 0xC8,
		0x08, 0xC8, 0x08, 0xC8, 0x08, 0x16, 0x9D, 0xFF, 0xFF, 0x16, 0x9D, 0xC8, 0x08, 0xC8, 0x08, 0xAB,
		0x21, 0xFF, 0xFF, 0xFF, 0xFF, 0xAB, 0x21, 0xC8, 0x08, 0xC8, 0x08, 0x10, 0x53, 0xFF, 0xFF, 0xBF,
		0xF7, 0x09, 0x11, 0x0B, 0x82, 0xFF, 0xFF, 0xC8, 0x08, 0xC0, 0x01, 0x37, 0xF7, 0x81, 0xBB, 0xD6,
		0x0B, 0x96, 0xE9, 0x08, 0x7E, 0xEF, 0xFF, 0xFF, 0xD2, 0x6B, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08,
		0xEF, 0x52, 0xFF, 0xFF, 0x3D, 0xE7, 0xC8, 0x08, 0xC8, 0x08, 0xD2, 0x6B, 0xFF, 0xFF, 0xBB, 0xD6,
		0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x4A, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x52, 0x00, 0x0A,
		0x96, 0x8E, 0x42, 0xFF, 0xFF, 0xFF, 0xFF, 0xEC, 0x29, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x09,
		0x11, 0xBF, 0xF7, 0xFF, 0xFF, 0xAB, 0x21, 0xC8, 0x08, 0xF9, 0xB5, 0xFF, 0xFF, 0xF6, 0x94, 0xC8,
		0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x7A, 0xCE, 0xFF, 0xFF, 0xD5, 0x94, 0x00, 0x0A, 0x96,
		0x95, 0x8C, 0xFF, 0xFF, 0x3D, 0xE7, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08,
		0xF9, 0xB5, 0xFF, 0xFF, 0xD2, 0x6B, 0x09, 0x11, 0xBF, 0xF7, 0xFF, 0xFF, 0xEF, 0x52, 0xC8, 0x08,
		0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x95, 0x8C, 0xFF, 0xFF, 0xBB, 0xD6, 0x00, 0x0A, 0x80, 0x01,
		0xBB, 0xD6, 0xFF, 0xFF, 0x16, 0x9D, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08,
		0xD2, 0x6B, 0xFF, 0xFF, 0xF9, 0xB5, 0xCF, 0x4A, 0xFF, 0xFF, 0xBF, 0xF7, 0x09, 0x11, 0xC8, 0x08,
		0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x8E, 0x42, 0xFF, 0xFF, 0xFF, 0xFF, 0xAB, 0x21, 0xC8, 0x08,
		0xC8, 0x08, 0x8E, 0x42, 0x16, 0x9D, 0x54, 0x84, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x54, 0x84,
		0x16, 0x9D, 0x1E, 0x98, 0xAB, 0x21, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x53, 0xC8, 0x08, 0xC8, 0x08,
		0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xAB, 0x21, 0xFF, 0xFF, 0xBF, 0xF7, 0xD5, 0x94, 0xFF, 0xFF,
		0x3A, 0xC6, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0x09, 0x11, 0xBF, 0xF7,
		0xFF, 0xFF, 0xD2, 0x6B, 0x6A, 0xC8, 0x08, 0x1E, 0x97, 0xD2, 0x6B, 0xFF, 0xFF, 0xFF, 0xFF, 0x4A,
		0x19, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xBB, 0xD6, 0xFF,
		0xFF, 0xDF, 0xFF, 0xFF, 0xFF, 0x33, 0x7C, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8,
		0x08, 0xC8, 0x08, 0xF9, 0xB5, 0xFF, 0xFF, 0xD5, 0x2B, 0xDE, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x84, 0xF9, 0xB5, 0xFF, 0xFF, 0x5A, 0xC6, 0xC8, 0x08, 0x06, 0x85, 0x95, 0x8C, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0x0C, 0x32, 0x06, 0x88, 0x13, 0x7C, 0xFF, 0xFF, 0xBF, 0xF7, 0x09, 0x11, 0xC8,
		0x08, 0xC8, 0x08, 0xCB, 0x29, 0x29, 0x11, 0x00, 0x02, 0x84, 0x09, 0x11, 0xBF, 0xF7, 0xFF, 0xFF,
		0x33, 0x7C, 0x07, 0x85, 0x8E, 0x42, 0xFF, 0xFF, 0xFF, 0xFF, 0x7E, 0xEF, 0xC8, 0x08, 0x06, 0x89,
		0x0C, 0x32, 0xFF, 0xFF, 0xFF, 0xFF, 0x8E, 0x42, 0xC8, 0x08, 0x54, 0x84, 0xFF, 0xFF, 0xFC, 0xDE,
		0x09, 0x11, 0x00, 0x01, 0x84, 0xEF, 0x52, 0xFF, 0xFF, 0xFF, 0xFF, 0x4D, 0x3A, 0x07, 0x84, 0xE9,
		0x08, 0x7E, 0xEF, 0xFF, 0xFF, 0x77, 0xAD, 0x68, 0xC8, 0x08, 0x88, 0x7E, 0xEF, 0xFF, 0xFF, 0x95,
		0x8C, 0xC8, 0x08, 0xF9, 0xB5, 0xFF, 0xFF, 0xFF, 0xFF, 0x8A, 0x21, 0x00, 0x01, 0x84, 0x8A, 0x21,
		0x4D, 0x3A, 0x4D, 0x3A, 0xE9, 0x08, 0x68, 0xC8, 0x08, 0x83, 0xEC, 0x29, 0x4D, 0x3A, 0x8A, 0x21,
		0x08, 0x88, 0xEC, 0x29, 0x4D, 0x3A, 0xCC, 0x29, 0xC8, 0x08, 0xCC, 0x29, 0xD5, 0x94, 0x0F, 0x53,
		0xC8, 0x08, 0x00, 0x01, 0x60, 0x03, 0xC8, 0x08, 0x00, 0x60, 0x86, 0xC8, 0x08, 0xC8, 0x08, 0x30,
		0x5B, 0x13, 0x74, 0x16, 0x9D, 0x5A, 0xC6, 0xD0, 0x3B, 0xE3, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x66, 0xC8, 0x08, 0x85, 0x2D, 0x32, 0x0F, 0x53, 0xD2, 0x6B, 0x16, 0x9D, 0x19,
		0xBE, 0xD0, 0x3A, 0x03, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0xC8, 0x08,
		0x84, 0xEC, 0x29, 0xCF, 0x4A, 0xB2, 0x6B, 0x16, 0x9D, 0xD0, 0x3B, 0x6E, 0x42, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xF3, 0x2D, 0x02, 0xC8, 0x08, 0x84, 0xC8, 0x08, 0xC8, 0x08, 0xC8,
		0x08, 0xC8, 0x08,
	};
	const std::vector<uint8_t> narrowTile = {
		0x7B, 0x02, 0x5A, 0xE7, 0x12, 0x4A, 0xB6, 0xFA, 0x20, 0x00, 0x40, 0x00, 0x19, 0x00, 0x00, 0x00,
		0x19, 0x00, 0x00, 0x00, 0xC0, 0x0C, 0xC8, 0x08, 0x84, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8,
		0x08, 0xF0, 0xDC, 0x07, 0x84, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08, 0xC8, 0x08,
	};
	const size_t slot = 20 + 64 * 64 * 2;
	std::vector<uint8_t> file = textTile;
	file.resize(slot, 0);
	file.insert(file.end(), narrowTile.begin(), narrowTile.end());
	std::vector<RdpCacheTile> tiles;
	size_t unread = 0;
	check(decodeRdpBmcCache(file, tiles, unread) && tiles.size() == 2 && unread == 0, "bmc cache: two slots, two tiles");
	if (tiles.size() == 2) {
		Sha256Stream digest;
		digest.update(tiles[0].pixels.data(), tiles[0].pixels.size());
		check(tiles[0].width == 64 && tiles[0].height == 64
		      && digest.hexDigest() == L"9C99DF2D5DDB7505F23F01F6D51CD1553C74DB2A52D4662083106709A394B723",
		      "bmc cache: a tile of text, pixel for pixel as bmc-tools decodes it");
		bool blue = tiles[1].width == 32 && tiles[1].height == 64 && tiles[1].pixels.size() == 4u * 32 * 64;
		for (size_t i = 0; blue && i < tiles[1].pixels.size(); i += 4)
			blue = tiles[1].pixels[i] == 66 && tiles[1].pixels[i + 1] == 24 && tiles[1].pixels[i + 2] == 8 && tiles[1].pixels[i + 3] == 0xFF;
		check(blue, "bmc cache: a tile 32 pixels wide decoded with rows of 32, not 64");
	}
	// The data of a tile cut short, an order the codec has not, a length past the slot.
	std::vector<uint8_t> cut = textTile;
	cut[12] = 100;   // the length: 100 bytes of the 1135
	std::vector<uint8_t> unknownOrder = narrowTile;
	unknownOrder[20] = 0xA0;   // order 5 of the regular ones: none
	std::vector<uint8_t> tooLong = narrowTile;
	writeLittleEndian<uint32_t>(tooLong.data() + 12, (uint32_t)slot);
	for (const auto& forged : { cut, unknownOrder }) {
		tiles.clear();
		check(decodeRdpBmcCache(forged, tiles, unread) && tiles.empty() && unread == 1, "bmc cache: a forged tile decoded");
	}
	tiles.clear();
	check(!decodeRdpBmcCache(tooLong, tiles, unread) && tiles.empty(), "bmc cache: a length past the slot read");
	// A run longer than the tile: refused, nothing written past it.
	const uint8_t megaColorRun[] = { 0xF3, 0xFF, 0xFF, 0x34, 0x12 };
	std::vector<uint16_t> out;
	check(!rdpRleDecompress16(megaColorRun, sizeof megaColorRun, 64, 64, out) && out.size() == 64 * 64,
	      "bmc cache: a run of 65535 pixels in a tile of 4096");
	check(bmcBytesPerPixel(L"BCACHE22.BMC") == 2 && bmcBytesPerPixel(L"bcache24.bmc") == 0 && bmcBytesPerPixel(L"bcache2.bmc") == 0,
	      "bmc cache: only the depth measured is decoded");
}

/*! The tiles of a `.bmc` bitmap cache as WAC decodes them, one line each —
 *  index|width|height|SHA-256 of the BGRA pixels, rows from the top — for a
 *  confrontation with bmc-tools on a file of the test VM.
 *  @param path the cache
 *  @param folder where to write each tile as tile_<NNNN>.bmp, to look at it; nullptr for none
 *  @return 0 if the file has the layout */
int dumpBmcCache(const wchar_t* path, const wchar_t* folder) {
	std::vector<uint8_t> bytes;
	if (!readWholeFile(path, 512ull * 1024 * 1024, bytes)) return 2;
	std::vector<RdpCacheTile> tiles;
	size_t unread = 0;
	if (!decodeRdpBmcCache(bytes, tiles, unread)) return 1;
	std::printf("tiles=%zu unread=%zu\n", tiles.size(), unread);
	for (size_t i = 0; i < tiles.size(); ++i) {
		Sha256Stream digest;
		digest.update(tiles[i].pixels.data(), tiles[i].pixels.size());
		std::printf("%zu|%u|%u|%ls\n", i, tiles[i].width, tiles[i].height, digest.hexDigest().c_str());
		if (!folder) continue;
		wchar_t name[32];
		swprintf(name, 32, L"tile_%04zu.bmp", i);
		const std::vector<uint8_t> bmp = rdpTileBmp(tiles[i]);
		std::ofstream(std::filesystem::path(folder) / name, std::ios::binary).write(reinterpret_cast<const char*>(bmp.data()), (std::streamsize)bmp.size());
	}
	return 0;
}

int wmain(int argc, wchar_t** argv) {
	if ((argc == 3 || argc == 4) && std::wcscmp(argv[1], L"--bmc") == 0) return dumpBmcCache(argv[2], argc == 4 ? argv[3] : nullptr);
	shimcacheWindows7();
	shimcacheVista();
	rdpBmcCache();
	shimcacheWindows8();
	shimcacheWindowsXp();
	prefetchVersion17();
	classicEventLog();
	userAssistXp();
	setupApiXp();
	recycleBinInfo2();
	jobFile();
	firewallXp();
	thumbsDb();
	destListVersion();
	powershell();
	setupapi();
	firewallLog();
	partitionTables();
	cmTraceLog();
	internetShortcut();
	recycleBin();
	hosts();
	errorReport();
	defender();
	defenderHistory();
	zoneIdentifier();
	registryLot2();
	securityDescriptors();
	ntfsVolumes();
	shortcutVolumeSerial();
	dpapiMasterKeys();
	userShellFolders();
	sqliteReader();
	prefetchReference();
	thumbcache();
	thumbcacheWindows7();
	mboxMail();
	check(plainExtension(L"report.PDF") == L"pdf" && plainExtension(L"..\\..\\Windows\\evil.exe") == L"exe"
	      && plainExtension(L"x.<script>") == L"" && plainExtension(L"noextension") == L"" && plainExtension(L"a.toolongext") == L""
	      && plainExtension(L"a.") == L"" && plainExtension(L"a.\u00e9t\u00e9") == L"",
	      "mail: an attachment's name gives at most a plain extension, never a path");
	check(to_hex(0x0BD30981u, 8, HexLetters::Upper) == L"0BD30981" && to_hex(0x200u, 8, HexLetters::Upper, true) == L"0x00000200"
	      && to_hex(0ULL, 1, HexLetters::Lower, true) == L"0x0" && to_hex((uint8_t)0xAB) == L"ab" && to_hex(-1, 1) == L"ffffffff",
	      "to_hex: the forms it replaced (%08X, 0x%08X, 0x%llx), two digits by default, a negative as its unsigned bits");
	chromiumHistory();
	check(urlValueNumber(L"url1") == 1 && urlValueNumber(L"URL25") == 25 && urlValueNumber(L"url") == 0
	      && urlValueNumber(L"url1a") == 0 && urlValueNumber(L"urlx") == 0 && urlValueNumber(L"url1234567890") == 0
	      && urlValueNumber(L"MRUList") == 0, "typed urls: url<N> numbered, anything else refused");
	firefoxHistory();
	loginsAndCookies();
	{
		std::wstring user, page;
		check(splitWebCacheUrl(L"Visited: wac@https://x.invalid/a@b", user, page) && user == L"wac" && page == L"https://x.invalid/a@b"
		      && splitWebCacheUrl(L":2026090720260914: wac@:Host: Ce PC", user, page) && user == L"wac" && page == L":Host: Ce PC"
		      && !splitWebCacheUrl(L"https://x.invalid/", user, page) && !splitWebCacheUrl(L":20260907x: wac@y", user, page)
		      && !splitWebCacheUrl(L"Visited: nouser", user, page),
		      "webcache: history URLs split into user and page, others left whole");
	}
	{
		/* An iedownload record laid out as Internet Explorer 11 wrote it on the
		   test VMs: version 0x8C on Windows 11, 0x89 on Windows 8.1, where the
		   address and the strings come 8 bytes earlier. */
		auto blob = [](const std::wstring& last, uint8_t version = 0x8C) {
			const size_t shift = version == 0x89 ? 8 : 0;
			std::vector<uint8_t> b(0x158 - shift, 0);
			b[0] = version;
			b[0x50] = 23;                                       // the file's size
			// A sockaddr_in: AF_INET on 16 bits, port 8765 in network order, 127.0.0.1.
			b[0xA0 - shift] = 2; b[0xA2 - shift] = 0x22; b[0xA3 - shift] = 0x3D;
			b[0xA4 - shift] = 127; b[0xA7 - shift] = 1;
			for (const std::wstring& t : { std::wstring(L"text/plain"), std::wstring(L"C:\\Users\\wac\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Low\\IE\\0VDERP2C\\w[1].txt"),
			                               std::wstring(L"http://127.0.0.1:8765/w.txt"), last }) {
				for (wchar_t c : t) { b.push_back((uint8_t)c); b.push_back((uint8_t)(c >> 8)); }
				b.push_back(0); b.push_back(0);
			}
			return b;
		};
		Json saved = Json::obj(), unsaved = Json::obj();
		auto text = [](const Json& o, const wchar_t* k) { const Json* v = o.find(k); return v ? v->text() : std::wstring(); };
		check(decodeIeDownload(blob(L"C:\\Users\\wac\\Downloads\\w.txt"), saved) && text(saved, L"Url") == L"http://127.0.0.1:8765/w.txt"
		      && text(saved, L"TargetPath") == L"C:\\Users\\wac\\Downloads\\w.txt" && text(saved, L"FileSize") == L"23"
		      && text(saved, L"ServerAddress") == L"127.0.0.1" && text(saved, L"MimeType") == L"text/plain" && !saved.find(L"SuggestedName"),
		      "iedownload: a saved download — URL, path, size, server, MIME type");
		check(decodeIeDownload(blob(L"w.txt"), unsaved) && text(unsaved, L"SuggestedName") == L"w.txt" && !unsaved.find(L"TargetPath"),
		      "iedownload: not saved — only the name it would take");
		Json older = Json::obj(), unknown = Json::obj();
		check(decodeIeDownload(blob(L"C:\\Users\\wac\\Downloads\\w.txt", 0x89), older) && text(older, L"MimeType") == L"text/plain"
		      && text(older, L"ServerAddress") == L"127.0.0.1" && text(older, L"Url") == L"http://127.0.0.1:8765/w.txt"
		      && text(older, L"FileSize") == L"23",
		      "iedownload: the layout of Windows 8.1 (version 0x89) — MIME type, server, URL, size");
		check(!decodeIeDownload(blob(L"w.txt", 0x8A), unknown) && !unknown.find(L"Url"),
		      "iedownload: a version not measured refused, nothing emitted");
		const std::vector<uint8_t> whole = blob(L"C:\\Users\\wac\\Downloads\\w.txt");
		bool refused = true;
		for (size_t cut : { (size_t)0, (size_t)0x100, (size_t)0x158, whole.size() - 3 }) {
			GuardedCopy copy(std::vector<uint8_t>(whole.begin(), whole.begin() + cut), GuardSide::After);
			Json none = Json::obj();
			refused = refused && !decodeIeDownload(std::vector<uint8_t>(copy.data(), copy.data() + copy.size()), none) && !none.find(L"Url");
		}
		check(refused, "iedownload: a truncated record refused, nothing emitted");
	}
	{
		/* An RDP bitmap cache laid out as mstsc wrote it on the test VM: the
		   header, then a 2 x 1 tile and a 1 x 2 tile (64 x 64 and 64 x 32 there). */
		std::vector<uint8_t> cache = { 'R', 'D', 'P', '8', 'b', 'm', 'p', 0, 6, 0, 0, 0 };
		auto tile = [&](uint32_t key, uint16_t w, uint16_t h, uint8_t first) {
			for (int i = 0; i < 4; ++i) cache.push_back((uint8_t)(key >> (8 * i)));
			for (int i = 0; i < 4; ++i) cache.push_back(0);
			cache.push_back((uint8_t)w); cache.push_back((uint8_t)(w >> 8));
			cache.push_back((uint8_t)h); cache.push_back((uint8_t)(h >> 8));
			for (int p = 0; p < 4 * w * h; ++p) cache.push_back((uint8_t)(first + p));
		};
		tile(0xBFB017F6u, 2, 1, 10);
		tile(0x80BF8DA0u, 1, 2, 50);
		uint32_t version = 0;
		std::vector<RdpCacheTile> tiles;
		const bool decoded = decodeRdpBitmapCache(cache, version, tiles);
		check(decoded && version == 6 && tiles.size() == 2 && tiles[0].key1 == 0xBFB017F6u && tiles[0].width == 2
		      && tiles[0].height == 1 && tiles[0].pixels.size() == 8 && tiles[0].pixels[0] == 10
		      && tiles[1].height == 2 && tiles[1].pixels[7] == 57,
		      "rdp cache: header, two tiles of their own sizes, pixels where the file has them");
		std::vector<uint8_t> cut(cache.begin(), cache.end() - 3);
		std::vector<RdpCacheTile> partial;
		check(decodeRdpBitmapCache(cut, version, partial) && partial.size() == 1,
		      "rdp cache: a tile cut by the end of the file ends the reading, the tiles before it kept");
		std::vector<RdpCacheTile> none;
		std::vector<uint8_t> other(cache);
		other[0] = 'X';
		check(!decodeRdpBitmapCache(other, version, none) && none.empty(), "rdp cache: a file without the header refused");
		// The 1 x 2 tile as a BMP: rows from the bottom — the second row first.
		const std::vector<uint8_t> bmp = rdpTileBmp(tiles[1]);
		check(bmp.size() == 54 + 8 && bmp[0] == 'B' && bmp[1] == 'M' && bmp[28] == 32 && bmp[54] == 54 && bmp[58] == 50,
		      "rdp cache: a tile as a 32-bit BMP, its rows from the bottom");
		Json settings = Json::obj();
		parseRdpFile(L"screen mode id:i:2\r\nfull address:s:srv.example:3389\r\nusername:s:CORP\\admin\r\nnot a setting\r\n", settings);
		const Json* address = settings.find(L"FullAddress");
		const Json* user = settings.find(L"Username");
		check(address && address->text() == L"srv.example:3389" && user && user->text() == L"CORP\\admin"
		      && settings.find(L"ScreenModeId") && settings.size() == 3,
		      "rdp file: name:type:value lines, a value holding colons kept whole, other lines ignored");
		check(isIncomingRdpEvent(L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149, L"")
		      && isIncomingRdpEvent(L"Security", 4624, L"10") && !isIncomingRdpEvent(L"Security", 4624, L"3")
		      && isIncomingRdpEvent(L"Security", 4778, L"") && !isIncomingRdpEvent(L"System", 1149, L"")
		      && !isIncomingRdpEvent(L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 42, L""),
		      "rdp server: the RDP events of their logs kept, Security's logons of type 10 only");
	}
	{
		/* A WEVT_TEMPLATE whose EVNT block, like AppReadiness.dll's, has data
		   after its 48-byte descriptors: its declared size is not 16 + 48 x
		   count. A step deduced from that size read every descriptor after the
		   first at the wrong place (B-023). */
		std::vector<uint8_t> d(64, 0);
		auto put32 = [&](size_t at, uint32_t v) { for (int i = 0; i < 4; ++i) d[at + i] = (uint8_t)(v >> (8 * i)); };
		memcpy(d.data(), "CRIM", 4);
		put32(12, 1);                    // one provider
		put32(32, 40);                   // its WEVT at 40 (GUID at 16 left zero)
		memcpy(d.data() + 40, "WEVT", 4);
		put32(52, 1);                    // one descriptor
		put32(60, 64);                   // EVNT at 64
		const uint32_t events = 3, trailing = 12;
		d.resize(64 + 16 + events * 48 + trailing, 0);
		memcpy(d.data() + 64, "EVNT", 4);
		put32(68, 16 + events * 48 + trailing);
		put32(72, events);
		for (uint32_t n = 0; n < events; ++n) {
			const size_t at = 80 + n * 48;
			d[at] = (uint8_t)(n + 1);                // identifier, version 0
			put32(at + 16, 0xB0000000u + n + 1);   // message identifier
		}
		for (uint32_t k = 0; k < trailing; ++k) d[80 + events * 48 + k] = 0xEE;
		const uint8_t accented[] = { 'd', 'o', 'n', 'n', 0xC3, 0xA9, 'e', 's', ' ', 0xF0, 0x9F, 0x98, 0x80, ' ', 0xC3, 'x', 0xE2, 0x82 };
		check(utf8ToWide(accented, sizeof accented) == std::wstring(L"donn\u00e9es \xD83D\xDE00 \xFFFDx\xFFFD\xFFFD"),
		      "utf8ToWide: accent, character beyond U+FFFF as a surrogate pair, malformed bytes as U+FFFD");
		// A MESSAGETABLE of two entries: one UTF-16 (flag 1), one UTF-8 (flag 2).
		std::vector<uint8_t> table = { 1, 0, 0, 0,  1, 0, 0, 0,  2, 0, 0, 0,  16, 0, 0, 0 };
		const std::vector<uint8_t> unicode = { 12, 0, 1, 0, 'O', 0, 'K', 0, 0, 0, 0, 0 };
		const std::vector<uint8_t> utf8 = { 12, 0, 2, 0, 'd', 0xC3, 0xA9, 'j', 0xC3, 0xA0, 0, 0 };
		table.insert(table.end(), unicode.begin(), unicode.end());
		table.insert(table.end(), utf8.begin(), utf8.end());
		TableMessages messages;
		check(messages.analyse(table) == 2 && messages.text(1) == L"OK" && messages.text(2) == L"d\u00e9j\u00e0",
		      "message table: UTF-16 and UTF-8 entries decoded");
		{
			/* Template items and a value map, laid out as Windows 11's
			   providers have them (measured on Kernel-Power): the event's
			   template at 20 in its descriptor, the item's map at 8, the MAPS
			   offset array of one entry per map, a VMAP header of 20 bytes. */
			std::vector<uint8_t> w(64, 0);
			auto at32 = [&](size_t at, uint32_t v) { if (w.size() < at + 4) w.resize(at + 4, 0); for (int i = 0; i < 4; ++i) w[at + i] = (uint8_t)(v >> (8 * i)); };
			memcpy(w.data(), "CRIM", 4);
			at32(12, 1); at32(32, 40);
			memcpy(w.data() + 40, "WEVT", 4);
			at32(52, 2); at32(60, 80); at32(68, 200);              // EVNT at 80, MAPS at 200
			w.resize(400, 0);
			memcpy(w.data() + 80, "EVNT", 4); at32(84, 16 + 48); at32(88, 1);
			w[96] = 7; at32(96 + 16, 0x30); at32(96 + 20, 300);    // event 7 v0, message 0x30, template at 300
			memcpy(w.data() + 200, "MAPS", 4); at32(204, 52); at32(208, 1); at32(212, 216);
			memcpy(w.data() + 216, "VMAP", 4); at32(220, 36); at32(232, 2);
			at32(236, 0); at32(240, 0x10); at32(244, 2); at32(248, 0x12);   // 0 -> Connected, 2 -> Disconnected
			memcpy(w.data() + 300, "TEMP", 4); at32(308, 2); at32(316, 340);
			w[344] = 0x08; w[345] = 0x08; at32(348, 216);           // item 0: UInt32 with the map
			w[364] = 0x15;                                          // item 1: HexInt64
			const std::vector<uint8_t> labels = { 2, 0, 0, 0,  0x10, 0, 0, 0,  0x10, 0, 0, 0,  28, 0, 0, 0,
			                                      0x12, 0, 0, 0,  0x12, 0, 0, 0,  36, 0, 0, 0,
			                                      8, 0, 2, 0, 'O', 'n', 0, 0,  12, 0, 2, 0, 'O', 'f', 'f', '\r', '\n', 0, 0, 0 };
			TableMessages labelTable;
			WevtMetadata typed;
			const bool parsed = typed.analyse(w, L"") == 1 && labelTable.analyse(labels) == 2;
			const std::vector<WevtItem>* items = typed.items(7, 0);
			const SystemMessages none;
			check(parsed && items && items->size() == 2
			      && formatItemValue((*items)[0], typed.valueMap((*items)[0].map), labelTable, none, L"2") == L"Off"
			      && formatItemValue((*items)[0], typed.valueMap((*items)[0].map), labelTable, none, L"5") == L"5"
			      && formatItemValue((*items)[1], typed.valueMap((*items)[1].map), labelTable, none, L"0x3e7") == L"0x3E7",
			      "wevt: template items read, a value map's label shown, an unmapped value kept, hexadecimal in upper case");
			// A MESSAGETABLE of UTF-16 entries, one block per message.
			auto messageTable = [](const std::vector<std::pair<uint32_t, std::wstring>>& entries) {
				std::vector<uint8_t> t(4 + entries.size() * 12, 0);
				auto at32 = [&](size_t at, uint32_t v) { for (int i = 0; i < 4; ++i) t[at + i] = (uint8_t)(v >> (8 * i)); };
				at32(0, (uint32_t)entries.size());
				for (size_t b = 0; b < entries.size(); ++b) {
					at32(4 + b * 12, entries[b].first); at32(8 + b * 12, entries[b].first); at32(12 + b * 12, (uint32_t)t.size());
					const std::wstring text = entries[b].second + L"\r\n";
					const size_t length = 4 + (text.size() + 1) * 2;
					t.push_back((uint8_t)length); t.push_back((uint8_t)(length >> 8)); t.push_back(1); t.push_back(0);
					for (wchar_t c : text) { t.push_back((uint8_t)c); t.push_back((uint8_t)(c >> 8)); }
					t.push_back(0); t.push_back(0);
				}
				return t;
			};
			TableMessages errors, ntStatus;
			errors.analyse(messageTable({ { 0, L"L'opération a réussi." }, { 2, L"Le fichier spécifié est introuvable." },
			                              { 5, L"Accès refusé." }, { 87, L"Paramètre incorrect." },
			                              { 0x80070005u, L"Erreur d'accès général refusé" }, { 0x80073CF1u, L"Le package est introuvable." } }));
			ntStatus.analyse(messageTable({ { 0, L"STATUS_SUCCESS" } }));
			SystemMessages system;
			system.errors = &errors;
			system.ntStatus = &ntStatus;
			auto typedAs = [](uint8_t in, uint8_t out) { WevtItem i; i.inType = in; i.outType = out; return i; };
			check(formatItemValue(typedAs(0x08, 0x1E), nullptr, labelTable, system, L"87") == L"Paramètre incorrect."
			      && formatItemValue(typedAs(0x07, 0x20), nullptr, labelTable, system, L"-2147009295") == L"Le package est introuvable."
			      && formatItemValue(typedAs(0x08, 0x20), nullptr, labelTable, system, L"0x80070002") == L"Le fichier spécifié est introuvable."
			      && formatItemValue(typedAs(0x07, 0x20), nullptr, labelTable, system, L"-1") == L"Unknown HResult Error code: 0xefffffff"
			      && formatItemValue(typedAs(0x08, 0x20), nullptr, labelTable, system, L"2147942405") == L"Accès refusé."
			      && formatItemValue(typedAs(0x08, 0x1F), nullptr, labelTable, system, L"0") == L"STATUS_SUCCESS"
			      && formatItemValue(typedAs(0x10, 0x13), nullptr, labelTable, system, L"0x1b3c") == L"0x1b3c"
			      && formatItemValue(typedAs(0x08, 0x12), nullptr, labelTable, system, L"2147746053") == L"0x80040105"
			      && formatItemValue(typedAs(0x07, 0x12), nullptr, labelTable, system, L"-2147221243") == L"0x80040105"
			      && formatItemValue(typedAs(0x08, 0x1D), nullptr, labelTable, system, L"2147746053") == L"0x80040105"
			      && formatItemValue(typedAs(0x14, 0x1E), nullptr, labelTable, system, L"0x80070002") == L"Le fichier spécifié est introuvable."
			      && formatItemValue(typedAs(0x0E, 0x0F), nullptr, labelTable, system, L"A57F6B1D") == L"0xA57F6B1D"
			      && formatItemValue(typedAs(0x0E, 0x19), nullptr, labelTable, system, L"0200E3817F0000010000000000000000") == L"127.0.0.1:58241",
			      "wevt: error codes by the system's text (Win32, HRESULT, its Win32 family, unknown, NTSTATUS), ErrorCode and integer in hexadecimal, pointer kept, binary and socket address");
			/* As the messages show them (measured): a double with 15 significant
			   digits (ReadyBoost 1015, Vista and Windows 11); a win:ErrorCode in
			   decimal under Vista (UMDF 2105), in hexadecimal under Windows 7;
			   a pointer in hexadecimal under both (UMDF 2101's %8). */
			check(formatItemValue(typedAs(0x0C, 0x00), nullptr, labelTable, system, L"17.469029324133604") == L"17.4690293241336"
			      && formatItemValue(typedAs(0x0C, 0x00), nullptr, labelTable, system, L"0") == L"0"
			      && formatItemValue(typedAs(0x08, 0x1D), nullptr, labelTable, system, L"3221225659", true) == L"3221225659"
			      && formatItemValue(typedAs(0x08, 0x1D), nullptr, labelTable, system, L"3221225659") == L"0xC00000BB"
			      && formatItemValue(typedAs(0x10, 0x13), nullptr, labelTable, system, L"0x0", true) == L"0x0",
			      "wevt: a double with 15 significant digits; Vista's win:ErrorCode in decimal, a pointer in hexadecimal");
			// A bitmap: the flags set, labelled, joined by commas; 0 by the map's label of 0.
			WevtValueMap flags;
			flags.bitmap = true;
			flags.labels = { { 0x0, 0x10 }, { 0x10, 0x12 }, { 0x4000000, 0x10 } };
			check(formatItemValue(typedAs(0x08, 0x08), &flags, labelTable, system, L"67108880") == L"Off,On"
			      && formatItemValue(typedAs(0x08, 0x08), &flags, labelTable, system, L"0") == L"0"
			      && formatItemValue(typedAs(0x08, 0x08), &flags, labelTable, system, L"1") == L"1",
			      "wevt: a bitmap's labels of the flags set, comma-joined; zero and no flag known: the value");
		}
		WevtMetadata meta;
		check(meta.analyse(d, L"") == 3 && meta.messageId(1, 0) == 0xB0000001u && meta.messageId(2, 0) == 0xB0000002u
		      && meta.messageId(3, 0) == 0xB0000003u,
		      "wevt: three 48-byte descriptors read, data after them in the block ignored");
	}
	{
		// Property-store values as Windows 11's Windows.db stores them (measured on the test VM).
		Json o = Json::obj();
		auto text = [&](const wchar_t* k) { const Json* v = o.find(k); return v ? v->text() : std::wstring(L"<absent>"); };
		addSearchBlob(o, L"DateModified", 64, { 0x77, 0xDB, 0xD2, 0x8C, 0xC4, 0xAD, 0xDC, 0x01 });   // VT_FILETIME
		addSearchBlob(o, L"Size", 21, { 0x22, 0x0B, 0, 0, 0, 0, 0, 0 });                              // VT_UI8: 2850
		addSearchBlob(o, L"VolumeId", 72, { 0xFA, 0x16, 0xCA, 0x3D, 0xCE, 0x6C, 0x46, 0x15,
		                                    0x9B, 0x57, 0x1D, 0x64, 0x41, 0xCB, 0x04, 0x88 });   // VT_CLSID
		addSearchBlob(o, L"Kind", 65, { 'f', 0, 'o', 0, 'l', 0, 'd', 0, 'e', 0, 'r', 0 });      // UTF-16, no terminator
		addSearchBlob(o, L"Keywords", 0x101F, { 'a', 0, 0, 0, 'b', 0, 0, 0 });                   // VT_VECTOR | VT_LPWSTR
		addSearchBlob(o, L"Odd", 65, { 'f', 0, 'o' });                                           // odd size: not UTF-16
		addSearchBlob(o, L"Zero", 64, { 0, 0, 0, 0, 0, 0, 0, 0 });                               // a zero date: nothing
		const Json* keywords = o.find(L"Keywords");
		check(text(L"DateModifiedUtc").compare(0, 19, L"2026-03-06T23:54:20") == 0 && text(L"Size") == L"2850"
		      && text(L"VolumeId") == L"{3DCA16FA-6CCE-1546-9B57-1D6441CB0488}" && text(L"Kind") == L"folder"
		      && keywords && keywords->size() == 2 && text(L"Odd") == L"66006F" && !o.find(L"ZeroUtc"),
		      "search index: FILETIME, VT_UI8, CLSID, UTF-16 text and vector decoded; odd blob in hex; zero date left out");
	}
	{
		/* Windows 7's index (SystemIndex_0A): two AutoSummary values as the
		   test VM's Windows.edb holds them. The first is in runs (form 0),
		   one of them the right quotation mark U+2019 of "opponent’s"; the
		   second one byte per character (form 1), the harness's witness. */
		const std::vector<uint8_t> runs = {
			0xB3, 0x91, 0x02, 0x43, 0xD9, 0x6E, 0x69, 0x7B, 0x9B, 0x7C, 0x62, 0x6B, 0x9F, 0x6F, 0x62, 0x6B,
			0xD0, 0x63, 0x7B, 0x75, 0x87, 0x67, 0x62, 0x60, 0xCA, 0x6C, 0x7F, 0x79, 0xD6, 0x3C, 0x79, 0x7B,
			0xFE, 0x45, 0x02, 0x49, 0xF1, 0x04, 0x65, 0x4A, 0xFE, 0x5B, 0x59, 0x00, 0xBF, 0x7C, 0x42, 0x4B,
			0xFA, 0x10, 0x53, 0x51, 0xE6, 0x5D, 0x58, 0x41, 0xFF, 0x18, 0x4E, 0x56, 0xEA, 0x1C, 0x5D, 0x55,
			0x9E, 0x30, 0x37, 0x32, 0x92, 0x36, 0x6A, 0x62, 0x94, 0x3A, 0x6A, 0x2D, 0x90, 0x21, 0x3E, 0x2F,
			0x97, 0x35, 0x72, 0x37, 0x80, 0x35, 0x3F, 0x3C, 0x98, 0x2C, 0x7A, 0x3F, 0xCF, 0x3A, 0x2C, 0x33,
			0xB6, 0x0E, 0x06, 0x48, 0xF7, 0x30, 0x0E, 0x07, 0xFB, 0x1F, 0x03, 0x00, 0xB1, 0x09, 0x1C, 0x4A,
			0xAA, 0x03, 0x52, 0x02, 0xAF, 0x11, 0x56, 0x14, 0xA2, 0x0A, 0x09, 0x0A, 0xEF, 0x08, 0x11, 0x5A,
			0x50, 0xE1, 0xF2, 0xF2, 0x42, 0xF6, 0xE3, 0xA2, 0x4F, 0xE0, 0xEF, 0xAE, 0x50, 0xFC, 0xFE, 0xE5,
			0x4D, 0xF5, 0xFC, 0xE2, 0x26, 0xB4, 0x8F, 0x95, 0x2B, 0xEB, 0xBA, 0xF5, 0x46, 0xF2, 0xF9, 0xB4
		};
		const std::vector<uint8_t> bytes = {
			0x28, 0x77, 0x63, 0x65, 0x5E, 0x61, 0x67, 0x70, 0x42, 0x60, 0x7D, 0x67, 0x51, 0x62, 0x6B, 0x79,
			0x4A, 0x22, 0x22, 0x24, 0x0B, 0x25, 0x26, 0x23, 0x04, 0x28, 0x23, 0x2D, 0x0C, 0x2C, 0x2A, 0x3A,
			0x6A, 0x4F, 0x4C, 0x52, 0x68, 0x4A, 0x53, 0x02, 0x65, 0x5D, 0x0A, 0x4A, 0x6A, 0x4F, 0x5B, 0x47,
			0x7C, 0x5E, 0x46, 0x16, 0x69, 0x51, 0x5B, 0x5D, 0x78, 0x56
		};
		// The obfuscation is its own inverse: values built here, decoded, encoded so.
		auto encode = [](std::vector<uint8_t> v) {
			const uint32_t mask = 0x05000113u ^ (uint32_t)v.size();
			for (size_t i = 0; i < v.size(); ++i) v[i] ^= (uint8_t)(mask >> (8 * (i & 3))) ^ (uint8_t)i;
			return v;
		};
		const std::vector<uint8_t> cut = encode({ 0x00, 0x05, 0x00, 'a', 'b' });   // a run of 5, 2 there
		const std::vector<uint8_t> unknown = encode({ 0x02, 'a', 'b' });           // a form not known
		std::wstring a, b, c, d;
		check(decodeSearchText(runs, a) && a.compare(0, 10, L"Enjoy the ") == 0 && a.find(L"opponent\u2019s king.") != std::wstring::npos
		      && decodeSearchText(bytes, b) && b == L"wacsearchwitness20261015093904 contenu du document temoin",
		      "search index: Windows 7's text decoded, in runs and one byte per character");
		check(!decodeSearchText(cut, c) && !decodeSearchText(unknown, d),
		      "search index: Windows 7's text with a run past its end, or of another form, decoded");
	}
	{
		/* UserData whose values are attributes before child elements: UMDF's
		   event 2004 as Windows 7 renders it (measured). Windows' message is
		   "loading driver %4 at level %3 for device %1": the attributes come
		   first, the namespace declarations are none. */
		const std::unique_ptr<XmlNode> root = xmlParse(
			L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>2004</EventID></System>"
			L"<UserData><UMDFHostAddDeviceBegin instance='WPDBUSENUMROOT\\UMB\\2&amp;37C186B' lifetime='{16C46B32-D0DF-4BA1-8AA2-4D7F005CBA1B}'"
			L" xmlns:auto-ns2='http://schemas.microsoft.com/win/2004/08/events' xmlns='http://www.microsoft.com/DriverFrameworks/UserMode/Event'>"
			L"<Level>0</Level><Service>WpdFs</Service><DriverClsid>{112DE495-AC4C-46F8-B663-6A4266C53313}</DriverClsid>"
			L"</UMDFHostAddDeviceBegin></UserData></Event>", true);
		const std::vector<std::wstring> expected = { L"WPDBUSENUMROOT\\UMB\\2&37C186B", L"{16C46B32-D0DF-4BA1-8AA2-4D7F005CBA1B}",
		                                             L"0", L"WpdFs", L"{112DE495-AC4C-46F8-B663-6A4266C53313}" };
		bool read = false;
		if (root) {
			const Event e(*root, L"Microsoft-Windows-DriverFrameworks-UserMode/Operational", 1, L"x.evtx");
			read = e.rawValues == expected && e.rawNames.size() == 5 && e.rawNames[0] == L"instance" && e.rawNames[3] == L"Service";
		}
		check(read, "events: UserData's attributes read first, in order, without the namespace declarations");
	}
	{
		/* RecentFileCache.bcf of the Windows 7 VM: its header and first path,
		   as Windows wrote them; then a second path whose count passes the
		   file's end, which ends the reading with the first one kept. */
		std::vector<uint8_t> bytes = {
			0xFE, 0xFF, 0xEE, 0xFF, 0x11, 0x22, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0D, 0x0B, 0x1D, 0x9E,
			0x22, 0x00, 0x00, 0x00 };
		for (const wchar_t c : std::wstring(L"c:\\windows\\system32\\sdiagnhost.exe")) { bytes.push_back((uint8_t)c); bytes.push_back(0); }
		bytes.push_back(0);
		bytes.push_back(0);
		std::vector<std::wstring> paths;
		check(decodeRecentFileCache(bytes, paths) && paths == std::vector<std::wstring>{ L"c:\\windows\\system32\\sdiagnhost.exe" },
		      "RecentFileCache.bcf: the path of Windows 7 read");
		std::vector<uint8_t> forged = bytes;
		for (const uint8_t b : { 0xFF, 0xFF, 0xFF, 0x7F, 0x61, 0x00 }) forged.push_back(b);   // 2^31 characters, one there
		std::vector<uint8_t> foreign = bytes;
		foreign[0] = 0x00;
		check(decodeRecentFileCache(forged, paths) && paths.size() == 1 && !decodeRecentFileCache(foreign, paths) && paths.empty(),
		      "RecentFileCache.bcf: a forged count read past the file, or a file without the signature decoded");
	}
	check(webCacheFile(L"C:\\c\\IE\\", L"L4YBWS0NA4VP7Z24E5E1CFPFBODANLF1", 3, L"wac[1].hta") == L"C:\\c\\IE\\E5E1CFPF\\wac[1].hta"
	      && webCacheFile(L"C:\\c\\IE\\", L"L4YBWS0NA4VP7Z24E5E1CFPFBODANLF1", 4, L"x") == L"C:\\c\\IE\\BODANLF1\\x"
	      && webCacheFile(L"C:\\c\\IE\\", L"L4YBWS0NA4VP7Z24E5E1CFPFBODANLF1", 5, L"x").empty()
	      && webCacheFile(L"C:\\c\\IE\\", L"L4YBWS0N", 0, L"x").empty() && webCacheFile(L"C:\\c\\IE\\", L"L4YBWS0N", 1, L"").empty(),
	      "webcache: the cached file found by its subfolder, indexed from 1; outside the list, none");
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
