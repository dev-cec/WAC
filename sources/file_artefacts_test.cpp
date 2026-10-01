/*! \file
 *  \brief Checks the decoders of the small file artefacts on inputs whose
 *  result is known: PowerShell history, setupapi.dev.log, recycle bin `$I`,
 *  hosts, Report.wer, Defender's MPLog, DetectionHistory and quarantine,
 *  Zone.Identifier, and the registry values of the second lot (TrustRecords,
 *  firewall rules, certificate Blob), the NTFS security descriptors of
 *  $Secure:$SDS, the NTFS boot sector and change journal header, and the
 *  volume serial of a shortcut.
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
#include "defender_history.h"
#include "defender_log.h"
#include "zone_identifiers.h"
#include "registry_lot2.h"
#include "security_descriptors.h"
#include "ntfs_volumes.h"
#include "recent_docs.h"
#include "guard_page.h"
#include <cstdio>
#include <cstring>

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

} // namespace

int wmain() {
	powershell();
	setupapi();
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
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
