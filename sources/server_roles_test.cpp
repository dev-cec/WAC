/*! \file
 *  \brief Checks the readers of the server roles (dns_server.h, dhcp_server.h, hyperv.h)
 *  on the forms measured on a real Server 2022, and on what a forged file can hold.
 *
 *  Usage (runs under wine): server_roles_test.exe
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include "dhcp_server.h"
#include "dns_server.h"
#include "hyperv.h"
#include "user_access_log.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned g_checks = 0, g_failures = 0;

//! Records one check, printing a failure.
void check(bool ok, const char* what) {
	++g_checks;
	if (ok) return;
	++g_failures;
	printf("FAILED: %s\n", what);
}

//! The zone file Windows wrote for the witness zone, comments and layout included.
const wchar_t ZONE[] =
	L";\r\n;  Database file wac-witness.test.dns for Default zone scope in zone wac-witness.test.\r\n;      Zone version:  6\r\n;\r\n\r\n"
	L"@                       IN  SOA wac-test. hostmaster. (\r\n"
	L"                        \t\t6            ; serial number\r\n"
	L"                        \t\t900          ; refresh\r\n"
	L"                        \t\t600          ; retry\r\n"
	L"                        \t\t86400        ; expire\r\n"
	L"                        \t\t3600       ) ; default TTL\r\n\r\n"
	L";\r\n;  Zone NS records\r\n;\r\n\r\n"
	L"@                       NS\twac-test.\r\n\r\n"
	L"@                       MX\t10\tmail.wac-witness.test.\r\n"
	L"alias                   CNAME\thost1.wac-witness.test.\r\n"
	L"host1                   600\tA\t192.0.2.10\r\n"
	L"                        AAAA\t2001:db8::10\r\n"
	L"note                    TXT\t( \"wac witness; quoted \\\"text\\\"\" )\r\n";

//! The witness zone: each record's owner, TTL and type as Get-DnsServerResourceRecord lists them.
void zoneFile() {
	const std::vector<DnsZoneRecord> r = parseDnsZoneFile(ZONE, L"wac-witness.test", L"C:\\z.dns");
	check(r.size() == 7, "seven records in the witness zone");
	if (r.size() != 7) return;
	check(r[0].type == L"SOA" && r[0].name == L"wac-witness.test" && r[0].ttl == 3600 && r[0].line == 6, "SOA over several lines");
	check(r[0].data == L"wac-test. hostmaster. 6 900 600 86400 3600", "SOA's comments left out");
	check(r[1].type == L"NS" && r[1].data == L"wac-test." && r[1].ttl == 3600, "NS takes the SOA's TTL");
	check(r[2].type == L"MX" && r[2].data == L"10 mail.wac-witness.test.", "MX keeps its preference");
	check(r[4].name == L"host1.wac-witness.test" && r[4].ttl == 600 && r[4].data == L"192.0.2.10", "A with its own TTL");
	check(r[5].name == L"host1.wac-witness.test" && r[5].type == L"AAAA" && r[5].ttl == 3600, "a blank owner is the previous one, its TTL not inherited");
	check(r[6].type == L"TXT" && r[6].data == L"\"wac witness; quoted \\\"text\\\"\"", "a ; in quotes is no comment");
	check(r[4].dnsClass == L"IN", "the class defaults to IN");
}

//! $ORIGIN, $TTL, class before TTL, absolute names; what does not read leaves the rest.
void zoneDirectives() {
	const std::vector<DnsZoneRecord> r = parseDnsZoneFile(
		L"$TTL 300\n$ORIGIN sub.example.\nwww IN 60 A 1.2.3.4\nabs.example. A 5.6.7.8\n7 8\n@ AAAA ::1\n\"unfinished\n", L"example", L"f");
	check(r.size() >= 3, "$ORIGIN and $TTL read");
	if (r.size() < 3) return;
	check(r[0].name == L"www.sub.example" && r[0].ttl == 60, "class before TTL");
	check(r[1].name == L"abs.example" && r[1].ttl == 300, "an absolute name, the default TTL");
	check(r[2].name == L"sub.example" && r[2].type == L"AAAA", "@ is the current origin, a line without type left out");
	check(parseDnsZoneFile(std::wstring(100000, L'('), L"z", L"f").empty(), "parentheses never closed");
	check(parseDnsZoneFile(L"", L"z", L"f").empty(), "an empty file");
}

//! The debug log's lines, as the French server wrote them; dates as stored.
void debugLog() {
	const std::vector<DnsLogEntry> e = parseDnsDebugLog(
		L"DNS Server log file creation at 04/11/2026 09:04:04\r\n\r\nMessage logging key:\r\n\tField #  Information\r\n"
		L"04/11/2026 09:04:07 F20 Note: got GQCS failure on a dead socket context status=995\r\n"
		L"04/11/2026 09:05:43 0F28 PACKET  0000015ADA261A90 UDP Rcv 127.0.0.1       ee7a   Q [0001   D   NOERROR] AAAA   (5)host1(11)wac-witness(4)test(0)\r\n\r\n"
		L"11/4/2026 9:05:43 AM 0F1C PACKET  0000015ADA25EFD0 UDP Snd 127.0.0.1       1c7e R Q [8085 A DR  NOERROR] A      (5)host1(11)wac-witness(4)test(0)\r\n", L"f");
	check(e.size() == 3, "the key is left out, each dated line read");
	if (e.size() != 3) return;
	check(e[0].text == L"Note: got GQCS failure on a dead socket context status=995" && e[0].packet.empty(), "a note kept as text");
	check(e[1].timeAsStored == L"04/11/2026 09:05:43" && e[1].direction == L"Rcv" && e[1].remoteAddress == L"127.0.0.1" && !e[1].response, "a query");
	check(e[1].flags == L"0001" && e[1].flagCodes == L"D" && e[1].responseCode == L"NOERROR", "its flags");
	check(e[1].questionType == L"AAAA" && e[1].questionName == L"host1.wac-witness.test", "the question's name in clear");
	check(e[2].timeAsStored == L"11/4/2026 9:05:43 AM" && e[2].response && e[2].flagCodes == L"ADR", "a response on a 12-hour clock");
	const std::vector<DnsLogEntry> forged = parseDnsDebugLog(L"01/01/2026 00:00:00 1 PACKET x UDP Rcv a b Q [1 D NOERROR] A (99)x(0)\r\n01/01/2026 00:00:00 1 PACKET\r\n", L"f");
	check(forged.size() == 2 && forged[0].questionName == L"(99)x(0)", "a name's length beyond the line: left as written");
}

//! The audit log: columns by position under a translated header, date MM/dd/yy.
void auditLog() {
	const std::vector<DhcpLogEntry> e = parseDhcpAuditLog(
		L"\t\tJournal d'activité du service DHCP Microsoft\r\n\r\nID, Date, Heure, Description, Adresse IP\r\n"
		L"00,11/04/26,09:04:14,Démarré,,,,,0,6,,,,,,,,,0\r\n"
		L"10,11/04/26,10:00:00,Attribuer,192.0.2.151,leased.test,00155D000002,,1234,0,,,,,,,,,0\r\n"
		L"11,11/04/26,10:00:01,Renouvellement, deux virgules, ici,192.0.2.151,leased.test,00155D000002,,1234,0,,,,,,,,,0\r\n"
		L"12,13/45/26,10:00:02,date impossible,,,,,0,6,,,,,,,,,0\r\n"
		L"99,short\r\n", L"f", false);
	check(e.size() == 4, "the header and a short line left out");
	if (e.size() != 4) return;
	check(e[0].eventId == L"00" && e[0].description == L"Démarré" && e[0].address.empty(), "a service line");
	FILETIME expected;
	check(iso8601UtcToFiletime(L"2026-11-04T10:00:00Z", expected) && CompareFileTime(&e[1].time, &expected) == 0, "MM/dd/yy, as written");
	check(e[1].address == L"192.0.2.151" && e[1].hostName == L"leased.test" && e[1].hardwareAddress == L"00155D000002" && e[1].transactionId == L"1234", "a lease's fields");
	check(e[2].description == L"Renouvellement, deux virgules, ici" && e[2].address == L"192.0.2.151", "commas in a description do not shift the columns");
	check(e[3].timeAsStored == L"13/45/26 10:00:02" && !e[3].time.dwLowDateTime && !e[3].time.dwHighDateTime, "an impossible date stays as stored");
	const std::vector<DhcpLogEntry> v6 = parseDhcpAuditLog(L"11000,11/04/26,09:04:14,Solicit,2001:db8::1,h,0,14,0001,user,,2001:db8::\r\n", L"f", true);
	check(v6.size() == 1 && v6[0].duidBytes == L"0001" && v6[0].userName == L"user" && v6[0].subnetPrefix == L"2001:db8::", "the IPv6 log's columns");
}

//! What the lease database's columns hold, as measured.
void leaseColumns() {
	check(dhcpAddressText(0xC0000297) == L"192.0.2.151", "an address from its Long column");
	check(dhcpClientId({ 0x00, 0x02, 0x00, 0xC0, 0x01, 0x00, 0x15, 0x5D, 0x00, 0x00, 0x02 }) == L"00-15-5d-00-00-02", "subnet and type left out of the client id");
	check(dhcpClientId({ 0x00, 0x02, 0x00, 0xC0, 0x01 }).empty(), "no client id in a short value");
}

//! Appends one key and text value in the layout measured in a .vmcx.
void appendPair(std::vector<uint8_t>& out, const char* key, const std::wstring& value) {
	const size_t keySize = strlen(key) + 1;
	out.push_back((uint8_t)keySize);
	out.insert(out.end(), key, key + keySize);
	const uint32_t bytes = (uint32_t)value.size() * 2;
	for (int i = 0; i < 4; ++i) out.push_back((uint8_t)(bytes >> (8 * i)));
	for (const wchar_t c : value) { out.push_back((uint8_t)c); out.push_back((uint8_t)(c >> 8)); }
}

//! The pairs of a .vmcx: each once, what is no text left out, nothing read beyond the buffer.
void vmcx() {
	std::vector<uint8_t> b(12, 0);
	appendPair(b, "name", L"wac-witness-vm");
	b.insert(b.end(), 7, 0);
	appendPair(b, "pathname", L"C:\\wactest\\é.vhdx");
	appendPair(b, "name", L"wac-witness-vm");   // the file holds its tree twice
	appendPair(b, "binary", std::wstring(L"\x0001\x0002"));
	b.push_back(5);                              // a key announced, the buffer ending
	const auto pairs = readVmcxStrings(b.data(), b.size());
	check(pairs.size() == 2, "two pairs, each once, the binary left out");
	if (pairs.size() != 2) return;
	check(pairs[0].first == L"name" && pairs[0].second == L"wac-witness-vm", "a name");
	check(pairs[1].first == L"pathname" && pairs[1].second == L"C:\\wactest\\é.vhdx", "a path, not ASCII");
	std::vector<uint8_t> lying = { 5, 'n', 'a', 'm', 'e', 0, 0xFF, 0xFF, 0xFF, 0x7F, 'a', 0 };
	check(readVmcxStrings(lying.data(), lying.size()).empty(), "a length beyond the file");
	// A length within the value's limit, beyond the size given: what follows the size must not be read.
	const std::vector<uint8_t> shortOfIt = { 5, 'n', 'a', 'm', 'e', 0, 8, 0, 0, 0, 'a', 0, 'b', 0, 'c', 0, 'd', 0 };
	check(readVmcxStrings(shortOfIt.data(), shortOfIt.size() - 4).empty(), "a plausible length beyond the file");
	check(readVmcxStrings(nullptr, 0).empty(), "an empty file");
}

/*! Forged text files whose cost grows with what they announce: each must stay
 *  bounded, a real name, line or record being far below the limits. */
void forgedSizes() {
	std::wstring zone;
	for (int i = 0; i < 2000; ++i) zone += L"$ORIGIN a\n";
	zone += L"h A 192.0.2.1\n";
	const auto records = parseDnsZoneFile(zone, L"z", L"f");
	check(records.size() == 1 && records[0].name.size() < 300, "repeated $ORIGIN: the name stays within a DNS name's size");

	std::wstring open = L"h TXT (";
	for (int i = 0; i < 100000; ++i) open += L" a";
	const auto swallowed = parseDnsZoneFile(open, L"z", L"f");
	check(swallowed.size() == 1 && swallowed[0].data.size() <= 2 * 70000, "an open parenthesis: the record's words are bounded");

	const std::wstring commas(200000, L',');
	check(parseDhcpAuditLog(L"10,11/04/26,10:00:00" + commas + L"\n", L"f", false).empty(), "an audit line of commas: refused");
	std::wstring words = L"11/4/2026 09:05:43 0F28 PACKET";
	for (int i = 0; i < 40000; ++i) words += L" a";
	check(parseDnsDebugLog(words + L"\n", L"f").empty(), "a debug log line of words: refused");
	check(parseDhcpAuditLog(L"10,11/04/26,10:00:00,a,b,c,192.0.2.1,h,00,,1,0,,,,,,,,,0\n", L"f", false).size() == 1, "a description with commas: still read");
}

} // namespace

//! User Access Logging: an address in any size a forged database can hold, a day of any year.
void userAccess() {
	check(userAccessAddressText({ 127, 0, 0, 1 }) == L"127.0.0.1", "an IPv4 address");
	std::vector<uint8_t> loopback(16, 0);
	loopback[15] = 1;
	check(userAccessAddressText(loopback) == L"::1", "an IPv6 address");
	check(userAccessAddressText({ 0xAB, 0x01, 0xFF }) == L"AB01FF", "a size of neither: hexadecimal");
	check(userAccessAddressText({}).empty(), "no address: nothing");
	check(userAccessDatabaseCandidate(L"current.mdb") && userAccessDatabaseCandidate(L"{830a41f6-7656-47af-a9d4-39217a905d06}.mdb"),
	      "a database named .mdb is read");
	check(userAccessDatabaseCandidate(std::wstring(L"\x6630") + L'\xDB1C' + L"\x0239"),
	      "a database without extension, as Server 2016 names a past period's, is read");
	check(!userAccessDatabaseCandidate(L"svc.log") && !userAccessDatabaseCandidate(L"svcres00001.jrs")
	      && !userAccessDatabaseCandidate(L"svc.chk") && !userAccessDatabaseCandidate(L"current.jfm"),
	      "the engine's own files are not read as databases");
	check(!userAccessDatabaseCandidate(L"sub\\current.mdb") && !userAccessDatabaseCandidate(L""), "a subfolder's file, an empty name: not read");
	check(userAccessDayDate(2026, 308) == L"2026-11-04", "day 308 of 2026, as measured on 4 November");
	check(userAccessDayDate(2026, 1) == L"2026-01-01", "the first day");
	check(userAccessDayDate(2026, 60) == L"2026-03-01", "day 60 of a common year");
	check(userAccessDayDate(2024, 60) == L"2024-02-29", "day 60 of a leap year");
	check(userAccessDayDate(2024, 366) == L"2024-12-31", "the last day of a leap year");
	check(userAccessDayDate(2100, 366).empty(), "2100 is not a leap year");
	check(userAccessDayDate(2026, 366).empty(), "no day 366 in a common year");
	check(userAccessDayDate(2026, 0).empty(), "no day 0");
	check(userAccessDayDate(0, 10).empty(), "no year: no date");
}

int wmain() {
	zoneFile();
	zoneDirectives();
	debugLog();
	auditLog();
	leaseColumns();
	vmcx();
	forgedSizes();
	userAccess();
	printf("%u checks, %u failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
