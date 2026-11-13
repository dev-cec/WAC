/*! \file
 *  \brief Inputs forged by whoever controls the examined machine, read by WAC:
 *         what the security review of version 4.0 found, and a mutation run
 *         over the text and binary readers the version added.
 *
 *  Each named check holds one defect seen on this code: a name of a directory
 *  index that climbs out of the exhibit store, a path of a web server's
 *  configuration that climbs out of the collection at the conversion, a chain
 *  of Apache `Define` doubling its text until the memory runs out, a digit
 *  that is no ASCII digit in a scripts.ini, and a view of a hostile SQLite
 *  database that runs unbounded SQL.
 *
 *  The mutation run has a fixed seed, so a failure reproduces. Binary inputs
 *  lie against a guard page (guard_page.h); an exception that escapes a reader
 *  ends the test, as it would end a collection.
 *
 *  Usage: hostile_input_test [mutations per input] — built by
 *  `build-windows.sh --test`, runs under Wine. Exit code: 0 if all checks hold.
 */
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <random>
#include <string>
#include <vector>
#include "active_directory.h"
#include "application_trace_files.h"
#include "audit.h"
#include "dhcp_server.h"
#include "dns_server.h"
#include "group_policies.h"
#include "hyperv.h"
#include "guard_page.h"
#include "raw_hive.h"
#include "sqlite_reader.h"
#include "sqlite3.h"
#include "tools.h"
#include "w3c_log.h"
#include "web_installations.h"
#include "web_server.h"
#include "xml_light.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned g_checks = 0, g_failures = 0;

//! Records one check, printing a failure.
void check(bool ok, const char* what) {
	++g_checks;
	if (ok) return;
	++g_failures;
	printf("FAILED: %s\n", what);
}

//! Appends a little-endian number.
template <typename T> void put(std::vector<uint8_t>& out, T value) {
	for (size_t i = 0; i < sizeof(T); ++i) out.push_back((uint8_t)(value >> (8 * i)));
}

/*! A node of a directory index with one entry per name, then the last entry.
 *  @param names the file names
 *  @return the node's bytes, its header first */
std::vector<uint8_t> indexNode(const std::vector<std::wstring>& names) {
	std::vector<uint8_t> node;
	put<uint32_t>(node, 16);   // first entry, from the header
	node.resize(16, 0);
	for (const std::wstring& name : names) {
		const size_t size = 0x10 + 0x42 + 2 * name.size();
		const size_t padded = (size + 7) & ~(size_t)7;
		const size_t at = node.size();
		put<uint64_t>(node, 0x0001000000000040ull);   // file reference
		put<uint16_t>(node, (uint16_t)padded);
		put<uint16_t>(node, (uint16_t)(0x42 + 2 * name.size()));
		put<uint16_t>(node, 0);                       // flags
		put<uint16_t>(node, 0);
		node.resize(at + 0x10 + 0x40, 0);             // the $FILE_NAME before its name
		node.push_back((uint8_t)name.size());
		node.push_back(1);                            // Win32 namespace
		for (wchar_t c : name) put<uint16_t>(node, (uint16_t)c);
		node.resize(at + padded, 0);
	}
	put<uint64_t>(node, 0);
	put<uint16_t>(node, 0x10);
	put<uint16_t>(node, 0);
	put<uint16_t>(node, 2);                           // the last entry
	put<uint16_t>(node, 0);
	return node;
}

/*! A name of a forged index never reaches the path a copy is written to:
 *  outDir + "\\" + name, opened by Win32, would climb out of the store, up to
 *  WAC.exe on the collection medium. */
void forgedIndexNames() {
	const std::vector<uint8_t> node = indexNode({ L"genuine.log", L"..\\..\\..\\WAC.exe", L"a/../b", L"c:d", L"..", L". .", L"plain name.txt" });
	std::vector<RawDirEntry> entries;
	parseDirectoryIndexNode(node.data(), node.data() + node.size(), entries);
	bool climbing = false, genuine = false, plain = false;
	for (const RawDirEntry& e : entries) {
		if (e.name.find_first_of(L"\\/:") != std::wstring::npos || e.name == L".." || e.name == L". .") climbing = true;
		if (e.name == L"genuine.log") genuine = true;
		if (e.name == L"plain name.txt") plain = true;
	}
	check(!climbing, "a forged name of a directory index is refused");
	check(genuine && plain, "the genuine names beside it are kept");
}

/*! Stays under the collection, whatever the examined machine's configuration
 *  says: at the conversion, `..` would read the analyst's own files into the JSON. */
void pathsStayUnderTheCollection() {
	conf.systemDrive = L"C:";
	const std::wstring root = L"Z:\\case\\working";
	const auto inside = [&](const std::wstring& path) {
		return path.compare(0, root.size(), root) == 0 && path.find(L"..") == std::wstring::npos;
	};
	check(inside(pathUnder(root, L"C:\\inetpub\\..\\..\\..\\..\\Users\\analyst\\.ssh")), "`..` does not climb out of the root");
	check(inside(pathUnder(root, L"D:\\a\\..\\..\\..\\secret")), "nor from a secondary volume");
	check(inside(pathUnder(root, L"C:\\a\\.. \\.. \\..\\secret")), "nor with spaces after the dots");
	check(inside(pathUnder(root, L"C:\\a/../../../secret")), "nor with forward slashes");
	check(pathUnder(root, L"C:\\a\\..\\b\\c.log") == root + L"\\b\\c.log", "a `..` inside the path is resolved as Windows does");
	check(pathUnder(root, L"C:\\Windows\\System32\\config") == root + L"\\Windows\\System32\\config", "an ordinary path is unchanged");
	check(pathUnder(root, L"C:\\Users\\a..b\\file..txt") == root + L"\\Users\\a..b\\file..txt", "dots inside a name are not a `..`");
}

//! Serves files held in memory, as the tests of the web readers do.
WebConfigFiles filesOf(const std::wstring& path, const std::wstring& content) {
	WebConfigFiles files;
	files.read = [path, content](const std::wstring& asked, std::wstring& text) {
		if (asked != path) return false;
		text = content;
		return true;
	};
	files.matches = [](const std::wstring&) { return std::vector<std::wstring>{}; };
	return files;
}

//! A line of `Define` per doubling: 2^64 characters from a few kilobytes, if nothing bounds them.
void apacheDefinesDoNotGrowWithoutBound() {
	std::wstring text = L"Define a0 xxxxxxxx\n";
	for (int i = 1; i <= 64; ++i)
		text += L"Define a" + std::to_wstring(i) + L" ${a" + std::to_wstring(i - 1) + L"}${a" + std::to_wstring(i - 1) + L"}\n";
	text += L"DocumentRoot C:/site/${a64}\nDocumentRoot C:/plain\n";
	WebCandidate candidate;
	candidate.product = L"Apache";
	candidate.root = L"C:\\apache";
	candidate.configFile = L"C:\\apache\\conf\\httpd.conf";
	const WebInstallation out = parseApacheConfiguration(candidate, filesOf(candidate.configFile, text));
	bool plain = false, reasonable = true;
	for (const WebHost& h : out.hosts)
		for (const std::wstring& root : h.documentRoots) {
			if (root == L"C:\\plain") plain = true;
			if (root.size() > 1024 * 1024) reasonable = false;
		}
	check(plain && reasonable, "a chain of Define neither exhausts the memory nor stops the reading");
}

//! A field of "#Fields:" cannot stand in for the record's own keys: each key once in the object, the file's name the true one.
void w3cFieldsCannotShadowTheRecord() {
	const std::wstring log = L"#Fields: date time File Line Time a a\n2026-10-24 15:01:02 forged.log 999 x 1 2\n";
	const std::vector<W3cLogEntry> entries = parseW3cLog(log, L"true.log", {}, W3cTime::Utc);
	check(entries.size() == 1, "the W3C line is read");
	if (entries.empty()) return;
	const std::wstring json = entries[0].toJson().dump();
	const auto count = [&json](const std::wstring& what) {
		size_t found = 0;
		for (size_t at = json.find(what); at != std::wstring::npos; at = json.find(what, at + 1)) ++found;
		return found;
	};
	check(count(L"\"File\":") == 1 && count(L"\"Line\":") == 1 && count(L"\"Time\":") == 1 && count(L"\"A\":") == 1, "each W3C key once");
	check(json.find(L"true.log") < json.find(L"forged.log"), "the W3C file is the true one, the forged field set apart");
	check(json.find(L"OtherFields") != std::wstring::npos && json.find(L"forged.log") != std::wstring::npos, "the forged W3C field is kept, not lost");
}

//! An exception in a phase of the run ends that phase only: what follows (the seal, the log) still runs.
void aPhaseThatThrowsDoesNotEndTheRun() {
	check(runPhase(L"a phase that works", [] {}), "a phase that works is complete");
	check(!runPhase(L"out of memory", [] { throw std::bad_alloc(); }), "std::bad_alloc is caught");
	check(!runPhase(L"a thrown number", [] { throw 1; }), "any other exception is caught");
}

//! A digit of another script: iswdigit may say yes, std::stoul throws.
void scriptNumbersAreAscii() {
	const std::wstring text = L"[Logon]\n\u0663CmdLine=evil.cmd\n0CmdLine=genuine.cmd\n";
	const std::vector<Json> scripts = parsePolicyScripts(text, L"Machine", L"Script");
	check(scripts.size() == 1, "a key that starts with a digit of another script is not a script's number");
}

/*! A hostile database, whose view runs an endless recursive query and whose
 *  name is one a reader looks for. */
void hostileSqliteDatabase() {
	std::error_code ec;
	const std::filesystem::path folder = std::filesystem::temp_directory_path(ec) / L"wac_hostile_input_test";
	std::filesystem::remove_all(folder, ec);
	std::filesystem::create_directories(folder, ec);
	conf.mountpoint = folder.wstring();
	const std::filesystem::path file = folder / L"forged.db";
	sqlite3* db = nullptr;
	check(sqlite3_open(file.string().c_str(), &db) == SQLITE_OK
	      && sqlite3_exec(db, "CREATE TABLE plain(a TEXT); INSERT INTO plain VALUES('kept');"
	                          "CREATE VIEW endless AS WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) SELECT n FROM c;",
	                      nullptr, nullptr, nullptr) == SQLITE_OK, "the forged database is built");
	sqlite3_close(db);
	{
		SqliteDatabase reader;
		check(reader.open(file.wstring()) == ERROR_SUCCESS, "it opens");
		size_t rows = 0;
		check(reader.query("SELECT a FROM plain", [&](const SqliteRow&) { ++rows; }) == ERROR_SUCCESS && rows == 1, "a table is read");
		rows = 0;
		const HRESULT viewed = reader.query("SELECT n FROM endless LIMIT 3", [&](const SqliteRow&) { ++rows; });
		check(viewed != ERROR_SUCCESS && rows == 0, "a view of the examined machine's database does not run");
	}
	std::filesystem::remove_all(folder, ec);
}

//! Mutates bytes at random, sometimes cutting the end or repeating a part.
template <typename Text> Text mutated(const Text& seed, std::mt19937& random) {
	Text out = seed;
	if (out.empty()) return out;
	const unsigned changes = 1 + random() % 8;
	for (unsigned i = 0; i < changes && !out.empty(); ++i) {
		const size_t at = random() % out.size();
		switch (random() % 5) {
		case 0: out[at] = (typename Text::value_type)(random() & 0xFFFF); break;
		case 1: out.erase(at, 1 + random() % 16); break;
		case 2: out.insert(at, out.substr(random() % out.size(), 1 + random() % 32)); break;
		case 3: out.resize(at); break;
		default: out[at] = (typename Text::value_type)"\"'<>[]{}$%;:=\\/\n\r #0"[random() % 21]; break;
		}
	}
	return out;
}

const wchar_t HTTPD[] = L"ServerRoot \"C:/apache\"\nDefine X y\nListen 80\nDocumentRoot \"${X}/htdocs\"\nInclude conf/*.conf\n"
	L"<VirtualHost *:80>\nServerName a\nCustomLog logs/a.log combined\nErrorLog logs/e.log\nAlias /x C:/x\n</VirtualHost>\nLoadModule a modules/a.so\n";
const wchar_t NGINX_CONF[] = L"http {\n server { listen 80; server_name a; root html; access_log logs/a.log; include x/*.conf; }\n}\nload_module m.dll;\n";
const wchar_t W3C[] = L"#Software: IIS\n#Time Format: UTC\n#Fields: date time cs-method cs-uri-stem sc-status time-taken\n2026-10-24 15:01:02 GET /a 200 12\n2026-10-24 15:01:03 POST /b - 123456789012345678\n";
const wchar_t ACCESS[] = L"1.2.3.4 - bob [10/Oct/2026:13:55:36 +0200] \"GET /a?b=c HTTP/1.1\" 200 2326 \"http://r\" \"UA\"";
const wchar_t ERRORS[] = L"[Fri Sep 09 10:42:29.902022 2011] [core:error] [pid 35708:tid 4328636416] [client 1.2.3.4:1] msg";
const wchar_t NGINX_ERROR[] = L"2026/10/24 15:01:02 [error] 123#456: *1 open() failed";
const wchar_t SCRIPTS[] = L"[Logon]\n0CmdLine=a.cmd\n0Parameters=-x\n[Logoff]\n1CmdLine=b.cmd\n";
const wchar_t TASKS[] = L"<ScheduledTasks clsid=\"{1}\"><TaskV2 clsid=\"{2}\" name=\"n\" changed=\"c\"><Properties action=\"U\" runAs=\"r\" cpassword=\"x\"><Task><Actions><Exec><Command>c</Command><Arguments>a&amp;&#x41;&#65;</Arguments></Exec></Actions></Task></Properties></TaskV2></ScheduledTasks>";
const wchar_t WEB_CONFIG[] = L"<configuration><connectionStrings><add name=\"a\" connectionString=\"Data Source=|DataDirectory|\\a.db;Password='x'\" providerName=\"p\"/></connectionStrings></configuration>";
const wchar_t HOST_CONFIG[] = L"<configuration><system.applicationHost><sites><site name=\"s\" id=\"1\"><bindings><binding protocol=\"http\" bindingInformation=\"*:80:\"/></bindings><application path=\"/\"><virtualDirectory path=\"/\" physicalPath=\"%SystemDrive%\\inetpub\\wwwroot\"/></application><logFile directory=\"C:\\l\"/></site></sites><applicationPools><add name=\"p\"><processModel identityType=\"x\"/></add></applicationPools></system.applicationHost></configuration>";

const wchar_t DNS_ZONE[] = L"$TTL 60\r\n$ORIGIN a.test.\r\n@ IN SOA a. b. ( 1 2 3 4 5 ) ; c\r\nh 600 A 192.0.2.1\r\n  AAAA ::1\r\nt TXT ( \"x;\\\"y\" )\r\n";
const wchar_t DNS_LOG[] = L"Key\r\n04/11/2026 09:04:07 F20 Note: x\r\n04/11/2026 09:05:43 0F28 PACKET  00 UDP Rcv 127.0.0.1 ee7a R Q [8085 A DR  NOERROR] A (5)host1(4)test(0)\r\n";
const wchar_t DHCP_LOG[] = L"ID, Date\r\n10,11/04/26,10:00:00,Assign,192.0.2.1,h,00155D000002,,1234,0,,,,,,,,,0\r\n";
// With secret blocks (application_trace_files.cpp, secretBlockEnd): a PEM key, an .ovpn's <pkcs12>.
const wchar_t TRACE_LOG[] = L"header\r\n2026-11-08T14:03:21.457+01:00 Connection from 10.0.0.5\r\n   at A.B()\r\n[2026/11/08 14:03:22] next\r\n"
                            L"<key>\r\n -----BEGIN PRIVATE KEY----- \r\nMIIE\r\n-----END PRIVATE KEY-----\r\n</key>\r\n<pkcs12>\r\nAAAA\r\n</pkcs12>\r\n";
const wchar_t TRACE_XML[] = L"<FileZilla3><Servers><Server><Host>h</Host><Pass encoding=\"base64\">c2VjcmV0</Pass></Server></Servers></FileZilla3>";
const wchar_t TRACE_JSON[] = L"{\"a\":[1,{\"password\":\"p\",\"b\":\"c\"}],\"d\":true}";
const wchar_t TRACE_INI[] = L"[Sessions\\bob]\r\nHostName=h\r\nPassword=enc\r\n";

//! Every text reader once on a mutated text: none may throw, none may hang.
void textReaders(const std::wstring& seed, size_t kind) {
	switch (kind) {
	case 0: { WebCandidate c; c.product = L"Apache"; c.root = L"C:\\a"; c.configFile = L"C:\\a\\c"; parseApacheConfiguration(c, filesOf(c.configFile, seed)); break; }
	case 1: { WebCandidate c; c.product = L"nginx"; c.root = L"C:\\a"; c.configFile = L"C:\\a\\c"; parseNginxConfiguration(c, filesOf(c.configFile, seed)); break; }
	case 2: for (const W3cLogEntry& e : parseIisLog(seed, L"f")) e.toJson(); break;
	case 3: parseAccessLogLine(seed, L"f", 1).toJson(); break;
	case 4: case 5: parseErrorLogLine(seed, L"f", 1).toJson(); break;
	case 6: parsePolicyScripts(seed, L"Machine", L"Script"); parseIniText(seed); break;
	case 7: parsePolicyTasks(seed, L"Machine"); storedPasswordElements(seed); break;
	case 8: for (const IisConnectionString& c : parseConnectionStrings(seed, L"f", L"C:\\s")) c.toJson(); break;
	case 9: for (const DnsZoneRecord& r : parseDnsZoneFile(seed, L"z", L"f")) r.toJson(); break;
	case 10: for (const DnsLogEntry& e : parseDnsDebugLog(seed, L"f")) e.toJson(); break;
	case 11: for (const DhcpLogEntry& e : parseDhcpAuditLog(seed, L"f", false)) e.toJson(); for (const DhcpLogEntry& e : parseDhcpAuditLog(seed, L"f", true)) e.toJson(); break;
	case 12: { textRecords(seed); WrittenTime time; leadingTime(seed, time); break; }
	case 13: { bool secret = false; structuredContent(TraceFormat::Xml, seed, secret).dump(); break; }
	case 14: { bool secret = false; structuredContent(TraceFormat::Json, seed, secret).dump(); break; }
	case 15: { bool secret = false; structuredContent(TraceFormat::Ini, seed, secret).dump(); break; }
	default: { const IisConfiguration c = parseIisConfiguration(seed, L"f"); iisSources(c); for (const IisSite& s : c.sites) s.toJson(); break; }
	}
}

//! The binary readers, each input against a guard page.
void binaryReaders(const std::vector<uint8_t>& seed, std::mt19937& random) {
	const std::string seedText(seed.begin(), seed.end());
	for (const GuardSide side : { GuardSide::After, GuardSide::Before }) {
		const std::string text = mutated(seedText, random);
		const std::vector<BYTE> input(text.begin(), text.end());
		GuardedCopy copy(input, side);
		if (!copy.data()) continue;
		for (const PolicyRegistryEntry& e : parseRegistryPol(copy.data(), copy.size())) e.toJson();
		parseReplicationMetadata(copy.data(), copy.size());
		DirectoryChange change;
		parseLinkMetadata(copy.data(), copy.size(), change);
		readVmcxStrings(copy.data(), copy.size());
		dhcpClientId(std::vector<uint8_t>(copy.data(), copy.data() + copy.size()));
		std::vector<RawDirEntry> entries;
		if (copy.size() >= 4) parseDirectoryIndexNode(copy.data(), copy.data() + copy.size(), entries);
	}
}

/*! The mutation run.
 *  @param rounds mutations per input */
void mutationRun(size_t rounds) {
	const std::vector<std::wstring> seeds = { HTTPD, NGINX_CONF, W3C, ACCESS, ERRORS, NGINX_ERROR, SCRIPTS, TASKS, WEB_CONFIG, DNS_ZONE, DNS_LOG, DHCP_LOG,
	                                          TRACE_LOG, TRACE_XML, TRACE_JSON, TRACE_INI, HOST_CONFIG };
	std::mt19937 random(0x57414334);   // fixed: a failure reproduces
	size_t done = 0;
	for (size_t kind = 0; kind < seeds.size(); ++kind)
		for (size_t i = 0; i < rounds; ++i, ++done) textReaders(mutated(seeds[kind], random), kind);
	std::vector<uint8_t> pol = { 'P', 'R', 'e', 'g', 1, 0, 0, 0 };
	for (const char c : { '[', 'K', '\0', ';', 'V', '\0', ';' }) put<uint16_t>(pol, (uint16_t)c);
	put<uint32_t>(pol, 4); put<uint16_t>(pol, ';'); put<uint32_t>(pol, 4); put<uint16_t>(pol, ';'); put<uint32_t>(pol, 7); put<uint16_t>(pol, ']');
	std::vector<uint8_t> replication(16 + 48 * 3, 0);
	replication[0] = 1; replication[8] = 3;
	const std::vector<std::vector<uint8_t>> binaries = { pol, replication, indexNode({ L"a", L"bb" }) };
	for (const std::vector<uint8_t>& seed : binaries)
		for (size_t i = 0; i < rounds; ++i, done += 2) binaryReaders(seed, random);
	check(true, "the mutation run ended");
	printf("%zu mutated inputs read\n", done);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	const size_t rounds = argc > 1 ? (size_t)_wtoi(argv[1]) : 2000;
	forgedIndexNames();
	pathsStayUnderTheCollection();
	w3cFieldsCannotShadowTheRecord();
	aPhaseThatThrowsDoesNotEndTheRun();
	scriptNumbersAreAscii();
	hostileSqliteDatabase();
	apacheDefinesDoNotGrowWithoutBound();
	mutationRun(rounds);
	printf("%u checks, %u failed\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
