/*! \file
 *  \brief Checks the ESE reader: records built as the format lays them out
 *  (fixed, variable, tagged, multi-valued, null), hostile variants, the BITS
 *  blobs and SRUM's identities read through it — and,
 *  given a database, dumps every table for a comparison with an independent
 *  reader (vmtest/lib/ese-compare.py, dissect.esedb).
 *
 *  WHY THIS TEST. A record read one byte off still gives values — wrong ones:
 *  every column is found through an offset. Each case here has a known
 *  result; a length that lies must be refused, never read beyond.
 *
 *  Usage (runs under wine): ese_test.exe [database.dat]
 */
#include "bits_jobs.h"
#include "ese_database.h"
#include "srum.h"
#include <algorithm>
#include <cstdio>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const char* what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::printf("  FAILED  %s\n", what);
}

void put16(std::vector<uint8_t>& b, uint16_t v) { b.push_back((uint8_t)v); b.push_back((uint8_t)(v >> 8)); }
void put32(std::vector<uint8_t>& b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (8 * i))); }

EseColumn column(uint32_t id, uint32_t type, uint32_t size, uint32_t offset, uint32_t codePage = 0) {
	EseColumn c;
	c.id = id; c.type = type; c.size = size; c.offset = offset; c.codePage = codePage;
	return c;
}

//! The cell of a column, or nullptr.
const EseCell* cellOf(const EseRecord& r, uint32_t id) {
	for (const EseCell& c : r) if (c.columnId == id) return &c;
	return nullptr;
}

/*! A record: Long 1 = 7, Short 2 null, variable 128 = "ab", 129 empty,
 *  tagged 256 = UTF-16 "hé", 257 multi-valued { "x", "yz" }. */
void records() {
	const std::vector<EseColumn> columns = {
		column(1, 4, 4, 0), column(2, 3, 2, 4), column(128, 10, 0, 0, 1252), column(129, 9, 0, 0),
		column(256, 12, 0, 0, 1200), column(257, 10, 0, 0, 1252) };
	std::vector<uint8_t> r = { 2, 129 };
	put16(r, 4 + 6 + 1);                                    // end of the fixed data, bitmap included
	put32(r, 7); put16(r, 0);                               // fixed values
	r.push_back(0x02);                                      // bitmap: column 2 null
	put16(r, 2); put16(r, 0x8002);                          // variables: "ab", then empty
	r.push_back('a'); r.push_back('b');
	const size_t tagged = r.size();
	// Two pairs (identifier, offset); large pages: a flag byte heads each value.
	put16(r, 256); put16(r, 8);
	put16(r, 257); put16(r, 8 + 1 + 4);
	r.push_back(0); put16(r, L'h'); put16(r, 0xE9);
	r.push_back(0x08);                                      // multi-valued: offsets 4 and 5, then "x", "yz"
	put16(r, 4); put16(r, 5); r.push_back('x'); r.push_back('y'); r.push_back('z');
	const EseRecord record = parseEseRecord(r, columns, false, true);
	const EseCell* fixed = cellOf(record, 1);
	check(fixed && eseCellToJson(columns[0], *fixed).text() == L"7", "fixed column: its value");
	check(!cellOf(record, 2), "fixed column: null in the bitmap, left out");
	const EseCell* variable = cellOf(record, 128);
	check(variable && eseCellToJson(columns[2], *variable).text() == L"ab", "variable column: its value");
	check(!cellOf(record, 129), "variable column: empty, left out");
	const EseCell* text = cellOf(record, 256);
	check(text && eseCellToJson(columns[4], *text).text() == L"hé", "tagged column: UTF-16 text");
	const EseCell* multi = cellOf(record, 257);
	check(multi && multi->values.size() == 2 && eseCellToJson(columns[5], *multi).size() == 2
	      && eseCellToJson(columns[5], *multi).members()[1].second.text() == L"yz", "tagged column: two values");
	(void)tagged;
	// Hostile: the end of the fixed data beyond the record; a tagged offset beyond.
	std::vector<uint8_t> lying = r;
	lying[2] = 0xFF; lying[3] = 0x7F;
	check(parseEseRecord(lying, columns, false, true).empty(), "record: fixed data beyond the record accepted");
	std::vector<uint8_t> cut(r.begin(), r.begin() + (long)tagged + 6);
	const EseRecord partial = parseEseRecord(cut, columns, false, true);
	check(cellOf(partial, 128) && !cellOf(partial, 256), "record: a tagged value beyond the record read");
}

/*! 7-bit compressed values, as the Windows.edb of Windows 8.1 holds them
 *  (record 83 and 128 of its property store), each confronted with
 *  dissect.esedb. */
void sevenBit() {
	// Scheme 1, header 0x0F: bytes of UTF-16 text, the last one the zero high byte of "s".
	std::vector<uint8_t> name = { 0x0f, 0x4f, 0x00, 0x1c, 0x50, 0x06, 0xb8, 0x01, 0x62, 0x40, 0x18, 0x20, 0x07, 0x94, 0x01,
	                              0x20, 0x80, 0x1d, 0x90, 0x06, 0x90, 0x01, 0x65, 0xc0, 0x1b, 0x90, 0x01, 0xcd, 0x01 };
	check(decompressSevenBit(name) && name.size() == 32
	      && std::wstring(reinterpret_cast<const wchar_t*>(name.data()), 16) == L"Openbare video\u2019s",
	      "7-bit, scheme 1: UTF-16 text whose last byte is a zero, kept");
	// Scheme 2, header 0x10: its low bits say 7 bits of padding, so 7 characters, not 8.
	std::vector<uint8_t> kind = { 0x10, 0x70, 0xf9, 0xfb, 0x2c, 0x0f, 0xb7, 0x01 };
	check(decompressSevenBit(kind) && kind.size() == 14
	      && std::wstring(reinterpret_cast<const wchar_t*>(kind.data()), 7) == L"program",
	      "7-bit, scheme 2: the padding of the last byte is no character");
	std::vector<uint8_t> xpress = { 0x18, 1, 2, 3 }, header = { 0x0f };
	check(!decompressSevenBit(xpress) && xpress.size() == 4 && !decompressSevenBit(header),
	      "7-bit: another scheme, or a header alone, left untouched");
}

//! A UTF-16 string preceded by its length in characters, terminator included.
void putPascal(std::vector<uint8_t>& b, const std::wstring& s) {
	put32(b, (uint32_t)s.size() + 1);
	for (wchar_t c : s) put16(b, (uint16_t)c);
	put16(b, 0);
}

/*! A BITS job and file as the witness of the test VM lays them out, then
 *  lengths that lie; SRUM's keys and identities. */
void artefacts() {
	const uint8_t xfer[16] = { 0x36, 0xDA, 0x56, 0x77, 0x6F, 0x51, 0x5A, 0x43, 0xAC, 0xAC, 0x44, 0xA2, 0x48, 0xFF, 0xF3, 0x4D };
	const uint8_t jobGuid[16] = { 0x65, 0x2C, 0x1A, 0x76, 0x1A, 0xD5, 0xBB, 0x4D, 0x8B, 0xB6, 0x61, 0x00, 0x00, 0xA8, 0x91, 0x92 };
	const uint8_t fileGuid[16] = { 0x51, 0x4C, 0x24, 0x3B, 0x1F, 0xDE, 0xBF, 0x49, 0xAA, 0x7E, 0x19, 0x8D, 0x8A, 0x22, 0x5A, 0x96 };
	std::vector<uint8_t> job(16, 0xA1);
	put32(job, 0); put32(job, 2); put32(job, 3); put32(job, 0);
	job.insert(job.end(), jobGuid, jobGuid + 16);
	putPascal(job, L"WacTestJob"); putPascal(job, L"witness"); putPascal(job, L"C:\\Windows\\System32\\cmd.exe");
	putPascal(job, L"/c echo wac-bits-test"); putPascal(job, L"S-1-5-18");
	put32(job, 3);
	for (int i = 0; i < 40; ++i) job.push_back(0);                 // access token, as BITS keeps it
	job.insert(job.end(), xfer, xfer + 16); put32(job, 1); job.insert(job.end(), fileGuid, fileGuid + 16);
	job.insert(job.end(), xfer, xfer + 16);
	put32(job, 0); put32(job, 0); put32(job, 600); put32(job, 1209600);
	put32(job, 0xBBFF61E8); put32(job, 0x01DD50A0); put32(job, 0xBC0963AC); put32(job, 0x01DD50A0);
	BitsJob j;
	check(parseBitsJob(job, j) && j.parsed && j.metadataParsed, "BITS job: a well-formed blob refused");
	check(j.id == L"{761A2C65-D51A-4DBB-8BB6-610000A89192}" && j.name == L"WacTestJob" && j.state == 3,
	      "BITS job: identifier, name, state");
	check(j.notifyProgram == L"C:\\Windows\\System32\\cmd.exe" && j.notifyArguments == L"/c echo wac-bits-test"
	      && j.ownerSid == L"S-1-5-18" && j.notifyFlags == 3, "BITS job: notification command line and owner");
	check(j.fileIds.size() == 1 && j.fileIds[0] == L"{3B244C51-DE1F-49BF-AA7E-198D8A225A96}", "BITS job: its file's identifier");
	check(j.retryDelay == 600 && j.noProgressTimeout == 1209600 && j.createdUtc.dwHighDateTime == 0x01DD50A0,
	      "BITS job: retry delay, timeout, creation");
	std::vector<uint8_t> lying = job;
	lying[48] = 0xFF; lying[49] = 0xFF; lying[50] = 0xFF;          // the name's length
	BitsJob refused;
	check(!parseBitsJob(lying, refused) && !refused.parsed, "BITS job: a name longer than the blob accepted");

	std::vector<uint8_t> file(16, 0xE4);
	putPascal(file, L"C:\\wactest\\wac-bits.bin"); putPascal(file, L"https://wac-test.invalid/wac-bits.bin");
	putPascal(file, L"C:\\wactest\\BIT6F76.tmp");
	for (int i = 0; i < 8; ++i) file.push_back(0);
	for (int i = 0; i < 8; ++i) file.push_back(0xFF);
	file.push_back(0);
	putPascal(file, L"C:\\"); putPascal(file, L"\\\\?\\Volume{fa16ca3d-ce6c-4615-9b57-1d6441cb0488}\\");
	BitsFile f;
	check(parseBitsFile(file, f) && f.source == L"https://wac-test.invalid/wac-bits.bin"
	      && f.destination == L"C:\\wactest\\wac-bits.bin" && f.totalBytes == UINT64_MAX && f.drive == L"C:\\",
	      "BITS file: source, destination, unknown size, drive");
	std::vector<uint8_t> cut(file.begin(), file.end() - 10);
	BitsFile partial;
	check(!parseBitsFile(cut, partial), "BITS file: a volume beyond the blob accepted");

	/* A queue file of Windows 8.1 as BITS wrote the witness's (qmgr1.dat):
	   its header, the job between two delimiters, without the blob's header,
	   two files written in it — the first followed by its trailer —, the
	   metadata after the second XFER. */
	const uint8_t delimiter[16] = { 0x8C, 0x93, 0xEA, 0x64, 0x03, 0x0F, 0x68, 0x40, 0xB4, 0x6F, 0xF9, 0x7F, 0xE5, 0x1D, 0x4D, 0xCD };
	std::vector<uint8_t> queue(60, 0x11);
	queue.insert(queue.end(), delimiter, delimiter + 16);
	std::vector<uint8_t> control(job.begin() + 16, job.end());
	const auto firstXfer = std::search(control.begin(), control.end(), xfer, xfer + 16);
	control.erase(firstXfer, control.end());                        // the control part and its access token
	queue.insert(queue.end(), control.begin(), control.end());
	queue.insert(queue.end(), xfer, xfer + 16); put32(queue, 2);
	queue.insert(queue.end(), file.begin() + 16, file.end());
	const uint8_t trailer[12] = { 3, 0, 0, 0, 0x98, 0xDE, 0x5D, 0x5E, 0xFF, 0xFF, 0xFF, 0xFF };
	queue.insert(queue.end(), trailer, trailer + 12);
	for (int i = 0; i < 61; ++i) queue.push_back(0);
	std::vector<uint8_t> second(file.begin() + 16, file.end());
	second[4] = 'D';                                                // D:\wactest\wac-bits.bin
	queue.insert(queue.end(), second.begin(), second.end());
	queue.insert(queue.end(), xfer, xfer + 16);
	put32(queue, 0); put32(queue, 0); put32(queue, 600); put32(queue, 1209600);
	put32(queue, 0xBBFF61E8); put32(queue, 0x01DD50A0); put32(queue, 0xBC0963AC); put32(queue, 0x01DD50A0);
	queue.insert(queue.end(), delimiter, delimiter + 16);
	std::vector<BitsJob> queued;
	check(parseBitsQueue(queue, L"C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr1.dat", queued) && queued.size() == 1
	      && queued[0].id == L"{761A2C65-D51A-4DBB-8BB6-610000A89192}" && queued[0].notifyArguments == L"/c echo wac-bits-test"
	      && queued[0].metadataParsed && queued[0].retryDelay == 600,
	      "BITS queue: the job between its delimiters, its command line and metadata");
	check(queued.size() == 1 && queued[0].inlineFiles.size() == 2 && queued[0].inlineFiles[0].source == L"https://wac-test.invalid/wac-bits.bin"
	      && queued[0].inlineFiles[1].destination == L"D:\\wactest\\wac-bits.bin",
	      "BITS queue: its two files, the second found past the first one's trailer");
	std::vector<BitsJob> none;
	check(!parseBitsQueue(std::vector<uint8_t>(64, 0), L"qmgr0.dat", none) && none.empty(), "BITS queue: an empty queue gives a job");

	check(srumKey(L"Energy Data") == L"EnergyData" && srumKey(L"BytesRecvd") == L"BytesRecvd", "SRUM: column names as keys");
	check(srumProviderName(L"{973f5d5c-1d90-4944-be8e-24b94231a174}") == L"NetworkUsage"
	      && srumProviderName(L"{B6D82AF1-F780-4E17-8077-6CB9AD8A6FC4}").empty(), "SRUM: documented providers only");
	const std::vector<uint8_t> system = { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };
	std::vector<uint8_t> path;
	for (wchar_t c : std::wstring(L"svchost.exe")) put16(path, (uint16_t)c);
	put16(path, 0);
	check(srumIdentity(3, system) == L"S-1-5-18" && srumIdentity(0, path) == L"svchost.exe", "SRUM: identities, SID and text");
}

//! Dumps every record of every table, one JSON line each, for ese-compare.py.
void dump(const std::wstring& path) {
	EseDatabase db;
	const HRESULT opened = db.open(path);
	check(opened == ERROR_SUCCESS, "database: not opened");
	if (opened != ERROR_SUCCESS) return;
	for (const EseTable& t : db.tables()) {
		for (const EseRecord& r : db.records(t)) {
			Json o = Json::obj();
			for (const EseCell& cell : r)
				for (const EseColumn& c : t.columns)
					if (c.id == cell.columnId) o.add(c.name, eseCellToJson(c, cell));
			// On one line: the layout's newlines and tabs out (those of the values are escaped).
			std::wstring line = o.dump();
			line.erase(std::remove_if(line.begin(), line.end(), [](wchar_t c) { return c == L'\n' || c == L'\t'; }), line.end());
			std::printf("%s\t%s\n", encodeText(t.name).c_str(), encodeText(line).c_str());
		}
	}
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	records();
	sevenBit();
	artefacts();
	if (argc > 1) dump(argv[1]);
	std::fprintf(stderr, "%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
