/*! \file
 *  \brief Checks the change journal decoder against the compiler's record
 *         layout, the journal walk, and hostile records.
 *
 *  WHY THIS TEST. The decoder reads USN records with its own offsets; a wrong
 *  one gives dates, names or references that are valid and false. Here the
 *  records are built with structures whose layout comes from the compiler,
 *  not from the decoder: every field must come back as written. Version 2 is
 *  MinGW's USN_RECORD (winioctl.h); version 3, which MinGW does not declare,
 *  is written below from Microsoft's documentation of USN_RECORD_V3, and its
 *  published offsets are checked at compile time.
 *
 *  Then a journal is laid out as NTFS leaves it — records of both versions,
 *  a range record (version 4), zeros between pages — behind a leading offset
 *  (LeadingSparseBytes), and read through UsnJournal::getData: every record
 *  must be found, the numbers must be the offsets in the whole stream, and
 *  the paths must be rebuilt through the $MFT of mft_fixtures.sh.
 *
 *  Finally every record, damaged at random, is decoded against a PAGE_NOACCESS
 *  page on both sides (guard_page.h).
 *
 *  Usage: usn_journal_test `<folder of mft_fixtures.sh>`
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <winioctl.h>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>
#include "consigne.h"
#include "guard_page.h"
#include "mft.h"
#include "raw_hive.h"
#include "tools.h"
#include "usn_journal.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

/*! Records one check, printing the first failures. */
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::printf("  FAILED  %s\n", what.c_str());
}

std::string narrow(const std::wstring& w) {
	std::string s;
	for (wchar_t c : w) s += c < 0x80 ? (char)c : '?';
	return s;
}

/*! USN_RECORD_V3 as Microsoft documents it (winioctl.h of the Windows SDK),
 *  which MinGW's headers lack: 128-bit references (FILE_ID_128). Named for the
 *  test, not after the SDK, so that it never clashes with the SDK's own. */
struct DocumentedRecordV3 {
	DWORD RecordLength;
	WORD MajorVersion;
	WORD MinorVersion;
	FILE_ID_128 FileReferenceNumber;
	FILE_ID_128 ParentFileReferenceNumber;
	USN Usn;
	LARGE_INTEGER TimeStamp;
	DWORD Reason;
	DWORD SourceInfo;
	DWORD SecurityId;
	DWORD FileAttributes;
	WORD FileNameLength;
	WORD FileNameOffset;
	WCHAR FileName[1];
};
using SdkRecordV2 = USN_RECORD;   //!< MinGW's USN_RECORD has the layout of USN_RECORD_V2
// The name offsets Microsoft documents: the fixed part of each version.
static_assert(offsetof(SdkRecordV2, FileName) == 0x3C, "USN_RECORD_V2: the name follows 60 bytes");
static_assert(offsetof(DocumentedRecordV3, FileName) == 0x4C, "USN_RECORD_V3: the name follows 76 bytes");

//! What a test record holds, written through the compiler's layout.
struct Fields {
	uint64_t file, parent, usn, ticks;
	uint32_t reason, source, security, attributes;
	std::wstring name;
};

//! A record of version 2 or 3, laid out by the compiler, padded to 8 bytes.
std::vector<BYTE> record(int major, const Fields& f) {
	const size_t fixed = major == 2 ? offsetof(SdkRecordV2, FileName) : offsetof(DocumentedRecordV3, FileName);
	const size_t length = (fixed + 2 * f.name.size() + 7) & ~(size_t)7;
	std::vector<BYTE> bytes(length, 0);
	if (major == 2) {
		SdkRecordV2 r = {};
		r.RecordLength = (DWORD)length;
		r.MajorVersion = 2;
		r.FileReferenceNumber = f.file;
		r.ParentFileReferenceNumber = f.parent;
		r.Usn = (USN)f.usn;
		r.TimeStamp.QuadPart = (LONGLONG)f.ticks;
		r.Reason = f.reason;
		r.SourceInfo = f.source;
		r.SecurityId = f.security;
		r.FileAttributes = f.attributes;
		r.FileNameLength = (WORD)(2 * f.name.size());
		r.FileNameOffset = (WORD)fixed;
		std::memcpy(bytes.data(), &r, fixed);
	}
	else {
		DocumentedRecordV3 r = {};
		r.RecordLength = (DWORD)length;
		r.MajorVersion = 3;
		std::memcpy(r.FileReferenceNumber.Identifier, &f.file, 8);          // low 64 bits: the NTFS reference
		std::memcpy(r.ParentFileReferenceNumber.Identifier, &f.parent, 8);
		r.Usn = (USN)f.usn;
		r.TimeStamp.QuadPart = (LONGLONG)f.ticks;
		r.Reason = f.reason;
		r.SourceInfo = f.source;
		r.SecurityId = f.security;
		r.FileAttributes = f.attributes;
		r.FileNameLength = (WORD)(2 * f.name.size());
		r.FileNameOffset = (WORD)fixed;
		std::memcpy(bytes.data(), &r, fixed);
	}
	std::memcpy(bytes.data() + fixed, f.name.data(), 2 * f.name.size());
	return bytes;
}

//! Both versions, every field back as written.
void fields() {
	const Fields f = { 0x0003000000000040ULL, 0x0005000000000005ULL, 0x1234508ULL, 132539328001234567ULL,
	                   USN_REASON_FILE_CREATE | USN_REASON_CLOSE, USN_SOURCE_DATA_MANAGEMENT, 0x105,
	                   FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN, L"outil.exe" };
	for (int major : { 2, 3 }) {
		const std::vector<BYTE> bytes = record(major, f);
		UsnRecord r;
		const std::string v = "version " + std::to_string(major) + ": ";
		check(r.parse(bytes.data(), bytes.size(), f.usn), v + "not decoded");
		check(r.fileEntry == 0x40 && r.fileSequence == 3, v + "file reference");
		check(r.parentEntry == 5 && r.parentSequence == 5, v + "parent reference");
		check(r.usn == f.usn, v + "usn");
		check((((uint64_t)r.timestamp.dwHighDateTime << 32) | r.timestamp.dwLowDateTime) == f.ticks, v + "timestamp");
		check(r.reason == f.reason && r.sourceInfo == f.source && r.securityId == f.security
		      && r.attributes == f.attributes, v + "reason, source, security or attributes");
		check(r.name == f.name, v + "name \"" + narrow(r.name) + "\"");
		// Read from another place than its own number: refused (a misplaced offset).
		check(!r.parse(bytes.data(), bytes.size(), f.usn + 8), v + "record read out of step accepted");
	}
}

/*! A journal as NTFS leaves it, read through UsnJournal::getData, paths
 *  through the $MFT of mft_fixtures.sh. */
void journal(const std::wstring& folder) {
	conf.systemDrive = L"C:";
	const uint64_t leading = 0x40000000;          // 1 GiB freed at the start of the stream
	std::vector<BYTE> stream;
	auto append = [&](int major, Fields f) {
		f.usn = leading + stream.size();
		const std::vector<BYTE> r = record(major, f);
		stream.insert(stream.end(), r.begin(), r.end());
	};
	append(2, { 0x0001000000000040ULL, 0x0005000000000005ULL, 0, 132539328000000000ULL,
	            USN_REASON_FILE_CREATE, 0, 0, FILE_ATTRIBUTE_ARCHIVE, L"file1.bin" });
	append(3, { 0x0001000000000018ULL, 0x000B00000000000BULL, 0, 132539328010000000ULL,
	            USN_REASON_DATA_EXTEND | 0x02000000u, 0, 0, 0, L"$Quota" });
	// A range record (version 4): counted, not converted.
	std::vector<BYTE> range(0x40, 0);
	range[0] = 0x40;
	range[4] = 4;
	stream.insert(stream.end(), range.begin(), range.end());
	stream.resize(4096, 0);                       // the end of the page: zeros
	// A parent reused since (sequence 9 in the reference, 5 in the $MFT): its path is not made up.
	append(2, { 0x0001000000000041ULL, 0x0009000000000005ULL, 0, 132539328020000000ULL,
	            USN_REASON_FILE_DELETE | USN_REASON_CLOSE, 0, 0, 0, L"gone.txt" });
	const std::wstring streamFile = folder + L"\\usn-stream.bin";
	std::ofstream(std::filesystem::path(streamFile), std::ios::binary)
		.write(reinterpret_cast<const char*>(stream.data()), (std::streamsize)stream.size());

	RawHiveExtraction mftLine, journalLine;
	mftLine.volumePath = L"C:\\$MFT";
	mftLine.outputPath = folder + L"\\mft.bin";
	mftLine.result = ERROR_SUCCESS;
	journalLine.volumePath = L"C:\\$Extend\\$UsnJrnl:$J";
	journalLine.outputPath = streamFile;
	journalLine.result = ERROR_SUCCESS;
	journalLine.fingerprints.leadingSparseBytes = leading;
	ExhibitStoreAdd({ mftLine, journalLine }, L"test");

	Mft mft;
	check(mft.getData() == ERROR_SUCCESS, "the $MFT exhibit is not loaded");
	UsnJournal usn;
	check(usn.getData() == ERROR_SUCCESS, "the journal exhibit is not read");
	check(usn.records.size() == 3 && usn.rangeRecords == 1,
	      "records found: " + std::to_string(usn.records.size()) + " + " + std::to_string(usn.rangeRecords) + " range");
	if (usn.records.size() != 3) return;
	check(usn.records[0].usn == leading && usn.records[2].usn == leading + 4096, "numbers are not offsets in the whole stream");
	const Json first = usn.records[0].toJson(mft), second = usn.records[1].toJson(mft), third = usn.records[2].toJson(mft);
	const Json* path = first.find(L"Path");
	check(path && path->text() == L"C:\\file1.bin" && !first.find(L"PathIncomplete"), "path of a file of the root");
	path = second.find(L"Path");
	check(path && path->text() == L"C:\\$Extend\\$Quota", "path through $Extend");
	const Json* reasons = second.find(L"Reasons");
	check(reasons && reasons->text() == L"DATA_EXTEND, 0x02000000", "an unknown reason bit is not kept in hexadecimal");
	check(third.find(L"PathIncomplete") != nullptr, "the parent reused since is named");
	reasons = third.find(L"Reasons");
	check(reasons && reasons->text() == L"FILE_DELETE, CLOSE", "reasons of a deletion");
}

//! Damaged records against a guard page on both sides.
void hostile() {
	std::mt19937_64 rng(20260926);
	const Fields f = { 0x40, 5, 0, 1, USN_REASON_CLOSE, 0, 0, 0, L"a-name-of-some-length.txt" };
	for (int major : { 2, 3 }) {
		const std::vector<BYTE> clean = record(major, f);
		for (int n = 0; n < 3000; ++n) {
			std::vector<BYTE> damaged = clean;
			for (int k = 0; k < 1 + (int)(rng() % 4); ++k) damaged[rng() % damaged.size()] = (BYTE)rng();
			damaged.resize(rng() % (damaged.size() + 1));
			for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
				GuardedCopy copy(damaged, side);
				UsnRecord r;
				r.parse(copy.data(), copy.size(), 0);
			}
		}
	}
	check(true, "hostile records");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) { std::printf("usage: usn_journal_test <folder of mft_fixtures.sh>\n"); return 2; }
	fields();
	journal(argv[1]);
	hostile();
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
