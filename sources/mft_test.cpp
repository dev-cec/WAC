/*! \file
 *  \brief Confronts the $MFT decoder with ntfsinfo, and throws hostile
 *         records at it.
 *
 *  WHY THIS TEST. A wrong offset in a FILE record gives dates, names or sizes
 *  that are valid and false — nothing fails at run time. The reference is
 *  ntfsinfo (ntfs-3g), an independent implementation of NTFS, on a volume
 *  formatted by mkntfs (mft_fixtures.sh): for every record in use, the
 *  sequence number, the flags, the parent, the long name, the size, the
 *  four dates of $STANDARD_INFORMATION and of $FILE_NAME (to the second,
 *  ntfsinfo's precision; all distinct in the file records) and the named
 *  streams must agree. The paths are then
 *  rebuilt through Mft::pathOf from the same $MFT, with a stale sequence
 *  number that must make them incomplete rather than made up.
 *
 *  Then every record, damaged at random, is decoded against a PAGE_NOACCESS
 *  page on both sides (guard_page.h): no read may leave the record, whatever
 *  lengths and offsets it announces.
 *
 *  Usage: mft_test `<folder of mft_fixtures.sh>`
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include "consigne.h"
#include "guard_page.h"
#include "mft.h"
#include "raw_hive.h"
#include "test_exhibits.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;
const size_t RECORD_SIZE = 1024;                       //!< mkntfs' record size
const long long UNIX_EPOCH_TICKS = 116444736000000000LL; //!< 1970-01-01 in FILETIME ticks

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

//! A FILETIME in seconds since 1970, as ntfsinfo prints it (rounded down).
long long seconds(const FILETIME& f) {
	const long long ticks = ((long long)f.dwHighDateTime << 32) | f.dwLowDateTime;
	return (ticks - UNIX_EPOCH_TICKS) / 10000000 - ((ticks - UNIX_EPOCH_TICKS) % 10000000 < 0 ? 1 : 0);
}

std::vector<std::string> split(const std::string& line, char separator) {
	std::vector<std::string> parts;
	std::stringstream stream(line);
	for (std::string part; std::getline(stream, part, separator);) parts.push_back(part);
	if (!line.empty() && line.back() == separator) parts.push_back("");
	return parts;
}

//! The UTF-8 name of the reference, compared on its UTF-16 form.
std::wstring widen(const std::string& utf8) { return decodeText(utf8, CP_UTF8); }

/*! Every record of the reference, decoded by MftEntry::parse. */
void againstNtfsinfo(const std::vector<uint8_t>& mft, const std::wstring& referencePath) {
	std::ifstream reference{ std::filesystem::path(referencePath) };
	unsigned lines = 0;
	for (std::string line; std::getline(reference, line);) {
		const std::vector<std::string> f = split(line, '|');
		if (f.size() != 16) continue;
		++lines;
		const uint64_t number = std::stoull(f[0]);
		const std::string at = "record " + f[0] + " (" + f[5] + ")";
		if ((number + 1) * RECORD_SIZE > mft.size()) { check(false, at + ": beyond the $MFT"); continue; }
		std::vector<uint8_t> record(mft.begin() + number * RECORD_SIZE, mft.begin() + (number + 1) * RECORD_SIZE);
		MftEntry e;
		if (!applyNtfsFixup(record.data(), record.size()) || !e.parse(record.data(), record.size(), number)) {
			check(false, at + ": not decoded");
			continue;
		}
		check(e.sequence == std::stoul(f[1]), at + ": sequence " + std::to_string(e.sequence));
		check(e.inUse == (f[2] == "1") && e.directory == (f[3] == "1"), at + ": flags");
		check(e.parentEntry == std::stoull(f[4]), at + ": parent " + std::to_string(e.parentEntry));
		check(e.name == widen(f[5]), at + ": name \"" + narrow(e.name) + "\"");
		if (f[6] == "-") check(e.directory || !e.sizeKnown, at + ": a size where ntfsinfo reads none");
		else check(e.sizeKnown && e.size == std::stoull(f[6]), at + ": size " + std::to_string(e.size));
		const FILETIME dates[8] = { e.created, e.modified, e.mftModified, e.accessed,
		                            e.fileNameCreated, e.fileNameModified, e.fileNameMftModified, e.fileNameAccessed };
		static const char* const NAMES[8] = { "created", "modified", "record changed", "accessed",
		                                      "$FILE_NAME created", "$FILE_NAME modified",
		                                      "$FILE_NAME record changed", "$FILE_NAME accessed" };
		for (int k = 0; k < 8; ++k)
			check(seconds(dates[k]) == std::stoll(f[7 + k]), at + ": " + NAMES[k] + " " + std::to_string(seconds(dates[k])));
		std::string streams;
		for (const std::wstring& s : e.streams) streams += (streams.empty() ? "" : ",") + narrow(s);
		check(streams == f[15], at + ": streams \"" + streams + "\"");
	}
	check(lines >= 15, "reference: only " + std::to_string(lines) + " record(s)");
}

/*! A copy of mft.bin whose record 64 (file1.bin) is marked not in use.
 *  @param folder the fixtures' folder
 *  @return the copy's path */
std::wstring freedCopy(const std::wstring& folder) {
	std::ifstream in(std::filesystem::path(folder + L"\\mft.bin"), std::ios::binary);
	std::vector<char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	const size_t flags = 64 * 1024 + 22;   // the record's flags, bit 0: in use
	if (bytes.size() > flags) bytes[flags] &= ~1;
	const std::wstring freed = folder + L"\\mft-freed.bin";
	std::ofstream(std::filesystem::path(freed), std::ios::binary).write(bytes.data(), (std::streamsize)bytes.size());
	return freed;
}

/*! The paths, rebuilt by Mft::pathOf from the $MFT registered as an exhibit,
 *  placed in an output folder under the fixtures' folder. */
void paths(const std::wstring& folder) {
	conf.systemDrive = L"C:";
	// A second volume, G:, the same $MFT: the exhibit index is built once, on
	// the first lookup, after every exhibit is registered — as in a conversion.
	const std::wstring output = folder + L"\\output";
	ExhibitStoreAdd({ placedExhibit(output, L"C:\\$MFT", folder + L"\\mft.bin"),
	                  placedExhibit(output, L"G:\\$MFT", folder + L"\\mft.bin"),
	                  placedExhibit(output, L"F:\\$MFT", freedCopy(folder)) }, L"test");
	Mft mft;
	check(mft.getData(L"C:") == ERROR_SUCCESS, "the $MFT exhibit is not loaded");
	bool complete = false;
	check(mft.pathOf(64, 1, complete) == L"C:\\file1.bin" && complete, "path of file1.bin");
	check(mft.pathOf(24, 1, complete) == L"C:\\$Extend\\$Quota" && complete, "path through $Extend");
	check(mft.pathOf(67, 0, complete) == L"C:\\r\u00e9sum\u00e9.txt" && complete, "non-ASCII name");
	// A reference to a record reused since: the name found now is another file's.
	const std::wstring stale = mft.pathOf(64, 7, complete);
	check(stale.empty() && !complete, "stale sequence number: path \"" + narrow(stale) + "\" made up");
	// A record that does not exist.
	check(mft.pathOf(1u << 30, 0, complete).empty() && !complete, "record beyond the $MFT named");

	// A second volume: its own exhibit, its paths under its own letter.
	Mft other;
	check(other.getData(L"G:") == ERROR_SUCCESS && other.volume() == L"G:", "the $MFT exhibit of G: is not loaded");
	check(other.pathOf(64, 1, complete) == L"G:\\file1.bin" && complete, "path on the second volume");
	Mft absent;
	check(absent.getData(L"H:") != ERROR_SUCCESS, "a volume without a $MFT exhibit is read");
}

/*! A freed record: the same $MFT, file1.bin's record (64) marked not in use
 *  — its flags, outside the update sequence's places. Its last path is still
 *  given, for what referenced it; but it is no file's path NOW. */
void freedRecord() {
	Mft mft;
	bool complete = false;
	check(mft.getData(L"F:") == ERROR_SUCCESS && mft.pathOf(64, 1, complete) == L"F:\\file1.bin",
	      "freed record: its last path still given");
	check(mft.livePathOf(64, 1, complete).empty() && !complete, "freed record: no current path, its name may be another file's now");
	check(mft.livePathOf(67, 0, complete) == L"F:\\r\u00e9sum\u00e9.txt" && complete, "a record in use: its current path");
}

/*! Every record, damaged at random, against a guard page on both sides. */
void hostile(const std::vector<uint8_t>& mft) {
	std::mt19937_64 rng(20260926);
	unsigned decoded = 0;
	for (size_t at = 0; at + RECORD_SIZE <= mft.size(); at += RECORD_SIZE) {
		std::vector<BYTE> clean(mft.begin() + at, mft.begin() + at + RECORD_SIZE);
		if (std::memcmp(clean.data(), "FILE", 4) != 0 || !applyNtfsFixup(clean.data(), clean.size())) continue;
		for (int n = 0; n < 300; ++n) {
			std::vector<BYTE> damaged = clean;
			for (int k = 0; k < 1 + (int)(rng() % 8); ++k) damaged[4 + rng() % (damaged.size() - 4)] = (BYTE)rng();
			// Truncated records too: the size given is the only bound.
			damaged.resize(0x30 + rng() % (damaged.size() - 0x30 + 1));
			for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
				GuardedCopy copy(damaged, side);
				MftEntry e;
				if (e.parse(copy.data(), copy.size(), at / RECORD_SIZE)) ++decoded;
			}
		}
	}
	check(decoded > 0, "no damaged record decoded: the loop tested nothing");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) { std::printf("usage: mft_test <folder of mft_fixtures.sh>\n"); return 2; }
	const std::wstring folder = argv[1];
	std::ifstream in(std::filesystem::path(folder + L"\\mft.bin"), std::ios::binary);
	const std::vector<uint8_t> mft((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	check(mft.size() >= 16 * RECORD_SIZE, "mft.bin missing or truncated");
	againstNtfsinfo(mft, folder + L"\\mft-reference.txt");
	paths(folder);
	freedRecord();
	hostile(mft);
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
