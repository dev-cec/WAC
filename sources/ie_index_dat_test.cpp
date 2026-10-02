/*! \file
 *  \brief Checks the index.dat decoder against pymsiecf on real files, and
 *         against truncated and damaged ones.
 *
 *  WHY THIS TEST. The decoder reads records at offsets the file declares; a
 *  wrong one gives URLs, times or counts that are valid and false. The
 *  reference is pymsiecf — libmsiecf's reader, written independently of WAC —
 *  on four real index.dat files of the plaso project's test data
 *  (ie_index_fixtures.sh): every record it lists, entries and recovered ones,
 *  must come back with the same fields, and none more.
 *
 *  Then every file is decoded truncated at many sizes and with bytes damaged
 *  at random, against a PAGE_NOACCESS page on both sides (guard_page.h): a
 *  read past the bytes given faults.
 *
 *  Usage: ie_index_dat_test `<folder of ie_index_fixtures.sh>`
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include "guard_page.h"
#include "ie_index_dat.h"
#include "tools.h"
#include "web_client.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::printf("  FAILED  %s\n", what.c_str());
}

//! @return the bytes of a file
std::vector<uint8_t> readAll(const std::wstring& path) {
	std::ifstream in(std::filesystem::path(path), std::ios::binary);
	return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

//! @return a record as the reference writes it, from `location` on
std::string line(const IeIndexRecord& r) {
	std::ostringstream o;
	o << encodeText(r.location) << '|' << encodeText(r.filename) << '|' << r.cacheDirectory << '|';
	if (r.kind == L"URL")
		o << r.primaryTime << '|' << r.secondaryTime << '|' << r.expiry << '|' << r.lastChecked << '|' << r.hits << '|' << r.data.size();
	else o << "0|0|0|0|0|0";
	return o.str();
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc < 2) { std::printf("usage: ie_index_dat_test <folder of ie_index_fixtures.sh>\n"); return 2; }
	const std::wstring folder = argv[1];
	// The reference, by file then offset: "kind|recovered|location|…".
	std::map<std::string, std::map<uint32_t, std::string>> reference;
	std::ifstream ref(std::filesystem::path(folder + L"\\ie-index-reference.txt"));
	for (std::string text; std::getline(ref, text);) {
		if (!text.empty() && text.back() == '\r') text.pop_back();
		std::istringstream fields(text);
		std::string file, offset;
		std::getline(fields, file, '|');
		std::getline(fields, offset, '|');
		std::string rest;
		std::getline(fields, rest);
		reference[file][(uint32_t)std::stoul(offset)] = rest;
	}
	check(reference.size() == 4, "reference: four files");
	std::mt19937 random(20261002);
	for (const auto& [name, expected] : reference) {
		const std::vector<uint8_t> bytes = readAll(folder + L"\\" + decodeText(name, CP_UTF8));
		IeIndexFile file;
		check(parseIeIndexDat(bytes.data(), bytes.size(), file), name + ": an MSIE Cache File 5.2");
		check(file.records.size() == expected.size(),
		      name + ": " + std::to_string(file.records.size()) + " record(s), pymsiecf " + std::to_string(expected.size()));
		unsigned different = 0;
		for (const IeIndexRecord& r : file.records) {
			const auto e = expected.find(r.offset);
			const std::string mine = encodeText(r.kind) + "|" + (r.recovered ? "1" : "0") + "|" + line(r);
			if (e == expected.end() || e->second != mine) {
				if (++different <= 3) std::printf("    %s @%u: WAC %s\n                pymsiecf %s\n", name.c_str(), r.offset, mine.c_str(),
				                                  e == expected.end() ? "(none)" : e->second.c_str());
			}
		}
		check(different == 0, name + ": every record identical to pymsiecf's (" + std::to_string(different) + " different)");

		// Hostile: truncated, then damaged, against a guard page on both sides.
		for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
			for (size_t cut = 0; cut <= bytes.size(); cut += 1 + bytes.size() / 64) {
				GuardedCopy copy(std::vector<uint8_t>(bytes.begin(), bytes.begin() + cut), side);
				IeIndexFile partial;
				parseIeIndexDat(copy.data(), copy.size(), partial);
			}
			for (int round = 0; round < 50; ++round) {
				std::vector<uint8_t> damaged = bytes;
				for (int k = 0; k < 64; ++k) damaged[random() % damaged.size()] = (uint8_t)random();
				GuardedCopy copy(damaged, side);
				IeIndexFile partial;
				parseIeIndexDat(copy.data(), copy.size(), partial);
			}
		}
		check(true, name + ": truncated and damaged copies decoded within their bytes");
	}
	// The conversion: container from the folder, user and page, cached file, headers.
	{
		std::vector<WebClientRecord> records;
		WebClientRecord base;
		base.source = L"C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\index.dat";
		check(readIeIndexDat(folder + L"\\history.dat", base, records) == ERROR_SUCCESS && !records.empty(), "conversion: history read");
		auto text = [](const Json& o, const wchar_t* k) { const Json* v = o.find(k); return v ? v->text() : std::wstring(); };
		// The records come in the hash tables' order: each is found by a field of its own.
		auto find = [&](const wchar_t* key, const std::wstring& value) {
			for (const WebClientRecord& r : records) { const Json o = r.toJson(); if (text(o, key) == value) return o; }
			return Json::obj();
		};
		const Json first = find(L"Url", L"Visited: gold_administrator@http://www.msn.com/?ocid=iehp");
		check(text(first, L"Container") == L"History" && text(first, L"User") == L"gold_administrator"
		      && text(first, L"Page") == L"http://www.msn.com/?ocid=iehp"
		      && text(first, L"AccessedUtc") == timeToIso8601Utc(FILETIME{ (DWORD)(130849743185120000ULL & 0xFFFFFFFF), (DWORD)(130849743185120000ULL >> 32) }),
		      "conversion: history entry — container, user, page, last visit (primary time, UTC)");
		records.clear();
		base.source = L"C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\index.dat";
		readIeIndexDat(folder + L"\\content.dat", base, records);
		const Json cached = find(L"Filename", L"4f1880[1].ico");
		check(text(cached, L"Container") == L"Content"
		      && text(cached, L"CachedFile") == L"C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\ENG3X4ZR\\4f1880[1].ico"
		      && text(cached, L"ResponseHeaders").rfind(L"HTTP/1.1 200 OK", 0) == 0 && !text(cached, L"ModifiedUtc").empty(),
		      "conversion: cache entry — its cached file in its directory, the server's headers, both times");
		records.clear();
		base.source = L"C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\MSHist012013031020130311\\index.dat";
		readIeIndexDat(folder + L"\\mshist.dat", base, records);
		const Json daily = find(L"Url", L":2013031020130311: -@:Host: windowsupdate.microsoft.com");
		check(text(daily, L"Container") == L"MSHist012013031020130311" && !daily.find(L"IndexCreatedUtc")
		      && text(daily, L"AccessedUtc") == timeToIso8601Utc(FILETIME{ (DWORD)(130073819316190000ULL & 0xFFFFFFFF), (DWORD)(130073819316190000ULL >> 32) }),
		      "conversion: daily history — its visit is the primary time, UTC (the local secondary not used)");
	}
	std::vector<uint8_t> notIndex(0x5000, 0);
	IeIndexFile none;
	check(!parseIeIndexDat(notIndex.data(), notIndex.size(), none), "a file without the signature refused");
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
