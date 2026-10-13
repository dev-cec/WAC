/*! \file
 *  \brief Checks the replay of a hive's transaction logs (hive_recover.cpp)
 *         on a hive and logs forged here, entry by entry.
 *
 *  WHY THIS TEST. A replay that drops an entry, or applies a stale one, gives
 *  a hive that still opens and still reads: only the keys of the lost pages
 *  are missing or old, without any error. On real hives that shows by chance;
 *  here each page of the forged hive is filled with one letter, and each entry
 *  of the logs writes another, so that the letter left in a page says exactly
 *  which entry was applied last:
 *    - the entry numbered as the hive's secondary sequence IS APPLIED — it was
 *      skipped once, one entry lost at every replay;
 *    - the entries numbered below it are not: they are in the hive already;
 *    - what follows a break of the sequence in a log is leftover, not applied;
 *    - an entry that grows the hive extends the file and the base block's size
 *      of the bins data; the base block ends clean, one past the last entry,
 *      with a valid checksum;
 *    - the undo log gives the original pages and size back;
 *    - an entry whose digest is wrong ends the chain.
 *
 *  Usage: hive_recover_test `<work folder>` — built by `build-windows.sh
 *  --test`, runs under Wine.
 */
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include "conversions.h"
#include "hive_recover.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok) { ++g_failures; std::printf("  FAILED  %s\n", what.c_str()); }
}

const uint32_t PAGE = 4096;
const uint32_t SEQUENCE = 500;   //!< the forged hive's secondary sequence: the next entry it expects

//! Writes a whole file.
void writeFile(const std::filesystem::path& file, const std::vector<uint8_t>& bytes) {
	std::ofstream out(file, std::ios::binary | std::ios::trunc);
	out.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size());
}

//! Reads a whole file.
std::vector<uint8_t> readFile(const std::filesystem::path& file) {
	std::ifstream in(file, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

/*! A dirty primary hive: its base block, then `pages` pages of bins data
 *  filled with 'a', 'b', 'c'… */
std::vector<uint8_t> forgedHive(uint32_t pages) {
	std::vector<uint8_t> hive(PAGE + pages * PAGE, 0);
	std::memcpy(hive.data(), "regf", 4);
	writeLittleEndian<uint32_t>(hive.data() + 0x04, SEQUENCE + 1);   // primary: a write was under way
	writeLittleEndian<uint32_t>(hive.data() + 0x08, SEQUENCE);       // secondary
	writeLittleEndian<uint32_t>(hive.data() + 0x28, pages * PAGE);   // size of the bins data
	for (uint32_t p = 0; p < pages; ++p) std::memset(hive.data() + PAGE + p * PAGE, 'a' + (int)p, PAGE);
	return hive;
}

/*! One entry of a log: `letter` written over each page named.
 *  @param binsPages size of the bins data once the entry is applied, in pages */
std::vector<uint8_t> forgedEntry(uint32_t sequence, uint32_t binsPages, const std::vector<uint32_t>& pages, char letter) {
	const size_t header = 40 + 8 * pages.size();
	std::vector<uint8_t> entry((header + pages.size() * PAGE + 511) / 512 * 512, 0);
	std::memcpy(entry.data(), "HvLE", 4);
	writeLittleEndian<uint32_t>(entry.data() + 4, (uint32_t)entry.size());
	writeLittleEndian<uint32_t>(entry.data() + 12, sequence);
	writeLittleEndian<uint32_t>(entry.data() + 16, binsPages * PAGE);
	writeLittleEndian<uint32_t>(entry.data() + 20, (uint32_t)pages.size());
	for (size_t k = 0; k < pages.size(); ++k) {
		writeLittleEndian<uint32_t>(entry.data() + 40 + 8 * k, pages[k] * PAGE);
		writeLittleEndian<uint32_t>(entry.data() + 44 + 8 * k, PAGE);
		std::memset(entry.data() + header + k * PAGE, letter, PAGE);
	}
	writeLittleEndian<uint64_t>(entry.data() + 24, HiveLogDigest(entry.data() + 40, entry.size() - 40));
	writeLittleEndian<uint64_t>(entry.data() + 32, HiveLogDigest(entry.data(), 32));
	return entry;
}

//! A log: its base block, then the entries one after the other.
std::vector<uint8_t> forgedLog(const std::vector<std::vector<uint8_t>>& entries) {
	std::vector<uint8_t> log(512, 0);
	std::memcpy(log.data(), "regf", 4);
	writeLittleEndian<uint32_t>(log.data() + 0x1C, 6);
	for (const std::vector<uint8_t>& e : entries) log.insert(log.end(), e.begin(), e.end());
	return log;
}

//! The letters left in the pages of a hive file, one per page.
std::string letters(const std::vector<uint8_t>& hive) {
	std::string text;
	for (size_t offset = PAGE; offset + PAGE <= hive.size(); offset += PAGE) {
		bool uniform = true;
		for (size_t k = 1; k < PAGE; ++k) uniform = uniform && hive[offset + k] == hive[offset];
		text += uniform ? (hive[offset] ? (char)hive[offset] : '0') : '?';
	}
	return text;
}

//! The base block's checksum as the format defines it: XOR of its first 127 DWORDs.
uint32_t checksum(const std::vector<uint8_t>& hive) {
	uint32_t x = 0;
	for (size_t k = 0; k < 127; ++k) x ^= readLittleEndian<uint32_t>(hive.data() + 4 * k);
	return x;
}

//! Undoes a replay with its undo log, as its format (hive_recover.h) lets a third party do.
std::vector<uint8_t> undone(std::vector<uint8_t> hive, const std::vector<uint8_t>& undo) {
	if (undo.size() < 56 || std::memcmp(undo.data(), "WACUNDO1", 8) != 0) return {};
	const uint32_t count = readLittleEndian<uint32_t>(undo.data() + 40);
	hive.resize((size_t)readLittleEndian<uint64_t>(undo.data() + 44));
	size_t content = 56 + 12ull * count;
	for (uint32_t k = 0; k < count; ++k) {
		const uint64_t offset = readLittleEndian<uint64_t>(undo.data() + 56 + 12ull * k);
		const uint32_t size = readLittleEndian<uint32_t>(undo.data() + 56 + 12ull * k + 8);
		if (content + size > undo.size() || offset + size > hive.size()) return {};
		std::memcpy(hive.data() + offset, undo.data() + content, size);
		content += size;
	}
	return hive;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc < 2) { std::printf("usage: hive_recover_test <work folder>\n"); return 2; }
	const std::filesystem::path folder = argv[1];
	std::error_code ec;
	std::filesystem::create_directories(folder, ec);
	const std::filesystem::path hive = folder / L"FORGED";
	const std::wstring md5 = L"0123456789abcdef0123456789abcdef";

	/* 1. The whole case. Hive of 3 pages "abc", expecting entry 500.
	      LOG2, the older log: 498 and 499, already in the hive ('x', 'y' on page 0).
	      LOG1: 500 writes 'P' on page 0; 501 'Q' on page 1; 502 grows the
	      hive to 5 pages and writes 'R' on page 4; then a leftover of an
	      earlier generation, 497, which would write 'z' on page 2. */
	const std::vector<uint8_t> original = forgedHive(3);
	writeFile(hive, original);
	writeFile(hive.wstring() + L".LOG2", forgedLog({ forgedEntry(498, 3, { 0 }, 'x'), forgedEntry(499, 3, { 0 }, 'y') }));
	writeFile(hive.wstring() + L".LOG1", forgedLog({ forgedEntry(500, 3, { 0 }, 'P'), forgedEntry(501, 3, { 1 }, 'Q'),
	                                                forgedEntry(502, 5, { 4 }, 'R'), forgedEntry(497, 3, { 2 }, 'z') }));
	HiveReplayInfo r = ReplayHiveLogs(hive, md5);
	std::vector<uint8_t> replayed = readFile(hive);
	check(r.ok && r.applied, "replay: not carried out");
	check(letters(replayed).substr(0, 1) == "P", "the entry numbered as the hive's sequence (500) was not applied: page 0 holds '"
	      + letters(replayed).substr(0, 1) + "'");
	check(letters(replayed) == "PQc0R", "pages after the replay: " + letters(replayed) + ", expected PQc0R");
	check(r.keptEntries == 3 && r.leftoverEntries == 1 && r.discardedEntries == 0,
	      "entries: " + std::to_string(r.keptEntries) + " applied, " + std::to_string(r.leftoverEntries) + " leftover, "
	      + std::to_string(r.discardedEntries) + " discarded; expected 3, 1, 0");
	check(replayed.size() == PAGE + 5 * PAGE && readLittleEndian<uint32_t>(replayed.data() + 0x28) == 5 * PAGE,
	      "a growing entry: file or base block not extended to 5 pages");
	check(readLittleEndian<uint32_t>(replayed.data() + 4) == 503 && readLittleEndian<uint32_t>(replayed.data() + 8) == 503
	      && r.finalSequence == 503, "base block: not clean at 503, one past the last entry applied");
	check(readLittleEndian<uint32_t>(replayed.data() + 508) == checksum(replayed), "base block: checksum not recomputed");
	check(undone(replayed, readFile(hive.wstring() + L".undo")) == original, "the undo log does not give the original hive back");

	/* 2. Replayed again with the same logs: nothing left to apply, nothing changed. */
	r = ReplayHiveLogs(hive, md5);
	check(r.ok && !r.applied && readFile(hive) == replayed, "a second replay of the same logs changed the hive");

	/* 3. An entry whose body was altered ends the chain: 500 applied, 501 and 502 not. */
	writeFile(hive, original);
	std::vector<uint8_t> altered = forgedEntry(501, 3, { 1 }, 'Q');
	altered[altered.size() - 600] ^= 1;
	writeFile(hive.wstring() + L".LOG1", forgedLog({ forgedEntry(500, 3, { 0 }, 'P'), altered, forgedEntry(502, 3, { 2 }, 'R') }));
	std::filesystem::remove(hive.wstring() + L".LOG2", ec);
	r = ReplayHiveLogs(hive, md5);
	check(r.ok && letters(readFile(hive)) == "Pbc" && r.keptEntries == 1 && r.discardedEntries == 1,
	      "an altered entry: pages " + letters(readFile(hive)) + ", expected Pbc with one entry discarded");

	/* 4. A page past the bins data its entry announces: the entry is refused. */
	writeFile(hive, original);
	writeFile(hive.wstring() + L".LOG1", forgedLog({ forgedEntry(500, 3, { 3 }, 'P') }));
	r = ReplayHiveLogs(hive, md5);
	check(r.ok && !r.applied && readFile(hive) == original, "a page outside the announced bins data was written");

	std::filesystem::remove_all(folder, ec);
	std::printf("%u check(s), %u failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
