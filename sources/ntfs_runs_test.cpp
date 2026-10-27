/*! \file
 *  \brief Checks decodeNtfsRuns: data runs decoded exactly, a forged list
 *         refused whole, and nothing read outside the attribute; and the
 *         other bounds the raw reader takes from a record — a resident
 *         attribute's value, the compression unit, the index block size.
 *
 *  WHY THIS TEST. The data runs say where a file's clusters lie. Read from a
 *  deleted record (B-036), they are what an intruder or a damaged disk left:
 *  a header announcing fields of up to 15 bytes shifted the bytes past the
 *  width of the integer, and a run of length zero or before the volume's
 *  start was taken as it came. The lists here are built by hand, so that the
 *  expected runs are known; random lists are then placed against a
 *  PAGE_NOACCESS page (guard_page.h), both sides, and compared with an
 *  independent decoder.
 *
 *  Usage: ntfs_runs_test
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <cstdio>
#include <random>
#include <string>
#include <vector>
#include "guard_page.h"
#include "raw_hive.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned long long g_checks = 0, g_failures = 0;

/*! Records one check, printing the first failures. */
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! @return whether two lists of runs are the same
bool same(const std::vector<NtfsRun>& a, const std::vector<NtfsRun>& b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); ++i)
		if (a[i].lcn != b[i].lcn || a[i].count != b[i].count) return false;
	return true;
}

//! Decodes a list given as bytes.
std::vector<NtfsRun> decode(const std::vector<BYTE>& bytes) {
	return decodeNtfsRuns(bytes.data(), bytes.data() + bytes.size());
}

/*! Lists whose runs are known: the examples of the Linux-NTFS documentation,
 *  a backwards run, a sparse run, the end of the attribute without a zero. */
void known() {
	check(same(decode({ 0x21, 0x18, 0x34, 0x56, 0x00 }), { { 0x5634, 0x18 } }), "one run");
	check(same(decode({ 0x31, 0x38, 0x73, 0x25, 0x34, 0x32, 0x14, 0x01, 0xE5, 0x11, 0x02, 0x00 }),
	           { { 0x342573, 0x38 }, { 0x342573 + 0x211E5, 0x114 } }), "two runs");
	check(same(decode({ 0x11, 0x30, 0x60, 0x11, 0x10, 0xF0, 0x00 }), { { 0x60, 0x30 }, { 0x50, 0x10 } }),
	      "a run backwards (negative offset)");
	check(same(decode({ 0x11, 0x30, 0x60, 0x01, 0x10, 0x11, 0x08, 0x10, 0x00 }),
	           { { 0x60, 0x30 }, { -1, 0x10 }, { 0x70, 0x08 } }), "a sparse run, the next relative to the one before it");
	check(same(decode({ 0x11, 0x30, 0x60 }), { { 0x60, 0x30 } }), "end of the attribute without a terminating zero");
	check(same(decode({ 0x18, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x00 }), { { 0x10, 0x01 } }), "an 8-byte length");
	check(decode({ 0x00 }).empty() && decode({}).empty(), "an empty list");
}

/*! Forged lists: each refused whole, none half decoded. */
void forged() {
	const struct { std::vector<BYTE> bytes; const char* what; } cases[] = {
		{ { 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x10, 0x00 }, "length field of 9 bytes" },
		{ { 0x0F, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00 }, "length field of 15 bytes" },
		{ { 0x91, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00 }, "offset field of 9 bytes" },
		{ { 0xF1, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00 }, "offset field of 15 bytes" },
		{ { 0x10, 0x60, 0x00 }, "length field of 0 bytes" },
		{ { 0x11, 0x00, 0x60, 0x00 }, "run of length zero" },
		{ { 0x11, 0x30, 0x60, 0x21, 0x10 }, "run truncated by the end of the attribute" },
		{ { 0x11, 0x30, 0xF0, 0x00 }, "first run before the volume's start" },
		{ { 0x11, 0x30, 0x60, 0x11, 0x10, 0x80, 0x00 }, "a run that goes back before the volume's start" },
		{ { 0x11, 0x30, 0x60, 0x19, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00 }, "a good run, then a forged one" },
	};
	for (const auto& c : cases) check(decode(c.bytes).empty(), std::string("forged list accepted: ") + c.what);
}

/*! Independent decoder, on 128-bit integers: what decodeNtfsRuns must
 *  return, overflows included. */
std::vector<NtfsRun> expected(const std::vector<BYTE>& b) {
	std::vector<NtfsRun> runs;
	__int128 previous = 0;
	size_t i = 0;
	while (i < b.size() && b[i] != 0) {
		const size_t lengthSize = b[i] & 0x0F, offsetSize = b[i] >> 4;
		if (lengthSize < 1 || lengthSize > 8 || offsetSize > 8 || i + 1 + lengthSize + offsetSize > b.size()) return {};
		unsigned __int128 count = 0;
		for (size_t k = 0; k < lengthSize; ++k) count |= (unsigned __int128)b[i + 1 + k] << (8 * k);
		if (count == 0) return {};
		NtfsRun run{ -1, (uint64_t)count };
		if (offsetSize) {
			__int128 offset = 0;
			for (size_t k = 0; k < offsetSize; ++k) offset |= (__int128)b[i + 1 + lengthSize + k] << (8 * k);
			if (b[i + lengthSize + offsetSize] & 0x80) offset -= (__int128)1 << (8 * offsetSize);
			// Two's complement on 64 bits, as NTFS adds them.
			previous = (int64_t)(uint64_t)(previous + offset);
			if (previous < 0) return {};
			run.lcn = (int64_t)previous;
		}
		runs.push_back(run);
		i += 1 + lengthSize + offsetSize;
	}
	return runs;
}

/*! Random lists, mostly sound, sometimes damaged, against a guard page. */
void guarded(std::mt19937_64& rng) {
	for (int n = 0; n < 50000; ++n) {
		std::vector<BYTE> b;
		for (int runs = (int)(rng() % 6); runs > 0; --runs) {
			const unsigned lengthSize = 1 + (unsigned)(rng() % 3), offsetSize = (unsigned)(rng() % 4);
			b.push_back((BYTE)(lengthSize | offsetSize << 4));
			for (unsigned k = 0; k < lengthSize + offsetSize; ++k) b.push_back((BYTE)rng());
		}
		if (rng() % 2) b.push_back(0);
		for (int k = (int)(rng() % 3); k > 0 && !b.empty(); --k) b[rng() % b.size()] = (BYTE)rng();
		if (!b.empty() && rng() % 4 == 0) b.resize(rng() % b.size());
		const std::vector<NtfsRun> wanted = expected(b);
		for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
			GuardedCopy copy(b, side);
			check(same(decodeNtfsRuns(copy.data(), copy.data() + copy.size()), wanted), "random list: runs differ");
		}
	}
}

} // namespace

/*! Runs every check.
 * @return 0 if all passed */
/*! A resident attribute's value bounded by the attribute; the compression
 *  unit's exponent and the index block size bounded (B-050, lot 1: a forged
 *  $DATA of 0x7FFFFFFF bytes in a 1 KiB record was copied from past it). */
void attributeBounds() {
	// A resident attribute of 0x28 bytes: header 0x18, value of 0x10 bytes at 0x18.
	std::vector<uint8_t> a(0x28, 0);
	auto put32 = [&](size_t at, uint32_t v) { for (int i = 0; i < 4; ++i) a[at + i] = (uint8_t)(v >> (8 * i)); };
	put32(0, 0x80); put32(4, 0x28); put32(0x10, 0x10); a[0x14] = 0x18;
	const uint8_t* value = nullptr;
	uint32_t length = 0;
	check(residentAttributeValue(a.data(), value, length) && value == a.data() + 0x18 && length == 0x10,
	      "resident value: within its attribute, given");
	put32(0x10, 0x7FFFFFFF);
	check(!residentAttributeValue(a.data(), value, length), "resident value: a length past the attribute refused");
	put32(0x10, 0x10); a[0x14] = 0x20;
	check(!residentAttributeValue(a.data(), value, length), "resident value: an offset that ends it past the attribute refused");
	put32(4, 0x10);
	check(!residentAttributeValue(a.data(), value, length), "resident value: an attribute shorter than its header refused");
	check(compressionUnitClusters(4) == 16 && compressionUnitClusters(16) == 65536 && compressionUnitClusters(17) == 0
	      && compressionUnitClusters(40) == 0 && compressionUnitClusters(65535) == 0,
	      "compression unit: NTFS's 16 clusters, a forged exponent refused before any shift");
	check(plausibleIndexBlockSize(4096) && plausibleIndexBlockSize(512) && plausibleIndexBlockSize(65536)
	      && !plausibleIndexBlockSize(0) && !plausibleIndexBlockSize(256) && !plausibleIndexBlockSize(4095)
	      && !plausibleIndexBlockSize(131072) && !plausibleIndexBlockSize(0xFFFFFFF0u),
	      "index block size: a power of two from 512 bytes to 64 KiB, nothing else");
}

int main() {
	std::mt19937_64 rng(20261022);
	known();
	forged();
	guarded(rng);
	attributeBounds();
	std::printf("%s: %llu check(s), %llu failure(s)\n", g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
