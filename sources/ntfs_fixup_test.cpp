/*! \file
 *  \brief Checks applyNtfsFixup: a torn NTFS record is refused, a sound one
 *         restored exactly, a malformed array rejected, and nothing is read
 *         outside the record.
 *
 *  WHY THIS TEST. NTFS writes a $MFT record or an index block sector by sector,
 *  and marks the end of every 512-byte stride with an update sequence number.
 *  WAC applied the fixups without comparing that number: a record torn by an
 *  interrupted write came out as plausible data, a mix of two versions, with
 *  no error. The records here are built by hand, so that the expected result
 *  of each is known: a sound record (the real bytes must come back), a record
 *  torn in each of its strides, arrays that are malformed (odd offset, wrong
 *  count, past the first stride), records whose size is not a multiple of 512.
 *  Random records are then placed against a PAGE_NOACCESS page (guard_page.h),
 *  both sides, and the verdict is compared with an independent check.
 *
 *  Usage: ntfs_fixup_test
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <cstdio>
#include <cstring>
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

void put16(std::vector<BYTE>& r, size_t at, uint16_t v) {
	r[at] = (BYTE)(v & 0xFF);
	r[at + 1] = (BYTE)(v >> 8);
}

uint16_t get16(const BYTE* p) { return (uint16_t)(p[0] | (p[1] << 8)); }

/*! A record as NTFS writes it: random content, then the real end of every
 *  stride saved in the array and replaced by the sequence number.
 *  @param size record size (multiple of 512)
 *  @param arrayOffset offset of the update sequence array (0x30 for FILE, 0x28 for INDX)
 *  @param clean receives the record as it must read after the fixups */
std::vector<BYTE> written(std::mt19937_64& rng, size_t size, uint16_t arrayOffset, std::vector<BYTE>& clean) {
	clean.assign(size, 0);
	for (BYTE& b : clean) b = (BYTE)rng();
	std::memcpy(clean.data(), size == 4096 && arrayOffset == 0x28 ? "INDX" : "FILE", 4);
	const size_t count = size / 512 + 1;
	put16(clean, 4, arrayOffset);
	put16(clean, 6, (uint16_t)count);
	const uint16_t sequence = (uint16_t)(rng() | 1);
	put16(clean, arrayOffset, sequence);
	for (size_t i = 1; i < count; ++i) {             // the array holds the real ends
		clean[arrayOffset + 2 * i] = clean[i * 512 - 2];
		clean[arrayOffset + 2 * i + 1] = clean[i * 512 - 1];
	}
	std::vector<BYTE> disk = clean;
	for (size_t i = 1; i < count; ++i) put16(disk, i * 512 - 2, sequence);
	return disk;
}

void soundAndTorn(std::mt19937_64& rng) {
	const struct { size_t size; uint16_t offset; } shapes[] = { { 1024, 0x30 }, { 4096, 0x30 }, { 4096, 0x28 }, { 512, 0x2A } };
	for (const auto& shape : shapes) {
		for (int n = 0; n < 200; ++n) {
			std::vector<BYTE> clean;
			std::vector<BYTE> disk = written(rng, shape.size, shape.offset, clean);
			std::vector<BYTE> r = disk;
			check(applyNtfsFixup(r.data(), r.size()) && r == clean,
			      "sound record of " + std::to_string(shape.size) + " bytes: not restored exactly");
			// Torn in each stride: refused, and left as read.
			for (size_t i = 1; i <= shape.size / 512; ++i) {
				std::vector<BYTE> torn = disk;
				torn[i * 512 - 1] ^= 0x5A;
				const std::vector<BYTE> before = torn;
				check(!applyNtfsFixup(torn.data(), torn.size()) && torn == before,
				      "record torn in stride " + std::to_string(i) + " of " + std::to_string(shape.size) + ": accepted");
			}
		}
	}
}

void malformed(std::mt19937_64& rng) {
	std::vector<BYTE> clean;
	const std::vector<BYTE> disk = written(rng, 1024, 0x30, clean);
	const struct { size_t at; uint16_t value; const char* what; } cases[] = {
		{ 4, 0x31, "odd array offset" },
		{ 4, 0x04, "array over the header" },
		{ 4, 0x1FE, "array past the first stride" },
		{ 6, 2, "count too small" },
		{ 6, 4, "count too large" },
		{ 6, 0, "count zero" },
		{ 6, 0xFFFF, "count huge" },
	};
	for (const auto& c : cases) {
		std::vector<BYTE> r = disk;
		put16(r, c.at, c.value);
		check(!applyNtfsFixup(r.data(), r.size()), std::string("malformed array accepted: ") + c.what);
	}
	std::vector<BYTE> r = disk;
	check(!applyNtfsFixup(r.data(), 1000), "size not a multiple of 512 accepted");
	check(!applyNtfsFixup(r.data(), 0), "empty record accepted");
	check(!applyNtfsFixup(nullptr, 1024), "null record accepted");
}

/*! Independent verdict: what the fixups must say about a record. */
bool expected(const std::vector<BYTE>& r) {
	if (r.size() < 512 || r.size() % 512) return false;
	const size_t offset = get16(&r[4]), count = get16(&r[6]);
	if (offset < 8 || offset % 2 || count != r.size() / 512 + 1 || offset + 2 * count > 512) return false;
	for (size_t i = 1; i < count; ++i)
		if (get16(&r[i * 512 - 2]) != get16(&r[offset])) return false;
	return true;
}

void guarded(std::mt19937_64& rng) {
	for (int n = 0; n < 20000; ++n) {
		const size_t size = 512 * (1 + rng() % 8);
		std::vector<BYTE> clean;
		std::vector<BYTE> r = written(rng, size, (uint16_t)(0x28 + 2 * (rng() % 4)), clean);
		// Corrupt a few bytes, the header fields most of the time.
		for (int k = (int)(rng() % 4); k > 0; --k) r[rng() % 3 == 0 ? rng() % size : 4 + rng() % 4] = (BYTE)rng();
		const bool verdict = expected(r);
		for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
			GuardedCopy copy(r, side);
			check(applyNtfsFixup(copy.data(), copy.size()) == verdict, "random record: verdict differs");
		}
	}
}

} // namespace

/*! Runs every check.
 * @return 0 if all passed */
int main() {
	std::mt19937_64 rng(20260924);
	soundAndTorn(rng);
	malformed(rng);
	guarded(rng);
	std::printf("%s: %llu check(s), %llu failure(s)\n", g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
