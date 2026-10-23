/*! \file
 *  \brief Checks the recovery of deleted files (deleted_files.h) on a volume
 *         held in memory: what is recovered is the deleted content exactly,
 *         a cluster given to another file is never published as the file's,
 *         and a forged record never makes the reading leave the volume.
 *
 *  WHY THIS TEST. A recovery that goes wrong gives a file that looks right:
 *  the bytes of whatever lies in the clusters now. Each case here builds a
 *  record and a volume whose expected outcome is known — a resident file, a
 *  contiguous one, a fragmented one, clusters taken before the reading or
 *  during it, clusters read back zero (TRIM), a valid data length shorter
 *  than the size, a sparse run — and the forged lists (past the volume, two
 *  runs on the same clusters, sizes that do not match) must be refused
 *  before any cluster is read. Every read the recovery asks for is checked:
 *  inside the volume, and on clusters free at that moment. Random damaged
 *  records are then parsed against a PAGE_NOACCESS page (guard_page.h).
 *
 *  Usage: deleted_files_test
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>
#include "deleted_files.h"
#include "guard_page.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned long long g_checks = 0, g_failures = 0;

/*! Records one check, printing the first failures. */
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

const uint32_t CLUSTER = 512;
const uint64_t CLUSTERS = 4096;

/*! A volume in memory: its clusters, which are in use, and what the
 *  recovery asked of it. */
struct Volume {
	std::vector<uint8_t> bytes = std::vector<uint8_t>(CLUSTER * CLUSTERS);
	std::vector<bool> used = std::vector<bool>(CLUSTERS, false);
	uint64_t takenAfterRead = UINT64_MAX;   //!< a cluster NTFS gives to another file while it is read
	bool badRead = false;                    //!< a read asked for a cluster in use, or outside the volume
	size_t reads = 0;

	ClusterSource source() {
		ClusterSource s;
		s.clusterSize = CLUSTER;
		s.clusters = CLUSTERS;
		s.allocation = [this](uint64_t lcn, uint64_t count, std::vector<bool>& inUse) {
			if (lcn >= CLUSTERS || count > CLUSTERS - lcn) { badRead = true; return false; }
			inUse.assign(used.begin() + (ptrdiff_t)lcn, used.begin() + (ptrdiff_t)(lcn + count));
			return true;
		};
		s.read = [this](uint64_t lcn, uint64_t count, uint8_t* out) {
			++reads;
			if (lcn >= CLUSTERS || count > CLUSTERS - lcn) { badRead = true; return false; }
			for (uint64_t k = lcn; k < lcn + count; ++k) if (used[(size_t)k]) badRead = true;
			std::memcpy(out, bytes.data() + lcn * CLUSTER, (size_t)(count * CLUSTER));
			if (takenAfterRead >= lcn && takenAfterRead < lcn + count) used[(size_t)takenAfterRead] = true;
			return true;
		};
		return s;
	}
	//! Fills clusters with recognisable bytes.
	void fill(uint64_t lcn, uint64_t count, uint8_t seed) {
		for (uint64_t k = lcn * CLUSTER; k < (lcn + count) * CLUSTER; ++k) bytes[(size_t)k] = (uint8_t)(seed + k * 7 + 1);
	}
	//! The bytes of clusters.
	std::vector<uint8_t> clusters(uint64_t lcn, uint64_t count) const {
		return std::vector<uint8_t>(bytes.begin() + (ptrdiff_t)(lcn * CLUSTER), bytes.begin() + (ptrdiff_t)((lcn + count) * CLUSTER));
	}
};

void put16(std::vector<uint8_t>& r, size_t at, uint16_t v) { r[at] = (uint8_t)v; r[at + 1] = (uint8_t)(v >> 8); }
void put32(std::vector<uint8_t>& r, size_t at, uint32_t v) { for (int k = 0; k < 4; ++k) r[at + k] = (uint8_t)(v >> (8 * k)); }
void put64(std::vector<uint8_t>& r, size_t at, uint64_t v) { for (int k = 0; k < 8; ++k) r[at + k] = (uint8_t)(v >> (8 * k)); }

/*! A deleted FILE record of 1024 bytes, fixups already applied, holding
 *  `attributes` (each a whole attribute) after the header. */
std::vector<uint8_t> record(const std::vector<std::vector<uint8_t>>& attributes, uint16_t flags = 0, uint16_t sequence = 7) {
	std::vector<uint8_t> r(1024, 0);
	std::memcpy(r.data(), "FILE", 4);
	put16(r, 0x10, sequence);
	put16(r, 0x14, 0x38);
	put16(r, 0x16, flags);
	size_t p = 0x38;
	for (const std::vector<uint8_t>& a : attributes) { std::memcpy(r.data() + p, a.data(), a.size()); p += a.size(); }
	put32(r, p, 0xFFFFFFFF);
	put32(r, 0x18, (uint32_t)(p + 8));
	put32(r, 0x1C, 1024);
	return r;
}

//! A resident unnamed $DATA holding `value`.
std::vector<uint8_t> residentData(const std::vector<uint8_t>& value) {
	std::vector<uint8_t> a(0x18 + ((value.size() + 7) & ~(size_t)7), 0);
	put32(a, 0, 0x80);
	put32(a, 4, (uint32_t)a.size());
	put32(a, 0x10, (uint32_t)value.size());
	put16(a, 0x14, 0x18);
	std::memcpy(a.data() + 0x18, value.data(), value.size());
	return a;
}

//! A non-resident unnamed $DATA with these runs (encoded) and sizes.
std::vector<uint8_t> nonResidentData(const std::vector<uint8_t>& runs, uint64_t lastVcn, uint64_t allocated,
                                     uint64_t size, uint64_t initialized, uint16_t flags = 0) {
	std::vector<uint8_t> a(0x40 + ((runs.size() + 1 + 7) & ~(size_t)7), 0);
	put32(a, 0, 0x80);
	put32(a, 4, (uint32_t)a.size());
	a[8] = 1;
	put16(a, 0x0C, flags);
	put64(a, 0x18, lastVcn);
	put16(a, 0x20, 0x40);
	put64(a, 0x28, allocated);
	put64(a, 0x30, size);
	put64(a, 0x38, initialized);
	std::memcpy(a.data() + 0x40, runs.data(), runs.size());
	return a;
}

//! An $ATTRIBUTE_LIST, its content left empty: its presence is what counts.
std::vector<uint8_t> attributeList() {
	std::vector<uint8_t> a(0x18, 0);
	put32(a, 0, 0x20);
	put32(a, 4, 0x18);
	put16(a, 0x14, 0x18);
	return a;
}

//! Recovers a record's content on a volume, the sink collecting it.
Recovery recover(const std::vector<uint8_t>& rec, Volume& v, std::vector<uint8_t>& content) {
	content.clear();
	const DeletedRecord r = parseDeletedRecord(rec.data(), rec.size());
	return recoverContent(r.data, v.source(), [&](const uint8_t* d, size_t n) { content.insert(content.end(), d, d + n); });
}

void residentFile() {
	Volume v;
	const std::vector<uint8_t> text = { 'W', 'A', 'C', ' ', 'w', 'i', 't', 'n', 'e', 's', 's', '\n' };
	const std::vector<uint8_t> rec = record({ residentData(text) });
	const DeletedRecord r = parseDeletedRecord(rec.data(), rec.size());
	check(r.fileRecord && !r.inUse && r.baseRecord && r.sequence == 7 && r.data.resident, "resident record misread");
	std::vector<uint8_t> content;
	const Recovery rc = recover(rec, v, content);
	check(rc.state == RecoveryState::Recovered && content == text && rc.recoveredBytes == text.size() && v.reads == 0,
	      "resident file: content not the record's");
}

void contiguousFile() {
	Volume v;
	v.fill(100, 4, 1);
	// One run: 4 clusters at 100; 1800 bytes of content.
	const std::vector<uint8_t> rec = record({ nonResidentData({ 0x11, 4, 100 }, 3, 4 * CLUSTER, 1800, 1800) });
	std::vector<uint8_t> content;
	const Recovery rc = recover(rec, v, content);
	std::vector<uint8_t> expected = v.clusters(100, 4);
	expected.resize(1800);
	check(rc.state == RecoveryState::Recovered && content == expected && rc.missing.empty() && rc.recoveredBytes == 1800 && !v.badRead,
	      "contiguous file: not recovered exactly");
}

void fragmentedFile() {
	Volume v;
	v.fill(300, 2, 3);
	v.fill(50, 3, 9);
	// 2 clusters at 300, then 3 at 50 (offset -250), sparse 1, 2048 + 512 bytes: 6 clusters.
	const std::vector<uint8_t> runs = { 0x21, 2, 0x2C, 0x01, 0x21, 3, 0x06, 0xFF, 0x01, 1 };
	const std::vector<uint8_t> rec = record({ nonResidentData(runs, 5, 6 * CLUSTER, 6 * CLUSTER, 6 * CLUSTER) });
	std::vector<uint8_t> content;
	const Recovery rc = recover(rec, v, content);
	std::vector<uint8_t> expected = v.clusters(300, 2);
	const std::vector<uint8_t> second = v.clusters(50, 3);
	expected.insert(expected.end(), second.begin(), second.end());
	expected.resize(6 * CLUSTER, 0);                         // the sparse cluster: zeros
	check(rc.state == RecoveryState::Recovered && content == expected && !v.badRead, "fragmented file with a sparse run: not recovered exactly");
}

void takenClusters() {
	// One cluster of four given to another file before the reading.
	{
		Volume v;
		v.fill(200, 4, 5);
		v.used[201] = true;
		const std::vector<uint8_t> rec = record({ nonResidentData({ 0x21, 4, 0xC8, 0x00 }, 3, 4 * CLUSTER, 4 * CLUSTER, 4 * CLUSTER) });
		std::vector<uint8_t> content;
		const Recovery rc = recover(rec, v, content);
		std::vector<uint8_t> expected = v.clusters(200, 4);
		std::memset(expected.data() + CLUSTER, 0, CLUSTER);
		check(rc.state == RecoveryState::Partial && content == expected && rc.missing.size() == 1
		      && rc.missing[0].offset == CLUSTER && rc.missing[0].length == CLUSTER && rc.recoveredBytes == 3 * CLUSTER,
		      "a cluster in use: not a hole of zeros, or not listed");
		check(!v.badRead, "a cluster in use was read");
	}
	// Given to another file WHILE the clusters are read: a hole too.
	{
		Volume v;
		v.fill(200, 4, 5);
		v.takenAfterRead = 203;
		const std::vector<uint8_t> rec = record({ nonResidentData({ 0x21, 4, 0xC8, 0x00 }, 3, 4 * CLUSTER, 4 * CLUSTER - 100, 4 * CLUSTER - 100) });
		std::vector<uint8_t> content;
		const Recovery rc = recover(rec, v, content);
		check(rc.state == RecoveryState::Partial && rc.missing.size() == 1 && rc.missing[0].offset == 3 * CLUSTER
		      && rc.missing[0].length == CLUSTER - 100 && content.size() == 4 * CLUSTER - 100
		      && std::all_of(content.begin() + 3 * CLUSTER, content.end(), [](uint8_t b) { return b == 0; }),
		      "a cluster taken during the reading: published as the file's");
	}
	// Every cluster taken: nothing recovered.
	{
		Volume v;
		v.used[10] = v.used[11] = true;
		const std::vector<uint8_t> rec = record({ nonResidentData({ 0x11, 2, 10 }, 1, 2 * CLUSTER, 2 * CLUSTER, 2 * CLUSTER) });
		std::vector<uint8_t> content;
		const Recovery rc = recover(rec, v, content);
		check(rc.state == RecoveryState::Overwritten && rc.recoveredBytes == 0 && v.reads == 0, "every cluster taken: not Overwritten");
	}
}

void zeroedAndShort() {
	// Free clusters read back zero: TRIM.
	{
		Volume v;
		const std::vector<uint8_t> rec = record({ nonResidentData({ 0x11, 2, 40 }, 1, 2 * CLUSTER, 2 * CLUSTER, 2 * CLUSTER) });
		std::vector<uint8_t> content;
		check(recover(rec, v, content).state == RecoveryState::Zeroed, "clusters read back zero: not Zeroed");
	}
	// Valid data length shorter than the size: the rest zeros, not read.
	{
		Volume v;
		v.fill(60, 4, 2);
		v.used[62] = v.used[63] = true;                      // beyond the valid length: must not matter
		const std::vector<uint8_t> rec = record({ nonResidentData({ 0x11, 4, 60 }, 3, 4 * CLUSTER, 4 * CLUSTER, 700) });
		std::vector<uint8_t> content;
		const Recovery rc = recover(rec, v, content);
		std::vector<uint8_t> expected = v.clusters(60, 2);
		expected.resize(700);
		expected.resize(4 * CLUSTER, 0);
		check(rc.state == RecoveryState::Recovered && content == expected && rc.recoveredBytes == 700 && rc.missing.empty() && !v.badRead,
		      "valid data length: the tail not zeros, or clusters beyond it read");
	}
}

void refused() {
	const struct { std::vector<uint8_t> attribute; const char* what; } cases[] = {
		{ nonResidentData({ 0x21, 4, 0xFE, 0x0F }, 3, 4 * CLUSTER, 4 * CLUSTER, 4 * CLUSTER), "a run past the volume's end" },
		{ nonResidentData({ 0x11, 4, 100, 0x11, 4, 0xFE }, 7, 8 * CLUSTER, 8 * CLUSTER, 8 * CLUSTER), "two runs on the same clusters" },
		{ nonResidentData({ 0x11, 4, 100 }, 9, 10 * CLUSTER, 4 * CLUSTER, 4 * CLUSTER), "runs shorter than the last cluster" },
		{ nonResidentData({ 0x11, 4, 100 }, 3, 40 * CLUSTER, 4 * CLUSTER, 4 * CLUSTER), "allocated size not the runs'" },
		{ nonResidentData({ 0x11, 4, 100 }, 3, 4 * CLUSTER, 5 * CLUSTER, 4 * CLUSTER), "size beyond the clusters" },
		{ nonResidentData({ 0x11, 4, 100 }, 3, 4 * CLUSTER, 4 * CLUSTER, 5 * CLUSTER), "valid length beyond the size" },
		{ nonResidentData({ 0x19, 4, 0, 0, 0, 0, 0, 0, 0, 0, 100 }, 3, 4 * CLUSTER, 4 * CLUSTER, 4 * CLUSTER), "a forged run header" },
		{ nonResidentData({ 0x11, 4, 100 }, 3, 4 * CLUSTER, 4 * CLUSTER, 4 * CLUSTER, 0x0001), "compressed" },
		{ nonResidentData({ 0x11, 4, 100 }, 3, 4 * CLUSTER, 4 * CLUSTER, 4 * CLUSTER, 0x4000), "encrypted" },
	};
	for (const auto& c : cases) {
		Volume v;
		v.fill(100, 4, 4);
		std::vector<uint8_t> content;
		const Recovery rc = recover(record({ c.attribute }), v, content);
		check(rc.state == RecoveryState::NotRecoverable && !rc.reason.empty() && content.empty() && v.reads == 0 && !v.badRead,
		      std::string("not refused before reading: ") + c.what);
	}
	// Runs continued in an extension record: what the base record holds is not the whole file.
	Volume v;
	std::vector<uint8_t> content;
	const Recovery rc = recover(record({ attributeList(), nonResidentData({ 0x11, 4, 100 }, 3, 8 * CLUSTER, 8 * CLUSTER, 8 * CLUSTER) }), v, content);
	check(rc.state == RecoveryState::NotRecoverable && rc.reason.find("ATTRIBUTE_LIST") != std::string::npos && v.reads == 0,
	      "runs in extension records: not refused");
	// A record reused since: in use, and the parse says so.
	const std::vector<uint8_t> inUse = record({ residentData({ 1, 2, 3 }) }, 0x01);
	check(parseDeletedRecord(inUse.data(), inUse.size()).inUse, "record in use not said so");
}

void names() {
	check(safeFileName(L"rapport.docx") == L"rapport.docx", "a plain name changed");
	check(safeFileName(L"a:b*c?.exe") == L"a_b_c_.exe", "forbidden characters kept");
	check(safeFileName(L"end. ") == L"end._" || safeFileName(L"end. ") == L"end__", "trailing dot or space kept");
	check(safeFileName(L"") == L"_" && safeFileName(std::wstring(300, L'x')).size() == 120, "empty or long name");
}

/*! Damaged records, parsed against a guard page; their recovery never leaves the volume. */
void guarded(std::mt19937_64& rng) {
	const std::vector<uint8_t> sound = record({ residentData({ 'x', 'y' }), nonResidentData({ 0x21, 4, 0x10, 0x01, 0x11, 2, 0x40 }, 5, 6 * CLUSTER, 6 * CLUSTER, 6 * CLUSTER) });
	for (int n = 0; n < 20000; ++n) {
		std::vector<uint8_t> r = sound;
		for (int k = 1 + (int)(rng() % 6); k > 0; --k) r[rng() % 0x140] = (uint8_t)rng();
		if (rng() % 8 == 0) r.resize(rng() % r.size());
		for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
			GuardedCopy copy(r, side);
			const DeletedRecord parsed = parseDeletedRecord(copy.data(), copy.size());
			Volume v;
			std::vector<uint8_t> content;
			size_t handed = 0;
			const Recovery rc = recoverContent(parsed.data, v.source(), [&](const uint8_t*, size_t m) { handed += m; });
			check(!v.badRead, "damaged record: a read outside the volume or on a cluster in use");
			check(rc.state == RecoveryState::NotRecoverable || handed == parsed.data.size, "damaged record: content not of its size");
		}
	}
}

} // namespace

/*! Runs every check.
 * @return 0 if all passed */
int wmain() {
	std::mt19937_64 rng(20261022);
	residentFile();
	contiguousFile();
	fragmentedFile();
	takenClusters();
	zeroedAndShort();
	refused();
	names();
	guarded(rng);
	std::printf("%s: %llu check(s), %llu failure(s)\n", g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
