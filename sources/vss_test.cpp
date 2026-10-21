/*! \file
 *  \brief Checks the raw reading of shadow copies (vss.cpp).
 *
 *  WHY THIS TEST. A wrong rule in the application of the stores gives a
 *  copy whose files are valid and wrong — a block of the current volume
 *  where the copy held another —, which nothing at run time reveals.
 *
 *  Without argument: a volume of 64 blocks built here, two copies whose
 *  answers are set by hand block by block, not computed by the algorithm:
 *    - a block the older copy's store holds, read from the store, and from
 *      the volume by the newer copy;
 *    - a forwarder of the older store to the newer one;
 *    - a block only the newer store holds, read through it by both copies;
 *    - an overlay of one sector, which serves its own copy only, also when
 *      an older copy reads through its store;
 *    - an ignored descriptor (flag 0x4);
 *    - a block the newer copy did not use, zeros for it alone;
 *    - copies listed oldest first though the catalog gives the newer first,
 *      their identifiers, times and machine names; a copy deleted whose
 *      store Windows keeps (flag 0x100), told from the others and read;
 *    - a block Windows copies to the newer store after the lists were
 *      read, seen once the lists are refreshed, the older store kept;
 *    - a catalog whose chain loops, refused.
 *
 *  With an image: `vss_test <volume image>` lists the copies of a real
 *  volume and the SHA-256 of each copy's whole volume, to confront with
 *  libvshadow (vmtest/lib/vss-reference.py).
 *
 *  Built by `build-windows.sh --test`, runs under Wine.
 */
#include "vss.h"
#include "sha.h"
#include "portable_conversions.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok) { ++g_failures; std::printf("  FAILED  %s\n", what.c_str()); }
}

const uint64_t B = ShadowCopies::BLOCK;
const uint8_t VSS_ID[16] = { 0x6B, 0x87, 0x08, 0x38, 0x76, 0xC1, 0x48, 0x4E,
                             0xB7, 0xAE, 0x04, 0x04, 0x6E, 0x6C, 0xC7, 0x52 };

//! The synthetic volume, and the writing of its VSS structures.
struct Volume {
	std::vector<uint8_t> bytes = std::vector<uint8_t>(64 * B);

	//! Block `index` filled with `value` (the volume's current content).
	void fill(uint64_t index, uint8_t value) { std::memset(bytes.data() + index * B, value, B); }
	//! A block header: VSS identifier, version 1, record type, next block.
	void header(uint64_t index, uint32_t type, uint64_t next) {
		uint8_t* h = bytes.data() + index * B;
		std::memset(h, 0, B);
		std::memcpy(h, VSS_ID, 16);
		writeLittleEndian<uint32_t>(h + 16, 1);
		writeLittleEndian<uint32_t>(h + 20, type);
		writeLittleEndian<uint64_t>(h + 32, index * B);
		writeLittleEndian<uint64_t>(h + 40, next);
	}
	//! A store's block descriptor, slot `slot` of the list in block `index`.
	void descriptor(uint64_t index, size_t slot, uint64_t original, uint64_t relative, uint64_t stored,
	                uint32_t flags, uint32_t bitmap = 0) {
		uint8_t* e = bytes.data() + index * B + 128 + slot * 32;
		writeLittleEndian<uint64_t>(e, original);
		writeLittleEndian<uint64_t>(e + 8, relative);
		writeLittleEndian<uint64_t>(e + 16, stored);
		writeLittleEndian<uint32_t>(e + 24, flags);
		writeLittleEndian<uint32_t>(e + 28, bitmap);
	}
	//! A store header with its copy's identifiers and machine names.
	void storeHeader(uint64_t index, uint8_t idByte, const std::u16string& machine) {
		header(index, 4, 0);
		uint8_t* s = bytes.data() + index * B + 128;
		std::memset(s + 16, idByte, 16);          // copy identifier
		std::memset(s + 32, idByte + 1, 16);      // set identifier
		writeLittleEndian<uint32_t>(s + 48, 0x9);
		writeLittleEndian<uint32_t>(s + 56, 0x2001D);
		size_t at = 64;
		for (int twice = 0; twice < 2; ++twice) {
			writeLittleEndian<uint16_t>(s + at, (uint16_t)(machine.size() * 2));
			at += 2;
			for (char16_t c : machine) { writeLittleEndian<uint16_t>(s + at, (uint16_t)c); at += 2; }
		}
	}
	ShadowCopies open(std::wstring& diagnostic, bool& ok) {
		ShadowCopies copies;
		ok = copies.open([this](uint64_t offset, uint8_t* out, size_t size) {
			if (offset + size > bytes.size()) return false;
			std::memcpy(out, bytes.data() + offset, size);
			return true;
		}, bytes.size(), diagnostic);
		return copies;
	}
};

/*! Builds the volume: current blocks 0x10 + index; the older copy (store 0,
 *  created at time 100) and the newer one (store 1, time 200), its catalog
 *  giving the newer first. */
Volume buildVolume() {
	Volume v;
	for (uint64_t i = 8; i < 64; ++i) v.fill(i, (uint8_t)(0x10 + i));
	// Store data: what the blocks held before.
	v.fill(40, 0xA0);   // block 10 as the older copy saw it
	v.fill(42, 0xA2);   // block 12's sector 3, older copy (overlay)
	v.fill(43, 0xA3);   // block 21 as the newer copy saw it, block 20 as the older one did
	v.fill(44, 0xA4);   // block 30 as both copies saw it
	v.fill(45, 0xA5);   // block 26 as the older copy saw it
	v.fill(46, 0xA6);   // block 33's first sector, newer copy (overlay)

	// Volume header at 0x1E00 of block 0: catalog in block 1.
	uint8_t* vh = v.bytes.data() + 0x1E00;
	std::memcpy(vh, VSS_ID, 16);
	writeLittleEndian<uint32_t>(vh + 16, 1);
	writeLittleEndian<uint32_t>(vh + 20, 1);
	writeLittleEndian<uint64_t>(vh + 48, 1 * B);

	v.header(1, 2, 0);
	struct Entry { uint8_t id; uint64_t time, headerBlock, listBlock, bitmapBlock; };
	const Entry entries[2] = { { 0x22, 200, 5, 6, 7 }, { 0x11, 100, 2, 3, 4 } };   // newer first
	size_t at = 128;
	for (const Entry& e : entries) {
		uint8_t* two = v.bytes.data() + B + at;
		writeLittleEndian<uint64_t>(two, 2);
		writeLittleEndian<uint64_t>(two + 8, v.bytes.size());
		std::memset(two + 16, e.id, 16);
		writeLittleEndian<uint64_t>(two + 40, e.id == 0x11 ? 0x140 : 0x40);   // the older one deleted
		writeLittleEndian<uint64_t>(two + 48, e.time);
		uint8_t* three = two + 128;
		writeLittleEndian<uint64_t>(three, 3);
		writeLittleEndian<uint64_t>(three + 8, e.listBlock * B);
		std::memset(three + 16, e.id, 16);
		writeLittleEndian<uint64_t>(three + 32, e.headerBlock * B);
		writeLittleEndian<uint64_t>(three + 48, e.bitmapBlock * B);
		at += 256;
	}
	v.storeHeader(2, 0x31, u"OLD");
	v.storeHeader(5, 0x41, u"NEW");

	// Older store: block 10 kept; block 20 forwarded to the newer store's
	// block 21; block 12's sector 3 as an overlay; block 25 ignored; a
	// forwarder 26 -> 27 that a later descriptor of 27 takes over.
	v.header(3, 3, 0);
	v.descriptor(3, 0, 10 * B, 0, 40 * B, 0);
	v.descriptor(3, 1, 20 * B, 21 * B, 0, 0x1);
	v.descriptor(3, 2, 12 * B, 1, 42 * B, 0x2, 1u << 3);
	v.descriptor(3, 3, 25 * B, 0, 41 * B, 0x4);
	v.descriptor(3, 4, 26 * B, 27 * B, 0, 0x1);
	v.descriptor(3, 5, 27 * B, 2 * B, 45 * B, 0);
	v.header(4, 6, 0);   // bitmap: every block used

	// Newer store: blocks 21 and 30 kept; block 50 unused by its copy.
	v.header(6, 3, 0);
	v.descriptor(6, 0, 21 * B, 0, 43 * B, 0);
	v.descriptor(6, 1, 30 * B, B, 44 * B, 0);
	v.descriptor(6, 2, 33 * B, 1, 46 * B, 0x2, 1u);
	v.header(7, 6, 0);
	v.bytes[7 * B + 128 + 50 / 8] = (uint8_t)(1u << (50 % 8));
	return v;
}

//! True when `size` bytes of copy `index` at `offset` all equal `value`.
bool reads(ShadowCopies& copies, size_t index, uint64_t offset, size_t size, uint8_t value) {
	std::vector<uint8_t> out(size, 0x55);
	if (!copies.read(index, offset, out.data(), size)) return false;
	for (uint8_t b : out) if (b != value) return false;
	return true;
}

void syntheticChecks() {
	Volume v = buildVolume();
	std::wstring diagnostic;
	bool ok = false;
	ShadowCopies copies = v.open(diagnostic, ok);
	check(ok && copies.copies().size() == 2, "the two copies are read");
	if (copies.copies().size() != 2) return;
	const ShadowCopyInfo& older = copies.copies()[0];
	const ShadowCopyInfo& newer = copies.copies()[1];
	check(older.creationTime == 100 && newer.creationTime == 200, "the copies are listed oldest first");
	check(older.storeId[0] == 0x11 && older.copyId[0] == 0x31 && older.copySetId[0] == 0x32, "the older copy's identifiers");
	check(older.operatingMachine == L"OLD" && older.serviceMachine == L"OLD" && newer.operatingMachine == L"NEW",
	      "the machine names");
	check(older.context == 0x9 && older.attributes == 0x2001D, "the context and attributes");
	check(older.deleted && !newer.deleted, "a copy deleted, its store kept (flag 0x100), told from the others");
	check(older.storedBlocks == 2 && newer.storedBlocks == 2, "the blocks each store holds (forwarders, overlays, ignored apart)");

	// Older copy.
	check(reads(copies, 0, 10 * B, B, 0xA0), "older copy: its store's block");
	check(reads(copies, 0, 20 * B, B, 0xA3), "older copy: a forwarder read in the newer store, at the block it names");
	check(reads(copies, 0, 26 * B, B, 0xA5) && reads(copies, 0, 27 * B, B, 0x10 + 27),
	      "older copy: a forwarder taken over by the descriptor of the block it named");
	check(reads(copies, 0, 30 * B, B, 0xA4), "older copy: a block only the newer store holds");
	check(reads(copies, 0, 12 * B + 3 * 512, 512, 0xA2), "older copy: the overlay's sector");
	check(reads(copies, 0, 12 * B, 3 * 512, 0x10 + 12) && reads(copies, 0, 12 * B + 4 * 512, B - 4 * 512, 0x10 + 12),
	      "older copy: the sectors around the overlay, from the volume");
	check(reads(copies, 0, 25 * B, B, 0x10 + 25), "older copy: an ignored descriptor, read from the volume");
	check(reads(copies, 0, 50 * B, B, 0x10 + 50), "older copy: a block the newer copy did not use, from the volume");
	// Newer copy.
	check(reads(copies, 1, 10 * B, B, 0x10 + 10), "newer copy: a block only the older store holds, from the volume");
	check(reads(copies, 1, 12 * B, B, 0x10 + 12), "newer copy: the older copy's overlay does not apply");
	check(reads(copies, 1, 21 * B, B, 0xA3) && reads(copies, 1, 30 * B, B, 0xA4), "newer copy: its store's blocks");
	check(reads(copies, 1, 20 * B, B, 0x10 + 20), "newer copy: the older store's forwarder does not apply");
	check(reads(copies, 1, 33 * B, 512, 0xA6), "newer copy: its overlay's sector");
	check(reads(copies, 0, 33 * B, 512, 0x10 + 33), "older copy: the newer copy's overlay, crossed, does not apply");
	check(reads(copies, 1, 50 * B, B, 0x00), "newer copy: a block it did not use reads as zeros");
	// A read across blocks, not aligned.
	std::vector<uint8_t> across(2 * B);
	check(copies.read(0, 9 * B + 100, across.data(), across.size()) && across[0] == 0x10 + 9
	      && across[B - 100] == 0xA0 && across[2 * B - 101] == 0xA0 && across[2 * B - 1] == 0x10 + 11,
	      "a read across three blocks, from an unaligned offset");
	check(!copies.read(0, v.bytes.size() - 10, across.data(), 20), "a read past the volume is refused");
	check(!copies.read(2, 0, across.data(), 1), "an index past the copies is refused");

	/* Windows writes block 35 after the lists were read: its earlier content
	   goes to the newer store, the volume holds the new one. Before a
	   refresh, the copies read the new content; after it, the earlier one,
	   and the older store's blocks are still there. */
	v.fill(47, 0xA7);
	v.descriptor(6, 3, 35 * B, 3 * B, 47 * B, 0);
	v.fill(35, 0xEE);
	check(reads(copies, 1, 35 * B, B, 0xEE), "before a refresh, a block copied since is read from the volume");
	check(copies.refresh(diagnostic), "the refresh reads the catalog and the most recent store again");
	check(reads(copies, 1, 35 * B, B, 0xA7) && reads(copies, 0, 35 * B, B, 0xA7),
	      "after it, both copies read the block's earlier content");
	check(reads(copies, 0, 10 * B, B, 0xA0) && reads(copies, 0, 20 * B, B, 0xA3),
	      "the older store's blocks are kept by the refresh");

	// A catalog whose chain loops.
	Volume looping = buildVolume();
	writeLittleEndian<uint64_t>(looping.bytes.data() + B + 40, B);
	ShadowCopies refused = looping.open(diagnostic, ok);
	check(!ok && diagnostic.find(L"loops") != std::wstring::npos, "a catalog chain that loops is refused");

	// No VSS header: no copy, and said so.
	Volume none;
	ShadowCopies empty = none.open(diagnostic, ok);
	check(ok && empty.copies().empty() && diagnostic.find(L"no VSS header") != std::wstring::npos, "a volume without copies");
}

//! A GUID's 16 bytes as Windows writes it.
std::string guidText(const std::array<uint8_t, 16>& g) {
	char text[40];
	std::snprintf(text, sizeof text, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	              readLittleEndian<uint32_t>(g.data()), readLittleEndian<uint16_t>(g.data() + 4),
	              readLittleEndian<uint16_t>(g.data() + 6), g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
	return text;
}

/*! Lists the copies of a volume image and the SHA-256 of each copy's
 *  whole volume. @return 0, or 1 if the image could not be read */
int imageMode(const wchar_t* path) {
	std::ifstream image(path, std::ios::binary);
	if (!image) { std::printf("cannot open the image\n"); return 1; }
	image.seekg(0, std::ios::end);
	const uint64_t size = (uint64_t)image.tellg();
	ShadowCopies copies;
	std::wstring diagnostic;
	const bool ok = copies.open([&image](uint64_t offset, uint8_t* out, size_t count) {
		image.clear();
		image.seekg((std::streamoff)offset);
		return (bool)image.read(reinterpret_cast<char*>(out), (std::streamsize)count);
	}, size, diagnostic);
	std::printf("%s: %ls\n", ok ? "read" : "FAILED", diagnostic.c_str());
	if (!ok) return 1;
	std::vector<uint8_t> chunk(64 * ShadowCopies::BLOCK);
	for (size_t i = 0; i < copies.copies().size(); ++i) {
		const ShadowCopyInfo& c = copies.copies()[i];
		const uint64_t volume = std::min<uint64_t>(c.volumeSize, size);
		Sha256Stream digest;
		bool readable = true;
		for (uint64_t at = 0; at < volume && readable; at += chunk.size()) {
			const size_t n = (size_t)std::min<uint64_t>(chunk.size(), volume - at);
			readable = copies.read(i, at, chunk.data(), n);
			digest.update(chunk.data(), n);
		}
		std::printf("%zu|%s|%s|%s|%llu|%llu|0x%x|0x%x|%ls|%ls|%llu|%ls\n", i, guidText(c.storeId).c_str(),
		            guidText(c.copyId).c_str(), guidText(c.copySetId).c_str(), (unsigned long long)c.creationTime,
		            (unsigned long long)c.volumeSize, c.context, c.attributes, c.operatingMachine.c_str(),
		            c.serviceMachine.c_str(), (unsigned long long)c.storedBlocks,
		            readable ? digest.hexDigest().c_str() : L"UNREADABLE");
	}
	return 0;
}

} // namespace

/*! Runs the checks, or lists an image's copies.
 *  @param argc,argv nothing, or the path of a volume image
 *  @return 0 if every check passed */
int wmain(int argc, wchar_t** argv) {
	if (argc > 1) return imageMode(argv[1]);
	syntheticChecks();
	std::printf("%u check(s), %u failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
