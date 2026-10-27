/*! \file
 *  \brief Checks the FAT and exFAT reader: the 8.3 checksum on a known name,
 *  hostile boot sectors and chains — and, given volume images, lists their
 *  entries (deleted included) for a comparison with an independent reader
 *  (vmtest/lib/fat-compare.py, dissect.fat) and with what Windows wrote.
 *
 *  Usage (runs under wine): fat_test.exe [image…]
 */
#include "fat_volume.h"
#include <cstdio>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const char* what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::fprintf(stderr, "  FAILED  %s\n", what);
}

//! A volume in memory.
class MemorySource : public VolumeSource {
public:
	explicit MemorySource(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}
	bool read(uint64_t offset, size_t size, std::vector<uint8_t>& out) override {
		if (offset > bytes_.size() || size > bytes_.size() - offset) return false;
		out.assign(bytes_.begin() + (size_t)offset, bytes_.begin() + (size_t)offset + size);
		return true;
	}
	uint64_t size() const override { return bytes_.size(); }
private:
	std::vector<uint8_t> bytes_;
};

//! The checksum on a name whose value the FAT specification's algorithm gives; hostile boot sectors.
void synthetic() {
	const uint8_t name[11] = { 'F', 'O', 'O', ' ', ' ', ' ', ' ', ' ', 'B', 'A', 'R' };
	uint8_t expected = 0;
	for (uint8_t c : name) expected = (uint8_t)(((expected & 1) ? 0x80 : 0) + (expected >> 1) + c);
	check(fatShortNameChecksum(name) == expected, "8.3 checksum");
	// A boot sector without its signature, then one whose FAT exceeds the volume.
	std::vector<uint8_t> volume(64 * 1024, 0);
	FatVolume none;
	MemorySource empty(volume);
	check(!none.open(empty), "boot sector without signature accepted");
	volume[510] = 0x55; volume[511] = 0xAA;
	volume[11] = 0x00; volume[12] = 0x02; volume[13] = 1; volume[14] = 1; volume[16] = 2;
	volume[17] = 0x10; volume[19] = 0x80; volume[22] = 0xFF; volume[23] = 0x7F;   // a FAT of 32767 sectors
	FatVolume lying;
	MemorySource hostile(volume);
	check(!lying.open(hostile), "FAT beyond the volume accepted");

	// FAT12: 512-byte sectors and clusters, one FAT sector, a 16-entry root.
	// Folder LOOP starts at cluster 2, whose chain goes 2 → 3 → 2: it must end.
	std::vector<uint8_t> image(200 * 512, 0);
	const uint8_t boot[] = { 0xEB, 0x3C, 0x90, 'M', 'S', 'D', 'O', 'S', '5', '.', '0', 0x00, 0x02, 1, 1, 0, 1, 16, 0, 200, 0, 0xF8, 1, 0 };
	std::copy(std::begin(boot), std::end(boot), image.begin());
	image[510] = 0x55; image[511] = 0xAA;
	uint8_t* fat = image.data() + 512;
	fat[0] = 0xF8; fat[1] = 0xFF; fat[2] = 0xFF;          // clusters 0 and 1 reserved
	fat[3] = 0x03; fat[4] = 0x20; fat[5] = 0x00;          // cluster 2 → 3, cluster 3 → 2
	uint8_t* root = image.data() + 1024;
	const char loop[11] = { 'L', 'O', 'O', 'P', ' ', ' ', ' ', ' ', ' ', ' ', ' ' };
	std::copy(loop, loop + 11, root);
	root[11] = 0x10; root[26] = 2;                        // a folder, first cluster 2
	for (uint32_t cluster : { 2u, 3u }) {                 // each cluster: "." then a file
		uint8_t* d = image.data() + 1536 + (cluster - 2) * 512;
		std::fill(d, d + 11, (uint8_t)' '); d[0] = '.'; d[11] = 0x10; d[26] = (uint8_t)cluster;
		const char file[11] = { 'F', 'I', 'L', 'E', (char)('0' + cluster), ' ', ' ', ' ', 'T', 'X', 'T' };
		std::copy(file, file + 11, d + 32); d[32 + 28] = 1;
	}
	MemorySource looping(image);
	FatVolume cyclic;
	check(cyclic.open(looping) && cyclic.type() == L"FAT12", "FAT12 volume not opened");
	const std::vector<FatEntry> found = cyclic.entries();
	// The first cluster ends the directory (a zero entry after FILE2): what matters is that the loop ends.
	check(found.size() == 2 && found[0].path == L"\\LOOP" && found[1].path == L"\\LOOP\\FILE2.TXT",
	      "a looping FAT chain ends");

	/* A present file whose name's first byte is really 0xE5, stored 0x05 as
	   FAT wants, beside a deleted one (0xE5 written over its first byte): only
	   the second is deleted, and only it loses its first letter. */
	std::vector<uint8_t> named = image;
	uint8_t* entries = named.data() + 1024;
	std::fill(entries, entries + 64, (uint8_t)0);
	const char present[11] = { 0x05, 'B', 'C', ' ', ' ', ' ', ' ', ' ', 'T', 'X', 'T' };
	const char removed[11] = { (char)0xE5, 'E', 'L', ' ', ' ', ' ', ' ', ' ', 'T', 'X', 'T' };
	std::copy(present, present + 11, entries);
	std::copy(removed, removed + 11, entries + 32);
	MemorySource twoNames(named);
	FatVolume e5;
	const std::vector<FatEntry> e5found = e5.open(twoNames) ? e5.entries() : std::vector<FatEntry>();
	check(e5found.size() == 2 && !e5found[0].deleted && !e5found[0].nameIncomplete && e5found[0].shortName.size() == 7
	      && e5found[0].shortName[0] != L'_' && e5found[0].shortName.compare(1, 6, L"BC.TXT") == 0,
	      "a present name starting with 0xE5 (stored 0x05) is not taken for a deleted one");
	check(e5found.size() == 2 && e5found[1].deleted && e5found[1].nameIncomplete && e5found[1].shortName == L"_EL.TXT",
	      "a deleted name loses its first letter, said incomplete");
}

//! Lists an image: one line per entry, "path|size|deleted|directory|modified|utc or local|name incomplete".
void list(const wchar_t* path) {
	FileVolumeSource source(path);
	FatVolume volume;
	check(source.isOpen() && volume.open(source), "image not opened");
	const std::vector<FatEntry> entries = volume.entries();   // the label is in the root: read first
	// The copy a collection writes must give back the same entries, from its bytes alone.
	const std::wstring copy = std::wstring(path) + L".copy";
	{
		const std::string bytes = volumeCopyBytes(source);
		FILE* f = _wfopen(copy.c_str(), L"wb");
		if (f) { fwrite(bytes.data(), 1, bytes.size(), f); fclose(f); }
	}
	CopiedVolumeSource copied;
	FatVolume again;
	check(copied.load(copy) && again.open(copied), "metadata copy not read back");
	const std::vector<FatEntry> fromCopy = again.entries();
	bool same = fromCopy.size() == entries.size();
	for (size_t i = 0; same && i < entries.size(); ++i) same = fromCopy[i].path == entries[i].path && fromCopy[i].size == entries[i].size;
	check(same, "metadata copy: other entries than the volume's");
	_wremove(copy.c_str());
	std::printf("# %s %s\n", encodeText(volume.type()).c_str(), encodeText(volume.label()).c_str());
	for (const FatEntry& e : entries) {
		std::printf("%s|%llu|%d|%d|%s|%s|%d\n", encodeText(e.path).c_str(), (unsigned long long)e.size, e.deleted ? 1 : 0,
		            e.directory ? 1 : 0, encodeText(timeToIso8601Utc(e.modified)).c_str(), e.modifiedUtc ? "utc" : "local", e.nameIncomplete ? 1 : 0);
	}
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	synthetic();
	for (int i = 1; i < argc; ++i) list(argv[i]);
	std::fprintf(stderr, "%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
