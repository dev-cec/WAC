/*! \file
 *  \brief Confronts the ZIP extraction with Python's zipfile, then with
 *  damaged archives.
 *
 *  WHY THIS TEST. --update-trust takes Microsoft's blocklist of vulnerable
 *  drivers out of a ZIP archive: a wrong extraction would hand a wrong list
 *  to the check of the drivers. Each archive given must extract into the
 *  files an independent implementation wrote, byte for byte; the same archive
 *  truncated and damaged at random (fixed seed) must never make the
 *  extraction read out of bounds — built with AddressSanitizer and UBSan —
 *  and a damaged content must be refused by its CRC-32, never returned.
 *
 *  Usage: zip_test `<archive>` `<folder another tool extracted it to>` ...
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. inflate.cpp zip.cpp zip_test.cpp -o zip_test
 */
#include "zip.h"
#include <cstdio>
#include <fstream>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

std::vector<uint8_t> readAll(const std::string& path) {
	std::ifstream f(path, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

} // namespace

/*! Runs every check.
 * @param argc,argv pairs `<archive>` `<reference extraction folder>`
 * @return 0 if all passed */
int main(int argc, char** argv) {
	if (argc < 3 || (argc - 1) % 2) { std::printf("usage: zip_test <archive> <extracted folder> ...\n"); return 2; }
	std::mt19937_64 rng(20260926);
	for (int a = 1; a + 1 < argc; a += 2) {
		const std::vector<uint8_t> zip = readAll(argv[a]);
		std::vector<ArchiveFile> files;
		std::string reason;
		check(ZipExtract(zip, files, reason), std::string(argv[a]) + ": refused: " + reason);
		for (const ArchiveFile& f : files)
			check(f.content == readAll(std::string(argv[a + 1]) + "/" + f.name),
			      std::string(argv[a]) + ": " + f.name + " differs from the reference extraction");
		check(!files.empty(), std::string(argv[a]) + ": no file");
		std::set<std::vector<uint8_t>> held;
		for (const ArchiveFile& f : files) held.insert(f.content);
		for (size_t cut = 0; cut < zip.size(); cut += 1 + zip.size() / 64) {
			std::vector<uint8_t> truncated(zip.begin(), zip.begin() + (long)cut);
			std::vector<ArchiveFile> out;
			check(!ZipExtract(truncated, out, reason), std::string(argv[a]) + ": truncated at "
			      + std::to_string(cut) + " still extracted");
		}
		for (int m = 0; m < 500; ++m) {
			std::vector<uint8_t> damaged = zip;
			const int edits = 1 + (int)(rng() % 6);
			for (int k = 0; k < edits; ++k) damaged[rng() % damaged.size()] = (uint8_t)rng();
			std::vector<ArchiveFile> out;
			/* Whatever is returned is a content the archive held — a damaged
			   content is refused by its CRC-32; a damaged NAME may go unseen,
			   ZIP does not protect it. */
			if (ZipExtract(damaged, out, reason))
				for (const ArchiveFile& f : out)
					check(held.count(f.content) == 1, std::string(argv[a]) + ": damaged, " + f.name + " returned altered");
			else ++g_checks;
		}
	}
	check(Crc32((const uint8_t*)"123456789", 9) == 0xCBF43926u, "CRC-32 check value");
	std::printf("%d archive(s); %s: %llu check(s), %llu failure(s)\n", (argc - 1) / 2,
	            g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
