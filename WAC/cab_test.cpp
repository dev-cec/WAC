/*! \file
 *  \brief Confronts the cabinet extraction with cabextract, then with
 *  damaged cabinets.
 *
 *  WHY THIS TEST. --update-trust takes Microsoft's trust lists out of their
 *  cabinets: a wrong extraction would hand a wrong list to the signature
 *  check. Each cabinet given must extract into the files cabextract wrote
 *  (an independent implementation) byte for byte; the same cabinet truncated
 *  and damaged at random (fixed seed) must never make the extraction read out
 *  of bounds — built with AddressSanitizer and UBSan.
 *
 *  Usage: cab_test `<cabinet>` `<folder cabextract extracted it to>` ...
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. inflate.cpp cab.cpp cab_test.cpp -o cab_test
 */
#include "cab.h"
#include <cstdio>
#include <fstream>
#include <random>
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
 * @param argc,argv pairs `<cabinet>` `<cabextract's folder>`
 * @return 0 if all passed */
int main(int argc, char** argv) {
	if (argc < 3 || (argc - 1) % 2) { std::printf("usage: cab_test <cabinet> <cabextract folder> ...\n"); return 2; }
	std::mt19937_64 rng(20260926);
	for (int a = 1; a + 1 < argc; a += 2) {
		const std::vector<uint8_t> cab = readAll(argv[a]);
		std::vector<CabFile> files;
		std::string reason;
		check(CabExtract(cab, files, reason), std::string(argv[a]) + ": refused: " + reason);
		for (const CabFile& f : files)
			check(f.content == readAll(std::string(argv[a + 1]) + "/" + f.name),
			      std::string(argv[a]) + ": " + f.name + " differs from cabextract's");
		check(!files.empty(), std::string(argv[a]) + ": no file");
		for (size_t cut = 0; cut < cab.size(); cut += 1 + cab.size() / 64) {
			std::vector<uint8_t> truncated(cab.begin(), cab.begin() + (long)cut);
			std::vector<CabFile> out;
			CabExtract(truncated, out, reason);
			++g_checks;
		}
		for (int m = 0; m < 500; ++m) {
			std::vector<uint8_t> damaged = cab;
			const int edits = 1 + (int)(rng() % 6);
			for (int k = 0; k < edits; ++k) damaged[rng() % damaged.size()] = (uint8_t)rng();
			std::vector<CabFile> out;
			CabExtract(damaged, out, reason);
			++g_checks;
		}
	}
	std::printf("%d cabinet(s); %s: %llu check(s), %llu failure(s)\n", (argc - 1) / 2,
	            g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
