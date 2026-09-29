/*! \file
 *  \brief Confronts the LZNT1 decompression with Windows's own compressor.
 *
 *  The judge is ntdll's `RtlCompressBuffer`: it is given a known file to
 *  compress, compression unit by compression unit, then the units are
 *  decompressed here and compared byte for byte. A wrong decompressor most often
 *  decodes WITHOUT an error and returns wrong data — hence the exhaustive
 *  comparison rather than a mere size check.
 *
 *  Usage: lznt1_test `<original>` `<compressed.bin>` `<index.idx>`
 *    index.idx: one line "<n> <original_size> <compressed_size>" per unit, in
 *    order; a null compressed size signals a unit Windows gave up compressing
 *    (it is then stored as it is).
 *
 *  Excluded from WAC's build by the "_test.cpp" pattern.
 *  Native build: g++ -std=c++17 -I. lznt1.cpp lznt1_test.cpp -o lznt1_test
 */
#include "lznt1.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

/*! Runs the test.
 * @param argc,argv `<original>` `<compressed.bin>` `<index.idx>`
 * @return 0 if every check passed */
int main(int argc, char** argv){
	if (argc < 4){
		std::cout << "usage: lznt1_test <original> <compressed.bin> <index.idx>\n";
		return 2;
	}
	std::ifstream fo(argv[1], std::ios::binary), fc(argv[2], std::ios::binary);
	std::ifstream fi(argv[3]);
	if (!fo || !fc || !fi){ std::cout << "file(s) unreadable\n"; return 2; }

	const std::vector<uint8_t> original((std::istreambuf_iterator<char>(fo)),
	                                     std::istreambuf_iterator<char>());
	const std::vector<uint8_t> compressed((std::istreambuf_iterator<char>(fc)),
	                                      std::istreambuf_iterator<char>());

	size_t posC = 0, posO = 0;
	int units = 0, wellFormed = 0, ignored = 0;
	unsigned long long bytes = 0;
	int n; size_t plainSize, packedSize;
	std::string line;
	while (std::getline(fi, line)){
		if (line.empty()) continue;
		if (std::sscanf(line.c_str(), "%d %zu %zu", &n, &plainSize, &packedSize) != 3) continue;
		if (packedSize == 0){
			// A unit Windows did not compress: NTFS stores it as it is.
			++ignored;
			posO += plainSize;
			continue;
		}
		++units;
		if (posC + packedSize > compressed.size()){ std::cout << "  FAILED  unit " << n
			<< ": compressed data truncated\n"; return 1; }

		std::vector<uint8_t> output(65536, 0xCC);   // witness pattern
		const size_t returned = Lznt1Inflate(compressed.data() + posC, packedSize,
		                                   output.data(), output.size());
		const bool sizeOk = (returned == plainSize);
		const bool contentOk = sizeOk && posO + plainSize <= original.size()
		                     && std::memcmp(output.data(), original.data() + posO, plainSize) == 0;
		if (contentOk) ++wellFormed;
		else {
			std::cout << "  FAILED  unit " << n << ": returned " << returned
			          << " expected " << plainSize;
			if (sizeOk){
				// First diverging byte: says WHERE the decoding went wrong.
				size_t k = 0;
				while (k < plainSize && output[k] == original[posO + k]) ++k;
				std::cout << ", first divergence at offset " << k;
			}
			std::cout << "\n";
		}
		bytes += returned;
		posC += packedSize;
		posO += plainSize;
	}
	std::cout << "  compressed units: " << units << ", passed: " << wellFormed
	          << ", left uncompressed by Windows: " << ignored << "\n";
	std::cout << "  bytes decompressed: " << bytes << "\n";
	const bool ok = (units > 0) && (wellFormed == units);
	std::cout << (ok ? "all passed" : "FAILURES") << "\n";
	return ok ? 0 : 1;
}
