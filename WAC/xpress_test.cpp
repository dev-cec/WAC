/*! \file
 *  \brief Confronts the XPRESS Huffman decompression with Windows's own
 *  compressor.
 *
 *  ntdll's `RtlCompressBuffer` compresses a known file, chunk by chunk, and this
 *  test decompresses here and compares BYTE FOR BYTE. A wrong decompressor most
 *  often produces wrong data WITHOUT raising an error — hence the exhaustive
 *  comparison rather than a size check.
 *
 *  Usage: xpress_test `<original>` `<compressed.bin>` `<index.idx>`
 *    index.idx: one line "<n> <original_size> <compressed_size>" per chunk, in
 *    order; a null compressed size = a chunk Windows gave up compressing (stored
 *    as it is).
 *
 *  Excluded from WAC's build by the "_test.cpp" pattern.
 *  Native build: g++ -std=c++17 -I. xpress.cpp xpress_test.cpp -o xpress_test
 */
#include "xpress.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

/*! Runs the test.
 * @param argc,argv `<original>` `<compressed.bin>` `<index.idx>`
 * @return 0 if every check passed */
int main(int argc, char** argv) {
	if (argc < 4) {
		std::cout << "usage: xpress_test <original> <compressed.bin> <index.idx>\n";
		return 2;
	}
	std::ifstream fo(argv[1], std::ios::binary), fc(argv[2], std::ios::binary);
	std::ifstream fi(argv[3]);
	if (!fo || !fc || !fi) { std::cout << "file(s) unreadable\n"; return 2; }

	const std::vector<uint8_t> original((std::istreambuf_iterator<char>(fo)),
	                                     std::istreambuf_iterator<char>());
	const std::vector<uint8_t> compressed((std::istreambuf_iterator<char>(fc)),
	                                      std::istreambuf_iterator<char>());

	size_t posC = 0, posO = 0;
	int chunks = 0, wellFormed = 0, ignores = 0;
	unsigned long long bytes = 0;
	std::string line;
	int n; size_t plainSize, packedSize;

	while (std::getline(fi, line)) {
		if (line.empty()) continue;
		if (std::sscanf(line.c_str(), "%d %zu %zu", &n, &plainSize, &packedSize) != 3) continue;
		if (packedSize == 0) { ++ignores; posO += plainSize; continue; }
		++chunks;
		if (posC + packedSize > compressed.size()) {
			std::cout << "  FAILED  chunk " << n << ": data truncated\n";
			return 1;
		}

		std::vector<uint8_t> output(plainSize, 0xCC);       // witness pattern
		const size_t returned = XpressHuffmanInflate(compressed.data() + posC, packedSize,
		                                           output.data(), output.size());
		const bool sizeOk = (returned == plainSize);
		const bool contentOk = sizeOk && posO + plainSize <= original.size()
		                     && std::memcmp(output.data(), original.data() + posO, plainSize) == 0;
		if (contentOk) ++wellFormed;
		else {
			std::cout << "  FAILED  chunk " << n << ": returned " << returned
			          << " expected " << plainSize;
			if (sizeOk) {
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

	std::cout << "  compressed chunks: " << chunks << ", passed: " << wellFormed
	          << ", left uncompressed by Windows: " << ignores << "\n";
	std::cout << "  bytes decompressed: " << bytes << "\n";
	const bool ok = (chunks > 0) && (wellFormed == chunks);
	std::cout << (ok ? "all passed" : "FAILURES") << "\n";
	return ok ? 0 : 1;
}
