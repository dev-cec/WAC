/*  lznt1_test.cpp — confronte la decompression LZNT1 au compresseur de Windows.
 *
 *  Le juge est `RtlCompressBuffer` de ntdll : on lui done compresser un file
 *  known, unit de compression par unit de compression, puis on detend ici et
 *  on compare byte pour byte. Un decompresseur wrong se decode le plus souvent
 *  SANS error et rend des data fausses — d'ou la comparaison exhaustive
 *  plutot qu'un simple controle de size.
 *
 *  Usage : lznt1_test <original> <compressed.bin> <index.idx>
 *    index.idx : une line « <n> <taille_origine> <taille_compressee> » par
 *    unit, dans l'ordre ; une size compressee nulle signale une unit que
 *    Windows a renoncee a compresser (elle est alors stockee telle quelle).
 *
 *  Exclu du build de WAC par le reason « _test.cpp ».
 *  Compilation native : g++ -std=c++17 -I. lznt1.cpp lznt1_test.cpp -o lznt1_test
 */
#include "lznt1.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

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
			// Unite que Windows n'a pas compressee : NTFS la stocke telle quelle.
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
