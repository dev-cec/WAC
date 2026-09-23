/*  xpress_test.cpp — confronte la decompression XPRESS Huffman au compresseur
 *  de Windows lui-meme.
 *
 *  `RtlCompressBuffer` de ntdll comprime un file known, chunk par chunk,
 *  et ce test detend ici et compare OCTET POUR OCTET. Un decompresseur wrong
 *  product le plus souvent des data fausses SANS lever d'error — d'ou la
 *  comparaison exhaustive plutot qu'un controle de size.
 *
 *  Usage : xpress_test <original> <compressed.bin> <index.idx>
 *    index.idx : une line « <n> <taille_origine> <taille_compressee> » par
 *    chunk, dans l'ordre ; size compressee nulle = chunk que Windows a
 *    renonce a compress (stocke tel quel).
 *
 *  Exclu du build de WAC par le reason « _test.cpp ».
 *  Compilation native : g++ -std=c++17 -I. xpress.cpp xpress_test.cpp -o xpress_test
 */
#include "xpress.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
	if (argc < 4) {
		std::cout << "usage: xpress_test <original> <compresse.bin> <index.idx>\n";
		return 2;
	}
	std::ifstream fo(argv[1], std::ios::binary), fc(argv[2], std::ios::binary);
	std::ifstream fi(argv[3]);
	if (!fo || !fc || !fi) { std::cout << "fichier(s) illisible(s)\n"; return 2; }

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
			std::cout << "  ECHEC  morceau " << n << " : donnees tronquees\n";
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
			std::cout << "  ECHEC  morceau " << n << " : rendu " << returned
			          << " attendu " << plainSize;
			if (sizeOk) {
				size_t k = 0;
				while (k < plainSize && output[k] == original[posO + k]) ++k;
				std::cout << ", premier ecart a l'offset " << k;
			}
			std::cout << "\n";
		}
		bytes += returned;
		posC += packedSize;
		posO += plainSize;
	}

	std::cout << "  morceaux comprimes : " << chunks << ", conformes : " << wellFormed
	          << ", non comprimes par Windows : " << ignores << "\n";
	std::cout << "  octets detendus : " << bytes << "\n";
	const bool ok = (chunks > 0) && (wellFormed == chunks);
	std::cout << (ok ? "tous conformes" : "ECHECS") << "\n";
	return ok ? 0 : 1;
}
