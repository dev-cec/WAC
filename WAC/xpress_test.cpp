/*  xpress_test.cpp — confronte la decompression XPRESS Huffman au compresseur
 *  de Windows lui-meme.
 *
 *  `RtlCompressBuffer` de ntdll comprime un fichier connu, morceau par morceau,
 *  et ce test detend ici et compare OCTET POUR OCTET. Un decompresseur faux
 *  produit le plus souvent des donnees fausses SANS lever d'erreur — d'ou la
 *  comparaison exhaustive plutot qu'un controle de taille.
 *
 *  Usage : xpress_test <original> <compresse.bin> <index.idx>
 *    index.idx : une ligne « <n> <taille_origine> <taille_compressee> » par
 *    morceau, dans l'ordre ; taille compressee nulle = morceau que Windows a
 *    renonce a comprimer (stocke tel quel).
 *
 *  Exclu du build de WAC par le motif « _test.cpp ».
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
	const std::vector<uint8_t> compresse((std::istreambuf_iterator<char>(fc)),
	                                      std::istreambuf_iterator<char>());

	size_t posC = 0, posO = 0;
	int morceaux = 0, conformes = 0, ignores = 0;
	unsigned long long octets = 0;
	std::string ligne;
	int n; size_t tailleO, tailleC;

	while (std::getline(fi, ligne)) {
		if (ligne.empty()) continue;
		if (std::sscanf(ligne.c_str(), "%d %zu %zu", &n, &tailleO, &tailleC) != 3) continue;
		if (tailleC == 0) { ++ignores; posO += tailleO; continue; }
		++morceaux;
		if (posC + tailleC > compresse.size()) {
			std::cout << "  ECHEC  morceau " << n << " : donnees tronquees\n";
			return 1;
		}

		std::vector<uint8_t> sortie(tailleO, 0xCC);       // motif temoin
		const size_t rendu = XpressHuffmanDetendre(compresse.data() + posC, tailleC,
		                                           sortie.data(), sortie.size());
		const bool tailleOk = (rendu == tailleO);
		const bool contenuOk = tailleOk && posO + tailleO <= original.size()
		                     && std::memcmp(sortie.data(), original.data() + posO, tailleO) == 0;
		if (contenuOk) ++conformes;
		else {
			std::cout << "  ECHEC  morceau " << n << " : rendu " << rendu
			          << " attendu " << tailleO;
			if (tailleOk) {
				size_t k = 0;
				while (k < tailleO && sortie[k] == original[posO + k]) ++k;
				std::cout << ", premier ecart a l'offset " << k;
			}
			std::cout << "\n";
		}
		octets += rendu;
		posC += tailleC;
		posO += tailleO;
	}

	std::cout << "  morceaux comprimes : " << morceaux << ", conformes : " << conformes
	          << ", non comprimes par Windows : " << ignores << "\n";
	std::cout << "  octets detendus : " << octets << "\n";
	const bool ok = (morceaux > 0) && (conformes == morceaux);
	std::cout << (ok ? "tous conformes" : "ECHECS") << "\n";
	return ok ? 0 : 1;
}
