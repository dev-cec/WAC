/*  lznt1_test.cpp — confronte la decompression LZNT1 au compresseur de Windows.
 *
 *  Le juge est `RtlCompressBuffer` de ntdll : on lui fait compresser un fichier
 *  connu, unite de compression par unite de compression, puis on detend ici et
 *  on compare octet pour octet. Un decompresseur faux se decode le plus souvent
 *  SANS erreur et rend des donnees fausses — d'ou la comparaison exhaustive
 *  plutot qu'un simple controle de taille.
 *
 *  Usage : lznt1_test <original> <compresse.bin> <index.idx>
 *    index.idx : une ligne « <n> <taille_origine> <taille_compressee> » par
 *    unite, dans l'ordre ; une taille compressee nulle signale une unite que
 *    Windows a renoncee a compresser (elle est alors stockee telle quelle).
 *
 *  Exclu du build de WAC par le motif « _test.cpp ».
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
		std::cout << "usage: lznt1_test <original> <compresse.bin> <index.idx>\n";
		return 2;
	}
	std::ifstream fo(argv[1], std::ios::binary), fc(argv[2], std::ios::binary);
	std::ifstream fi(argv[3]);
	if (!fo || !fc || !fi){ std::cout << "fichier(s) illisible(s)\n"; return 2; }

	const std::vector<uint8_t> original((std::istreambuf_iterator<char>(fo)),
	                                     std::istreambuf_iterator<char>());
	const std::vector<uint8_t> compresse((std::istreambuf_iterator<char>(fc)),
	                                      std::istreambuf_iterator<char>());

	size_t posC = 0, posO = 0;
	int unites = 0, conformes = 0, ignorees = 0;
	unsigned long long octets = 0;
	int n; size_t tailleO, tailleC;
	std::string ligne;
	while (std::getline(fi, ligne)){
		if (ligne.empty()) continue;
		if (std::sscanf(ligne.c_str(), "%d %zu %zu", &n, &tailleO, &tailleC) != 3) continue;
		if (tailleC == 0){
			// Unite que Windows n'a pas compressee : NTFS la stocke telle quelle.
			++ignorees;
			posO += tailleO;
			continue;
		}
		++unites;
		if (posC + tailleC > compresse.size()){ std::cout << "  ECHEC  unite " << n
			<< " : donnees compressees tronquees\n"; return 1; }

		std::vector<uint8_t> sortie(65536, 0xCC);   // motif temoin
		const size_t rendu = Lznt1Detendre(compresse.data() + posC, tailleC,
		                                   sortie.data(), sortie.size());
		const bool tailleOk = (rendu == tailleO);
		const bool contenuOk = tailleOk && posO + tailleO <= original.size()
		                     && std::memcmp(sortie.data(), original.data() + posO, tailleO) == 0;
		if (contenuOk) ++conformes;
		else {
			std::cout << "  ECHEC  unite " << n << " : rendu " << rendu
			          << " attendu " << tailleO;
			if (tailleOk){
				// Premier octet divergent : dit OU le decodage a devie.
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
	std::cout << "  unites compressees : " << unites << ", conformes : " << conformes
	          << ", non compressees par Windows : " << ignorees << "\n";
	std::cout << "  octets detendus : " << octets << "\n";
	const bool ok = (unites > 0) && (conformes == unites);
	std::cout << (ok ? "tous conformes" : "ECHECS") << "\n";
	return ok ? 0 : 1;
}
