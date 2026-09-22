/*  authenticode_test.cpp — confronte la vérification d'authenticité de WAC à
 *  celle de Windows.
 *
 *  Usage :
 *    authenticode_test --catalogues <dossier>
 *        vérifie et indexe tous les .cat du dossier, et en fait le bilan ;
 *    authenticode_test --catalogues <dossier> --fichiers <liste>
 *        puis rend un verdict par fichier. <liste> : une ligne par fichier,
 *        « identifiant|chemin local ». Sortie : « identifiant|MICROSOFT|source »
 *        ou « identifiant|PRELEVE|motif ».
 *    authenticode_test --rsa <module hex> <exposant hex> <signature hex> <sha256 hex>
 *        vérifie une signature RSA isolée (confrontation à OpenSSL).
 *
 *  Le juge est Get-AuthenticodeSignature, exécuté dans la VM sur les mêmes
 *  fichiers (cf. vmtest/README.md). Ce programme lit les fichiers par
 *  l'API : c'est un outil de test, pas la collecte.
 *
 *  Compilation (Linux) :
 *    g++ -std=c++17 -O2 -I. authenticode.cpp rsa.cpp sha.cpp authenticode_test.cpp
 */
#include "authenticode.h"
#include "rsa.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <map>
#include <sstream>
#include <vector>
#include <chrono>

namespace {

std::vector<uint8_t> lire(const std::filesystem::path& p) {
	std::ifstream f(p, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

std::vector<uint8_t> hex(const std::string& h) {
	std::vector<uint8_t> r;
	for (size_t i = 0; i + 1 < h.size(); i += 2) r.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
	return r;
}

std::string utf8(const std::wstring& w) {
	std::string r;
	for (wchar_t c : w) {
		if (c < 0x80) r += (char)c;
		else if (c < 0x800) { r += (char)(0xC0 | (c >> 6)); r += (char)(0x80 | (c & 0x3F)); }
		else { r += (char)(0xE0 | (c >> 12)); r += (char)(0x80 | ((c >> 6) & 0x3F)); r += (char)(0x80 | (c & 0x3F)); }
	}
	return r;
}

} // namespace

int main(int argc, char** argv) {
	if (argc == 6 && std::strcmp(argv[1], "--rsa") == 0) {
		const auto n = hex(argv[2]), e = hex(argv[3]), s = hex(argv[4]), h = hex(argv[5]);
		const bool ok = RsaVerifierPkcs1(n.data(), n.size(), e.data(), e.size(), s.data(), s.size(),
		                                 AlgoEmpreinte::Sha256, h.data(), h.size());
		std::cout << (ok ? "VALIDE" : "INVALIDE") << "\n";
		return ok ? 0 : 1;
	}
	std::string dossier, liste;
	for (int i = 1; i + 1 < argc; i += 2) {
		if (std::strcmp(argv[i], "--catalogues") == 0) dossier = argv[i + 1];
		else if (std::strcmp(argv[i], "--fichiers") == 0) liste = argv[i + 1];
	}
	if (dossier.empty()) { std::cerr << "usage : voir l'en-tête du fichier\n"; return 2; }

	IndexCatalogues index;
	std::map<std::string, size_t> refus;
	size_t lus = 0;
	const auto t0 = std::chrono::steady_clock::now();
	for (const auto& e : std::filesystem::directory_iterator(dossier)) {
		if (e.path().extension() != ".cat") continue;
		const std::vector<uint8_t> d = lire(e.path());
		++lus;
		if (!index.ajouter(e.path().filename().wstring(), d.data(), d.size())) {
			const SignatureVerifiee s = VerifierPkcs7(d.data(), d.size());
			++refus[s.valide ? (s.signataireAccepte ? std::string("aucune empreinte indexable")
			                                         : "signataire non retenu : " + utf8(s.signataire))
			                 : s.motif];
		}
	}
	const double duree = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
	std::cerr << lus << " catalogue(s) lus, " << index.catalogues() << " retenus, "
	          << index.empreintes() << " empreinte(s) indexées, en " << duree << " s\n";
	for (const auto& r : refus) std::cerr << "  refusés : " << r.second << " — " << r.first << "\n";

	if (liste == "-") {                                 // empreintes indexées, en hexa
		index.vider(std::cout);
		return 0;
	}
	if (liste.empty()) return 0;
	std::ifstream l(liste);
	std::string ligne;
	size_t ms = 0, autres = 0;
	while (std::getline(l, ligne)) {
		if (!ligne.empty() && ligne.back() == '\r') ligne.pop_back();
		const size_t barre = ligne.find('|');
		if (barre == std::string::npos) continue;
		const std::string id = ligne.substr(0, barre);
		std::ifstream f(std::filesystem::u8path(ligne.substr(barre + 1)), std::ios::binary);
		if (!f) { std::cout << id << "|ILLISIBLE|\n"; continue; }
		const std::vector<uint8_t> octets((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		AnalyseurPe pe;
		pe.sputn((const char*)octets.data(), (std::streamsize)octets.size());
		pe.terminer();
		VerdictMicrosoft v;
		if (pe.estPe()) v = EvaluerPe(pe, index);
		else {
			// Script ou document : catalogue (octets bruts), puis signature
			// PowerShell intégrée.
			uint8_t h[32];
			sha256Octets(octets.data(), octets.size(), h);
			v = EvaluerParCatalogue(h, index);
			if (!v.microsoft) {
				const VerdictMicrosoft ps = EvaluerScriptPowerShell(octets.data(), octets.size());
				if (ps.microsoft || ps.motif != "pas de signature intégrée") v = ps;
			}
		}
		if (v.microsoft) { ++ms; std::cout << id << "|MICROSOFT|" << utf8(v.source) << "\n"; }
		else { ++autres; std::cout << id << "|PRELEVE|" << v.motif << "\n"; }
	}
	std::cerr << ms << " authentifié(s) Microsoft, " << autres << " à prélever\n";
	return 0;
}
