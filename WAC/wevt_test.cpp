/*  wevt_test.cpp — verifie la chaine qui rend le message en clair d'un evenement.
 *
 *  POURQUOI CE TEST. La chaine compte CINQ maillons — registre, ressources PE,
 *  WEVT_TEMPLATE, MESSAGETABLE, substitution — et chacun echoue en silence : le
 *  champ disparait, la collecte reste valide, et rien ne dit que le maillon est
 *  casse. Deux defauts ont ete pris de cette facon en ecrivant ce code :
 *    - les descripteurs d'un fournisseur font HUIT octets, pas quatre. Lus par
 *      quatre, les blocs ne sont jamais trouves : 0 evenement decrit sur un
 *      fournisseur qui en decrit 202.
 *    - un descripteur d'evenement fait 48 octets, pas 44. Avec un pas de 44, un
 *      enregistrement sur douze seulement est coherent, sans aucune erreur.
 *      Le pas se DEDUIT donc de la taille annoncee du bloc.
 *
 *  Usage : wevt_test <fichier.dll> <fichier.dll.mui> <guid> [id[:version] ...]
 *    Les deux fichiers sont ceux d'un fournisseur reel : les metadonnees sont
 *    dans le binaire, les textes dans son satellite localise.
 *
 *  Exclu du build de WAC par le motif « _test.cpp ».
 *  Compilation native : g++ -std=c++17 -I. pe_resource.cpp wevt.cpp wevt_test.cpp -o wevt_test
 */
#include "pe_resource.h"
#include "wevt.h"
#include <iostream>
#include <string>
#include <vector>

namespace {

//! Rend une chaine large en UTF-8, pour un terminal.
std::string utf8(const std::wstring& w) {
	std::string r;
	for (wchar_t c : w) {
		const unsigned long u = (unsigned long)c;
		if (u < 0x80) r += (char)u;
		else if (u < 0x800) { r += (char)(0xC0 | (u >> 6)); r += (char)(0x80 | (u & 0x3F)); }
		else { r += (char)(0xE0 | (u >> 12)); r += (char)(0x80 | ((u >> 6) & 0x3F));
		       r += (char)(0x80 | (u & 0x3F)); }
	}
	return r;
}

std::wstring large(const std::string& s) { return std::wstring(s.begin(), s.end()); }

} // namespace

int main(int argc, char** argv) {
	if (argc < 4) {
		std::cout << "usage: wevt_test <dll> <mui> <guid> [id[:version] ...]\n";
		return 2;
	}
	PeResource dll, mui;
	if (!dll.ouvrir(large(argv[1]))) {
		std::cout << "  ECHEC  binaire : " << utf8(dll.erreur()) << "\n";
		return 1;
	}
	if (!mui.ouvrir(large(argv[2]))) {
		std::cout << "  ECHEC  satellite : " << utf8(mui.erreur()) << "\n";
		return 1;
	}

	int echecs = 0;

	const std::vector<uint8_t> resWevt = dll.ressourceNommee(L"WEVT_TEMPLATE");
	const std::vector<uint8_t> resMsg  = mui.ressource(PE_RT_MESSAGETABLE);
	std::cout << (resWevt.empty() ? "  ECHEC  " : "  ok     ")
	          << "WEVT_TEMPLATE lue (" << resWevt.size() << " octets)\n";
	std::cout << (resMsg.empty() ? "  ECHEC  " : "  ok     ")
	          << "MESSAGETABLE lue (" << resMsg.size() << " octets)\n";
	if (resWevt.empty() || resMsg.empty()) return 1;

	MetadonneesWevt meta;
	const size_t nbEvenements = meta.analyser(resWevt, large(argv[3]));
	TableMessages table;
	const size_t nbMessages = table.analyser(resMsg);
	std::cout << (nbEvenements ? "  ok     " : "  ECHEC  ")
	          << nbEvenements << " evenement(s) decrit(s)\n";
	std::cout << (nbMessages ? "  ok     " : "  ECHEC  ")
	          << nbMessages << " message(s)\n";
	if (!nbEvenements || !nbMessages) return 1;

	// Chaque identifiant demande doit remonter jusqu'a un texte non vide.
	for (int i = 4; i < argc; ++i) {
		const std::string a = argv[i];
		const size_t sep = a.find(':');
		const uint16_t id = (uint16_t)strtoul(a.substr(0, sep).c_str(), nullptr, 10);
		const uint8_t ver = (uint8_t)(sep == std::string::npos ? 0
		                              : strtoul(a.substr(sep + 1).c_str(), nullptr, 10));
		const uint32_t idMessage = meta.identifiantMessage(id, ver);
		const std::wstring modele = idMessage ? table.texte(idMessage) : std::wstring();
		const bool ok = !modele.empty();
		if (!ok) ++echecs;
		std::cout << (ok ? "  ok     " : "  ECHEC  ") << "evenement " << id
		          << " v" << (int)ver << " -> message " << idMessage << "\n";
		if (ok) {
			const std::vector<std::wstring> valeurs = { L"<1>", L"<2>", L"<3>", L"<4>" };
			std::cout << "         modele  : " << utf8(modele.substr(0, 150)) << "\n";
			std::cout << "         formate : "
			          << utf8(formaterMessage(modele, valeurs).substr(0, 150)) << "\n";
		}
	}

	/*  La substitution se verifie a part, sur des cas construits : une marque
	    sans donnee doit RESTER visible, l'effacer ferait croire a une phrase
	    complete. */
	struct Cas { const wchar_t* modele; const wchar_t* attendu; };
	const std::vector<Cas> cas = {
		{ L"a %1 b",            L"a <1> b" },
		{ L"%1 %2 %3",          L"<1> <2> <3>" },
		{ L"%9 manquant",       L"%9 manquant" },     // pas de donnee : marque gardee
		{ L"100%% sur",         L"100% sur" },
		{ L"ligne%nsuivante",   L"ligne\nsuivante" },
		{ L"tab%tici",          L"tab\tici" },
		{ L"%1!s! formate",     L"<1> formate" },     // consigne d'affichage retiree
		{ L"fin.%n%0",          L"fin." },            // %0 termine, sans saut final
		{ L"a%0 ignore",        L"a" },
		{ L"x%by%.%!",          L"x y.!" },
	};
	const std::vector<std::wstring> v = { L"<1>", L"<2>", L"<3>" };
	for (const Cas& c : cas) {
		const std::wstring r = formaterMessage(c.modele, v);
		const bool ok = (r == c.attendu);
		if (!ok) ++echecs;
		std::cout << (ok ? "  ok     " : "  ECHEC  ") << "substitution « "
		          << utf8(c.modele) << " »";
		if (!ok) std::cout << " -> « " << utf8(r) << " » au lieu de « "
		                   << utf8(c.attendu) << " »";
		std::cout << "\n";
	}

	std::cout << (echecs ? "ECHECS : " : "tous conformes (echecs : ") << echecs
	          << (echecs ? "\n" : ")\n");
	return echecs ? 1 : 0;
}
