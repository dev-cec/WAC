#include "wevt.h"
#include <cstring>

/*  wevt.cpp — voir wevt.h pour la chaîne à remonter et les formats.
 *
 *  Structures, telles que les décrit l'implémentation de référence de libyal
 *  (libfwevt) :
 *
 *    manifeste       « CRIM » (4), taille (4), majeur (2), mineur (2),
 *                    nombre de fournisseurs (4)                        = 16
 *    entrée          GUID (16), décalage des données (4)               = 20
 *    fournisseur     « WEVT » (4), taille (4), identifiant de message (4),
 *                    nombre de descripteurs (4), nombre d'inconnus (4) = 20
 *                    puis un décalage de 4 octets par descripteur
 *    événements      « EVNT » (4), taille (4), nombre d'événements (4),
 *                    inconnu (4)                                       = 16
 *    événement       identifiant (2), version (1), canal (1), niveau (1),
 *                    code d'opération (1), tâche (2), mots clés (8),
 *                    IDENTIFIANT DE MESSAGE (4), puis six champs de 4    = 44
 */

namespace {

inline uint16_t rd16(const std::vector<uint8_t>& d, size_t o) {
	if (o + 2 > d.size()) return 0;
	return (uint16_t)(d[o] | (d[o + 1] << 8));
}
inline uint32_t rd32(const std::vector<uint8_t>& d, size_t o) {
	if (o + 4 > d.size()) return 0;
	return (uint32_t)d[o] | ((uint32_t)d[o + 1] << 8)
	     | ((uint32_t)d[o + 2] << 16) | ((uint32_t)d[o + 3] << 24);
}

//! GUID à la forme « {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} », en minuscules.
std::wstring guidEnTexte(const std::vector<uint8_t>& d, size_t o) {
	if (o + 16 > d.size()) return std::wstring();
	static const wchar_t* h = L"0123456789abcdef";
	auto oct = [&](size_t i, std::wstring& s) {
		s += h[d[o + i] >> 4];
		s += h[d[o + i] & 0x0F];
	};
	std::wstring s = L"{";
	// Les trois premiers champs sont en petit boutien, les deux derniers non.
	for (int i : { 3, 2, 1, 0 }) oct((size_t)i, s);
	s += L'-';
	for (int i : { 5, 4 }) oct((size_t)i, s);
	s += L'-';
	for (int i : { 7, 6 }) oct((size_t)i, s);
	s += L'-';
	for (int i : { 8, 9 }) oct((size_t)i, s);
	s += L'-';
	for (int i = 10; i < 16; ++i) oct((size_t)i, s);
	s += L'}';
	return s;
}

//! Comparaison de GUID sans casse ni accolades.
bool memeGuid(std::wstring a, std::wstring b) {
	auto normalise = [](std::wstring& s) {
		std::wstring r;
		for (wchar_t c : s) {
			if (c == L'{' || c == L'}' || c == L'-') continue;
			r += (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
		}
		s = r;
	};
	normalise(a);
	normalise(b);
	return !a.empty() && a == b;
}

const size_t ENTREES_MAX = 65536;   // garde-fou sur les compteurs du fichier

} // namespace

//! Vrai si une ressource annonçait une taille de bloc incompatible avec son
//! compte d'événements : la ressource est alors ignorée plutôt que lue au hasard.
bool log_wevt_pas_incoherent = false;

// ---------------------------------------------------------------------------
//  MESSAGETABLE
// ---------------------------------------------------------------------------

size_t TableMessages::analyser(const std::vector<uint8_t>& d) {
	messages_.clear();
	if (d.size() < 4) return 0;
	const uint32_t nbBlocs = rd32(d, 0);
	if (nbBlocs == 0 || nbBlocs > ENTREES_MAX) return 0;

	for (uint32_t b = 0; b < nbBlocs; ++b) {
		const size_t e = 4 + (size_t)b * 12;
		if (e + 12 > d.size()) break;
		const uint32_t premier = rd32(d, e);
		const uint32_t dernier = rd32(d, e + 4);
		const uint32_t decalage = rd32(d, e + 8);
		if (dernier < premier || dernier - premier > ENTREES_MAX) continue;

		size_t p = decalage;
		for (uint32_t id = premier; id <= dernier; ++id) {
			if (p + 4 > d.size()) break;
			const uint16_t longueur = rd16(d, p);
			const uint16_t drapeaux = rd16(d, p + 2);
			if (longueur < 4 || p + longueur > d.size()) break;
			const size_t octetsTexte = (size_t)longueur - 4;

			std::wstring texte;
			if (drapeaux & 0x0001) {
				/*  UTF-16, cas des ressources modernes ; traiter le texte comme
				    une page de code rendrait un caractère sur deux.
				    Les unités sont lues DEUX OCTETS À LA FOIS et non par un
				    cast vers wchar_t : ce type fait deux octets sous Windows
				    mais QUATRE sous Linux, et le cast y relisait de l'UTF-16
				    comme de l'UTF-32 — ce module se veut vérifiable hors
				    Windows, la lecture doit donc l'être aussi. */
				texte.reserve(octetsTexte / 2);
				for (size_t i = 0; i + 1 < octetsTexte; i += 2)
					texte += (wchar_t)rd16(d, p + 4 + i);
			}
			else {
				// Page de code : on élargit octet par octet, faute de savoir
				// laquelle. Les modèles de messages sont en pratique latins.
				texte.reserve(octetsTexte);
				for (size_t i = 0; i < octetsTexte; ++i)
					texte += (wchar_t)(unsigned char)d[p + 4 + i];
			}
			while (!texte.empty() && (texte.back() == L'\0' || texte.back() == L'\r'
			                          || texte.back() == L'\n'))
				texte.pop_back();
			if (!texte.empty()) messages_.emplace(id, texte);
			p += longueur;
		}
	}
	return messages_.size();
}

std::wstring TableMessages::texte(uint32_t identifiant) const {
	const std::map<uint32_t, std::wstring>::const_iterator it = messages_.find(identifiant);
	return (it != messages_.end()) ? it->second : std::wstring();
}

// ---------------------------------------------------------------------------
//  WEVT_TEMPLATE
// ---------------------------------------------------------------------------

size_t MetadonneesWevt::analyser(const std::vector<uint8_t>& d,
                                 const std::wstring& guidFournisseur) {
	parIdEtVersion_.clear();
	parId_.clear();
	if (d.size() < 16 || std::memcmp(d.data(), "CRIM", 4) != 0) return 0;

	const uint32_t nbFournisseurs = rd32(d, 12);
	if (nbFournisseurs == 0 || nbFournisseurs > ENTREES_MAX) return 0;

	for (uint32_t i = 0; i < nbFournisseurs; ++i) {
		const size_t e = 16 + (size_t)i * 20;
		if (e + 20 > d.size()) break;
		const std::wstring guid = guidEnTexte(d, e);
		const uint32_t offset = rd32(d, e + 16);
		if (!guidFournisseur.empty() && !memeGuid(guid, guidFournisseur)) continue;
		if (offset + 20 > d.size()) continue;
		if (std::memcmp(d.data() + offset, "WEVT", 4) != 0) continue;

		const uint32_t nbDescripteurs = rd32(d, offset + 12);
		if (nbDescripteurs > ENTREES_MAX) continue;

		/*  Les descripteurs sont typés PAR LA SIGNATURE trouvée à leur
		    décalage, et non par leur rang : l'ordre des blocs n'est pas garanti,
		    et s'appuyer sur lui ferait lire des canaux comme des événements.
		    Chaque descripteur fait HUIT octets — un décalage et un champ
		    inexploité. Les lire par quatre donne des décalages qui pointent
		    n'importe où, et le bloc des événements n'est jamais trouvé
		    (constaté : 0 événement décrit sur un fournisseur qui en décrit 74). */
		for (uint32_t k = 0; k < nbDescripteurs; ++k) {
			const size_t dd = offset + 20 + (size_t)k * 8;
			if (dd + 4 > d.size()) break;
			const uint32_t bloc = rd32(d, dd);
			if (bloc + 16 > d.size()) continue;
			if (std::memcmp(d.data() + bloc, "EVNT", 4) != 0) continue;

			const uint32_t tailleBloc   = rd32(d, bloc + 4);
			const uint32_t nbEvenements = rd32(d, bloc + 8);
			if (nbEvenements == 0 || nbEvenements > ENTREES_MAX) continue;

			/*  LE PAS EST DÉDUIT DE LA TAILLE ANNONCÉE, et non codé en dur.
			    Un descripteur d'événement fait 48 octets — identifiant,
			    version, canal, niveau, code d'opération, tâche, mots clés, puis
			    huit champs de quatre octets dont l'identifiant de message.
			    Le déduire rend la lecture robuste à une évolution du format et,
			    surtout, la rend VÉRIFIABLE : un pas erroné de quatre octets
			    (constaté en écrivant ce code) donne des enregistrements dont un
			    sur douze seulement est cohérent, sans aucune erreur visible. */
			size_t pas = 48;
			if (tailleBloc > 16) {
				const size_t deduit = (size_t)(tailleBloc - 16) / nbEvenements;
				if (deduit >= 40 && deduit <= 128) pas = deduit;
				else {
					log_wevt_pas_incoherent = true;
					continue;               // taille et compte se contredisent
				}
			}

			for (uint32_t n = 0; n < nbEvenements; ++n) {
				const size_t ev = bloc + 16 + (size_t)n * pas;
				if (ev + pas > d.size()) break;
				const uint16_t id      = rd16(d, ev);
				const uint8_t  version = d[ev + 2];
				const uint32_t message = rd32(d, ev + 16);
				// 0 et 0xFFFFFFFF marquent tous deux « pas de message ».
				if (message == 0 || message == 0xFFFFFFFFu) continue;
				parIdEtVersion_.emplace(((uint32_t)id << 8) | version, message);
				parId_.emplace(id, message);
			}
		}
		if (!guidFournisseur.empty()) break;   // fournisseur trouve
	}
	return parIdEtVersion_.size();
}

uint32_t MetadonneesWevt::identifiantMessage(uint16_t identifiantEvenement,
                                             uint8_t version) const {
	const std::map<uint32_t, uint32_t>::const_iterator it =
		parIdEtVersion_.find(((uint32_t)identifiantEvenement << 8) | version);
	if (it != parIdEtVersion_.end()) return it->second;
	const std::map<uint16_t, uint32_t>::const_iterator it2 = parId_.find(identifiantEvenement);
	return (it2 != parId_.end()) ? it2->second : 0;
}

// ---------------------------------------------------------------------------
//  Substitution des marques
// ---------------------------------------------------------------------------

std::wstring formaterMessage(const std::wstring& modele,
                             const std::vector<std::wstring>& valeurs) {
	if (modele.empty()) return std::wstring();
	std::wstring r;
	r.reserve(modele.size() + 64);

	for (size_t i = 0; i < modele.size(); ++i) {
		if (modele[i] != L'%') { r += modele[i]; continue; }
		if (i + 1 >= modele.size()) { r += modele[i]; break; }

		const wchar_t suivant = modele[i + 1];
		if (suivant == L'%') { r += L'%'; ++i; continue; }
		if (suivant == L'n') { r += L'\n'; ++i; continue; }   // saut de ligne
		if (suivant == L't') { r += L'\t'; ++i; continue; }   // tabulation
		if (suivant < L'0' || suivant > L'9') { r += modele[i]; continue; }

		// Marque positionnelle : un ou plusieurs chiffres.
		size_t j = i + 1;
		unsigned long position = 0;
		while (j < modele.size() && modele[j] >= L'0' && modele[j] <= L'9') {
			position = position * 10 + (unsigned long)(modele[j] - L'0');
			++j;
			if (position > 999) break;              // absurde : on abandonne
		}
		/*  Certains modèles écrivent « %1!s! » : le format entre points
		    d'exclamation est une consigne d'affichage, pas du texte. */
		if (j < modele.size() && modele[j] == L'!') {
			const size_t fin = modele.find(L'!', j + 1);
			if (fin != std::wstring::npos) j = fin + 1;
		}
		if (position >= 1 && position <= valeurs.size()) {
			r += valeurs[position - 1];
			i = j - 1;
		}
		else {
			/*  MARQUE SANS DONNÉE : laissée telle quelle. L'effacer ferait
			    croire à une phrase complète alors qu'il manque une valeur — et
			    c'est précisément ce que l'analyste doit voir. */
			r.append(modele, i, j - i);
			i = j - 1;
		}
	}
	return r;
}
