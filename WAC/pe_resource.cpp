#include "pe_resource.h"
#include <fstream>
#include <cstring>
#include <filesystem>

/*  pe_resource.cpp — voir pe_resource.h.
 *
 *  STRUCTURE PARCOURUE
 *
 *    en-tête MZ           « MZ » ; l'offset de l'en-tête PE est à 0x3C
 *    en-tête PE           « PE\0\0 », puis l'en-tête de fichier (20 octets) et
 *                         l'en-tête optionnel, dont la magie distingue le 32 du
 *                         64 bits — ce qui décale la table des répertoires
 *    répertoires          le 3e (indice 2) est celui des ressources : RVA+taille
 *    table des sections   traduit les RVA en positions de fichier
 *    arbre de ressources  TROIS niveaux imbriqués : type, nom, langue. Chaque
 *                         niveau est un répertoire dont les entrées nommées
 *                         précèdent les entrées numérotées ; une entrée pointe
 *                         soit un sous-répertoire (bit 31 du décalage), soit une
 *                         description de données (RVA + taille).
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

//! Compare sans tenir compte de la casse (ASCII), les noms de type étant latins.
bool memeNom(const std::wstring& a, const std::wstring& b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); ++i) {
		wchar_t x = a[i], y = b[i];
		if (x >= L'a' && x <= L'z') x = (wchar_t)(x - L'a' + L'A');
		if (y >= L'a' && y <= L'z') y = (wchar_t)(y - L'a' + L'A');
		if (x != y) return false;
	}
	return true;
}

const size_t ENTREES_MAX    = 8192;   // garde-fou sur un répertoire

} // namespace

size_t PeResource::offsetDeRva(uint32_t rva) const {
	for (const Section& s : sections_) {
		// La taille VIRTUELLE borne l'appartenance, la taille BRUTE borne la
		// lecture : une section peut être plus grande en mémoire que sur disque.
		if (rva >= s.rva && rva < s.rva + (s.tailleVirtuelle ? s.tailleVirtuelle : s.tailleBrute)) {
			const uint32_t delta = rva - s.rva;
			if (delta >= s.tailleBrute) return 0;      // zone non présente sur disque
			const size_t pos = (size_t)s.offsetFichier + delta;
			return (pos < fichier_.size()) ? pos : 0;
		}
	}
	return 0;
}

bool PeResource::ouvrir(const std::wstring& chemin) {
	ouvert_ = false;
	erreur_.clear();
	sections_.clear();
	fichier_.clear();

	std::ifstream f(std::filesystem::path(chemin), std::ios::binary);
	if (!f) { erreur_ = L"ouverture impossible"; return false; }
	fichier_.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
	if (fichier_.size() < 0x40) { erreur_ = L"fichier trop court"; return false; }

	if (fichier_[0] != 'M' || fichier_[1] != 'Z') { erreur_ = L"signature MZ absente"; return false; }
	const uint32_t offsetPe = rd32(fichier_, 0x3C);
	if (offsetPe + 24 > fichier_.size()) { erreur_ = L"en-tete PE hors fichier"; return false; }
	if (std::memcmp(fichier_.data() + offsetPe, "PE\0\0", 4) != 0) {
		erreur_ = L"signature PE absente"; return false;
	}

	const uint16_t nbSections    = rd16(fichier_, offsetPe + 6);
	const uint16_t tailleOptions = rd16(fichier_, offsetPe + 20);
	const size_t   offsetOptions = offsetPe + 24;
	if (offsetOptions + tailleOptions > fichier_.size()) {
		erreur_ = L"en-tete optionnel hors fichier"; return false;
	}

	/*  La magie de l'en-tête optionnel décide de la position de la table des
	    répertoires : 0x10b pour du 32 bits (96 octets avant la table), 0x20b
	    pour du 64 bits (112). Se tromper ici fait lire le mauvais répertoire. */
	const uint16_t magie = rd16(fichier_, offsetOptions);
	size_t offsetRepertoires;
	if      (magie == 0x010B) offsetRepertoires = offsetOptions + 96;
	else if (magie == 0x020B) offsetRepertoires = offsetOptions + 112;
	else { erreur_ = L"en-tete optionnel de type inconnu"; return false; }

	// Répertoire des ressources : le troisieme (indice 2), 8 octets par entrée.
	rvaRessources_    = rd32(fichier_, offsetRepertoires + 2 * 8);
	tailleRessources_ = rd32(fichier_, offsetRepertoires + 2 * 8 + 4);
	if (rvaRessources_ == 0 || tailleRessources_ == 0) {
		erreur_ = L"aucune ressource"; return false;
	}

	// Table des sections, juste après l'en-tête optionnel.
	const size_t offsetSections = offsetOptions + tailleOptions;
	for (uint16_t i = 0; i < nbSections; ++i) {
		const size_t s = offsetSections + (size_t)i * 40;
		if (s + 40 > fichier_.size()) break;
		Section sec;
		sec.tailleVirtuelle = rd32(fichier_, s + 8);
		sec.rva             = rd32(fichier_, s + 12);
		sec.tailleBrute     = rd32(fichier_, s + 16);
		sec.offsetFichier   = rd32(fichier_, s + 20);
		sections_.push_back(sec);
	}
	if (sections_.empty()) { erreur_ = L"aucune section"; return false; }

	offsetRessources_ = offsetDeRva(rvaRessources_);
	if (offsetRessources_ == 0) { erreur_ = L"repertoire de ressources non localise"; return false; }

	ouvert_ = true;
	return true;
}

/*! Parcourt l'arbre de ressources et rend les octets de la première ressource
 *  dont le TYPE correspond, puis la langue voulue.
 *
 *  Le nom de niveau 2 n'est pas filtré : les fournisseurs n'utilisent qu'un seul
 *  nom par type, et retenir le premier évite d'imposer à l'appelant de connaître
 *  une convention de nommage qui n'est pas documentée.
 */
std::vector<uint8_t> PeResource::chercher(uint32_t type, const std::wstring& nomType,
                                         uint32_t langue) const {
	std::vector<uint8_t> vide;
	if (!ouvert_) return vide;

	//! Lit le nom d'une entrée (chaîne UTF-16 précédée de sa longueur).
	auto nomEntree = [&](uint32_t decalageNom) -> std::wstring {
		const size_t p = offsetRessources_ + (decalageNom & 0x7FFFFFFF);
		if (p + 2 > fichier_.size()) return std::wstring();
		const uint16_t n = rd16(fichier_, p);
		if (n == 0 || n > 512 || p + 2 + 2ULL * n > fichier_.size()) return std::wstring();
		std::wstring s;
		s.reserve(n);
		for (uint16_t i = 0; i < n; ++i) s.push_back((wchar_t)rd16(fichier_, p + 2 + 2ULL * i));
		return s;
	};

	// Niveau 1 : les types.
	const size_t r1 = offsetRessources_;
	const uint16_t nbNommes1  = rd16(fichier_, r1 + 12);
	const uint16_t nbNumeros1 = rd16(fichier_, r1 + 14);
	const size_t total1 = (size_t)nbNommes1 + nbNumeros1;
	if (total1 == 0 || total1 > ENTREES_MAX) return vide;

	for (size_t i = 0; i < total1; ++i) {
		const size_t e = r1 + 16 + i * 8;
		if (e + 8 > fichier_.size()) break;
		const uint32_t id  = rd32(fichier_, e);
		const uint32_t sub = rd32(fichier_, e + 4);

		bool correspond;
		if (i < nbNommes1) correspond = !nomType.empty() && memeNom(nomEntree(id), nomType);
		else               correspond = nomType.empty() && (id == type);
		if (!correspond) continue;
		if (!(sub & 0x80000000u)) break;      // un type doit mener a un sous-repertoire

		// Niveau 2 : les noms. On prend le premier.
		const size_t r2 = offsetRessources_ + (sub & 0x7FFFFFFF);
		if (r2 + 16 > fichier_.size()) break;
		const size_t total2 = (size_t)rd16(fichier_, r2 + 12) + rd16(fichier_, r2 + 14);
		if (total2 == 0 || total2 > ENTREES_MAX) break;

		for (size_t j = 0; j < total2; ++j) {
			const size_t e2 = r2 + 16 + j * 8;
			if (e2 + 8 > fichier_.size()) break;
			const uint32_t sub2 = rd32(fichier_, e2 + 4);
			if (!(sub2 & 0x80000000u)) continue;

			// Niveau 3 : les langues.
			const size_t r3 = offsetRessources_ + (sub2 & 0x7FFFFFFF);
			if (r3 + 16 > fichier_.size()) break;
			const size_t total3 = (size_t)rd16(fichier_, r3 + 12) + rd16(fichier_, r3 + 14);
			if (total3 == 0 || total3 > ENTREES_MAX) break;

			for (size_t k = 0; k < total3; ++k) {
				const size_t e3 = r3 + 16 + k * 8;
				if (e3 + 8 > fichier_.size()) break;
				const uint32_t idLangue = rd32(fichier_, e3);
				const uint32_t data     = rd32(fichier_, e3 + 4);
				if (data & 0x80000000u) continue;              // pas une donnee
				if (langue != 0 && idLangue != langue) continue;

				// Description de la donnée : RVA puis taille.
				const size_t d = offsetRessources_ + data;
				if (d + 8 > fichier_.size()) continue;
				const uint32_t rva    = rd32(fichier_, d);
				const uint32_t taille = rd32(fichier_, d + 4);
				const size_t pos = offsetDeRva(rva);
				if (pos == 0 || taille == 0 || pos + taille > fichier_.size()) continue;
				return std::vector<uint8_t>(fichier_.begin() + pos,
				                            fichier_.begin() + pos + taille);
			}
		}
		break;                                 // type trouve, inutile de continuer
	}
	return vide;
}

std::vector<uint8_t> PeResource::ressource(uint32_t type, uint32_t langue) const {
	return chercher(type, std::wstring(), langue);
}

std::vector<uint8_t> PeResource::ressourceNommee(const std::wstring& nomType,
                                                 uint32_t langue) const {
	return chercher(0, nomType, langue);
}

std::vector<std::wstring> PeResource::typesPresents() const {
	std::vector<std::wstring> types;
	if (!ouvert_) return types;
	const size_t r1 = offsetRessources_;
	const uint16_t nbNommes  = rd16(fichier_, r1 + 12);
	const uint16_t nbNumeros = rd16(fichier_, r1 + 14);
	const size_t total = (size_t)nbNommes + nbNumeros;
	if (total > ENTREES_MAX) return types;
	for (size_t i = 0; i < total; ++i) {
		const size_t e = r1 + 16 + i * 8;
		if (e + 8 > fichier_.size()) break;
		const uint32_t id = rd32(fichier_, e);
		if (i < nbNommes) {
			const size_t p = offsetRessources_ + (id & 0x7FFFFFFF);
			if (p + 2 > fichier_.size()) continue;
			const uint16_t n = rd16(fichier_, p);
			if (n == 0 || n > 512) continue;
			std::wstring s;
			for (uint16_t c = 0; c < n; ++c) s.push_back((wchar_t)rd16(fichier_, p + 2 + 2ULL * c));
			types.push_back(s);
		}
		else types.push_back(std::to_wstring(id));
	}
	return types;
}
