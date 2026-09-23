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
bool sameName(const std::wstring& a, const std::wstring& b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); ++i) {
		wchar_t x = a[i], y = b[i];
		if (x >= L'a' && x <= L'z') x = (wchar_t)(x - L'a' + L'A');
		if (y >= L'a' && y <= L'z') y = (wchar_t)(y - L'a' + L'A');
		if (x != y) return false;
	}
	return true;
}

const size_t MAX_ENTRIES    = 8192;   // garde-fou sur un répertoire

} // namespace

size_t PeResource::offsetDeRva(uint32_t rva) const {
	for (const Section& s : sections_) {
		// La taille VIRTUELLE borne l'appartenance, la taille BRUTE borne la
		// lecture : une section peut être plus grande en mémoire que sur disque.
		if (rva >= s.rva && rva < s.rva + (s.virtualSize ? s.virtualSize : s.rawSize)) {
			const uint32_t delta = rva - s.rva;
			if (delta >= s.rawSize) return 0;      // zone non présente sur disque
			const size_t pos = (size_t)s.fileOffset + delta;
			return (pos < file_.size()) ? pos : 0;
		}
	}
	return 0;
}

bool PeResource::open(const std::wstring& path) {
	open_ = false;
	error_.clear();
	sections_.clear();
	file_.clear();

	std::ifstream f(std::filesystem::path(path), std::ios::binary);
	if (!f) { error_ = L"ouverture impossible"; return false; }
	file_.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
	if (file_.size() < 0x40) { error_ = L"fichier trop court"; return false; }

	if (file_[0] != 'M' || file_[1] != 'Z') { error_ = L"signature MZ absente"; return false; }
	const uint32_t offsetPe = rd32(file_, 0x3C);
	if (offsetPe + 24 > file_.size()) { error_ = L"en-tete PE hors fichier"; return false; }
	if (std::memcmp(file_.data() + offsetPe, "PE\0\0", 4) != 0) {
		error_ = L"signature PE absente"; return false;
	}

	const uint16_t nbSections    = rd16(file_, offsetPe + 6);
	const uint16_t optionalHeaderSize = rd16(file_, offsetPe + 20);
	const size_t   offsetOptions = offsetPe + 24;
	if (offsetOptions + optionalHeaderSize > file_.size()) {
		error_ = L"en-tete optionnel hors fichier"; return false;
	}

	/*  La magie de l'en-tête optionnel décide de la position de la table des
	    répertoires : 0x10b pour du 32 bits (96 octets avant la table), 0x20b
	    pour du 64 bits (112). Se tromper ici fait lire le mauvais répertoire. */
	const uint16_t magic = rd16(file_, offsetOptions);
	size_t directoriesOffset;
	if      (magic == 0x010B) directoriesOffset = offsetOptions + 96;
	else if (magic == 0x020B) directoriesOffset = offsetOptions + 112;
	else { error_ = L"en-tete optionnel de type inconnu"; return false; }

	// Répertoire des ressources : le troisieme (indice 2), 8 octets par entrée.
	resourcesRva_    = rd32(file_, directoriesOffset + 2 * 8);
	resourcesSize_ = rd32(file_, directoriesOffset + 2 * 8 + 4);
	if (resourcesRva_ == 0 || resourcesSize_ == 0) {
		error_ = L"aucune ressource"; return false;
	}

	// Table des sections, juste après l'en-tête optionnel.
	const size_t offsetSections = offsetOptions + optionalHeaderSize;
	for (uint16_t i = 0; i < nbSections; ++i) {
		const size_t s = offsetSections + (size_t)i * 40;
		if (s + 40 > file_.size()) break;
		Section sec;
		sec.virtualSize = rd32(file_, s + 8);
		sec.rva             = rd32(file_, s + 12);
		sec.rawSize     = rd32(file_, s + 16);
		sec.fileOffset   = rd32(file_, s + 20);
		sections_.push_back(sec);
	}
	if (sections_.empty()) { error_ = L"aucune section"; return false; }

	resourcesOffset_ = offsetDeRva(resourcesRva_);
	if (resourcesOffset_ == 0) { error_ = L"repertoire de ressources non localise"; return false; }

	open_ = true;
	return true;
}

/*! Parcourt l'arbre de ressources et rend les octets de la première ressource
 *  dont le TYPE correspond, puis la langue voulue.
 *
 *  Le nom de niveau 2 n'est pas filtré : les fournisseurs n'utilisent qu'un seul
 *  nom par type, et retenir le premier évite d'imposer à l'appelant de connaître
 *  une convention de nommage qui n'est pas documentée.
 */
std::vector<uint8_t> PeResource::find(uint32_t type, const std::wstring& typeName,
                                         uint32_t language) const {
	std::vector<uint8_t> empty;
	if (!open_) return empty;

	//! Lit le nom d'une entrée (chaîne UTF-16 précédée de sa longueur).
	auto entryName = [&](uint32_t nameOffset) -> std::wstring {
		const size_t p = resourcesOffset_ + (nameOffset & 0x7FFFFFFF);
		if (p + 2 > file_.size()) return std::wstring();
		const uint16_t n = rd16(file_, p);
		if (n == 0 || n > 512 || p + 2 + 2ULL * n > file_.size()) return std::wstring();
		std::wstring s;
		s.reserve(n);
		for (uint16_t i = 0; i < n; ++i) s.push_back((wchar_t)rd16(file_, p + 2 + 2ULL * i));
		return s;
	};

	// Niveau 1 : les types.
	const size_t r1 = resourcesOffset_;
	const uint16_t nNamed1  = rd16(file_, r1 + 12);
	const uint16_t nNumbers1 = rd16(file_, r1 + 14);
	const size_t total1 = (size_t)nNamed1 + nNumbers1;
	if (total1 == 0 || total1 > MAX_ENTRIES) return empty;

	for (size_t i = 0; i < total1; ++i) {
		const size_t e = r1 + 16 + i * 8;
		if (e + 8 > file_.size()) break;
		const uint32_t id  = rd32(file_, e);
		const uint32_t sub = rd32(file_, e + 4);

		bool correspond;
		if (i < nNamed1) correspond = !typeName.empty() && sameName(entryName(id), typeName);
		else               correspond = typeName.empty() && (id == type);
		if (!correspond) continue;
		if (!(sub & 0x80000000u)) break;      // un type doit mener a un sous-repertoire

		// Niveau 2 : les noms. On prend le premier.
		const size_t r2 = resourcesOffset_ + (sub & 0x7FFFFFFF);
		if (r2 + 16 > file_.size()) break;
		const size_t total2 = (size_t)rd16(file_, r2 + 12) + rd16(file_, r2 + 14);
		if (total2 == 0 || total2 > MAX_ENTRIES) break;

		for (size_t j = 0; j < total2; ++j) {
			const size_t e2 = r2 + 16 + j * 8;
			if (e2 + 8 > file_.size()) break;
			const uint32_t sub2 = rd32(file_, e2 + 4);
			if (!(sub2 & 0x80000000u)) continue;

			// Niveau 3 : les langues.
			const size_t r3 = resourcesOffset_ + (sub2 & 0x7FFFFFFF);
			if (r3 + 16 > file_.size()) break;
			const size_t total3 = (size_t)rd16(file_, r3 + 12) + rd16(file_, r3 + 14);
			if (total3 == 0 || total3 > MAX_ENTRIES) break;

			for (size_t k = 0; k < total3; ++k) {
				const size_t e3 = r3 + 16 + k * 8;
				if (e3 + 8 > file_.size()) break;
				const uint32_t languageId = rd32(file_, e3);
				const uint32_t data     = rd32(file_, e3 + 4);
				if (data & 0x80000000u) continue;              // pas une donnee
				if (language != 0 && languageId != language) continue;

				// Description de la donnée : RVA puis taille.
				const size_t d = resourcesOffset_ + data;
				if (d + 8 > file_.size()) continue;
				const uint32_t rva    = rd32(file_, d);
				const uint32_t size = rd32(file_, d + 4);
				const size_t pos = offsetDeRva(rva);
				if (pos == 0 || size == 0 || pos + size > file_.size()) continue;
				return std::vector<uint8_t>(file_.begin() + pos,
				                            file_.begin() + pos + size);
			}
		}
		break;                                 // type trouve, inutile de continuer
	}
	return empty;
}

std::vector<uint8_t> PeResource::resource(uint32_t type, uint32_t language) const {
	return find(type, std::wstring(), language);
}

std::vector<uint8_t> PeResource::namedResource(const std::wstring& typeName,
                                                 uint32_t language) const {
	return find(0, typeName, language);
}

std::vector<std::wstring> PeResource::typesPresent() const {
	std::vector<std::wstring> types;
	if (!open_) return types;
	const size_t r1 = resourcesOffset_;
	const uint16_t nNamed  = rd16(file_, r1 + 12);
	const uint16_t nNumbers = rd16(file_, r1 + 14);
	const size_t total = (size_t)nNamed + nNumbers;
	if (total > MAX_ENTRIES) return types;
	for (size_t i = 0; i < total; ++i) {
		const size_t e = r1 + 16 + i * 8;
		if (e + 8 > file_.size()) break;
		const uint32_t id = rd32(file_, e);
		if (i < nNamed) {
			const size_t p = resourcesOffset_ + (id & 0x7FFFFFFF);
			if (p + 2 > file_.size()) continue;
			const uint16_t n = rd16(file_, p);
			if (n == 0 || n > 512) continue;
			std::wstring s;
			for (uint16_t c = 0; c < n; ++c) s.push_back((wchar_t)rd16(file_, p + 2 + 2ULL * c));
			types.push_back(s);
		}
		else types.push_back(std::to_wstring(id));
	}
	return types;
}
