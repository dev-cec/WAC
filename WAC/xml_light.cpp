/*  xml_light.cpp — voir xml_light.h. */
#include "xml_light.h"
#include <fstream>
#include <filesystem>
#include <vector>
#include <windows.h>

namespace {

//! Profondeur maximale : garde-fou contre un document forgé à imbrication extrême.
constexpr unsigned PROFONDEUR_MAX = 64;

//! Retire les espaces, tabulations et retours de ligne aux deux bords.
std::wstring elaguer(const std::wstring& s) {
	const wchar_t* blancs = L" \t\r\n";
	const size_t debut = s.find_first_not_of(blancs);
	if (debut == std::wstring::npos) return std::wstring();
	const size_t fin = s.find_last_not_of(blancs);
	return s.substr(debut, fin - debut + 1);
}

//! Remplace les cinq entités prédéfinies. Les autres sont laissées telles quelles :
//! mieux vaut un texte fidèle qu'une substitution devinée.
std::wstring decoderEntites(const std::wstring& s) {
	if (s.find(L'&') == std::wstring::npos) return s;   // cas courant : rien à faire
	std::wstring r;
	r.reserve(s.size());
	for (size_t i = 0; i < s.size(); ) {
		if (s[i] != L'&') { r += s[i++]; continue; }
		const size_t pv = s.find(L';', i);
		if (pv == std::wstring::npos || pv - i > 10) { r += s[i++]; continue; }
		const std::wstring e = s.substr(i + 1, pv - i - 1);
		if      (e == L"lt")   r += L'<';
		else if (e == L"gt")   r += L'>';
		else if (e == L"amp")  r += L'&';
		else if (e == L"quot") r += L'"';
		else if (e == L"apos") r += L'\'';
		else if (e.size() > 1 && e[0] == L'#') {        // référence numérique
			try {
				const int code = (e[1] == L'x' || e[1] == L'X')
					? std::stoi(e.substr(2), nullptr, 16)
					: std::stoi(e.substr(1));
				if (code > 0 && code < 0x110000) r += (wchar_t)code;
			}
			catch (...) { r += L'&' + e + L';'; }        // illisible : conservé brut
		}
		else { r += L'&' + e + L';'; }
		i = pv + 1;
	}
	return r;
}

//! Retire le préfixe de namespace : le schéma des tâches n'en a qu'un, implicite.
std::wstring sansPrefixe(const std::wstring& nom) {
	const size_t d = nom.find(L':');
	return (d == std::wstring::npos) ? nom : nom.substr(d + 1);
}

/*! Analyse un élément à partir de `pos`, positionné juste après son '<'.
 *  Rend nullptr en cas de document mal formé. */
std::unique_ptr<XmlNode> lireElement(const std::wstring& s, size_t& pos, unsigned profondeur) {
	if (profondeur > PROFONDEUR_MAX) return nullptr;

	// --- nom de la balise
	const size_t debutNom = pos;
	while (pos < s.size() && !iswspace(s[pos]) && s[pos] != L'>' && s[pos] != L'/') ++pos;
	if (pos >= s.size()) return nullptr;
	auto noeud = std::make_unique<XmlNode>();
	noeud->nom = sansPrefixe(s.substr(debutNom, pos - debutNom));
	if (noeud->nom.empty()) return nullptr;

	// --- attributs, jusqu'à '>' ou '/>'
	bool vide = false;
	while (pos < s.size()) {
		while (pos < s.size() && iswspace(s[pos])) ++pos;
		if (pos >= s.size()) return nullptr;
		if (s[pos] == L'/') { vide = true; ++pos; continue; }
		if (s[pos] == L'>') { ++pos; break; }

		const size_t dn = pos;
		while (pos < s.size() && s[pos] != L'=' && !iswspace(s[pos])
		       && s[pos] != L'>' && s[pos] != L'/') ++pos;
		const std::wstring nomAttr = sansPrefixe(s.substr(dn, pos - dn));
		while (pos < s.size() && iswspace(s[pos])) ++pos;
		std::wstring valeur;
		if (pos < s.size() && s[pos] == L'=') {
			++pos;
			while (pos < s.size() && iswspace(s[pos])) ++pos;
			if (pos < s.size() && (s[pos] == L'"' || s[pos] == L'\'')) {
				const wchar_t guillemet = s[pos++];
				const size_t dv = pos;
				while (pos < s.size() && s[pos] != guillemet) ++pos;
				if (pos >= s.size()) return nullptr;      // guillemet non fermé
				valeur = decoderEntites(s.substr(dv, pos - dv));
				++pos;
			}
		}
		if (!nomAttr.empty()) noeud->attributs.emplace_back(nomAttr, valeur);
	}
	if (vide) return noeud;                                // <balise ... />

	// --- contenu : texte et enfants, jusqu'à la balise fermante
	std::wstring texte;
	while (pos < s.size()) {
		if (s[pos] != L'<') { texte += s[pos++]; continue; }

		// commentaire, CDATA ou instruction : sautés (le CDATA garde son texte)
		if (s.compare(pos, 4, L"<!--") == 0) {
			const size_t f = s.find(L"-->", pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 3;
			continue;
		}
		if (s.compare(pos, 9, L"<![CDATA[") == 0) {
			const size_t f = s.find(L"]]>", pos);
			if (f == std::wstring::npos) return nullptr;
			texte += s.substr(pos + 9, f - pos - 9);
			pos = f + 3;
			continue;
		}
		if (pos + 1 < s.size() && (s[pos + 1] == L'?' || s[pos + 1] == L'!')) {
			const size_t f = s.find(L'>', pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 1;
			continue;
		}
		if (pos + 1 < s.size() && s[pos + 1] == L'/') {    // </balise> : fin
			const size_t f = s.find(L'>', pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 1;
			noeud->texte = decoderEntites(elaguer(texte));
			return noeud;
		}
		++pos;                                              // passe le '<'
		auto enfant = lireElement(s, pos, profondeur + 1);
		if (!enfant) return nullptr;
		noeud->enfants.push_back(std::move(enfant));
	}
	return nullptr;                                         // balise jamais fermée
}

} // namespace

const XmlNode* XmlNode::enfant(const std::wstring& nomEnfant) const {
	for (const std::unique_ptr<XmlNode>& e : enfants)
		if (e->nom == nomEnfant) return e.get();
	return nullptr;
}

std::wstring XmlNode::texteDe(const std::wstring& chemin) const {
	const XmlNode* courant = this;
	size_t debut = 0;
	while (courant && debut <= chemin.size()) {
		const size_t sep = chemin.find(L'/', debut);
		const std::wstring segment = chemin.substr(debut, sep == std::wstring::npos
		                                                  ? std::wstring::npos : sep - debut);
		if (segment.empty()) break;
		courant = courant->enfant(segment);
		if (sep == std::wstring::npos) break;
		debut = sep + 1;
	}
	return courant ? courant->texte : std::wstring();
}

std::wstring XmlNode::attribut(const std::wstring& nomAttribut) const {
	for (const std::pair<std::wstring, std::wstring>& a : attributs)
		if (a.first == nomAttribut) return a.second;
	return std::wstring();
}

std::vector<const XmlNode*> XmlNode::descendants(const std::wstring& nomRecherche) const {
	std::vector<const XmlNode*> trouves;
	// Parcours itératif : une arborescence forgée pourrait être très profonde.
	std::vector<const XmlNode*> pile{ this };
	while (!pile.empty()) {
		const XmlNode* n = pile.back();
		pile.pop_back();
		for (const std::unique_ptr<XmlNode>& e : n->enfants) {
			if (e->nom == nomRecherche) trouves.push_back(e.get());
			pile.push_back(e.get());
		}
	}
	return trouves;
}

std::unique_ptr<XmlNode> xmlAnalyser(const std::wstring& contenu) {
	size_t pos = 0;
	while (pos < contenu.size()) {
		if (contenu[pos] != L'<') { ++pos; continue; }
		// saute prologue, commentaires et doctype pour atteindre l'élément racine
		if (contenu.compare(pos, 4, L"<!--") == 0) {
			const size_t f = contenu.find(L"-->", pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 3;
			continue;
		}
		if (pos + 1 < contenu.size() && (contenu[pos + 1] == L'?' || contenu[pos + 1] == L'!')) {
			const size_t f = contenu.find(L'>', pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 1;
			continue;
		}
		++pos;
		return lireElement(contenu, pos, 0);
	}
	return nullptr;
}

std::unique_ptr<XmlNode> xmlLireFichier(const std::wstring& chemin) {
	std::ifstream f(std::filesystem::path(chemin), std::ios::binary);
	if (!f) return nullptr;
	const std::string octets((std::istreambuf_iterator<char>(f)),
	                          std::istreambuf_iterator<char>());
	if (octets.empty()) return nullptr;

	// UTF-16LE avec BOM : format écrit par le planificateur de tâches.
	if (octets.size() >= 2 && (unsigned char)octets[0] == 0xFF
	                       && (unsigned char)octets[1] == 0xFE) {
		std::wstring w(reinterpret_cast<const wchar_t*>(octets.data() + 2),
		               (octets.size() - 2) / sizeof(wchar_t));
		return xmlAnalyser(w);
	}
	// Sinon UTF-8, avec ou sans BOM.
	const int decalage = (octets.size() >= 3 && (unsigned char)octets[0] == 0xEF
	                      && (unsigned char)octets[1] == 0xBB
	                      && (unsigned char)octets[2] == 0xBF) ? 3 : 0;
	const int taille = MultiByteToWideChar(CP_UTF8, 0, octets.data() + decalage,
	                                       (int)octets.size() - decalage, nullptr, 0);
	if (taille <= 0) return nullptr;
	std::wstring w((size_t)taille, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, octets.data() + decalage,
	                    (int)octets.size() - decalage, &w[0], taille);
	return xmlAnalyser(w);
}
