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
std::wstring guidToText(const std::vector<uint8_t>& d, size_t o) {
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
	auto normalized = [](std::wstring& s) {
		std::wstring r;
		for (wchar_t c : s) {
			if (c == L'{' || c == L'}' || c == L'-') continue;
			r += (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
		}
		s = r;
	};
	normalized(a);
	normalized(b);
	return !a.empty() && a == b;
}

const size_t MAX_ENTRIES = 65536;   // garde-fou sur les compteurs du fichier

} // namespace

//! Vrai si une ressource annonçait une taille de bloc incompatible avec son
//! compte d'événements : la ressource est alors ignorée plutôt que lue au hasard.
bool log_wevt_pas_incoherent = false;

// ---------------------------------------------------------------------------
//  MESSAGETABLE
// ---------------------------------------------------------------------------

size_t TableMessages::analyse(const std::vector<uint8_t>& d) {
	messages_.clear();
	if (d.size() < 4) return 0;
	const uint32_t nBlocks = rd32(d, 0);
	if (nBlocks == 0 || nBlocks > MAX_ENTRIES) return 0;

	for (uint32_t b = 0; b < nBlocks; ++b) {
		const size_t e = 4 + (size_t)b * 12;
		if (e + 12 > d.size()) break;
		const uint32_t first = rd32(d, e);
		const uint32_t last = rd32(d, e + 4);
		const uint32_t offset = rd32(d, e + 8);
		if (last < first || last - first > MAX_ENTRIES) continue;

		size_t p = offset;
		for (uint32_t id = first; id <= last; ++id) {
			if (p + 4 > d.size()) break;
			const uint16_t length = rd16(d, p);
			const uint16_t flags = rd16(d, p + 2);
			if (length < 4 || p + length > d.size()) break;
			const size_t textBytes = (size_t)length - 4;

			std::wstring text;
			if (flags & 0x0001) {
				/*  UTF-16, cas des ressources modernes ; traiter le texte comme
				    une page de code rendrait un caractère sur deux.
				    Les unités sont lues DEUX OCTETS À LA FOIS et non par un
				    cast vers wchar_t : ce type fait deux octets sous Windows
				    mais QUATRE sous Linux, et le cast y relisait de l'UTF-16
				    comme de l'UTF-32 — ce module se veut vérifiable hors
				    Windows, la lecture doit donc l'être aussi. */
				text.reserve(textBytes / 2);
				for (size_t i = 0; i + 1 < textBytes; i += 2)
					text += (wchar_t)rd16(d, p + 4 + i);
			}
			else {
				// Page de code : on élargit octet par octet, faute de savoir
				// laquelle. Les modèles de messages sont en pratique latins.
				text.reserve(textBytes);
				for (size_t i = 0; i < textBytes; ++i)
					text += (wchar_t)(unsigned char)d[p + 4 + i];
			}
			while (!text.empty() && (text.back() == L'\0' || text.back() == L'\r'
			                          || text.back() == L'\n'))
				text.pop_back();
			if (!text.empty()) messages_.emplace(id, text);
			p += length;
		}
	}
	return messages_.size();
}

std::wstring TableMessages::text(uint32_t id) const {
	const std::map<uint32_t, std::wstring>::const_iterator it = messages_.find(id);
	return (it != messages_.end()) ? it->second : std::wstring();
}

// ---------------------------------------------------------------------------
//  WEVT_TEMPLATE
// ---------------------------------------------------------------------------

size_t WevtMetadata::analyse(const std::vector<uint8_t>& d,
                                 const std::wstring& providerGuid) {
	parIdEtVersion_.clear();
	parId_.clear();
	if (d.size() < 16 || std::memcmp(d.data(), "CRIM", 4) != 0) return 0;

	const uint32_t nProviders = rd32(d, 12);
	if (nProviders == 0 || nProviders > MAX_ENTRIES) return 0;

	for (uint32_t i = 0; i < nProviders; ++i) {
		const size_t e = 16 + (size_t)i * 20;
		if (e + 20 > d.size()) break;
		const std::wstring guid = guidToText(d, e);
		const uint32_t offset = rd32(d, e + 16);
		if (!providerGuid.empty() && !memeGuid(guid, providerGuid)) continue;
		if (offset + 20 > d.size()) continue;
		if (std::memcmp(d.data() + offset, "WEVT", 4) != 0) continue;

		const uint32_t nDescriptors = rd32(d, offset + 12);
		if (nDescriptors > MAX_ENTRIES) continue;

		/*  Les descripteurs sont typés PAR LA SIGNATURE trouvée à leur
		    décalage, et non par leur rang : l'ordre des blocs n'est pas garanti,
		    et s'appuyer sur lui ferait lire des canaux comme des événements.
		    Chaque descripteur fait HUIT octets — un décalage et un champ
		    inexploité. Les lire par quatre donne des décalages qui pointent
		    n'importe où, et le bloc des événements n'est jamais trouvé
		    (constaté : 0 événement décrit sur un fournisseur qui en décrit 74). */
		for (uint32_t k = 0; k < nDescriptors; ++k) {
			const size_t dd = offset + 20 + (size_t)k * 8;
			if (dd + 4 > d.size()) break;
			const uint32_t block = rd32(d, dd);
			if (block + 16 > d.size()) continue;
			if (std::memcmp(d.data() + block, "EVNT", 4) != 0) continue;

			const uint32_t blockSize   = rd32(d, block + 4);
			const uint32_t nEvents = rd32(d, block + 8);
			if (nEvents == 0 || nEvents > MAX_ENTRIES) continue;

			/*  LE PAS EST DÉDUIT DE LA TAILLE ANNONCÉE, et non codé en dur.
			    Un descripteur d'événement fait 48 octets — identifiant,
			    version, canal, niveau, code d'opération, tâche, mots clés, puis
			    huit champs de quatre octets dont l'identifiant de message.
			    Le déduire rend la lecture robuste à une évolution du format et,
			    surtout, la rend VÉRIFIABLE : un pas erroné de quatre octets
			    (constaté en écrivant ce code) donne des enregistrements dont un
			    sur douze seulement est cohérent, sans aucune erreur visible. */
			size_t pas = 48;
			if (blockSize > 16) {
				const size_t deduced = (size_t)(blockSize - 16) / nEvents;
				if (deduced >= 40 && deduced <= 128) pas = deduced;
				else {
					log_wevt_pas_incoherent = true;
					continue;               // taille et compte se contredisent
				}
			}

			for (uint32_t n = 0; n < nEvents; ++n) {
				const size_t ev = block + 16 + (size_t)n * pas;
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
		if (!providerGuid.empty()) break;   // fournisseur trouve
	}
	return parIdEtVersion_.size();
}

uint32_t WevtMetadata::messageId(uint16_t eventId,
                                             uint8_t version) const {
	const std::map<uint32_t, uint32_t>::const_iterator it =
		parIdEtVersion_.find(((uint32_t)eventId << 8) | version);
	if (it != parIdEtVersion_.end()) return it->second;
	const std::map<uint16_t, uint32_t>::const_iterator it2 = parId_.find(eventId);
	return (it2 != parId_.end()) ? it2->second : 0;
}

// ---------------------------------------------------------------------------
//  Substitution des marques
// ---------------------------------------------------------------------------

std::wstring formatMessage(const std::wstring& messageTemplate,
                             const std::vector<std::wstring>& values) {
	if (messageTemplate.empty()) return std::wstring();
	std::wstring r;
	r.reserve(messageTemplate.size() + 64);

	for (size_t i = 0; i < messageTemplate.size(); ++i) {
		if (messageTemplate[i] != L'%') { r += messageTemplate[i]; continue; }
		if (i + 1 >= messageTemplate.size()) { r += messageTemplate[i]; break; }

		const wchar_t next = messageTemplate[i + 1];
		if (next == L'%') { r += L'%'; ++i; continue; }
		if (next == L'n') { r += L'\n'; ++i; continue; }   // saut de ligne
		if (next == L't') { r += L'\t'; ++i; continue; }   // tabulation
		if (next == L'r') { r += L'\r'; ++i; continue; }   // retour chariot
		if (next == L'b') { r += L' ';  ++i; continue; }   // espace
		if (next == L'.' || next == L'!') { r += next; ++i; continue; }
		/*  « %0 » TERMINE le message, sans saut de ligne final (convention de
		    FormatMessage). Il était recopié tel quel : « …supprimées suite à la
		    suppression du profil utilisateur.\n%0 ». Un chiffre qui suit ferait
		    une marque %0N, qui n'existe pas : même traitement. */
		if (next == L'0') {
			while (!r.empty() && (r.back() == L'\n' || r.back() == L'\r')) r.pop_back();
			return r;
		}
		if (next < L'0' || next > L'9') { r += messageTemplate[i]; continue; }

		// Marque positionnelle : un ou plusieurs chiffres.
		size_t j = i + 1;
		unsigned long position = 0;
		while (j < messageTemplate.size() && messageTemplate[j] >= L'0' && messageTemplate[j] <= L'9') {
			position = position * 10 + (unsigned long)(messageTemplate[j] - L'0');
			++j;
			if (position > 999) break;              // absurde : on abandonne
		}
		/*  Certains modèles écrivent « %1!s! » : le format entre points
		    d'exclamation est une consigne d'affichage, pas du texte. */
		if (j < messageTemplate.size() && messageTemplate[j] == L'!') {
			const size_t end = messageTemplate.find(L'!', j + 1);
			if (end != std::wstring::npos) j = end + 1;
		}
		if (position >= 1 && position <= values.size()) {
			r += values[position - 1];
			i = j - 1;
		}
		else {
			/*  MARQUE SANS DONNÉE : laissée telle quelle. L'effacer ferait
			    croire à une phrase complète alors qu'il manque une valeur — et
			    c'est précisément ce que l'analyste doit voir. */
			r.append(messageTemplate, i, j - i);
			i = j - 1;
		}
	}
	return r;
}
