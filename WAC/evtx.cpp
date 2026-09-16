#include "evtx.h"
#include "tools.h"
#include <cstring>
#include <sstream>

/*  evtx.cpp — décodage des journaux d'événements Windows, hors ligne.
 *
 *  Voir evtx.h pour le format et la raison d'être de ce module. Les commentaires
 *  ici portent sur les choix d'implémentation, pas sur la structure du format.
 */

namespace {

// ---------------------------------------------------------------------------
//  Lectures bornées
// ---------------------------------------------------------------------------
/*  Toutes les lectures passent par ces accesseurs. Le fichier vient de la
 *  machine examinée : un décalage annoncé peut pointer n'importe où, y compris
 *  hors du tampon. Plutôt que de vérifier à chaque site d'appel — donc d'en
 *  oublier — on rend 0 hors limites et on laisse le contrôle de cohérence
 *  décider. Un enregistrement dont les champs valent 0 échoue à la validation ;
 *  il est signalé, il ne provoque pas de lecture hors zone.
 */
inline uint8_t  lire8 (const BYTE* b, size_t taille, size_t o) {
	return (o + 1 <= taille) ? b[o] : 0;
}
inline uint16_t lire16(const BYTE* b, size_t taille, size_t o) {
	if (o + 2 > taille) return 0;
	return (uint16_t)(b[o] | ((uint16_t)b[o + 1] << 8));
}
inline uint32_t lire32(const BYTE* b, size_t taille, size_t o) {
	if (o + 4 > taille) return 0;
	return (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8)
	     | ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24);
}
inline uint64_t lire64(const BYTE* b, size_t taille, size_t o) {
	if (o + 8 > taille) return 0;
	return (uint64_t)lire32(b, taille, o) | ((uint64_t)lire32(b, taille, o + 4) << 32);
}

// ---------------------------------------------------------------------------
//  Constantes du format
// ---------------------------------------------------------------------------
const size_t TAILLE_ENTETE_FICHIER = 4096;
const size_t TAILLE_CHUNK          = 65536;
const size_t TAILLE_ENTETE_CHUNK   = 512;
const size_t DEBUT_ENREGISTREMENTS = 512;   // dans le chunk
const uint32_t SIGNATURE_ENREG     = 0x00002a2a;

//! Jetons BinXML. Le bit 0x40 signifie « d'autres données suivent ».
enum : uint8_t {
	JET_EOF                 = 0x00,
	JET_OUVRE_ELEMENT       = 0x01,
	JET_FERME_DEBUT_BALISE  = 0x02,
	JET_FERME_ELEMENT_VIDE  = 0x03,
	JET_FIN_ELEMENT         = 0x04,
	JET_VALEUR              = 0x05,
	JET_ATTRIBUT            = 0x06,
	JET_CDATA               = 0x07,
	JET_REF_CARACTERE       = 0x08,
	JET_REF_ENTITE          = 0x09,
	JET_PI_CIBLE            = 0x0a,
	JET_PI_DONNEES          = 0x0b,
	JET_INSTANCE_TEMPLATE   = 0x0c,
	JET_SUBST_NORMALE       = 0x0d,
	JET_SUBST_OPTIONNELLE   = 0x0e,
	JET_ENTETE_FRAGMENT     = 0x0f,
};

//! Types de valeur BinXML (le bit 0x80 marque un tableau).
enum : uint8_t {
	T_NULL = 0x00, T_STRING = 0x01, T_ANSI = 0x02,
	T_INT8 = 0x03, T_UINT8 = 0x04, T_INT16 = 0x05, T_UINT16 = 0x06,
	T_INT32 = 0x07, T_UINT32 = 0x08, T_INT64 = 0x09, T_UINT64 = 0x0a,
	T_REAL32 = 0x0b, T_REAL64 = 0x0c, T_BOOL = 0x0d, T_BINAIRE = 0x0e,
	T_GUID = 0x0f, T_SIZE = 0x10, T_FILETIME = 0x11, T_SYSTIME = 0x12,
	T_SID = 0x13, T_HEX32 = 0x14, T_HEX64 = 0x15,
	T_EVTHANDLE = 0x20, T_BINXML = 0x21, T_EVTXML = 0x23,
	T_TABLEAU = 0x80,
};

//! Profondeur d'imbrication maximale. Un chunk corrompu peut décrire un
//! template qui se référence lui-même ; sans garde-fou, la pile déborde.
const unsigned PROFONDEUR_MAX = 24;

// ---------------------------------------------------------------------------
//  Échappement XML
// ---------------------------------------------------------------------------
/*  Les valeurs sortent telles quelles du journal : un nom de fichier peut
 *  contenir « & » ou « < ». Sans échappement, le XML produit serait mal formé
 *  et xml_light rendrait un arbre vide — l'événement serait perdu, pas
 *  seulement mal affiché.
 */
std::wstring echapper(const std::wstring& s) {
	std::wstring r;
	r.reserve(s.size());
	for (wchar_t c : s) {
		switch (c) {
		case L'&':  r += L"&amp;";  break;
		case L'<':  r += L"&lt;";   break;
		case L'>':  r += L"&gt;";   break;
		case L'"':  r += L"&quot;"; break;
		case L'\'': r += L"&apos;"; break;
		default:
			// Les caractères de contrôle sont interdits en XML 1.0 ; un journal
			// peut en contenir (données binaires rendues en chaîne).
			if (c < 0x20 && c != L'\t' && c != L'\n' && c != L'\r') r += L' ';
			else r += c;
		}
	}
	return r;
}

//! Représentation textuelle d'un SID brut, sans passer par une API du système.
std::wstring sidEnTexte(const BYTE* b, size_t taille) {
	if (taille < 8) return L"";
	const uint8_t revision = b[0];
	const uint8_t nbSousAutorites = b[1];
	if (taille < (size_t)8 + 4ULL * nbSousAutorites) return L"";
	// L'autorité est en GROS boutien, contrairement au reste du format.
	uint64_t autorite = 0;
	for (int i = 0; i < 6; ++i) autorite = (autorite << 8) | b[2 + i];
	std::wostringstream o;
	o << L"S-" << (unsigned)revision << L"-" << autorite;
	for (uint8_t i = 0; i < nbSousAutorites; ++i)
		o << L"-" << (unsigned long)lire32(b, taille, 8 + 4ULL * i);
	return o.str();
}

//! Flottant au format attendu par le visualiseur d'événements.
std::wstring reelEnTexte(double v) {
	std::wostringstream o;
	o.precision(6);
	o << std::fixed << v;
	return o.str();
}

// ---------------------------------------------------------------------------
//  Décodeur
// ---------------------------------------------------------------------------

//! Une valeur du tableau d'instance de template.
struct ValeurSubst {
	uint8_t type = T_NULL;
	size_t  offset = 0;   //!< dans le chunk
	size_t  taille = 0;
};

class Decodeur {
public:
	Decodeur(const BYTE* chunk, size_t tailleChunk)
		: c(chunk), tc(tailleChunk) {}

	/*! Décode le corps BinXML d'un enregistrement en texte XML.
	 *  @param debut offset du corps dans le chunk
	 *  @param fin   borne supérieure (fin de l'enregistrement)
	 */
	bool document(size_t debut, size_t fin, std::wstring& sortie) {
		if (debut >= fin || fin > tc) return false;
		size_t p = debut;
		return jetons(p, fin, nullptr, sortie, 0) && !sortie.empty();
	}

private:
	const BYTE* c;
	size_t tc;

	// -- noms ---------------------------------------------------------------
	/*  Un nom est désigné par un offset relatif au chunk, partagé entre
	 *  enregistrements. D'où la nécessité de garder le chunk entier : un
	 *  enregistrement ne se décode pas isolément.
	 */
	std::wstring nom(size_t offset) const {
		if (offset + 8 > tc) return L"";
		const uint16_t nbCar = lire16(c, tc, offset + 6);
		if (offset + 8 + 2ULL * nbCar > tc) return L"";
		return std::wstring(reinterpret_cast<const wchar_t*>(c + offset + 8), nbCar);
	}
	//! Taille occupée par une structure de nom (terminateur compris).
	size_t tailleNom(size_t offset) const {
		if (offset + 8 > tc) return 0;
		return 8 + 2ULL * (lire16(c, tc, offset + 6) + 1);
	}

	// -- valeurs ------------------------------------------------------------
	/*! Rend une valeur typée en texte.
	 *  @param indice pour un type tableau, l'élément voulu ; -1 = tous,
	 *         concaténés (cas qui ne se présente pas dans les journaux réels,
	 *         conservé pour ne rien perdre silencieusement)
	 */
	std::wstring valeur(uint8_t type, size_t off, size_t taille, int indice,
	                    unsigned profondeur) {
		if (off + taille > tc) return L"";
		const BYTE* d = c + off;

		if (type & T_TABLEAU) {
			const uint8_t base = type & 0x7f;
			std::vector<std::wstring> elements = tableau(base, off, taille, profondeur);
			if (indice >= 0)
				return (size_t)indice < elements.size() ? elements[indice] : L"";
			std::wstring r;
			for (size_t i = 0; i < elements.size(); ++i) {
				if (i) r += L" ";
				r += elements[i];
			}
			return r;
		}

		switch (type) {
		case T_NULL: return L"";
		case T_STRING: {
			// Sans terminateur : la taille annoncée fait foi.
			std::wstring s(reinterpret_cast<const wchar_t*>(d), taille / 2);
			while (!s.empty() && s.back() == L'\0') s.pop_back();
			return echapper(s);
		}
		case T_ANSI: {
			std::string s(reinterpret_cast<const char*>(d), taille);
			while (!s.empty() && s.back() == '\0') s.pop_back();
			return echapper(string_to_wstring(s));
		}
		case T_INT8:   return taille >= 1 ? std::to_wstring((int)(int8_t)d[0]) : L"";
		case T_UINT8:  return taille >= 1 ? std::to_wstring((unsigned)d[0]) : L"";
		case T_INT16:  return taille >= 2 ? std::to_wstring((int)(int16_t)lire16(c, tc, off)) : L"";
		case T_UINT16: return taille >= 2 ? std::to_wstring((unsigned)lire16(c, tc, off)) : L"";
		case T_INT32:  return taille >= 4 ? std::to_wstring((int32_t)lire32(c, tc, off)) : L"";
		case T_UINT32: return taille >= 4 ? std::to_wstring((uint32_t)lire32(c, tc, off)) : L"";
		case T_INT64:  return taille >= 8 ? std::to_wstring((int64_t)lire64(c, tc, off)) : L"";
		case T_UINT64: return taille >= 8 ? std::to_wstring((uint64_t)lire64(c, tc, off)) : L"";
		case T_REAL32: {
			if (taille < 4) return L"";
			float f; uint32_t v = lire32(c, tc, off); memcpy(&f, &v, 4);
			return reelEnTexte(f);
		}
		case T_REAL64: {
			if (taille < 8) return L"";
			double v; uint64_t u = lire64(c, tc, off); memcpy(&v, &u, 8);
			return reelEnTexte(v);
		}
		case T_BOOL:
			// 32 bits, pas un octet : « true » quelle que soit la valeur non nulle.
			return taille >= 4 ? (lire32(c, tc, off) ? L"true" : L"false") : L"";
		case T_BINAIRE:
			// Sans conversion : les données binaires d'un événement (4688, 4624)
			// portent de l'information qu'aucune interprétation ne remplace.
			return dump_wstring(const_cast<LPBYTE>(d), 0, (int)taille);
		case T_GUID: {
			if (taille < 16) return L"";
			GUID g; memcpy(&g, d, 16);
			return guid_to_wstring(g);
		}
		case T_SIZE:
			// Apparié à un entier hexadécimal 32 ou 64 bits selon la taille.
			return taille >= 8 ? to_hex((long long)lire64(c, tc, off))
			     : taille >= 4 ? to_hex((long long)lire32(c, tc, off)) : L"";
		case T_FILETIME: {
			if (taille < 8) return L"";
			const uint64_t v = lire64(c, tc, off);
			FILETIME ft = { (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) };
			// Les horodatages des journaux sont en UTC.
			return timeToIso8601Utc(ft);
		}
		case T_SYSTIME: {
			if (taille < 16) return L"";
			SYSTEMTIME st = { 0 };
			st.wYear   = lire16(c, tc, off);      st.wMonth        = lire16(c, tc, off + 2);
			st.wDayOfWeek = lire16(c, tc, off + 4); st.wDay        = lire16(c, tc, off + 6);
			st.wHour   = lire16(c, tc, off + 8);  st.wMinute       = lire16(c, tc, off + 10);
			st.wSecond = lire16(c, tc, off + 12); st.wMilliseconds = lire16(c, tc, off + 14);
			FILETIME ft = { 0 };
			if (!SystemTimeToFileTime(&st, &ft)) return L"";
			return timeToIso8601Utc(ft);
		}
		case T_SID:  return sidEnTexte(d, taille);
		case T_HEX32: return taille >= 4 ? to_hex((long long)(uint32_t)lire32(c, tc, off)) : L"";
		case T_HEX64: return taille >= 8 ? to_hex((long long)lire64(c, tc, off)) : L"";
		case T_BINXML:
		case T_EVTXML: {
			/*  Une valeur peut contenir un fragment BinXML entier : c'est le cas
			 *  des événements de transfert (UserData, RenderingInfo), où le
			 *  contenu réel est imbriqué dans une valeur de substitution. Sans
			 *  cette récursion, ces événements sortent vides. */
			if (profondeur >= PROFONDEUR_MAX) return L"";
			std::wstring imbrique;
			size_t p = off;
			if (!jetons(p, off + taille, nullptr, imbrique, profondeur + 1)) return L"";
			return imbrique;
		}
		case T_EVTHANDLE:
		default:
			// Pas de perte silencieuse : le type inconnu et ses octets sortent.
			log(2, L"🔥evtx : type de valeur non gere : " + to_hex(type));
			return dump_wstring(const_cast<LPBYTE>(d), 0, (int)taille);
		}
	}

	//! Découpe une valeur de type tableau en ses éléments.
	std::vector<std::wstring> tableau(uint8_t base, size_t off, size_t taille,
	                                  unsigned profondeur) {
		std::vector<std::wstring> r;
		if (taille == 0) return r;

		// Chaînes : séparées par leur terminateur, longueur variable.
		if (base == T_STRING) {
			size_t debut = off;
			for (size_t p = off; p + 2 <= off + taille; p += 2) {
				if (lire16(c, tc, p) == 0) {
					r.push_back(valeur(T_STRING, debut, p - debut, -1, profondeur));
					debut = p + 2;
				}
			}
			if (debut < off + taille)
				r.push_back(valeur(T_STRING, debut, off + taille - debut, -1, profondeur));
			return r;
		}
		if (base == T_ANSI) {
			size_t debut = off;
			for (size_t p = off; p < off + taille; ++p) {
				if (c[p] == 0) {
					r.push_back(valeur(T_ANSI, debut, p - debut, -1, profondeur));
					debut = p + 1;
				}
			}
			if (debut < off + taille)
				r.push_back(valeur(T_ANSI, debut, off + taille - debut, -1, profondeur));
			return r;
		}

		// Types de taille fixe.
		size_t pas = 0;
		switch (base) {
		case T_INT8: case T_UINT8:                       pas = 1;  break;
		case T_INT16: case T_UINT16:                     pas = 2;  break;
		case T_INT32: case T_UINT32: case T_REAL32:
		case T_BOOL: case T_HEX32:                       pas = 4;  break;
		case T_INT64: case T_UINT64: case T_REAL64:
		case T_FILETIME: case T_HEX64:                   pas = 8;  break;
		case T_GUID: case T_SYSTIME:                     pas = 16; break;
		case T_SIZE: pas = (taille % 8 == 0) ? 8 : 4;              break;
		case T_SID: {
			// Longueur variable : elle se déduit du nombre de sous-autorités.
			size_t p = off;
			while (p + 8 <= off + taille) {
				const size_t n = 8 + 4ULL * c[p + 1];
				if (p + n > off + taille) break;
				r.push_back(sidEnTexte(c + p, n));
				p += n;
			}
			return r;
		}
		default:
			// Tableau d'un type dont le pas est inconnu : on rend la valeur
			// entière plutôt que de la découper au hasard.
			r.push_back(valeur(base, off, taille, -1, profondeur));
			return r;
		}
		for (size_t p = off; p + pas <= off + taille; p += pas)
			r.push_back(valeur(base, p, pas, -1, profondeur));
		return r;
	}

	//! Nombre d'éléments d'une valeur de substitution de type tableau.
	size_t cardinalite(const ValeurSubst& v, unsigned profondeur) {
		if (!(v.type & T_TABLEAU)) return 1;
		return tableau(v.type & 0x7f, v.offset, v.taille, profondeur).size();
	}

	// -- flux de jetons -----------------------------------------------------
	/*! Décode une suite de jetons (fragment, élément, contenu).
	 *  @param p position courante, avancée au fil de la lecture
	 *  @param fin borne supérieure
	 *  @param subs valeurs de l'instance de template courante, ou nullptr
	 */
	bool jetons(size_t& p, size_t fin, const std::vector<ValeurSubst>* subs,
	            std::wstring& sortie, unsigned profondeur) {
		if (profondeur >= PROFONDEUR_MAX) return false;
		while (p < fin) {
			const uint8_t jeton = lire8(c, tc, p) & 0x0f;
			switch (jeton) {
			case JET_EOF:
				++p;
				return true;
			case JET_ENTETE_FRAGMENT:
				p += 4;                       // jeton, majeur, mineur, drapeaux
				break;
			case JET_OUVRE_ELEMENT:
				if (!element(p, fin, subs, sortie, profondeur)) return false;
				break;
			case JET_INSTANCE_TEMPLATE:
				if (!instanceTemplate(p, fin, sortie, profondeur)) return false;
				break;
			case JET_FIN_ELEMENT:
				++p;
				return true;                  // l'appelant ferme la balise
			case JET_VALEUR:
				if (!valeurTexte(p, fin, sortie, profondeur)) return false;
				break;
			case JET_SUBST_NORMALE:
			case JET_SUBST_OPTIONNELLE: {
				const uint16_t id = lire16(c, tc, p + 1);
				p += 4;
				if (subs && id < subs->size())
					sortie += valeur((*subs)[id].type, (*subs)[id].offset,
					                 (*subs)[id].taille, -1, profondeur);
				break;
			}
			case JET_CDATA: {
				const uint16_t nbCar = lire16(c, tc, p + 1);
				sortie += echapper(nom(p));   // même encodage : longueur + UTF-16
				p += 3 + 2ULL * nbCar;
				break;
			}
			case JET_REF_CARACTERE:
				sortie += L"&#" + std::to_wstring(lire16(c, tc, p + 1)) + L";";
				p += 3;
				break;
			case JET_REF_ENTITE: {
				const std::wstring n = nom(lire32(c, tc, p + 1));
				if (!n.empty()) sortie += L"&" + n + L";";
				p += 5;
				break;
			}
			case JET_PI_CIBLE: p += 5; break;
			case JET_PI_DONNEES: {
				const uint16_t nbCar = lire16(c, tc, p + 1);
				p += 3 + 2ULL * nbCar;
				break;
			}
			default:
				// Jeton inconnu : poursuivre ferait dériver la lecture sur des
				// données arbitraires. On arrête cet enregistrement.
				log(3, L"🔈evtx : jeton inconnu " + to_hex(lire8(c, tc, p)));
				return false;
			}
		}
		return true;
	}

	//! Jeton valeur (0x05/0x45) : du texte littéral dans le contenu.
	bool valeurTexte(size_t& p, size_t fin, std::wstring& sortie, unsigned profondeur) {
		const uint8_t type = lire8(c, tc, p + 1);
		if (type == T_STRING) {
			const uint16_t nbCar = lire16(c, tc, p + 2);
			const size_t octets = 2ULL * nbCar;
			if (p + 4 + octets > fin) return false;
			sortie += valeur(T_STRING, p + 4, octets, -1, profondeur);
			p += 4 + octets;
			return true;
		}
		// Le format n'autorise que le type chaîne ici ; tout autre indique une
		// lecture désynchronisée, qu'il vaut mieux signaler que propager.
		log(3, L"🔈evtx : jeton valeur de type " + to_hex(type));
		return false;
	}

	/*! Décode un élément et l'écrit sous forme de balise XML.
	 *
	 *  Le format place les attributs et le contenu dans le flux, alors que le XML
	 *  les veut de part et d'autre de « > ». Les attributs sont donc assemblés à
	 *  part avant d'écrire la balise d'ouverture.
	 */
	bool element(size_t& p, size_t fin, const std::vector<ValeurSubst>* subs,
	             std::wstring& sortie, unsigned profondeur) {
		if (profondeur >= PROFONDEUR_MAX) return false;
		const uint8_t jeton = lire8(c, tc, p);
		const bool aAttributs = (jeton & 0x40) != 0;

		/*  L'identifiant de dépendance (2 octets) est présent dans les journaux,
		 *  mais absent quand l'élément provient d'une valeur de substitution de
		 *  type BinXML. Rien ne le signale dans le flux : on retient la variante
		 *  dont la taille annoncée et le décalage de nom sont cohérents. */
		size_t q = p + 3;                          // avec identifiant de dépendance
		uint32_t tailleDonnees = lire32(c, tc, q);
		uint32_t offsetNom = lire32(c, tc, q + 4);
		if (offsetNom + 8 > tc || q + 4 + tailleDonnees > fin) {
			q = p + 1;                             // sans identifiant de dépendance
			tailleDonnees = lire32(c, tc, q);
			offsetNom = lire32(c, tc, q + 4);
			if (offsetNom + 8 > tc) return false;
		}
		const size_t finElement = q + 4 + tailleDonnees;
		q += 8;

		const std::wstring nomElement = nom(offsetNom);
		if (nomElement.empty()) return false;
		// Le nom peut être stocké sur place plutôt que référencé ailleurs.
		if (offsetNom == q) q += tailleNom(offsetNom);

		std::wstring attributs;
		if (aAttributs) {
			const uint32_t tailleListe = lire32(c, tc, q);
			q += 4;
			const size_t finListe = (q + tailleListe <= fin) ? q + tailleListe : fin;
			while (q < finListe) {
				const uint8_t jetonAttr = lire8(c, tc, q);
				if ((jetonAttr & 0x0f) != JET_ATTRIBUT) break;
				const uint32_t offsetNomAttr = lire32(c, tc, q + 1);
				q += 5;
				const std::wstring nomAttr = nom(offsetNomAttr);
				if (offsetNomAttr == q) q += tailleNom(offsetNomAttr);

				std::wstring val;
				if (!donneeAttribut(q, finListe, subs, val, profondeur)) break;
				/*  Attribut vide non écrit : le planificateur d'événements omet
				 *  lui-même les attributs sans valeur (`Provider` sans `Guid`),
				 *  et un attribut vide laisserait croire à une donnée absente du
				 *  journal alors qu'elle n'y a jamais été inscrite. */
				if (!nomAttr.empty() && !val.empty())
					attributs += L" " + nomAttr + L"=\"" + val + L"\"";
				if ((jetonAttr & 0x40) == 0) break;   // dernier attribut
			}
			q = finListe;
		}

		const uint8_t fermeture = lire8(c, tc, q);
		if ((fermeture & 0x0f) == JET_FERME_ELEMENT_VIDE) {
			++q;
			sortie += L"<" + nomElement + attributs + L"/>";
			p = (finElement > q) ? finElement : q;
			return true;
		}
		if ((fermeture & 0x0f) != JET_FERME_DEBUT_BALISE) return false;
		++q;

		/*  Substitution de type tableau : la spécification prescrit de répéter
		 *  l'ÉLÉMENT pour chaque élément du tableau — c'est ainsi qu'un
		 *  événement rend plusieurs `<Data>` depuis une seule définition. On ne
		 *  traite ce cas que lorsque la substitution constitue tout le contenu,
		 *  seule forme produite par les journaux Windows. */
		if (subs) {
			const uint8_t j = lire8(c, tc, q) & 0x0f;
			if ((j == JET_SUBST_NORMALE || j == JET_SUBST_OPTIONNELLE)
			    && (lire8(c, tc, q + 4) & 0x0f) == JET_FIN_ELEMENT) {
				const uint16_t id = lire16(c, tc, q + 1);
				if (id < subs->size() && ((*subs)[id].type & T_TABLEAU)) {
					const size_t n = cardinalite((*subs)[id], profondeur);
					for (size_t i = 0; i < n; ++i)
						sortie += L"<" + nomElement + attributs + L">"
						        + valeur((*subs)[id].type, (*subs)[id].offset,
						                 (*subs)[id].taille, (int)i, profondeur)
						        + L"</" + nomElement + L">";
					if (n == 0) sortie += L"<" + nomElement + attributs + L"/>";
					p = finElement;
					return true;
				}
			}
		}

		sortie += L"<" + nomElement + attributs + L">";
		const size_t finContenu = (finElement <= fin) ? finElement : fin;
		if (!jetons(q, finContenu, subs, sortie, profondeur + 1)) {
			// Contenu illisible : la balise est refermée pour que le document
			// reste bien formé, et l'enregistrement reste exploitable en partie.
			sortie += L"</" + nomElement + L">";
			return false;
		}
		sortie += L"</" + nomElement + L">";
		p = (finElement > q) ? finElement : q;
		return true;
	}

	//! Donnée d'un attribut : texte littéral ou substitution.
	bool donneeAttribut(size_t& p, size_t fin, const std::vector<ValeurSubst>* subs,
	                    std::wstring& val, unsigned profondeur) {
		while (p < fin) {
			const uint8_t jeton = lire8(c, tc, p);
			switch (jeton & 0x0f) {
			case JET_VALEUR:
				if (!valeurTexte(p, fin, val, profondeur)) return false;
				break;
			case JET_SUBST_NORMALE:
			case JET_SUBST_OPTIONNELLE: {
				const uint16_t id = lire16(c, tc, p + 1);
				p += 4;
				if (subs && id < subs->size())
					val += valeur((*subs)[id].type, (*subs)[id].offset,
					              (*subs)[id].taille, -1, profondeur);
				break;
			}
			case JET_REF_CARACTERE:
				val += L"&#" + std::to_wstring(lire16(c, tc, p + 1)) + L";";
				p += 3;
				break;
			case JET_REF_ENTITE: {
				const std::wstring n = nom(lire32(c, tc, p + 1));
				if (!n.empty()) val += L"&" + n + L";";
				p += 5;
				break;
			}
			default:
				return true;                  // fin de la donnée de cet attribut
			}
			if ((jeton & 0x40) == 0) return true;   // plus rien ne suit
		}
		return true;
	}

	/*! Décode une instance de template : la définition donne la structure, le
	 *  tableau de valeurs donne le contenu.
	 *
	 *  La définition peut être écrite sur place ou ailleurs dans le chunk — c'est
	 *  ce partage qui rend le format compact, et c'est pour cela qu'un
	 *  enregistrement ne se décode qu'avec son chunk entier sous la main.
	 */
	bool instanceTemplate(size_t& p, size_t fin, std::wstring& sortie,
	                      unsigned profondeur) {
		if (profondeur >= PROFONDEUR_MAX) return false;
		const size_t jeton = p;
		const uint32_t offsetDefinition = lire32(c, tc, jeton + 6);

		/*  « Directement après ce champ » = jeton + 10 : la définition suit, et
		 *  les données d'instance commencent après le fragment. Sinon la
		 *  définition est ailleurs et les données d'instance suivent le champ. */
		const bool surPlace = (offsetDefinition == jeton + 10);
		const size_t d = offsetDefinition;         // pointe le champ « suivante »
		if (d + 24 > tc) return false;
		const uint32_t tailleFragment = lire32(c, tc, d + 20);
		const size_t debutFragment = d + 24;
		if (debutFragment + tailleFragment > tc) return false;

		size_t donnees = surPlace ? (debutFragment + tailleFragment) : (jeton + 10);
		if (donnees + 4 > fin) return false;

		// Tableau des valeurs : descripteurs de 4 octets puis données.
		const uint32_t nbValeurs = lire32(c, tc, donnees);
		donnees += 4;
		// Garde-fou : 4 octets de descripteur minimum par valeur annoncée.
		if (nbValeurs > (fin - donnees) / 4) return false;
		std::vector<ValeurSubst> valeurs(nbValeurs);
		size_t offsetValeur = donnees + 4ULL * nbValeurs;
		for (uint32_t i = 0; i < nbValeurs; ++i) {
			valeurs[i].taille = lire16(c, tc, donnees + 4ULL * i);
			valeurs[i].type   = lire8(c, tc, donnees + 4ULL * i + 2);
			valeurs[i].offset = offsetValeur;
			offsetValeur += valeurs[i].taille;
			if (offsetValeur > tc) return false;
		}

		// Le fragment de la définition est décodé avec ces valeurs.
		size_t q = debutFragment;
		const bool ok = jetons(q, debutFragment + tailleFragment, &valeurs,
		                       sortie, profondeur + 1);
		p = offsetValeur;
		return ok;
	}
};

} // namespace

// ---------------------------------------------------------------------------
//  Lecture du fichier
// ---------------------------------------------------------------------------

std::wstring EvtxCanalDepuisNomFichier(const std::wstring& nomFichier) {
	std::wstring n = nomFichier;
	const size_t sep = n.find_last_of(L"\\/");
	if (sep != std::wstring::npos) n = n.substr(sep + 1);
	if (n.size() > 5 && enMinuscules(n.substr(n.size() - 5)) == L".evtx")
		n = n.substr(0, n.size() - 5);
	// « %4 » est la barre oblique du nom de canal, interdite dans un nom de
	// fichier ; d'autres caractères suivent la même convention.
	std::wstring r;
	for (size_t i = 0; i < n.size(); ++i) {
		if (n[i] == L'%' && i + 1 < n.size() && n[i + 1] == L'4') { r += L'/'; ++i; }
		else r += n[i];
	}
	return r;
}

HRESULT EvtxLireFichier(const std::wstring& chemin,
                        const std::function<bool(const EvtxEnregistrement&)>& surEnregistrement,
                        EvtxBilan* bilan) {
	EvtxBilan local;
	EvtxBilan& b = bilan ? *bilan : local;

	HANDLE h = CreateFileW(chemin.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		const DWORD err = GetLastError();
		b.diagnostic = L"ouverture impossible";
		log(2, L"🔥EvtxLireFichier " + chemin, err);
		return HRESULT_FROM_WIN32(err);
	}

	std::vector<BYTE> entete(TAILLE_ENTETE_FICHIER);
	DWORD lu = 0;
	if (!ReadFile(h, entete.data(), (DWORD)entete.size(), &lu, nullptr)
	    || lu < TAILLE_ENTETE_FICHIER) {
		CloseHandle(h);
		b.diagnostic = L"fichier tronque (" + std::to_wstring(lu) + L" octets)";
		return HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
	}
	if (memcmp(entete.data(), "ElfFile\0", 8) != 0) {
		CloseHandle(h);
		b.diagnostic = L"signature ElfFile absente";
		log(2, L"🔥evtx : " + chemin + L" n'est pas un journal EVTX");
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	b.enteteValide = true;
	const uint16_t drapeaux = lire16(entete.data(), entete.size(), 120);
	b.sale = (drapeaux & 0x0001) != 0;
	const uint16_t nbChunksAnnonces = lire16(entete.data(), entete.size(), 42);

	/*  On parcourt les chunks jusqu'à la fin du fichier, sans se limiter au
	 *  compte annoncé : un journal fermé brutalement en contient souvent
	 *  davantage, et ces chunks-là portent les événements les plus récents —
	 *  précisément ceux qui intéressent l'investigation. */
	std::vector<BYTE> chunk(TAILLE_CHUNK);
	bool continuer = true;
	unsigned long long chunksIgnores = 0;
	while (continuer) {
		if (!ReadFile(h, chunk.data(), (DWORD)chunk.size(), &lu, nullptr) || lu == 0) break;
		if (lu < TAILLE_ENTETE_CHUNK) break;
		if (memcmp(chunk.data(), "ElfChnk\0", 8) != 0) {
			/*  Chunk sans signature : soit de l'espace préalloué jamais écrit
			 *  (fin du fichier), soit un chunk abîmé au MILIEU du journal. On
			 *  ne peut pas distinguer les deux à cet endroit, et s'arrêter au
			 *  premier rencontré coûte cher : sur un journal dont un seul chunk
			 *  est corrompu, cela faisait perdre les 256 enregistrements
			 *  suivants sur 270. On passe donc au chunk suivant.
			 *  Un chunk vide n'est pas compté comme ignoré : seul un chunk qui
			 *  contient quelque chose sans porter la signature est signalé. */
			bool vide = true;
			for (size_t i = 0; i < lu && vide; ++i) if (chunk[i]) vide = false;
			if (!vide) ++chunksIgnores;
			continue;
		}
		++b.chunks;

		/*  « Free space offset » borne les enregistrements écrits. Un chunk
		 *  corrompu peut l'annoncer hors zone : on retombe alors sur la taille
		 *  du chunk, le reste étant filtré par la signature d'enregistrement. */
		size_t finEnregistrements = lire32(chunk.data(), lu, 48);
		if (finEnregistrements <= DEBUT_ENREGISTREMENTS || finEnregistrements > lu)
			finEnregistrements = lu;

		Decodeur decodeur(chunk.data(), lu);
		size_t p = DEBUT_ENREGISTREMENTS;
		while (p + 24 <= finEnregistrements) {
			if (lire32(chunk.data(), lu, p) != SIGNATURE_ENREG) break;
			const uint32_t taille = lire32(chunk.data(), lu, p + 4);
			// Un enregistrement fait au moins l'en-tête (24) et la copie de
			// taille finale (4) ; une taille aberrante arrêterait la lecture
			// sur des données arbitraires.
			if (taille < 28 || p + taille > finEnregistrements) break;

			EvtxEnregistrement e;
			e.identifiant = lire64(chunk.data(), lu, p + 8);
			const uint64_t v = lire64(chunk.data(), lu, p + 16);
			e.ecritUtc.dwLowDateTime  = (DWORD)(v & 0xFFFFFFFFULL);
			e.ecritUtc.dwHighDateTime = (DWORD)(v >> 32);

			if (decodeur.document(p + 24, p + taille - 4, e.xml)) {
				++b.lus;
				if (!surEnregistrement(e)) { continuer = false; break; }
			}
			else {
				++b.illisibles;
				log(3, L"🔈evtx : enregistrement " + std::to_wstring(e.identifiant)
				       + L" illisible dans " + chemin);
			}
			p += taille;
		}
	}
	CloseHandle(h);

	std::wostringstream diag;
	diag << b.chunks << L" chunk(s)";
	if (nbChunksAnnonces != b.chunks) diag << L" (" << nbChunksAnnonces << L" annonce(s))";
	diag << L", " << b.lus << L" enregistrement(s)";
	if (b.illisibles) diag << L", " << b.illisibles << L" illisible(s)";
	if (chunksIgnores) diag << L", " << chunksIgnores << L" chunk(s) abime(s)";
	if (b.sale) diag << L", journal non ferme proprement";
	b.diagnostic = diag.str();
	b.chunksIgnores = chunksIgnores;

	return (b.illisibles || chunksIgnores) ? S_FALSE : ERROR_SUCCESS;
}
