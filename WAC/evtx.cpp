#include "evtx.h"
#include "tools.h"
#include <cstring>
#include <sstream>

/*  evtx.cpp — offline decoding of Windows event logs.
 *
 *  See evtx.h for the format and the reason this module exists. The comments
 *  here are about implementation choices, not about the format's structure.
 */

namespace {

// ---------------------------------------------------------------------------
//  Bounded reads
// ---------------------------------------------------------------------------
/*  Every read goes through these accessors. The file comes from the examined
 *  machine: an announced offset can point anywhere, including outside the
 *  buffer. Rather than checking at every call site — and so forgetting some —
 *  they return 0 out of bounds and let the consistency check decide. A record
 *  whose fields are 0 fails validation; it is reported, it does not cause an
 *  out-of-range read.
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
//  Format constants
// ---------------------------------------------------------------------------
const size_t TAILLE_ENTETE_FICHIER = 4096;
const size_t TAILLE_CHUNK          = 65536;
const size_t TAILLE_ENTETE_CHUNK   = 512;
const size_t DEBUT_ENREGISTREMENTS = 512;   // within the chunk
const uint32_t SIGNATURE_ENREG     = 0x00002a2a;

//! BinXML tokens. Bit 0x40 means "more data follows".
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

//! BinXML value types (bit 0x80 marks an array).
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

//! Maximum nesting depth. A corrupt chunk can describe a template that
//! references itself; without a guard, the stack overflows.
const unsigned PROFONDEUR_MAX = 24;

// ---------------------------------------------------------------------------
//  XML escaping
// ---------------------------------------------------------------------------
/*  Values come straight from the log: a file name can contain "&" or "<".
 *  Without escaping, the XML produced would be malformed and xml_light would
 *  return an empty tree — the event would be lost, not just badly displayed.
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
			// Control characters are forbidden in XML 1.0; a log can contain them
			// (binary data rendered as a string).
			if (c < 0x20 && c != L'\t' && c != L'\n' && c != L'\r') r += L' ';
			else r += c;
		}
	}
	return r;
}

//! Text form of a raw SID, without going through a system API.
std::wstring sidEnTexte(const BYTE* b, size_t taille) {
	if (taille < 8) return L"";
	const uint8_t revision = b[0];
	const uint8_t nbSousAutorites = b[1];
	if (taille < (size_t)8 + 4ULL * nbSousAutorites) return L"";
	// The authority is BIG-endian, unlike the rest of the format.
	uint64_t autorite = 0;
	for (int i = 0; i < 6; ++i) autorite = (autorite << 8) | b[2 + i];
	std::wostringstream o;
	o << L"S-" << (unsigned)revision << L"-" << autorite;
	for (uint8_t i = 0; i < nbSousAutorites; ++i)
		o << L"-" << (unsigned long)lire32(b, taille, 8 + 4ULL * i);
	return o.str();
}

//! Floating-point value in the format Event Viewer expects.
std::wstring reelEnTexte(double v) {
	std::wostringstream o;
	o.precision(6);
	o << std::fixed << v;
	return o.str();
}

// ---------------------------------------------------------------------------
//  Decoder
// ---------------------------------------------------------------------------

//! One value of a template instance's array.
struct ValeurSubst {
	uint8_t type = T_NULL;
	size_t  offset = 0;   //!< within the chunk
	size_t  taille = 0;
};

class Decodeur {
public:
	Decodeur(const BYTE* chunk, size_t tailleChunk)
		: c(chunk), tc(tailleChunk) {}

	/*! Decodes a record's BinXML body into XML text.
	 *  @param debut offset of the body within the chunk
	 *  @param fin   upper bound (end of the record)
	 */
	bool document(size_t debut, size_t fin, std::wstring& sortie) {
		if (debut >= fin || fin > tc) return false;
		size_t p = debut;
		return jetons(p, fin, nullptr, sortie, 0) && !sortie.empty();
	}

private:
	const BYTE* c;
	size_t tc;

	// -- names --------------------------------------------------------------
	/*  A name is designated by an offset relative to the chunk, shared between
	 *  records. Hence the need to keep the whole chunk: a record cannot be
	 *  decoded in isolation.
	 */
	std::wstring nom(size_t offset) const {
		if (offset + 8 > tc) return L"";
		const uint16_t nbCar = lire16(c, tc, offset + 6);
		if (offset + 8 + 2ULL * nbCar > tc) return L"";
		return std::wstring(reinterpret_cast<const wchar_t*>(c + offset + 8), nbCar);
	}
	//! Size taken by a name structure (terminator included).
	size_t tailleNom(size_t offset) const {
		if (offset + 8 > tc) return 0;
		return 8 + 2ULL * (lire16(c, tc, offset + 6) + 1);
	}

	// -- values -------------------------------------------------------------
	/*! Renders a typed value as text.
	 *  @param indice for an array type, the wanted element; -1 = all of them,
	 *         concatenated (a case that does not occur in real logs, kept so as
	 *         to lose nothing silently)
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
			// No terminator: the announced size is authoritative.
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
			// 32 bits, not a byte: "true" whatever the non-zero value.
			return taille >= 4 ? (lire32(c, tc, off) ? L"true" : L"false") : L"";
		case T_BINAIRE:
			// No conversion: the binary data of an event (4688, 4624) carry
			// information that no interpretation replaces.
			return dump_wstring(const_cast<LPBYTE>(d), 0, (int)taille);
		case T_GUID: {
			if (taille < 16) return L"";
			GUID g; memcpy(&g, d, 16);
			return guid_to_wstring(g);
		}
		case T_SIZE:
			// Matched to a 32- or 64-bit hexadecimal integer depending on the size.
			return taille >= 8 ? to_hex((long long)lire64(c, tc, off))
			     : taille >= 4 ? to_hex((long long)lire32(c, tc, off)) : L"";
		case T_FILETIME: {
			if (taille < 8) return L"";
			const uint64_t v = lire64(c, tc, off);
			FILETIME ft = { (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) };
			// Log timestamps are in UTC.
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
			/*  A value can hold a whole BinXML fragment: that is the case of
			 *  forwarded events (UserData, RenderingInfo), where the real content is
			 *  nested inside a substitution value. Without this recursion, these
			 *  events come out empty. */
			if (profondeur >= PROFONDEUR_MAX) return L"";
			std::wstring imbrique;
			size_t p = off;
			if (!jetons(p, off + taille, nullptr, imbrique, profondeur + 1)) return L"";
			return imbrique;
		}
		case T_EVTHANDLE:
		default:
			// No silent loss: the unknown type and its bytes are output.
			log(2, L"🔥evtx : type de valeur non gere : " + to_hex(type));
			return dump_wstring(const_cast<LPBYTE>(d), 0, (int)taille);
		}
	}

	//! Splits an array-typed value into its elements.
	std::vector<std::wstring> tableau(uint8_t base, size_t off, size_t taille,
	                                  unsigned profondeur) {
		std::vector<std::wstring> r;
		if (taille == 0) return r;

		// Strings: separated by their terminator, variable length.
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

		// Fixed-size types.
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
			// Variable length: derived from the number of sub-authorities.
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
			// Array of a type whose stride is unknown: return the whole value
			// rather than splitting it at random.
			r.push_back(valeur(base, off, taille, -1, profondeur));
			return r;
		}
		for (size_t p = off; p + pas <= off + taille; p += pas)
			r.push_back(valeur(base, p, pas, -1, profondeur));
		return r;
	}

	//! Number of elements of an array-typed substitution value.
	size_t cardinalite(const ValeurSubst& v, unsigned profondeur) {
		if (!(v.type & T_TABLEAU)) return 1;
		return tableau(v.type & 0x7f, v.offset, v.taille, profondeur).size();
	}

	// -- token stream -------------------------------------------------------
	/*! Decodes a sequence of tokens (fragment, element, content).
	 *  @param p current position, advanced as reading goes
	 *  @param fin upper bound
	 *  @param subs values of the current template instance, or nullptr
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
				return true;                  // the caller closes the tag
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
				sortie += echapper(nom(p));   // same encoding: length + UTF-16
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
				// Unknown token: going on would make the reading drift over arbitrary
				// data. This record is abandoned.
				log(3, L"🔈evtx : jeton inconnu " + to_hex(lire8(c, tc, p)));
				return false;
			}
		}
		return true;
	}

	//! Value token (0x05/0x45): literal text in the content.
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
		// The format only allows the string type here; anything else means a
		// desynchronised read, better reported than propagated.
		log(3, L"🔈evtx : jeton valeur de type " + to_hex(type));
		return false;
	}

	/*! Decodes an element and writes it as an XML tag.
	 *
	 *  The format puts attributes and content in the stream, whereas XML wants
	 *  them on either side of ">". Attributes are therefore gathered separately
	 *  before writing the opening tag.
	 */
	bool element(size_t& p, size_t fin, const std::vector<ValeurSubst>* subs,
	             std::wstring& sortie, unsigned profondeur) {
		if (profondeur >= PROFONDEUR_MAX) return false;
		const uint8_t jeton = lire8(c, tc, p);
		const bool aAttributs = (jeton & 0x40) != 0;

		/*  The dependency identifier (2 bytes) is present in the logs, but absent
		 *  when the element comes from a BinXML-typed substitution value. Nothing
		 *  in the stream says so: the variant whose announced size and name offset
		 *  are consistent is kept. */
		size_t q = p + 3;                          // with dependency identifier
		uint32_t tailleDonnees = lire32(c, tc, q);
		uint32_t offsetNom = lire32(c, tc, q + 4);
		if (offsetNom + 8 > tc || q + 4 + tailleDonnees > fin) {
			q = p + 1;                             // without dependency identifier
			tailleDonnees = lire32(c, tc, q);
			offsetNom = lire32(c, tc, q + 4);
			if (offsetNom + 8 > tc) return false;
		}
		const size_t finElement = q + 4 + tailleDonnees;
		q += 8;

		const std::wstring nomElement = nom(offsetNom);
		if (nomElement.empty()) return false;
		// The name can be stored in place rather than referenced elsewhere.
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
				/*  Empty attribute not written: the event log itself omits
				 *  attributes without a value (`Provider` without `Guid`), and an empty
				 *  attribute would suggest data missing from the log when it was never
				 *  written there. */
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

		/*  Array-typed substitution: the specification requires repeating the
		 *  ELEMENT for each element of the array — that is how an event renders
		 *  several `<Data>` from a single definition. This case is only handled
		 *  when the substitution is the whole content, the only form Windows logs
		 *  produce. */
		if (subs) {
			const uint8_t j = lire8(c, tc, q) & 0x0f;
			if ((j == JET_SUBST_NORMALE || j == JET_SUBST_OPTIONNELLE)
			    && (lire8(c, tc, q + 4) & 0x0f) == JET_FIN_ELEMENT) {
				const uint16_t id = lire16(c, tc, q + 1);

				/*  OPTIONAL SUBSTITUTION WITH A NULL VALUE: the element is not
				    created. That is the format's rule, and it carries meaning: an empty
				    `<EventID></EventID>` reads as an identifier that could not be
				    decoded, whereas the record holds none. Seen on a real machine: a
				    record whose 16 substitutions are null came out with its whole System
				    section present and empty, which looked like a decoding defect — it
				    was the opposite, a faithful reading badly rendered. */
				if (j == JET_SUBST_OPTIONNELLE && id < subs->size()
				    && (*subs)[id].type == T_NULL) {
					p = finElement;
					return true;
				}

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
			// Unreadable content: the tag is closed so that the document stays
			// well-formed, and the record stays partly usable.
			sortie += L"</" + nomElement + L">";
			return false;
		}
		sortie += L"</" + nomElement + L">";
		p = (finElement > q) ? finElement : q;
		return true;
	}

	//! Data of an attribute: literal text or substitution.
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
				return true;                  // end of this attribute's data
			}
			if ((jeton & 0x40) == 0) return true;   // nothing follows
		}
		return true;
	}

	/*! Decodes a template instance: the definition gives the structure, the
	 *  value array gives the content.
	 *
	 *  The definition can be written in place or elsewhere in the chunk — that
	 *  sharing is what makes the format compact, and why a record can only be
	 *  decoded with its whole chunk at hand.
	 */
	bool instanceTemplate(size_t& p, size_t fin, std::wstring& sortie,
	                      unsigned profondeur) {
		if (profondeur >= PROFONDEUR_MAX) return false;
		const size_t jeton = p;
		const uint32_t offsetDefinition = lire32(c, tc, jeton + 6);

		/*  "Right after this field" = token + 10: the definition follows, and the
		 *  instance data start after the fragment. Otherwise the definition is
		 *  elsewhere and the instance data follow the field. */
		const bool surPlace = (offsetDefinition == jeton + 10);
		const size_t d = offsetDefinition;         // points to the "next" field
		if (d + 24 > tc) return false;
		const uint32_t tailleFragment = lire32(c, tc, d + 20);
		const size_t debutFragment = d + 24;
		if (debutFragment + tailleFragment > tc) return false;

		size_t donnees = surPlace ? (debutFragment + tailleFragment) : (jeton + 10);
		if (donnees + 4 > fin) return false;

		// Value array: 4-byte descriptors, then data.
		const uint32_t nbValeurs = lire32(c, tc, donnees);
		donnees += 4;
		// Guard: at least a 4-byte descriptor per announced value.
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

		// The definition's fragment is decoded with these values.
		size_t q = debutFragment;
		const bool ok = jetons(q, debutFragment + tailleFragment, &valeurs,
		                       sortie, profondeur + 1);
		p = offsetValeur;
		return ok;
	}
};

} // namespace

// ---------------------------------------------------------------------------
//  Reading the file
// ---------------------------------------------------------------------------

std::wstring EvtxCanalDepuisNomFichier(const std::wstring& nomFichier) {
	std::wstring n = nomFichier;
	const size_t sep = n.find_last_of(L"\\/");
	if (sep != std::wstring::npos) n = n.substr(sep + 1);
	if (n.size() > 5 && enMinuscules(n.substr(n.size() - 5)) == L".evtx")
		n = n.substr(0, n.size() - 5);
	// "%4" is the slash of the channel name, forbidden in a file name;
	// other characters follow the same convention.
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

	/*  Chunks are walked to the end of the file, not just up to the announced
	 *  count: a log closed abruptly often holds more, and those chunks carry the
	 *  most recent events — precisely the ones the investigation wants. */
	std::vector<BYTE> chunk(TAILLE_CHUNK);
	bool continuer = true;
	unsigned long long chunksIgnores = 0;
	while (continuer) {
		if (!ReadFile(h, chunk.data(), (DWORD)chunk.size(), &lu, nullptr) || lu == 0) break;
		if (lu < TAILLE_ENTETE_CHUNK) break;
		if (memcmp(chunk.data(), "ElfChnk\0", 8) != 0) {
			/*  Chunk without a signature: either preallocated space never written
			 *  (end of the file), or a damaged chunk in the MIDDLE of the log. The two
			 *  cannot be told apart here, and stopping at the first one is costly:
			 *  on a log with a single corrupt chunk, it lost the next 256 records
			 *  out of 270. So we move on to the next chunk.
			 *  An empty chunk is not counted as skipped: only a chunk that holds
			 *  something without the signature is reported. */
			bool vide = true;
			for (size_t i = 0; i < lu && vide; ++i) if (chunk[i]) vide = false;
			if (!vide) ++chunksIgnores;
			continue;
		}
		++b.chunks;

		/*  "Free space offset" bounds the written records. A corrupt chunk can
		 *  announce it out of range: the chunk size is then used, the rest being
		 *  filtered by the record signature. */
		size_t finEnregistrements = lire32(chunk.data(), lu, 48);
		if (finEnregistrements <= DEBUT_ENREGISTREMENTS || finEnregistrements > lu)
			finEnregistrements = lu;

		Decodeur decodeur(chunk.data(), lu);
		size_t p = DEBUT_ENREGISTREMENTS;
		while (p + 24 <= finEnregistrements) {
			if (lire32(chunk.data(), lu, p) != SIGNATURE_ENREG) break;
			const uint32_t taille = lire32(chunk.data(), lu, p + 4);
			// A record takes at least the header (24) and the trailing size copy
			// (4); an absurd size would stop the reading on arbitrary data.
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
