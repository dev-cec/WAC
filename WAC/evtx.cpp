#include "evtx.h"
#include "tools.h"
#include <cstring>
#include <sstream>

/*! \file
 *  \brief Offline decoding of Windows event logs.
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
inline uint8_t  read8 (const BYTE* b, size_t size, size_t o) {
	return (o + 1 <= size) ? b[o] : 0;
}
inline uint16_t read16(const BYTE* b, size_t size, size_t o) {
	if (o + 2 > size) return 0;
	return (uint16_t)(b[o] | ((uint16_t)b[o + 1] << 8));
}
inline uint32_t read32(const BYTE* b, size_t size, size_t o) {
	if (o + 4 > size) return 0;
	return (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8)
	     | ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24);
}
inline uint64_t read64(const BYTE* b, size_t size, size_t o) {
	if (o + 8 > size) return 0;
	return (uint64_t)read32(b, size, o) | ((uint64_t)read32(b, size, o + 4) << 32);
}

// ---------------------------------------------------------------------------
//  Format constants
// ---------------------------------------------------------------------------
const size_t FILE_HEADER_SIZE = 4096;
const size_t CHUNK_SIZE          = 65536;
const size_t CHUNK_HEADER_SIZE   = 512;
const size_t RECORDS_START = 512;   // within the chunk
const uint32_t SIGNATURE_ENREG     = 0x00002a2a;

//! BinXML tokens. Bit 0x40 means "more data follows".
enum : uint8_t {
	JET_EOF                 = 0x00,
	TOKEN_OPEN_ELEMENT       = 0x01,
	TOKEN_CLOSE_START_TAG  = 0x02,
	TOKEN_CLOSE_EMPTY_ELEMENT  = 0x03,
	JET_FIN_ELEMENT         = 0x04,
	TOKEN_VALUE              = 0x05,
	TOKEN_ATTRIBUTE            = 0x06,
	JET_CDATA               = 0x07,
	TOKEN_CHAR_REF       = 0x08,
	TOKEN_ENTITY_REF          = 0x09,
	TOKEN_PI_TARGET            = 0x0a,
	TOKEN_PI_DATA          = 0x0b,
	JET_INSTANCE_TEMPLATE   = 0x0c,
	TOKEN_SUBST_NORMAL       = 0x0d,
	TOKEN_SUBST_OPTIONAL   = 0x0e,
	TOKEN_FRAGMENT_HEADER     = 0x0f,
};

//! BinXML value types (bit 0x80 marks an array).
enum : uint8_t {
	T_NULL = 0x00, T_STRING = 0x01, T_ANSI = 0x02,
	T_INT8 = 0x03, T_UINT8 = 0x04, T_INT16 = 0x05, T_UINT16 = 0x06,
	T_INT32 = 0x07, T_UINT32 = 0x08, T_INT64 = 0x09, T_UINT64 = 0x0a,
	T_REAL32 = 0x0b, T_REAL64 = 0x0c, T_BOOL = 0x0d, T_BINARY = 0x0e,
	T_GUID = 0x0f, T_SIZE = 0x10, T_FILETIME = 0x11, T_SYSTIME = 0x12,
	T_SID = 0x13, T_HEX32 = 0x14, T_HEX64 = 0x15,
	T_EVTHANDLE = 0x20, T_BINXML = 0x21, T_EVTXML = 0x23,
	T_ARRAY = 0x80,
};

//! Maximum nesting depth. A corrupt chunk can describe a template that
//! references itself; without a guard, the stack overflows.
const unsigned MAX_DEPTH = 24;

// ---------------------------------------------------------------------------
//  XML escaping
// ---------------------------------------------------------------------------
/*  Values come straight from the log: a file name can contain "&" or "<".
 *  Without escaping, the XML produced would be malformed and xml_light would
 *  return an empty tree — the event would be lost, not just badly displayed.
 */
std::wstring escape(const std::wstring& s) {
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

//! Floating-point value in the format Event Viewer expects.
std::wstring realToText(double v) {
	std::wostringstream o;
	o.precision(6);
	o << std::fixed << v;
	return o.str();
}

// ---------------------------------------------------------------------------
//  Decoder
// ---------------------------------------------------------------------------

//! One value of a template instance's array.
struct SubstValue {
	uint8_t type = T_NULL;
	size_t  offset = 0;   //!< within the chunk
	size_t  size = 0;
};

class Decoder {
public:
	Decoder(const BYTE* chunk, size_t chunkSize)
		: c(chunk), tc(chunkSize) {}

	/*! Decodes a record's BinXML body into XML text.
	 *  @param start offset of the body within the chunk
	 *  @param end   upper bound (end of the record)
	 */
	bool document(size_t start, size_t end, std::wstring& output) {
		if (start >= end || end > tc) return false;
		size_t p = start;
		return tokens(p, end, nullptr, output, 0) && !output.empty();
	}

private:
	const BYTE* c;
	size_t tc;

	// -- names --------------------------------------------------------------
	/*  A name is designated by an offset relative to the chunk, shared between
	 *  records. Hence the need to keep the whole chunk: a record cannot be
	 *  decoded in isolation.
	 */
	std::wstring name(size_t offset) const {
		if (offset + 8 > tc) return L"";
		const uint16_t nbCar = read16(c, tc, offset + 6);
		if (offset + 8 + 2ULL * nbCar > tc) return L"";
		return std::wstring(reinterpret_cast<const wchar_t*>(c + offset + 8), nbCar);
	}
	//! Size taken by a name structure (terminator included).
	size_t nameSize(size_t offset) const {
		if (offset + 8 > tc) return 0;
		return 8 + 2ULL * (read16(c, tc, offset + 6) + 1);
	}

	// -- values -------------------------------------------------------------
	/*! Renders a typed value as text.
	 *  @param index for an array type, the wanted element; -1 = all of them,
	 *         concatenated (a case that does not occur in real logs, kept so as
	 *         to lose nothing silently)
	 */
	std::wstring value(uint8_t type, size_t off, size_t size, int index,
	                    unsigned depth) {
		if (off + size > tc) return L"";
		const BYTE* d = c + off;

		if (type & T_ARRAY) {
			const uint8_t base = type & 0x7f;
			std::vector<std::wstring> elements = array(base, off, size, depth);
			if (index >= 0)
				return (size_t)index < elements.size() ? elements[index] : L"";
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
			std::wstring s(reinterpret_cast<const wchar_t*>(d), size / 2);
			while (!s.empty() && s.back() == L'\0') s.pop_back();
			return escape(s);
		}
		case T_ANSI: {
			std::string s(reinterpret_cast<const char*>(d), size);
			while (!s.empty() && s.back() == '\0') s.pop_back();
			return escape(decodeText(s));
		}
		case T_INT8:   return size >= 1 ? std::to_wstring((int)(int8_t)d[0]) : L"";
		case T_UINT8:  return size >= 1 ? std::to_wstring((unsigned)d[0]) : L"";
		case T_INT16:  return size >= 2 ? std::to_wstring((int)(int16_t)read16(c, tc, off)) : L"";
		case T_UINT16: return size >= 2 ? std::to_wstring((unsigned)read16(c, tc, off)) : L"";
		case T_INT32:  return size >= 4 ? std::to_wstring((int32_t)read32(c, tc, off)) : L"";
		case T_UINT32: return size >= 4 ? std::to_wstring((uint32_t)read32(c, tc, off)) : L"";
		case T_INT64:  return size >= 8 ? std::to_wstring((int64_t)read64(c, tc, off)) : L"";
		case T_UINT64: return size >= 8 ? std::to_wstring((uint64_t)read64(c, tc, off)) : L"";
		case T_REAL32: {
			if (size < 4) return L"";
			float f; uint32_t v = read32(c, tc, off); memcpy(&f, &v, 4);
			return realToText(f);
		}
		case T_REAL64: {
			if (size < 8) return L"";
			double v; uint64_t u = read64(c, tc, off); memcpy(&v, &u, 8);
			return realToText(v);
		}
		case T_BOOL:
			// 32 bits, not a byte: "true" whatever the non-zero value.
			return size >= 4 ? (read32(c, tc, off) ? L"true" : L"false") : L"";
		case T_BINARY:
			// No conversion: the binary data of an event (4688, 4624) carry
			// information that no interpretation replaces.
			return dump_wstring(const_cast<LPBYTE>(d), 0, (int)size);
		case T_GUID: {
			if (size < 16) return L"";
			GUID g; memcpy(&g, d, 16);
			return guid_to_wstring(g);
		}
		case T_SIZE:
			// Matched to a 32- or 64-bit hexadecimal integer depending on the size.
			return size >= 8 ? to_hex(read64(c, tc, off))
			     : size >= 4 ? to_hex(read32(c, tc, off)) : L"";
		case T_FILETIME: {
			if (size < 8) return L"";
			const uint64_t v = read64(c, tc, off);
			FILETIME ft = { (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) };
			// Log timestamps are in UTC.
			return timeToIso8601Utc(ft);
		}
		case T_SYSTIME: {
			if (size < 16) return L"";
			SYSTEMTIME st = { 0 };
			st.wYear   = read16(c, tc, off);      st.wMonth        = read16(c, tc, off + 2);
			st.wDayOfWeek = read16(c, tc, off + 4); st.wDay        = read16(c, tc, off + 6);
			st.wHour   = read16(c, tc, off + 8);  st.wMinute       = read16(c, tc, off + 10);
			st.wSecond = read16(c, tc, off + 12); st.wMilliseconds = read16(c, tc, off + 14);
			FILETIME ft = { 0 };
			if (!SystemTimeToFileTime(&st, &ft)) return L"";
			return timeToIso8601Utc(ft);
		}
		case T_SID:  return sidToText(d, size);
		case T_HEX32: return size >= 4 ? to_hex((uint32_t)read32(c, tc, off)) : L"";
		case T_HEX64: return size >= 8 ? to_hex(read64(c, tc, off)) : L"";
		case T_BINXML:
		case T_EVTXML: {
			/*  A value can hold a whole BinXML fragment: that is the case of
			 *  forwarded events (UserData, RenderingInfo), where the real content is
			 *  nested inside a substitution value. Without this recursion, these
			 *  events come out empty. */
			if (depth >= MAX_DEPTH) return L"";
			std::wstring nested;
			size_t p = off;
			if (!tokens(p, off + size, nullptr, nested, depth + 1)) return L"";
			return nested;
		}
		case T_EVTHANDLE:
		default:
			// No silent loss: the unknown type and its bytes are output.
			log(2, L"🔥evtx: value type not handled: " + to_hex(type));
			return dump_wstring(const_cast<LPBYTE>(d), 0, (int)size);
		}
	}

	//! Splits an array-typed value into its elements.
	std::vector<std::wstring> array(uint8_t base, size_t off, size_t size,
	                                  unsigned depth) {
		std::vector<std::wstring> r;
		if (size == 0) return r;

		// Strings: separated by their terminator, variable length.
		if (base == T_STRING) {
			size_t start = off;
			for (size_t p = off; p + 2 <= off + size; p += 2) {
				if (read16(c, tc, p) == 0) {
					r.push_back(value(T_STRING, start, p - start, -1, depth));
					start = p + 2;
				}
			}
			if (start < off + size)
				r.push_back(value(T_STRING, start, off + size - start, -1, depth));
			return r;
		}
		if (base == T_ANSI) {
			size_t start = off;
			for (size_t p = off; p < off + size; ++p) {
				if (c[p] == 0) {
					r.push_back(value(T_ANSI, start, p - start, -1, depth));
					start = p + 1;
				}
			}
			if (start < off + size)
				r.push_back(value(T_ANSI, start, off + size - start, -1, depth));
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
		case T_SIZE: pas = (size % 8 == 0) ? 8 : 4;              break;
		case T_SID: {
			// Variable length: derived from the number of sub-authorities.
			size_t p = off;
			while (p + 8 <= off + size) {
				const size_t n = 8 + 4ULL * c[p + 1];
				if (p + n > off + size) break;
				r.push_back(sidToText(c + p, n));
				p += n;
			}
			return r;
		}
		default:
			// Array of a type whose stride is unknown: return the whole value
			// rather than splitting it at random.
			r.push_back(value(base, off, size, -1, depth));
			return r;
		}
		for (size_t p = off; p + pas <= off + size; p += pas)
			r.push_back(value(base, p, pas, -1, depth));
		return r;
	}

	//! Number of elements of an array-typed substitution value.
	size_t cardinalite(const SubstValue& v, unsigned depth) {
		if (!(v.type & T_ARRAY)) return 1;
		return array(v.type & 0x7f, v.offset, v.size, depth).size();
	}

	// -- token stream -------------------------------------------------------
	/*! Decodes a sequence of tokens (fragment, element, content).
	 *  @param p current position, advanced as reading goes
	 *  @param end upper bound
	 *  @param subs values of the current template instance, or nullptr
	 */
	bool tokens(size_t& p, size_t end, const std::vector<SubstValue>* subs,
	            std::wstring& output, unsigned depth) {
		if (depth >= MAX_DEPTH) return false;
		while (p < end) {
			const uint8_t token = read8(c, tc, p) & 0x0f;
			switch (token) {
			case JET_EOF:
				++p;
				return true;
			case TOKEN_FRAGMENT_HEADER:
				p += 4;                       // token, major, minor, flags
				break;
			case TOKEN_OPEN_ELEMENT:
				if (!element(p, end, subs, output, depth)) return false;
				break;
			case JET_INSTANCE_TEMPLATE:
				if (!instanceTemplate(p, end, output, depth)) return false;
				break;
			case JET_FIN_ELEMENT:
				++p;
				return true;                  // the caller closes the tag
			case TOKEN_VALUE:
				if (!textValue(p, end, output, depth)) return false;
				break;
			case TOKEN_SUBST_NORMAL:
			case TOKEN_SUBST_OPTIONAL: {
				const uint16_t id = read16(c, tc, p + 1);
				p += 4;
				if (subs && id < subs->size())
					output += value((*subs)[id].type, (*subs)[id].offset,
					                 (*subs)[id].size, -1, depth);
				break;
			}
			case JET_CDATA: {
				const uint16_t nbCar = read16(c, tc, p + 1);
				output += escape(name(p));   // same encoding: length + UTF-16
				p += 3 + 2ULL * nbCar;
				break;
			}
			case TOKEN_CHAR_REF:
				output += L"&#" + std::to_wstring(read16(c, tc, p + 1)) + L";";
				p += 3;
				break;
			case TOKEN_ENTITY_REF: {
				const std::wstring n = name(read32(c, tc, p + 1));
				if (!n.empty()) output += L"&" + n + L";";
				p += 5;
				break;
			}
			case TOKEN_PI_TARGET: p += 5; break;
			case TOKEN_PI_DATA: {
				const uint16_t nbCar = read16(c, tc, p + 1);
				p += 3 + 2ULL * nbCar;
				break;
			}
			default:
				// Unknown token: going on would make the reading drift over arbitrary
				// data. This record is abandoned.
				log(3, L"🔈evtx: unknown token " + to_hex(read8(c, tc, p)));
				return false;
			}
		}
		return true;
	}

	//! Value token (0x05/0x45): literal text in the content.
	bool textValue(size_t& p, size_t end, std::wstring& output, unsigned depth) {
		const uint8_t type = read8(c, tc, p + 1);
		if (type == T_STRING) {
			const uint16_t nbCar = read16(c, tc, p + 2);
			const size_t bytes = 2ULL * nbCar;
			if (p + 4 + bytes > end) return false;
			output += value(T_STRING, p + 4, bytes, -1, depth);
			p += 4 + bytes;
			return true;
		}
		// The format only allows the string type here; anything else means a
		// desynchronised read, better reported than propagated.
		log(3, L"🔈evtx: value token of type " + to_hex(type));
		return false;
	}

	/*! Decodes an element and writes it as an XML tag.
	 *
	 *  The format puts attributes and content in the stream, whereas XML wants
	 *  them on either side of ">". Attributes are therefore gathered separately
	 *  before writing the opening tag.
	 */
	bool element(size_t& p, size_t end, const std::vector<SubstValue>* subs,
	             std::wstring& output, unsigned depth) {
		if (depth >= MAX_DEPTH) return false;
		const uint8_t token = read8(c, tc, p);
		const bool hasAttributes = (token & 0x40) != 0;

		/*  The dependency identifier (2 bytes) is present in the logs, but absent
		 *  when the element comes from a BinXML-typed substitution value. Nothing
		 *  in the stream says so: the variant whose announced size and name offset
		 *  are consistent is kept. */
		size_t q = p + 3;                          // with dependency identifier
		uint32_t dataSize = read32(c, tc, q);
		uint32_t nameOffset = read32(c, tc, q + 4);
		if (nameOffset + 8 > tc || q + 4 + dataSize > end) {
			q = p + 1;                             // without dependency identifier
			dataSize = read32(c, tc, q);
			nameOffset = read32(c, tc, q + 4);
			if (nameOffset + 8 > tc) return false;
		}
		const size_t finElement = q + 4 + dataSize;
		q += 8;

		const std::wstring elementName = name(nameOffset);
		if (elementName.empty()) return false;
		// The name can be stored in place rather than referenced elsewhere.
		if (nameOffset == q) q += nameSize(nameOffset);

		std::wstring attributes;
		if (hasAttributes) {
			const uint32_t listSize = read32(c, tc, q);
			q += 4;
			const size_t listEnd = (q + listSize <= end) ? q + listSize : end;
			while (q < listEnd) {
				const uint8_t attrToken = read8(c, tc, q);
				if ((attrToken & 0x0f) != TOKEN_ATTRIBUTE) break;
				const uint32_t attrNameOffset = read32(c, tc, q + 1);
				q += 5;
				const std::wstring attrName = name(attrNameOffset);
				if (attrNameOffset == q) q += nameSize(attrNameOffset);

				std::wstring val;
				if (!attributeData(q, listEnd, subs, val, depth)) break;
				/*  Empty attribute not written: the event log itself omits
				 *  attributes without a value (`Provider` without `Guid`), and an empty
				 *  attribute would suggest data missing from the log when it was never
				 *  written there. */
				if (!attrName.empty() && !val.empty())
					attributes += L" " + attrName + L"=\"" + val + L"\"";
				if ((attrToken & 0x40) == 0) break;   // last attribute
			}
			q = listEnd;
		}

		const uint8_t closing = read8(c, tc, q);
		if ((closing & 0x0f) == TOKEN_CLOSE_EMPTY_ELEMENT) {
			++q;
			output += L"<" + elementName + attributes + L"/>";
			p = (finElement > q) ? finElement : q;
			return true;
		}
		if ((closing & 0x0f) != TOKEN_CLOSE_START_TAG) return false;
		++q;

		/*  Array-typed substitution: the specification requires repeating the
		 *  ELEMENT for each element of the array — that is how an event renders
		 *  several `<Data>` from a single definition. This case is only handled
		 *  when the substitution is the whole content, the only form Windows logs
		 *  produce. */
		if (subs) {
			const uint8_t j = read8(c, tc, q) & 0x0f;
			if ((j == TOKEN_SUBST_NORMAL || j == TOKEN_SUBST_OPTIONAL)
			    && (read8(c, tc, q + 4) & 0x0f) == JET_FIN_ELEMENT) {
				const uint16_t id = read16(c, tc, q + 1);

				/*  OPTIONAL SUBSTITUTION WITH A NULL VALUE: the element is not
				    created. That is the format's rule, and it carries meaning: an empty
				    `<EventID></EventID>` reads as an identifier that could not be
				    decoded, whereas the record holds none. Seen on a real machine: a
				    record whose 16 substitutions are null came out with its whole System
				    section present and empty, which looked like a decoding defect — it
				    was the opposite, a faithful reading badly rendered. */
				if (j == TOKEN_SUBST_OPTIONAL && id < subs->size()
				    && (*subs)[id].type == T_NULL) {
					p = finElement;
					return true;
				}

				if (id < subs->size() && ((*subs)[id].type & T_ARRAY)) {
					const size_t n = cardinalite((*subs)[id], depth);
					for (size_t i = 0; i < n; ++i)
						output += L"<" + elementName + attributes + L">"
						        + value((*subs)[id].type, (*subs)[id].offset,
						                 (*subs)[id].size, (int)i, depth)
						        + L"</" + elementName + L">";
					if (n == 0) output += L"<" + elementName + attributes + L"/>";
					p = finElement;
					return true;
				}
			}
		}

		output += L"<" + elementName + attributes + L">";
		const size_t contentEnd = (finElement <= end) ? finElement : end;
		if (!tokens(q, contentEnd, subs, output, depth + 1)) {
			// Unreadable content: the tag is closed so that the document stays
			// well-formed, and the record stays partly usable.
			output += L"</" + elementName + L">";
			return false;
		}
		output += L"</" + elementName + L">";
		p = (finElement > q) ? finElement : q;
		return true;
	}

	//! Data of an attribute: literal text or substitution.
	bool attributeData(size_t& p, size_t end, const std::vector<SubstValue>* subs,
	                    std::wstring& val, unsigned depth) {
		while (p < end) {
			const uint8_t token = read8(c, tc, p);
			switch (token & 0x0f) {
			case TOKEN_VALUE:
				if (!textValue(p, end, val, depth)) return false;
				break;
			case TOKEN_SUBST_NORMAL:
			case TOKEN_SUBST_OPTIONAL: {
				const uint16_t id = read16(c, tc, p + 1);
				p += 4;
				if (subs && id < subs->size())
					val += value((*subs)[id].type, (*subs)[id].offset,
					              (*subs)[id].size, -1, depth);
				break;
			}
			case TOKEN_CHAR_REF:
				val += L"&#" + std::to_wstring(read16(c, tc, p + 1)) + L";";
				p += 3;
				break;
			case TOKEN_ENTITY_REF: {
				const std::wstring n = name(read32(c, tc, p + 1));
				if (!n.empty()) val += L"&" + n + L";";
				p += 5;
				break;
			}
			default:
				return true;                  // end of this attribute's data
			}
			if ((token & 0x40) == 0) return true;   // nothing follows
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
	bool instanceTemplate(size_t& p, size_t end, std::wstring& output,
	                      unsigned depth) {
		if (depth >= MAX_DEPTH) return false;
		const size_t token = p;
		const uint32_t offsetDefinition = read32(c, tc, token + 6);

		/*  "Right after this field" = token + 10: the definition follows, and the
		 *  instance data start after the fragment. Otherwise the definition is
		 *  elsewhere and the instance data follow the field. */
		const bool inPlace = (offsetDefinition == token + 10);
		const size_t d = offsetDefinition;         // points to the "next" field
		if (d + 24 > tc) return false;
		const uint32_t fragmentSize = read32(c, tc, d + 20);
		const size_t fragmentStart = d + 24;
		if (fragmentStart + fragmentSize > tc) return false;

		size_t data = inPlace ? (fragmentStart + fragmentSize) : (token + 10);
		if (data + 4 > end) return false;

		// Value array: 4-byte descriptors, then data.
		const uint32_t nValues = read32(c, tc, data);
		data += 4;
		// Guard: at least a 4-byte descriptor per announced value.
		if (nValues > (end - data) / 4) return false;
		std::vector<SubstValue> values(nValues);
		size_t valueOffset = data + 4ULL * nValues;
		for (uint32_t i = 0; i < nValues; ++i) {
			values[i].size = read16(c, tc, data + 4ULL * i);
			values[i].type   = read8(c, tc, data + 4ULL * i + 2);
			values[i].offset = valueOffset;
			valueOffset += values[i].size;
			if (valueOffset > tc) return false;
		}

		// The definition's fragment is decoded with these values.
		size_t q = fragmentStart;
		const bool ok = tokens(q, fragmentStart + fragmentSize, &values,
		                       output, depth + 1);
		p = valueOffset;
		return ok;
	}
};

} // namespace

// ---------------------------------------------------------------------------
//  Reading the file
// ---------------------------------------------------------------------------

std::wstring EvtxChannelFromFileName(const std::wstring& fileName) {
	std::wstring n = fileName;
	const size_t sep = n.find_last_of(L"\\/");
	if (sep != std::wstring::npos) n = n.substr(sep + 1);
	if (n.size() > 5 && toLower(n.substr(n.size() - 5)) == L".evtx")
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

HRESULT EvtxReadFile(const std::wstring& path,
                        const std::function<bool(const EvtxRecord&)>& onRecord,
                        EvtxSummary* summary) {
	EvtxSummary local;
	EvtxSummary& b = summary ? *summary : local;

	HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		const DWORD err = GetLastError();
		b.diagnostic = L"cannot be opened";
		log(2, L"🔥EvtxLireFichier " + path, err);
		return HRESULT_FROM_WIN32(err);
	}

	std::vector<BYTE> header(FILE_HEADER_SIZE);
	DWORD read = 0;
	if (!ReadFile(h, header.data(), (DWORD)header.size(), &read, nullptr)
	    || read < FILE_HEADER_SIZE) {
		CloseHandle(h);
		b.diagnostic = L"file truncated (" + std::to_wstring(read) + L" octets)";
		return HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
	}
	if (memcmp(header.data(), "ElfFile\0", 8) != 0) {
		CloseHandle(h);
		b.diagnostic = L"ElfFile signature absent";
		log(2, L"🔥evtx : " + path + L" n'est pas un journal EVTX");
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	b.headerValid = true;
	const uint16_t flags = read16(header.data(), header.size(), 120);
	b.sale = (flags & 0x0001) != 0;
	const uint16_t nDeclaredChunks = read16(header.data(), header.size(), 42);

	/*  Chunks are walked to the end of the file, not just up to the announced
	 *  count: a log closed abruptly often holds more, and those chunks carry the
	 *  most recent events — precisely the ones the investigation wants. */
	std::vector<BYTE> chunk(CHUNK_SIZE);
	bool goOn = true;
	unsigned long long chunksIgnores = 0;
	while (goOn) {
		if (!ReadFile(h, chunk.data(), (DWORD)chunk.size(), &read, nullptr) || read == 0) break;
		if (read < CHUNK_HEADER_SIZE) break;
		if (memcmp(chunk.data(), "ElfChnk\0", 8) != 0) {
			/*  Chunk without a signature: either preallocated space never written
			 *  (end of the file), or a damaged chunk in the MIDDLE of the log. The two
			 *  cannot be told apart here, and stopping at the first one is costly:
			 *  on a log with a single corrupt chunk, it lost the next 256 records
			 *  out of 270. So we move on to the next chunk.
			 *  An empty chunk is not counted as skipped: only a chunk that holds
			 *  something without the signature is reported. */
			bool empty = true;
			for (size_t i = 0; i < read && empty; ++i) if (chunk[i]) empty = false;
			if (!empty) ++chunksIgnores;
			continue;
		}
		++b.chunks;

		/*  "Free space offset" bounds the written records. A corrupt chunk can
		 *  announce it out of range: the chunk size is then used, the rest being
		 *  filtered by the record signature. */
		size_t recordsEnd = read32(chunk.data(), read, 48);
		if (recordsEnd <= RECORDS_START || recordsEnd > read)
			recordsEnd = read;

		Decoder decoder(chunk.data(), read);
		size_t p = RECORDS_START;
		while (p + 24 <= recordsEnd) {
			if (read32(chunk.data(), read, p) != SIGNATURE_ENREG) break;
			const uint32_t size = read32(chunk.data(), read, p + 4);
			// A record takes at least the header (24) and the trailing size copy
			// (4); an absurd size would stop the reading on arbitrary data.
			if (size < 28 || p + size > recordsEnd) break;

			EvtxRecord e;
			e.id = read64(chunk.data(), read, p + 8);
			const uint64_t v = read64(chunk.data(), read, p + 16);
			e.writtenUtc.dwLowDateTime  = (DWORD)(v & 0xFFFFFFFFULL);
			e.writtenUtc.dwHighDateTime = (DWORD)(v >> 32);

			if (decoder.document(p + 24, p + size - 4, e.xml)) {
				++b.read;
				if (!onRecord(e)) { goOn = false; break; }
			}
			else {
				++b.unreadable;
				log(3, L"🔈evtx: record " + std::to_wstring(e.id)
				       + L" unreadable in " + path);
			}
			p += size;
		}
	}
	CloseHandle(h);

	std::wostringstream diag;
	diag << b.chunks << L" chunk(s)";
	if (nDeclaredChunks != b.chunks) diag << L" (" << nDeclaredChunks << L" declared)";
	diag << L", " << b.read << L" record(s)";
	if (b.unreadable) diag << L", " << b.unreadable << L" unreadable";
	if (chunksIgnores) diag << L", " << chunksIgnores << L" damaged chunk(s)";
	if (b.sale) diag << L", log not closed cleanly";
	b.diagnostic = diag.str();
	b.chunksIgnores = chunksIgnores;

	return (b.unreadable || chunksIgnores) ? S_FALSE : ERROR_SUCCESS;
}
