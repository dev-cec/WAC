#include "wevt.h"
#include "conversions.h"
#include <cstring>

/*! \file
 *  \brief Parsing of MESSAGETABLE and WEVT_TEMPLATE, and substitution of the marks.
 *
 *  See wevt.h for the chain to walk back and for the formats.
 *
 *  Structures, as libyal's reference implementation (libfwevt) describes them:
 *
 *    manifest        "CRIM" (4), size (4), major (2), minor (2),
 *                    number of providers (4)                        = 16
 *    entry           GUID (16), offset of the data (4)              = 20
 *    provider        "WEVT" (4), size (4), message identifier (4),
 *                    number of descriptors (4), number of unknowns (4) = 20
 *                    then an offset of 4 bytes per descriptor
 *    events          "EVNT" (4), size (4), number of events (4),
 *                    unknown (4)                                    = 16
 *    event           identifier (2), version (1), channel (1), level (1),
 *                    opcode (1), task (2), keywords (8),
 *                    MESSAGE IDENTIFIER (4), then six fields of 4     = 44
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

//! GUID in the form "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}", in lower case.
std::wstring guidToText(const std::vector<uint8_t>& d, size_t o) {
	if (o + 16 > d.size()) return std::wstring();
	static const wchar_t* h = L"0123456789abcdef";
	auto oct = [&](size_t i, std::wstring& s) {
		s += h[d[o + i] >> 4];
		s += h[d[o + i] & 0x0F];
	};
	std::wstring s = L"{";
	// The first three fields are little-endian, the last two are not.
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

//! GUID comparison, without regard to case or braces.
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

const size_t MAX_ENTRIES = 65536;   // guard on the file's counters

} // namespace

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
				/*  UTF-16, the case of modern resources; treating the text as a code
				    page would return every other character.
				    The units are read TWO BYTES AT A TIME and not by a cast to
				    wchar_t: that type is two bytes under Windows but FOUR under
				    Linux, and the cast re-read UTF-16 there as UTF-32 — this
				    module is meant to be verifiable outside Windows, so the
				    reading must be too. */
				text.reserve(textBytes / 2);
				for (size_t i = 0; i + 1 < textBytes; i += 2)
					text += (wchar_t)rd16(d, p + 4 + i);
			}
			else if (flags & 0x0002) {
				/*  UTF-8 (MESSAGE_RESOURCE_UTF8), which recent tables use — ESENT's
				    among them. Widened byte by byte, as the code-page case below,
				    "données" came out "donnÃ©es" (B-023). */
				text = utf8ToWide(d.data() + p + 4, textBytes);
			}
			else {
				// Code page: the bytes are widened one by one, for want of knowing
				// which one. Message templates are Latin in practice.
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

namespace {

/*! Reads a MAPS block's value maps. Measured on Windows 11's providers, and
 *  not as libfwevt's description says: the block's offset array has ONE
 *  ENTRY PER MAP (not one less), and a VMAP's header is 20 bytes — signature,
 *  size, offset of its name, a field of four bytes, count — before its
 *  entries { value, message identifier } (Kernel-Power: 124 = 20 + 13 x 8).
 *  A BMAP has the same layout, its entries one flag each (AppX: 276 = 20 +
 *  32 x 8); the field of four bytes is 1 there, 0 in a VMAP.
 *  @param d the resource
 *  @param block the MAPS block's offset
 *  @param maps receives the value maps, by offset */
void readMaps(const std::vector<uint8_t>& d, size_t block, std::map<uint32_t, WevtValueMap>& maps) {
	const uint32_t count = rd32(d, block + 8);
	if (count > MAX_ENTRIES) return;
	for (uint32_t i = 0; i < count; ++i) {
		const size_t entry = block + 12 + (size_t)i * 4;
		if (entry + 4 > d.size()) return;
		const uint32_t map = rd32(d, entry);
		if ((size_t)map + 20 > d.size()) continue;
		const bool bitmap = std::memcmp(d.data() + map, "BMAP", 4) == 0;
		if (!bitmap && std::memcmp(d.data() + map, "VMAP", 4) != 0) continue;
		const uint32_t size = rd32(d, map + 4);
		const uint32_t labels = rd32(d, map + 16);
		if (labels > MAX_ENTRIES || size < 20 || (size_t)map + size > d.size() || (size - 20) / 8 < labels) continue;
		WevtValueMap& m = maps[map];
		m.bitmap = bitmap;
		for (uint32_t k = 0; k < labels; ++k)
			m.labels.emplace(rd32(d, map + 20 + (size_t)k * 8), rd32(d, map + 24 + (size_t)k * 8));
	}
}

/*! Reads a template's items (TEMP): 20 bytes each — input type at 4, output
 *  type at 5, the offset of its value map at 8 (measured; libfwevt calls the
 *  field unknown), count at 12, length at 14, name offset at 16.
 *  @param d the resource
 *  @param at the template's offset
 *  @param templates receives its items, by offset
 *  @return true if the template was read */
bool readTemplate(const std::vector<uint8_t>& d, uint32_t at, std::map<uint32_t, std::vector<WevtItem>>& templates) {
	if (templates.count(at)) return true;
	if ((size_t)at + 40 > d.size() || std::memcmp(d.data() + at, "TEMP", 4) != 0) return false;
	const uint32_t count = rd32(d, at + 8);
	const uint32_t itemsAt = rd32(d, at + 16);
	if (count > MAX_ENTRIES || (count > 0 && ((size_t)itemsAt + (size_t)count * 20 > d.size()))) return false;
	std::vector<WevtItem> items;
	for (uint32_t k = 0; k < count; ++k) {
		const size_t item = itemsAt + (size_t)k * 20;
		WevtItem w;
		w.inType = d[item + 4];
		w.outType = d[item + 5];
		w.map = rd32(d, item + 8);
		items.push_back(w);
	}
	templates.emplace(at, std::move(items));
	return true;
}

/*! @return the value as a number, from its decimal, negative decimal or
 *  "0x" form; false if it is none. A negative value — an HRESULT logged as
 *  win:Int32, "-2147009295" — comes back in two's complement. */
bool parseNumber(const std::wstring& text, uint64_t& value) {
	const bool negative = !text.empty() && text[0] == L'-';
	const std::wstring digitsText = negative ? text.substr(1) : text;
	if (digitsText.empty()) return false;
	const bool hex = !negative && digitsText.size() > 2 && digitsText[0] == L'0' && (digitsText[1] == L'x' || digitsText[1] == L'X');
	value = 0;
	for (size_t i = hex ? 2 : 0; i < digitsText.size(); ++i) {
		const wchar_t c = digitsText[i];
		unsigned digit;
		if (c >= L'0' && c <= L'9') digit = (unsigned)(c - L'0');
		else if (hex && c >= L'a' && c <= L'f') digit = (unsigned)(c - L'a' + 10);
		else if (hex && c >= L'A' && c <= L'F') digit = (unsigned)(c - L'A' + 10);
		else return false;
		value = value * (hex ? 16 : 10) + digit;
	}
	if (negative) value = (uint64_t)0 - value;
	return true;
}

} // namespace

namespace {

//! @return a table's text without the line break that ends it; "" if absent
std::wstring tableText(const TableMessages* table, uint32_t id) {
	if (!table) return std::wstring();
	std::wstring text = table->text(id);
	while (!text.empty() && (text.back() == L'\n' || text.back() == L'\r' || text.back() == L' ')) text.pop_back();
	return text;
}

//! @return the number in hexadecimal, "0x" and its digits in the given case
std::wstring hexadecimal(uint64_t number, bool upper) {
	const wchar_t* digits = upper ? L"0123456789ABCDEF" : L"0123456789abcdef";
	std::wstring text;
	do { text.insert(text.begin(), digits[number & 0xF]); number >>= 4; } while (number);
	return L"0x" + text;
}

} // namespace

std::wstring formatItemValue(const WevtItem& item, const WevtValueMap* map, const TableMessages& messages,
                             const SystemMessages& system, const std::wstring& value) {
	// Input types (wtypes of the manifest) and output types, as libfwevt numbers them.
	const uint8_t IN_POINTER = 0x10, IN_HEX32 = 0x14, IN_HEX64 = 0x15;
	const uint8_t OUT_HEX_FIRST = 0x10, OUT_HEX_LAST = 0x13, OUT_ERROR_CODE = 0x1D, OUT_WIN32 = 0x1E,
	              OUT_NTSTATUS = 0x1F, OUT_HRESULT = 0x20;
	const uint8_t IN_BINARY = 0x0E, OUT_HEX_BINARY = 0x0F, OUT_SOCKET_ADDRESS = 0x19;
	if (item.inType == IN_BINARY) {
		// An AF_INET sockaddr, as hexadecimal text: family (2, little-endian), port and address in network order.
		if (item.outType == OUT_SOCKET_ADDRESS && value.size() >= 16 && value.compare(0, 4, L"0200") == 0) {
			uint64_t port = 0, address = 0;
			if (parseNumber(L"0x" + value.substr(4, 4), port) && parseNumber(L"0x" + value.substr(8, 8), address))
				return std::to_wstring((address >> 24) & 0xFF) + L"." + std::to_wstring((address >> 16) & 0xFF) + L"."
				       + std::to_wstring((address >> 8) & 0xFF) + L"." + std::to_wstring(address & 0xFF) + L":" + std::to_wstring(port);
		}
		if (item.outType == OUT_HEX_BINARY && !value.empty() && value.compare(0, 2, L"0x") != 0) return L"0x" + value;
		return value;
	}
	uint64_t number = 0;
	if (!parseNumber(value, number)) return value;
	if (map && map->bitmap && number != 0) {
		std::wstring labels;
		for (const auto& [flag, message] : map->labels) {
			if (flag == 0 || (number & flag) != flag) continue;
			const std::wstring text = tableText(&messages, message);
			if (text.empty()) continue;
			if (!labels.empty()) labels += L',';
			labels += text;
		}
		return labels.empty() ? value : labels;
	}
	if (map) {
		const auto label = map->labels.find((uint32_t)number);
		if (label == map->labels.end()) return value;
		const std::wstring text = tableText(&messages, label->second);
		return text.empty() ? value : text;
	}
	const uint32_t code = (uint32_t)number;   // an Int32 logged negative comes back to its 32 bits
	if (item.outType == OUT_WIN32 || item.outType == OUT_HRESULT) {
		std::wstring text = tableText(system.errors, code);
		if (text.empty() && (code >> 16) == 0x8007) text = tableText(system.errors, code & 0xFFFF);
		if (!text.empty()) return text;
		return item.outType == OUT_HRESULT && system.errors ? L"Unknown HResult Error code: " + hexadecimal(code, false) : value;
	}
	if (item.outType == OUT_NTSTATUS) {
		const std::wstring text = tableText(system.ntStatus, code);
		return text.empty() ? value : text;
	}
	if (item.outType == OUT_ERROR_CODE) return hexadecimal(code, true);
	if (item.inType == IN_POINTER) return value;
	if (item.inType == IN_HEX32 || item.inType == IN_HEX64 || (item.outType >= OUT_HEX_FIRST && item.outType <= OUT_HEX_LAST)) {
		// An input of 32 bits or less shows its own bits: a negative Int32 is not 64 bits wide.
		const uint8_t IN_UINT32 = 0x08;
		if (item.inType <= IN_UINT32 || item.inType == IN_HEX32) number &= 0xFFFFFFFFu;
		return hexadecimal(number, true);
	}
	return value;
}

const std::vector<WevtItem>* WevtMetadata::items(uint16_t eventId, uint8_t version) const {
	auto it = templateByIdVersion_.find(((uint32_t)eventId << 8) | version);
	uint32_t at = 0;
	if (it != templateByIdVersion_.end()) at = it->second;
	else {
		const auto byId = templateById_.find(eventId);
		if (byId == templateById_.end()) return nullptr;
		at = byId->second;
	}
	const auto t = templates_.find(at);
	return t != templates_.end() ? &t->second : nullptr;
}

const WevtValueMap* WevtMetadata::valueMap(uint32_t offset) const {
	const auto m = valueMaps_.find(offset);
	return m != valueMaps_.end() ? &m->second : nullptr;
}

size_t WevtMetadata::analyse(const std::vector<uint8_t>& d,
                                 const std::wstring& providerGuid) {
	parIdEtVersion_.clear();
	parId_.clear();
	templateByIdVersion_.clear();
	templateById_.clear();
	templates_.clear();
	valueMaps_.clear();
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

		/*  The descriptors are typed BY THE SIGNATURE found at their offset,
		    and not by their rank: the order of the blocks is not guaranteed, and
		    relying on it would have channels read as events.
		    Each descriptor is EIGHT bytes — an offset and an unused field.
		    Reading them four by four gives offsets that point anywhere, and the
		    block of events is never found (seen: 0 events described on a provider
		    that describes 74). */
		for (uint32_t k = 0; k < nDescriptors; ++k) {
			const size_t dd = offset + 20 + (size_t)k * 8;
			if (dd + 4 > d.size()) break;
			const uint32_t block = rd32(d, dd);
			if (block + 16 > d.size()) continue;
			if (std::memcmp(d.data() + block, "MAPS", 4) == 0) { readMaps(d, block, valueMaps_); continue; }
			if (std::memcmp(d.data() + block, "EVNT", 4) != 0) continue;

			const uint32_t blockSize   = rd32(d, block + 4);
			const uint32_t nEvents = rd32(d, block + 8);
			if (nEvents == 0 || nEvents > MAX_ENTRIES) continue;

			/*  AN EVENT DESCRIPTOR IS 48 BYTES — identifier, version, channel,
			    level, opcode, task, keywords, then eight fields of four bytes
			    among which the message identifier (libfwevt's description of the
			    format). The block's declared size is NOT 16 + 48 × count: data
			    follow the descriptors (716 bytes in AppReadiness.dll, whose 175
			    descriptors take 8,400). Deducing the step from that size, as WAC
			    did, gave 52 bytes there: every descriptor after the first read
			    four bytes further, false message identifiers or none — 81 of 175
			    events kept, and the messages of most manifest providers lost
			    (B-023). The declared size only bounds the descriptors. */
			const size_t pas = 48;
			if (blockSize < 16 || (blockSize - 16) / pas < nEvents) continue;   // the block cannot hold its descriptors

			for (uint32_t n = 0; n < nEvents; ++n) {
				const size_t ev = block + 16 + (size_t)n * pas;
				if (ev + pas > d.size()) break;
				const uint16_t id      = rd16(d, ev);
				const uint8_t  version = d[ev + 2];
				const uint32_t message = rd32(d, ev + 16);
				// 0 and 0xFFFFFFFF both mark "no message".
				if (message == 0 || message == 0xFFFFFFFFu) continue;
				parIdEtVersion_.emplace(((uint32_t)id << 8) | version, message);
				parId_.emplace(id, message);
				const uint32_t templateOffset = rd32(d, ev + 20);   // 0: no template
				if (templateOffset != 0 && readTemplate(d, templateOffset, templates_)) {
					templateByIdVersion_.emplace(((uint32_t)id << 8) | version, templateOffset);
					templateById_.emplace(id, templateOffset);
				}
			}
		}
		if (!providerGuid.empty()) break;   // provider found
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
//  Substitution of the marks
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
		if (next == L'n') { r += L'\n'; ++i; continue; }   // line break
		if (next == L't') { r += L'\t'; ++i; continue; }   // tabulation
		if (next == L'r') { r += L'\r'; ++i; continue; }   // carriage return
		if (next == L'b') { r += L' ';  ++i; continue; }   // space
		if (next == L'.' || next == L'!') { r += next; ++i; continue; }
		/*  "%0" ENDS the message, without a final line break (FormatMessage's
		    convention). It was copied as it was: "…deleted following the
		    deletion of the user profile.\n%0". A digit that follows would make a
		    %0N mark, which does not exist: same treatment. */
		if (next == L'0') {
			while (!r.empty() && (r.back() == L'\n' || r.back() == L'\r')) r.pop_back();
			return r;
		}
		if (next < L'0' || next > L'9') { r += messageTemplate[i]; continue; }

		// Positional mark: one or several digits.
		size_t j = i + 1;
		unsigned long position = 0;
		while (j < messageTemplate.size() && messageTemplate[j] >= L'0' && messageTemplate[j] <= L'9') {
			position = position * 10 + (unsigned long)(messageTemplate[j] - L'0');
			++j;
			if (position > 999) break;              // nonsensical: give up
		}
		/*  Some templates write "%1!s!": the format between exclamation marks
		    is a display instruction, not text. */
		if (j < messageTemplate.size() && messageTemplate[j] == L'!') {
			const size_t end = messageTemplate.find(L'!', j + 1);
			if (end != std::wstring::npos) j = end + 1;
		}
		if (position >= 1 && position <= values.size()) {
			r += values[position - 1];
			i = j - 1;
		}
		else {
			/*  A MARK WITHOUT DATA: left as it is. Erasing it would suggest a
			    complete sentence whereas a value is missing — and that is
			    precisely what the analyst must see. */
			r.append(messageTemplate, i, j - i);
			i = j - 1;
		}
	}
	return r;
}
