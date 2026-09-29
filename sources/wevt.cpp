#include "wevt.h"
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

//! True if a resource declared a block size incompatible with its count of
//! events: the resource is then ignored rather than read at random.
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
			if (std::memcmp(d.data() + block, "EVNT", 4) != 0) continue;

			const uint32_t blockSize   = rd32(d, block + 4);
			const uint32_t nEvents = rd32(d, block + 8);
			if (nEvents == 0 || nEvents > MAX_ENTRIES) continue;

			/*  THE STEP IS DEDUCED FROM THE DECLARED SIZE, and not hard-coded.
			    An event descriptor is 48 bytes — identifier, version, channel,
			    level, opcode, task, keywords, then eight fields of four bytes
			    among which the message identifier.
			    Deducing it makes the reading robust to a change of the format
			    and, above all, makes it VERIFIABLE: a wrong step of four bytes
			    (seen while writing this code) gives records of which only one in
			    twelve is coherent, with no visible error. */
			size_t pas = 48;
			if (blockSize > 16) {
				const size_t deduced = (size_t)(blockSize - 16) / nEvents;
				if (deduced >= 40 && deduced <= 128) pas = deduced;
				else {
					log_wevt_pas_incoherent = true;
					continue;               // size and count contradict each other
				}
			}

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
