/*! \file
 *  \brief Decoding of Chromium's SNSS session files and Firefox's mozLz4
 *         files (see browser_sessions.h).
 */
#include "browser_sessions.h"
#include "portable_conversions.h"

#include <cstring>

namespace {

const char SNSS_MAGIC[4] = { 'S', 'N', 'S', 'S' };
const size_t SNSS_HEADER = 8;                      //!< magic, then the version on 32 bits
// SessionService's command (components/sessions/core/session_service_commands.cc).
const uint8_t SESSION_UPDATE_TAB_NAVIGATION = 6;
// TabRestoreService's commands (components/sessions/core/tab_restore_service_impl.cc).
const uint8_t TAB_RESTORE_UPDATE_TAB_NAVIGATION = 1;
const uint8_t TAB_RESTORE_SELECTED_NAVIGATION_IN_TAB = 4;
const size_t SELECTED_NAVIGATION_SIZE = 16;       //!< id (32 bits), index (32 bits), time (64 bits)

const char MOZLZ4_MAGIC[8] = { 'm', 'o', 'z', 'L', 'z', '4', '0', '\0' };
const size_t MOZLZ4_HEADER = 12;                   //!< magic, then the decompressed size on 32 bits
const size_t LZ4_MIN_MATCH = 4;

/*! The UTF-16 code units of a title as a wide string, surrogate pairs joined
 *  where wchar_t has 32 bits (Linux) and kept as they are where it has 16
 *  (Windows). */
std::wstring fromUtf16(const uint8_t* bytes, size_t units) {
	std::wstring text;
	text.reserve(units);
	for (size_t i = 0; i < units; ++i) {
		char32_t unit = readLittleEndian<uint16_t>(bytes + 2 * i);
		if (sizeof(wchar_t) == 4 && unit >= 0xD800 && unit <= 0xDBFF && i + 1 < units) {
			const char32_t low = readLittleEndian<uint16_t>(bytes + 2 * (i + 1));
			if (low >= 0xDC00 && low <= 0xDFFF) {
				unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
				++i;
			}
		}
		text.push_back((wchar_t)unit);
	}
	return text;
}

/*! A base::Pickle being read: its payload after the 32-bit size, each field
 *  aligned to 32 bits. Any read past the payload fails and leaves the
 *  reader failed. */
class PickleReader {
public:
	PickleReader(const uint8_t* data, size_t size) {
		if (size < 4) return;
		const uint32_t payload = readLittleEndian<uint32_t>(data);
		if (payload > size - 4) return;
		data_ = data + 4;
		size_ = payload;
		ok_ = true;
	}
	bool ok() const { return ok_; }
	bool readInt(int32_t& value) {
		const uint8_t* p = take(4);
		if (p) value = (int32_t)readLittleEndian<uint32_t>(p);
		return p != nullptr;
	}
	bool readInt64(int64_t& value) {
		const uint8_t* p = take(8);
		if (p) value = (int64_t)readLittleEndian<uint64_t>(p);
		return p != nullptr;
	}
	bool readString(std::string& value) {
		int32_t length = 0;
		if (!readInt(length) || length < 0) return fail();
		const uint8_t* p = take((size_t)length);
		if (p) value.assign(reinterpret_cast<const char*>(p), (size_t)length);
		return p != nullptr;
	}
	bool readString16(std::wstring& value) {
		int32_t units = 0;
		if (!readInt(units) || units < 0 || (size_t)units > SIZE_MAX / 2) return fail();
		const uint8_t* p = take((size_t)units * 2);
		if (p) value = fromUtf16(p, (size_t)units);
		return p != nullptr;
	}
private:
	//! The next `length` bytes, the position then moved to the next 32-bit boundary.
	const uint8_t* take(size_t length) {
		if (!ok_ || length > size_ - position_) { fail(); return nullptr; }
		const uint8_t* p = data_ + position_;
		const size_t aligned = (length + 3) & ~(size_t)3;
		position_ = aligned > size_ - position_ ? size_ : position_ + aligned;
		return p;
	}
	bool fail() { ok_ = false; return false; }
	const uint8_t* data_ = nullptr;
	size_t size_ = 0, position_ = 0;
	bool ok_ = false;
};

/*! Reads the fields after the title, in order, up to the first one absent:
 *  an older browser wrote fewer, and what it did not write stays empty. */
void readOptionalFields(PickleReader& r, SnssNavigation& n) {
	std::string pageState;
	int32_t typeMask = 0, referrerPolicy = 0, userAgentOverride = 0;
	std::wstring searchTerms;
	if (!r.readString(pageState) || !r.readInt(n.transition) || !r.readInt(typeMask)) return;
	if (!r.readString(n.referrer) || !r.readInt(referrerPolicy) || !r.readString(n.originalUrl)) return;
	if (!r.readInt(userAgentOverride) || !r.readInt64(n.time)) return;
	if (!r.readString16(searchTerms)) return;
	if (!r.readInt(n.httpStatus)) n.httpStatus = 0;
}

/*! Reads a navigation's pickle (SerializedNavigationEntry::WriteToPickle,
 *  preceded by the tab).
 *  @return false if not even the tab, the index, the URL and the title can be read */
bool readNavigation(const uint8_t* data, size_t size, SnssNavigation& n) {
	PickleReader r(data, size);
	if (!r.readInt(n.tab) || !r.readInt(n.index) || !r.readString(n.url) || !r.readString16(n.title)) return false;
	readOptionalFields(r, n);
	return true;
}

} // namespace

bool decodeSnss(const uint8_t* data, size_t size, SnssKind kind, SnssContents& contents) {
	contents = SnssContents();
	if (!data || size < SNSS_HEADER || std::memcmp(data, SNSS_MAGIC, sizeof(SNSS_MAGIC)) != 0) return false;
	contents.version = (int32_t)readLittleEndian<uint32_t>(data + 4);
	const uint8_t navigationCommand = kind == SnssKind::Session ? SESSION_UPDATE_TAB_NAVIGATION
	                                                            : TAB_RESTORE_UPDATE_TAB_NAVIGATION;
	std::map<std::pair<int32_t, int32_t>, size_t> byTabAndIndex;   // -> place in navigations
	size_t position = SNSS_HEADER;
	while (size - position >= 2) {
		const uint16_t commandSize = readLittleEndian<uint16_t>(data + position);
		position += 2;
		if (commandSize == 0 || commandSize > size - position) break;   // a damaged or truncated command ends the file
		const uint8_t id = data[position];
		const uint8_t* payload = data + position + 1;
		const size_t payloadSize = commandSize - 1u;
		position += commandSize;
		if (id == navigationCommand) {
			SnssNavigation n;
			if (!readNavigation(payload, payloadSize, n)) continue;
			const std::pair<int32_t, int32_t> key(n.tab, n.index);
			const auto found = byTabAndIndex.find(key);
			if (found != byTabAndIndex.end()) contents.navigations[found->second] = std::move(n);
			else {
				byTabAndIndex.emplace(key, contents.navigations.size());
				contents.navigations.push_back(std::move(n));
			}
		}
		else if (kind == SnssKind::TabRestore && id == TAB_RESTORE_SELECTED_NAVIGATION_IN_TAB
		         && payloadSize >= SELECTED_NAVIGATION_SIZE) {
			const int32_t entry = (int32_t)readLittleEndian<uint32_t>(payload);
			contents.selectedIndex[entry] = (int32_t)readLittleEndian<uint32_t>(payload + 4);
			contents.closedTimes[entry] = (int64_t)readLittleEndian<uint64_t>(payload + 8);
		}
	}
	return true;
}

bool decompressLz4Block(const uint8_t* data, size_t size, size_t expected, std::vector<uint8_t>& output) {
	output.clear();
	output.reserve(expected);
	size_t position = 0;
	// A length: its 4-bit start, then bytes of 255 until a smaller one.
	auto length = [&](size_t start, size_t& value) {
		value = start;
		if (start != 15) return true;
		while (position < size) {
			const uint8_t more = data[position++];
			value += more;
			if (value > expected) return false;
			if (more != 255) return true;
		}
		return false;
	};
	while (position < size) {
		const uint8_t token = data[position++];
		size_t literals = 0;
		if (!length(token >> 4, literals) || literals > size - position || literals > expected - output.size()) return false;
		output.insert(output.end(), data + position, data + position + literals);
		position += literals;
		if (position == size) break;                      // the last sequence has no match
		if (size - position < 2) return false;
		const size_t offset = readLittleEndian<uint16_t>(data + position);
		position += 2;
		if (offset == 0 || offset > output.size()) return false;
		size_t match = 0;
		if (!length(token & 0x0F, match)) return false;
		match += LZ4_MIN_MATCH;
		if (match > expected - output.size()) return false;
		const size_t from = output.size() - offset;
		for (size_t i = 0; i < match; ++i) output.push_back(output[from + i]);   // may overlap itself
	}
	return output.size() == expected;
}

bool decompressMozLz4(const uint8_t* data, size_t size, size_t maximum, std::vector<uint8_t>& output) {
	output.clear();
	if (!data || size < MOZLZ4_HEADER || std::memcmp(data, MOZLZ4_MAGIC, sizeof(MOZLZ4_MAGIC)) != 0) return false;
	const uint32_t expected = readLittleEndian<uint32_t>(data + sizeof(MOZLZ4_MAGIC));
	if (expected > maximum) return false;
	return decompressLz4Block(data + MOZLZ4_HEADER, size - MOZLZ4_HEADER, expected, output);
}
