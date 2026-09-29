/*! \file
 *  \brief The version resource of a PE (see version_info.h).
 */
#include "version_info.h"

namespace {

const uint32_t FIXED_SIGNATURE = 0xFEEF04BD;
const size_t HEADER = 6;                           //!< wLength, wValueLength, wType
const int MAX_DEPTH = 4;                           //!< root, StringFileInfo, table, string

uint16_t le16(const std::vector<uint8_t>& b, size_t at) { return (uint16_t)(b[at] | (b[at + 1] << 8)); }
uint32_t le32(const std::vector<uint8_t>& b, size_t at) { return (uint32_t)le16(b, at) | ((uint32_t)le16(b, at + 2) << 16); }
size_t align4(size_t at) { return (at + 3) & ~(size_t)3; }

//! A node of the tree, located.
struct Node {
	std::wstring key;
	size_t value = 0, valueSize = 0;   //!< the value's position and size in bytes
	size_t children = 0, end = 0;      //!< where its children start, where it ends
	bool text = false;
};

/*! Reads the node at `at`, which must end by `limit`.
 *  @return false if it is malformed */
bool readNode(const std::vector<uint8_t>& b, size_t at, size_t limit, Node& n) {
	if (at + HEADER > limit) return false;
	const size_t length = le16(b, at), valueLength = le16(b, at + 2);
	n.text = le16(b, at + 4) == 1;
	if (length < HEADER || at + length > limit) return false;
	n.end = at + length;
	size_t k = at + HEADER;
	n.key.clear();
	for (; k + 1 < n.end; k += 2) {
		const uint16_t c = le16(b, k);
		if (!c) break;
		n.key += (wchar_t)c;
	}
	if (k + 1 >= n.end) return false;                        // the key's NUL is missing
	n.value = align4(k + 2);
	n.valueSize = n.text ? valueLength * 2 : valueLength;   // a text's length counts characters
	if (n.value > n.end || n.valueSize > n.end - n.value) n.valueSize = n.value > n.end ? 0 : n.end - n.value;
	n.children = align4(n.value + n.valueSize);
	return true;
}

//! A text value, up to its NUL.
std::wstring textOf(const std::vector<uint8_t>& b, const Node& n) {
	std::wstring text;
	for (size_t k = n.value; k + 1 < n.value + n.valueSize; k += 2) {
		const uint16_t c = le16(b, k);
		if (!c) break;
		text += (wchar_t)c;
	}
	return text;
}

//! Walks the children of `parent`, collecting the texts of StringFileInfo.
void walk(const std::vector<uint8_t>& b, const Node& parent, int depth, bool inStrings, VersionInfo& info) {
	if (depth > MAX_DEPTH) return;
	for (size_t at = parent.children; at < parent.end;) {
		Node child;
		if (!readNode(b, at, parent.end, child)) return;
		if (depth == 1) {
			if (child.key == L"StringFileInfo") walk(b, child, depth + 1, true, info);
		}
		else if (depth == 2 && inStrings) walk(b, child, depth + 1, true, info);        // a language table
		else if (depth == 3 && inStrings && !child.key.empty()) info.strings.emplace(child.key, textOf(b, child));
		const size_t next = align4(child.end);
		if (next <= at) return;
		at = next;
	}
}

} // namespace

bool ReadVersionInfo(const std::vector<uint8_t>& resource, VersionInfo& info) {
	info = VersionInfo{};
	Node root;
	if (!readNode(resource, 0, resource.size(), root) || root.key != L"VS_VERSION_INFO") return false;
	if (root.valueSize >= 52 && le32(resource, root.value) == FIXED_SIGNATURE) {
		info.fixed = true;
		info.fileVersion = ((uint64_t)le32(resource, root.value + 8) << 32) | le32(resource, root.value + 12);
	}
	walk(resource, root, 1, false, info);
	return true;
}

bool ParseFileVersion(const std::wstring& text, uint64_t& version) {
	uint64_t result = 0;
	size_t at = 0;
	for (int part = 0; part < 4; ++part) {
		if (at >= text.size() || text[at] < L'0' || text[at] > L'9') return false;
		uint32_t n = 0;
		for (; at < text.size() && text[at] >= L'0' && text[at] <= L'9'; ++at) {
			n = n * 10 + (uint32_t)(text[at] - L'0');
			if (n > 0xFFFF) return false;
		}
		result = (result << 16) | n;
		if (part < 3) {
			if (at >= text.size() || text[at] != L'.') return false;
			++at;
		}
	}
	if (at != text.size()) return false;
	version = result;
	return true;
}
