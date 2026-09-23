/*! \file
 *  \brief Implementation of the minimal XML reader (see xml_light.h).
 */
#include "xml_light.h"
#include "tools.h"
#include <fstream>
#include <filesystem>
#include <vector>
#include <windows.h>

namespace {

//! Maximum depth: a guard against a document forged with extreme nesting.
constexpr unsigned MAX_DEPTH = 64;

//! Strips the spaces, tabulations and line breaks at both edges.
std::wstring trim(const std::wstring& s) {
	const wchar_t* blanks = L" \t\r\n";
	const size_t start = s.find_first_not_of(blanks);
	if (start == std::wstring::npos) return std::wstring();
	const size_t end = s.find_last_not_of(blanks);
	return s.substr(start, end - start + 1);
}

//! Replaces the five predefined entities. The others are left as they are:
//! a faithful text is better than a guessed substitution.
std::wstring decodeEntities(const std::wstring& s) {
	if (s.find(L'&') == std::wstring::npos) return s;   // the common case: nothing to do
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
		else if (e.size() > 1 && e[0] == L'#') {        // numeric reference
			try {
				const int code = (e[1] == L'x' || e[1] == L'X')
					? std::stoi(e.substr(2), nullptr, 16)
					: std::stoi(e.substr(1));
				if (code > 0 && code < 0x110000) r += (wchar_t)code;
			}
			catch (...) { r += L'&' + e + L';'; }        // unreadable: kept raw
		}
		else { r += L'&' + e + L';'; }
		i = pv + 1;
	}
	return r;
}

//! Strips the namespace prefix: the task schema has only one, implicit.
std::wstring withoutPrefix(const std::wstring& name) {
	const size_t d = name.find(L':');
	return (d == std::wstring::npos) ? name : name.substr(d + 1);
}

/*! Parses an element from `pos`, positioned just after its '<'.
 *  Returns nullptr on a malformed document. */
std::unique_ptr<XmlNode> readElement(const std::wstring& s, size_t& pos, unsigned depth) {
	if (depth > MAX_DEPTH) return nullptr;

	// --- name of the tag
	const size_t nameStart = pos;
	while (pos < s.size() && !iswspace(s[pos]) && s[pos] != L'>' && s[pos] != L'/') ++pos;
	if (pos >= s.size()) return nullptr;
	auto node = std::make_unique<XmlNode>();
	node->name = withoutPrefix(s.substr(nameStart, pos - nameStart));
	if (node->name.empty()) return nullptr;

	// --- attributes, up to '>' or '/>'
	bool empty = false;
	while (pos < s.size()) {
		while (pos < s.size() && iswspace(s[pos])) ++pos;
		if (pos >= s.size()) return nullptr;
		if (s[pos] == L'/') { empty = true; ++pos; continue; }
		if (s[pos] == L'>') { ++pos; break; }

		const size_t dn = pos;
		while (pos < s.size() && s[pos] != L'=' && !iswspace(s[pos])
		       && s[pos] != L'>' && s[pos] != L'/') ++pos;
		const std::wstring attrName = withoutPrefix(s.substr(dn, pos - dn));
		while (pos < s.size() && iswspace(s[pos])) ++pos;
		std::wstring value;
		if (pos < s.size() && s[pos] == L'=') {
			++pos;
			while (pos < s.size() && iswspace(s[pos])) ++pos;
			if (pos < s.size() && (s[pos] == L'"' || s[pos] == L'\'')) {
				const wchar_t quote = s[pos++];
				const size_t dv = pos;
				while (pos < s.size() && s[pos] != quote) ++pos;
				if (pos >= s.size()) return nullptr;      // unclosed quote
				value = decodeEntities(s.substr(dv, pos - dv));
				++pos;
			}
		}
		if (!attrName.empty()) node->attributes.emplace_back(attrName, value);
	}
	if (empty) return node;                                // <tag ... />

	// --- content: text and children, up to the closing tag
	std::wstring text;
	while (pos < s.size()) {
		if (s[pos] != L'<') { text += s[pos++]; continue; }

		// comment, CDATA or instruction: skipped (the CDATA keeps its text)
		if (s.compare(pos, 4, L"<!--") == 0) {
			const size_t f = s.find(L"-->", pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 3;
			continue;
		}
		if (s.compare(pos, 9, L"<![CDATA[") == 0) {
			const size_t f = s.find(L"]]>", pos);
			if (f == std::wstring::npos) return nullptr;
			text += s.substr(pos + 9, f - pos - 9);
			pos = f + 3;
			continue;
		}
		if (pos + 1 < s.size() && (s[pos + 1] == L'?' || s[pos + 1] == L'!')) {
			const size_t f = s.find(L'>', pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 1;
			continue;
		}
		if (pos + 1 < s.size() && s[pos + 1] == L'/') {    // </tag>: end
			const size_t f = s.find(L'>', pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 1;
			node->text = decodeEntities(trim(text));
			return node;
		}
		++pos;                                              // past the '<'
		auto child = readElement(s, pos, depth + 1);
		if (!child) return nullptr;
		node->children.push_back(std::move(child));
	}
	return nullptr;                                         // tag never closed
}

} // namespace

const XmlNode* XmlNode::child(const std::wstring& childName) const {
	for (const std::unique_ptr<XmlNode>& e : children)
		if (e->name == childName) return e.get();
	return nullptr;
}

std::wstring XmlNode::textOf(const std::wstring& path) const {
	const XmlNode* current = this;
	size_t start = 0;
	while (current && start <= path.size()) {
		const size_t sep = path.find(L'/', start);
		const std::wstring segment = path.substr(start, sep == std::wstring::npos
		                                                  ? std::wstring::npos : sep - start);
		if (segment.empty()) break;
		current = current->child(segment);
		if (sep == std::wstring::npos) break;
		start = sep + 1;
	}
	return current ? current->text : std::wstring();
}

std::wstring XmlNode::attribute(const std::wstring& attributeName) const {
	for (const std::pair<std::wstring, std::wstring>& a : attributes)
		if (a.first == attributeName) return a.second;
	return std::wstring();
}

std::vector<const XmlNode*> XmlNode::descendants(const std::wstring& wantedName) const {
	std::vector<const XmlNode*> found;
	// Iterative walk: a forged tree could be very deep.
	std::vector<const XmlNode*> pile{ this };
	while (!pile.empty()) {
		const XmlNode* n = pile.back();
		pile.pop_back();
		for (const std::unique_ptr<XmlNode>& e : n->children) {
			if (e->name == wantedName) found.push_back(e.get());
			pile.push_back(e.get());
		}
	}
	return found;
}

std::unique_ptr<XmlNode> xmlParse(const std::wstring& content) {
	size_t pos = 0;
	while (pos < content.size()) {
		if (content[pos] != L'<') { ++pos; continue; }
		// skips the prologue, the comments and the doctype to reach the root element
		if (content.compare(pos, 4, L"<!--") == 0) {
			const size_t f = content.find(L"-->", pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 3;
			continue;
		}
		if (pos + 1 < content.size() && (content[pos + 1] == L'?' || content[pos + 1] == L'!')) {
			const size_t f = content.find(L'>', pos);
			if (f == std::wstring::npos) return nullptr;
			pos = f + 1;
			continue;
		}
		++pos;
		return readElement(content, pos, 0);
	}
	return nullptr;
}

std::unique_ptr<XmlNode> xmlReadFile(const std::wstring& path) {
	std::ifstream f(std::filesystem::path(path), std::ios::binary);
	if (!f) return nullptr;
	const std::string bytes((std::istreambuf_iterator<char>(f)),
	                          std::istreambuf_iterator<char>());
	if (bytes.empty()) return nullptr;

	// UTF-16LE with a BOM: the format the task scheduler writes.
	if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0xFF
	                       && (unsigned char)bytes[1] == 0xFE) {
		std::wstring w(reinterpret_cast<const wchar_t*>(bytes.data() + 2),
		               (bytes.size() - 2) / sizeof(wchar_t));
		return xmlParse(w);
	}
	// Otherwise UTF-8, with or without a BOM.
	const int offset = (bytes.size() >= 3 && (unsigned char)bytes[0] == 0xEF
	                      && (unsigned char)bytes[1] == 0xBB
	                      && (unsigned char)bytes[2] == 0xBF) ? 3 : 0;
	const std::wstring w = decodeText(std::string(bytes.begin() + offset, bytes.end()), CP_UTF8);
	if (w.empty()) return nullptr;
	return xmlParse(w);
}
