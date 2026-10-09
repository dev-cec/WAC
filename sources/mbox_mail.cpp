/*! \file
 *  \brief Thunderbird's mailboxes: mbox and MIME (see mbox_mail.h).
 */
#include "mbox_mail.h"
#include "conversions.h"
#include "tools.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>

namespace {

const int MIME_DEPTH_MAX = 16;   //!< deeper than any real message: a forged nesting

//! Lower case, ASCII only (header names, MIME types, parameter names).
std::string lowered(std::string s) {
	for (char& c : s) c = (char)std::tolower((unsigned char)c);
	return s;
}

//! Without the spaces and tabs around.
std::string trimmed(const std::string& s) {
	const size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
	return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
}

//! A header: its name (lower case) and its value, unfolded.
struct Header { std::string name, value; };

/*! The header block and the body of a part: the block ends at the first
 *  empty line (CRLF or LF).
 *  @return false if there is no empty line: no header block */
bool splitPart(const std::string& part, std::string& headers, std::string& body) {
	size_t at = 0;
	for (;;) {
		const size_t end = part.find('\n', at);
		if (end == std::string::npos) { headers = part; body.clear(); return !part.empty(); }
		const std::string line = part.substr(at, end - at);
		if (line.empty() || line == "\r") {
			headers = part.substr(0, at);
			body = part.substr(end + 1);
			return true;
		}
		at = end + 1;
	}
}

//! The headers of a block, folded lines joined.
std::vector<Header> parseHeaders(const std::string& block) {
	std::vector<Header> headers;
	size_t at = 0;
	while (at < block.size()) {
		size_t end = block.find('\n', at);
		if (end == std::string::npos) end = block.size();
		std::string line = block.substr(at, end - at);
		if (!line.empty() && line.back() == '\r') line.pop_back();
		at = end + 1;
		if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
			if (!headers.empty()) headers.back().value += " " + trimmed(line);
			continue;
		}
		const size_t colon = line.find(':');
		if (colon == std::string::npos || colon == 0) continue;
		headers.push_back({ lowered(trimmed(line.substr(0, colon))), trimmed(line.substr(colon + 1)) });
	}
	return headers;
}

//! The first header of that name, empty if none.
std::string headerOf(const std::vector<Header>& headers, const char* name) {
	for (const Header& h : headers) if (h.name == name) return h.value;
	return std::string();
}

//! The code page of a MIME character set; UTF-8 for an unknown one.
UINT codePageOf(const std::string& charset) {
	const std::string c = lowered(trimmed(charset));
	if (c == "utf-8" || c == "utf8") return CP_UTF8;
	if (c == "iso-8859-1" || c == "latin1") return 28591;
	if (c == "iso-8859-15") return 28605;
	if (c == "windows-1252" || c == "cp1252") return 1252;
	if (c == "us-ascii" || c == "ascii") return 20127;
	if (c == "windows-1251") return 1251;
	if (c == "iso-8859-2") return 28592;
	return c.empty() ? 20127 : CP_UTF8;
}

/*! A structured value: "type/subtype; name=value; …", the parameters by
 *  lower-case name, quotes removed; RFC 2231 continuations and charsets
 *  ("name*0*=utf-8''…") joined and decoded into `decoded`.
 *  @param value the header's value
 *  @param parameters receives the plain parameters
 *  @param decoded receives the RFC 2231 ones, decoded
 *  @return the main value, lower case */
std::string parseStructured(const std::string& value, std::map<std::string, std::string>& parameters,
                            std::map<std::string, std::wstring>& decoded) {
	std::vector<std::string> parts;
	std::string current;
	bool quoted = false;
	for (char c : value) {
		if (c == '"') { quoted = !quoted; continue; }
		if (c == ';' && !quoted) { parts.push_back(current); current.clear(); continue; }
		current += c;
	}
	parts.push_back(current);
	std::map<std::string, std::map<int, std::pair<std::string, bool>>> continued;   // name -> section -> text, encoded
	for (size_t i = 1; i < parts.size(); ++i) {
		const size_t eq = parts[i].find('=');
		if (eq == std::string::npos) continue;
		std::string name = lowered(trimmed(parts[i].substr(0, eq)));
		const std::string text = trimmed(parts[i].substr(eq + 1));
		const bool encoded = !name.empty() && name.back() == '*';
		if (encoded) name.pop_back();
		const size_t star = name.find('*');
		int section = 0;
		if (star != std::string::npos) {
			section = std::atoi(name.c_str() + star + 1);
			name = name.substr(0, star);
		}
		if (star == std::string::npos && !encoded) parameters[name] = text;
		else if (section >= 0 && section < 64) continued[name][section] = { text, encoded };
	}
	for (const auto& [name, sections] : continued) {
		std::string charset, bytes;
		for (const auto& [section, piece] : sections) {
			std::string text = piece.first;
			if (piece.second && section == 0) {
				// charset'language'value
				const size_t q1 = text.find('\''), q2 = q1 == std::string::npos ? q1 : text.find('\'', q1 + 1);
				if (q2 != std::string::npos) { charset = text.substr(0, q1); text = text.substr(q2 + 1); }
			}
			if (!piece.second) { bytes += text; continue; }
			for (size_t k = 0; k < text.size(); ++k) {
				if (text[k] == '%' && k + 2 < text.size() && std::isxdigit((unsigned char)text[k + 1]) && std::isxdigit((unsigned char)text[k + 2])) {
					bytes += (char)std::stoi(text.substr(k + 1, 2), nullptr, 16);
					k += 2;
				}
				else bytes += text[k];
			}
		}
		decoded[name] = decodeText(bytes, charset.empty() ? CP_UTF8 : codePageOf(charset));
	}
	return lowered(trimmed(parts[0]));
}

//! Quoted-printable (RFC 2045) to bytes; soft line breaks removed.
std::string decodeQuotedPrintable(const std::string& text) {
	std::string out;
	for (size_t i = 0; i < text.size(); ++i) {
		if (text[i] != '=') { out += text[i]; continue; }
		if (i + 1 < text.size() && (text[i + 1] == '\n' || (text[i + 1] == '\r' && i + 2 < text.size() && text[i + 2] == '\n'))) {
			i += text[i + 1] == '\r' ? 2 : 1;
			continue;
		}
		if (i + 2 < text.size() && std::isxdigit((unsigned char)text[i + 1]) && std::isxdigit((unsigned char)text[i + 2])) {
			out += (char)std::stoi(text.substr(i + 1, 2), nullptr, 16);
			i += 2;
		}
		else out += '=';
	}
	return out;
}

//! A part's body, decoded from its transfer encoding.
std::string decodeTransfer(const std::string& body, const std::string& encoding) {
	const std::string e = lowered(trimmed(encoding));
	if (e == "base64") {
		const std::vector<uint8_t> bytes = DecodeBase64(body);
		return std::string(bytes.begin(), bytes.end());
	}
	if (e == "quoted-printable") return decodeQuotedPrintable(body);
	return body;
}

void walkPart(const std::string& part, MimeMessage& m, int depth) {
	std::string block, body;
	if (!splitPart(part, block, body)) return;
	const std::vector<Header> headers = parseHeaders(block);
	std::map<std::string, std::string> type, disposition;
	std::map<std::string, std::wstring> typeDecoded, dispositionDecoded;
	std::string mime = parseStructured(headerOf(headers, "content-type"), type, typeDecoded);
	if (mime.empty()) mime = "text/plain";
	const std::string kind = parseStructured(headerOf(headers, "content-disposition"), disposition, dispositionDecoded);
	if (mime.rfind("multipart/", 0) == 0) {
		const auto boundary = type.find("boundary");
		if (boundary == type.end() || boundary->second.empty() || depth >= MIME_DEPTH_MAX) return;
		// The parts lie between "--boundary" lines; "--boundary--" ends them.
		const std::string delimiter = "--" + boundary->second;
		size_t at = body.find(delimiter);
		while (at != std::string::npos) {
			size_t start = body.find('\n', at);
			if (start == std::string::npos || body.compare(at + delimiter.size(), 2, "--") == 0) break;
			++start;
			size_t next = body.find("\n" + delimiter, start);
			const size_t end = next == std::string::npos ? body.size() : next;
			std::string sub = body.substr(start, end - start);
			if (!sub.empty() && sub.back() == '\r') sub.pop_back();
			walkPart(sub, m, depth + 1);
			at = next == std::string::npos ? next : next + 1;
		}
		return;
	}
	const std::string bytes = decodeTransfer(body, headerOf(headers, "content-transfer-encoding"));
	std::wstring name;
	if (dispositionDecoded.count("filename")) name = dispositionDecoded["filename"];
	else if (disposition.count("filename")) name = decodeEncodedWords(disposition["filename"]);
	else if (typeDecoded.count("name")) name = typeDecoded["name"];
	else if (type.count("name")) name = decodeEncodedWords(type["name"]);
	const bool attachment = kind == "attachment" || !name.empty() || mime == "message/rfc822";
	if (!attachment && mime == "text/plain" && m.body.empty()) {
		m.body = decodeText(bytes, codePageOf(type.count("charset") ? type["charset"] : ""));
		return;
	}
	if (!attachment && mime == "text/html" && m.html.empty()) {
		m.html.assign(bytes.begin(), bytes.end());
		return;
	}
	if (!attachment) return;
	MimeAttachment a;
	a.fileName = name;
	a.mimeType = decodeText(mime, CP_UTF8);
	a.data.assign(bytes.begin(), bytes.end());
	m.attachments.push_back(std::move(a));
}

} // namespace

std::wstring decodeEncodedWords(const std::string& value) {
	std::wstring out;
	size_t at = 0;
	bool lastEncoded = false;
	while (at < value.size()) {
		const size_t start = value.find("=?", at);
		if (start == std::string::npos) break;
		const size_t q1 = value.find('?', start + 2), q2 = q1 == std::string::npos ? q1 : value.find('?', q1 + 1);
		const size_t end = q2 == std::string::npos ? q2 : value.find("?=", q2 + 1);
		if (end == std::string::npos || q2 != q1 + 2) {   // "=?" not starting an encoded word: kept as written
			out += decodeText(value.substr(at, start + 2 - at), CP_UTF8);
			at = start + 2;
			lastEncoded = false;
			continue;
		}
		// Spaces between two encoded words are not part of the text (RFC 2047 §6.2).
		const std::string between = value.substr(at, start - at);
		if (!(lastEncoded && trimmed(between).empty())) out += decodeText(between, CP_UTF8);
		const std::string charset = value.substr(start + 2, q1 - start - 2);
		const char mode = (char)std::toupper((unsigned char)value[q1 + 1]);
		std::string text = value.substr(q2 + 1, end - q2 - 1), bytes;
		if (mode == 'B') { const std::vector<uint8_t> b = DecodeBase64(text); bytes.assign(b.begin(), b.end()); }
		else {
			std::replace(text.begin(), text.end(), '_', ' ');
			bytes = decodeQuotedPrintable(text);
		}
		const size_t star = charset.find('*');   // RFC 2231 language suffix
		out += decodeText(bytes, codePageOf(charset.substr(0, star)));
		at = end + 2;
		lastEncoded = true;
	}
	if (at < value.size()) out += decodeText(value.substr(at), CP_UTF8);
	return out;
}

bool parseMailDate(const std::string& text, FILETIME& utc) {
	static const char* const MONTHS[] = { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
	std::string s = text;
	const size_t comma = s.find(',');
	if (comma != std::string::npos) s = s.substr(comma + 1);
	std::vector<std::string> t;
	for (size_t at = 0; at < s.size();) {
		const size_t a = s.find_first_not_of(" \t", at);
		if (a == std::string::npos) break;
		const size_t b = s.find_first_of(" \t", a);
		t.push_back(s.substr(a, b == std::string::npos ? std::string::npos : b - a));
		at = b == std::string::npos ? s.size() : b;
	}
	if (t.size() < 4) return false;
	SYSTEMTIME st{};
	st.wDay = (WORD)std::atoi(t[0].c_str());
	const std::string month = lowered(t[1].substr(0, 3));
	for (WORD k = 0; k < 12; ++k) if (month == MONTHS[k]) st.wMonth = k + 1;
	int year = std::atoi(t[2].c_str());
	if (year < 50) year += 2000; else if (year < 100) year += 1900;
	st.wYear = (WORD)year;
	int h = 0, mi = 0, se = 0;
	if (st.wMonth == 0 || st.wDay == 0 || std::sscanf(t[3].c_str(), "%d:%d:%d", &h, &mi, &se) < 2) return false;
	st.wHour = (WORD)h; st.wMinute = (WORD)mi; st.wSecond = (WORD)se;
	int offset = 0;   // minutes east of UTC
	if (t.size() > 4) {
		const std::string z = t[4];
		if ((z[0] == '+' || z[0] == '-') && z.size() >= 5) {
			const int v = std::atoi(z.c_str() + 1);
			offset = (v / 100) * 60 + v % 100;
			if (z[0] == '-') offset = -offset;
		}
		else {
			static const std::map<std::string, int> ZONES = { { "edt", -240 }, { "est", -300 }, { "cdt", -300 }, { "cst", -360 },
			                                                  { "mdt", -360 }, { "mst", -420 }, { "pdt", -420 }, { "pst", -480 } };
			const auto it = ZONES.find(lowered(z));
			if (it != ZONES.end()) offset = it->second;
		}
	}
	FILETIME local{};
	if (!SystemTimeToFileTime(&st, &local)) return false;
	utc = filetimeFromTicks(ticksFromFiletime(local) - (uint64_t)((int64_t)offset * 600000000LL));
	return true;
}

bool parseMimeMessage(const std::string& raw, MimeMessage& m) {
	std::string block, body;
	if (!splitPart(raw, block, body)) return false;
	m.headers = block;
	const std::vector<Header> headers = parseHeaders(block);
	m.from = decodeEncodedWords(headerOf(headers, "from"));
	m.to = decodeEncodedWords(headerOf(headers, "to"));
	m.cc = decodeEncodedWords(headerOf(headers, "cc"));
	m.bcc = decodeEncodedWords(headerOf(headers, "bcc"));
	m.subject = decodeEncodedWords(headerOf(headers, "subject"));
	m.messageId = decodeText(headerOf(headers, "message-id"), CP_UTF8);
	const std::string date = headerOf(headers, "date");
	if (!date.empty()) parseMailDate(date, m.dateUtc);
	walkPart(raw, m, 0);
	return true;
}

bool forEachMboxMessage(const std::wstring& path, const std::function<void(MimeMessage&)>& onMessage, size_t& skipped) {
	skipped = 0;
	std::ifstream in(std::filesystem::path(extendedPath(path)), std::ios::binary);
	if (!in) return false;
	std::string line, current;
	size_t position = 0, start = 0;
	bool started = false, previousEmpty = true, oversized = false;
	auto flush = [&]() {
		if (!started) return;
		if (oversized) { ++skipped; return; }
		// The empty line before the next "From " separates; it is not the message's.
		if (current.size() >= 2 && current.compare(current.size() - 2, 2, "\r\n") == 0) current.resize(current.size() - 2);
		else if (!current.empty() && current.back() == '\n') current.pop_back();
		MimeMessage m;
		m.offset = start;
		if (parseMimeMessage(current, m)) onMessage(m);
	};
	while (std::getline(in, line)) {
		const size_t length = line.size() + 1;
		const bool separator = line.rfind("From ", 0) == 0 && previousEmpty;
		if (!started && !separator) return false;   // not an mbox
		if (separator) {
			flush();
			current.clear();
			oversized = false;
			started = true;
			start = position + length;
		}
		else if (!oversized) {
			if (current.size() + length > MBOX_MESSAGE_MAX) { oversized = true; current.clear(); }
			else { current += line; current += '\n'; }
		}
		previousEmpty = line.empty() || line == "\r";
		position += length;
	}
	flush();
	return started;
}
