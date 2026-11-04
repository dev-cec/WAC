/*! \file
 *  \brief The DNS Server role (see dns_server.h).
 */
#include "dns_server.h"
#include "registry_common.h"
#include "whole_file.h"
#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <map>
#include <sstream>

namespace {

//! Largest zone file or log read: more than a server's own limits allow in practice, a forged one is refused.
const uintmax_t FILE_MAX = 512ULL * 1024 * 1024;
const wchar_t PARAMETERS_KEY[] = L"Services\\DNS\\Parameters";
const wchar_t ZONES_KEY[] = L"Microsoft\\Windows NT\\CurrentVersion\\DNS Server\\Zones";
const wchar_t DNS_FOLDER[] = L"\\Windows\\System32\\dns";
const size_t ORIGIN_MAX = 255;        //!< RFC 1035's longest name: repeated $ORIGIN lines would otherwise grow every record's name
const size_t ENTRY_WORDS_MAX = 70000; //!< more than a record's 64 KiB of data can hold: a forged open parenthesis swallows no more
const size_t LOG_LINE_MAX = 65536;    //!< a debug log line is short; a forged one of millions of words is not cut into them

//! A word in upper case: record types and classes are case-insensitive (RFC 1035).
std::wstring toUpper(std::wstring word) {
	std::transform(word.begin(), word.end(), word.begin(), [](wchar_t c) { return (wchar_t)towupper(c); });
	return word;
}

//! The record classes of RFC 1035.
bool isDnsClass(const std::wstring& word) {
	const std::wstring upper = toUpper(word);
	return upper == L"IN" || upper == L"CH" || upper == L"HS" || upper == L"CS";
}

//! @return true for a decimal TTL, the only form Windows writes
bool isDecimal(const std::wstring& word) {
	return !word.empty() && word.size() < 11 && word.find_first_not_of(L"0123456789") == std::wstring::npos;
}

//! A word of a master file, and the line it is on.
struct ZoneWord { std::wstring text; size_t line; bool startsLine; };

/*! Cuts a master file into logical entries: a comment ends at its line, parentheses
 *  join lines, quotes hold spaces and escapes. The quotes stay in the word.
 *  @return one list of words per entry; the first word empty when the owner is blank */
std::vector<std::vector<ZoneWord>> zoneEntries(const std::wstring& text) {
	std::vector<std::vector<ZoneWord>> entries;
	std::vector<ZoneWord> current;
	size_t line = 1, depth = 0;
	bool atLineStart = true;
	const auto finish = [&] {
		if (!current.empty()) entries.push_back(std::move(current));
		current.clear();
	};
	for (size_t i = 0; i < text.size();) {
		const wchar_t c = text[i];
		if (c == L'\n') {
			if (depth == 0) finish();
			++line; ++i; atLineStart = true;
			continue;
		}
		if (c == L';') {
			while (i < text.size() && text[i] != L'\n') ++i;
			continue;
		}
		if (c == L'(') { ++depth; ++i; atLineStart = false; continue; }
		if (c == L')') { if (depth) --depth; ++i; atLineStart = false; continue; }
		if (c == L' ' || c == L'\t' || c == L'\r') {
			// A blank at the head of an entry: its owner is the previous one's.
			if (atLineStart && depth == 0 && current.empty() && c != L'\r') current.push_back({ L"", line, true });
			atLineStart = false; ++i;
			continue;
		}
		std::wstring word;
		const size_t wordLine = line;
		const bool startsLine = atLineStart;
		atLineStart = false;
		bool quoted = false;
		while (i < text.size()) {
			const wchar_t w = text[i];
			if (w == L'\\' && i + 1 < text.size() && text[i + 1] != L'\n') { word += w; word += text[i + 1]; i += 2; continue; }
			if (w == L'"') quoted = !quoted;
			else if (!quoted && (w == L' ' || w == L'\t' || w == L'\r' || w == L'\n' || w == L';' || w == L'(' || w == L')')) break;
			else if (w == L'\n') break;   // an open quote does not swallow the file
			word += w; ++i;
		}
		if (!word.empty() && current.size() < ENTRY_WORDS_MAX) current.push_back({ word, wordLine, startsLine });
	}
	finish();
	return entries;
}

//! A name made absolute under the origin, without its final dot.
std::wstring absoluteName(const std::wstring& name, const std::wstring& origin) {
	if (name == L"@") return origin;
	if (!name.empty() && name.back() == L'.') return name.substr(0, name.size() - 1);
	return origin.empty() ? name : name + L"." + origin;
}

/*! A debug log's question name, from its length-prefixed form.
 *  @param wire "(5)host1(4)test(0)"
 *  @return "host1.test"; the form as written if it does not read so */
std::wstring questionNameFromWire(const std::wstring& wire) {
	std::wstring out;
	size_t i = 0;
	while (i < wire.size()) {
		if (wire[i] != L'(') return wire;
		const size_t close = wire.find(L')', i);
		if (close == std::wstring::npos || close == i + 1 || close - i > 4) return wire;
		size_t length = 0;
		for (size_t d = i + 1; d < close; ++d) {
			if (!iswdigit(wire[d])) return wire;
			length = length * 10 + (wire[d] - L'0');
		}
		i = close + 1;
		if (length == 0) return i == wire.size() ? (out.empty() ? L"." : out) : wire;
		if (length > wire.size() - i) return wire;
		if (!out.empty()) out += L'.';
		out.append(wire, i, length);
		i += length;
	}
	return wire;   // no final (0): not the form said
}

//! The words of a line, separated by blanks.
std::vector<std::wstring> lineWords(const std::wstring& line) {
	std::vector<std::wstring> words;
	std::wistringstream in(line);
	for (std::wstring w; in >> w;) words.push_back(w);
	return words;
}

//! @return true if a word has the form of a date of the log: digits and separators, a separator inside
bool looksLikeDate(const std::wstring& word) {
	if (word.size() < 6 || word.size() > 10 || !iswdigit(word[0]) || !iswdigit(word.back())) return false;
	return word.find_first_of(L"/-.") != std::wstring::npos && word.find_first_not_of(L"0123456789/-.") == std::wstring::npos;
}

/*! Reads what follows "PACKET" in a line.
 *  @param words the line's words
 *  @param at the word after PACKET
 *  @param e receives the fields
 *  @return false if the line does not have the form, and is kept as text */
bool readPacket(const std::vector<std::wstring>& words, size_t at, DnsLogEntry& e) {
	// packet proto dir address xid [R] opcode [ flags codes... rcode ] type name
	if (words.size() < at + 5) return false;
	e.packet = words[at]; e.protocol = words[at + 1]; e.direction = words[at + 2];
	e.remoteAddress = words[at + 3]; e.transactionId = words[at + 4];
	size_t i = at + 5;
	if (i < words.size() && words[i] == L"R") { e.response = true; ++i; }
	if (i >= words.size()) return false;
	e.opcode = words[i++];
	if (i >= words.size() || words[i].empty() || words[i][0] != L'[') return false;
	e.flags = words[i].substr(1);
	if (e.flags.empty() && ++i < words.size()) e.flags = words[i];
	++i;
	std::wstring codes;
	while (i < words.size() && (words[i].empty() || words[i].back() != L']')) { codes += words[i]; ++i; }
	if (i >= words.size()) return false;
	e.responseCode = words[i].substr(0, words[i].size() - 1);
	if (e.responseCode.empty() && !codes.empty()) { e.responseCode = codes; codes.clear(); }
	e.flagCodes = codes;
	++i;
	if (i + 1 < words.size()) {
		e.questionType = words[i];
		e.questionName = questionNameFromWire(words[i + 1]);
	}
	return true;
}

/*! Adds the zones of the examined SOFTWARE hive, each with all its values.
 *  @param zones receives one object per zone
 *  @param files receives the zone's file name, lower case, for its name */
void readZones(Json& zones, std::map<std::wstring, std::wstring>& files) {
	if (!conf.Software) return;
	ORHKEY root = NULL;
	if (OROpenKey(conf.Software, ZONES_KEY, &root) != ERROR_SUCCESS) return;
	for (const Subkey& zone : subkeysOf(root)) {
		ORHKEY key = NULL;
		if (OROpenKey(root, zone.name.c_str(), &key) != ERROR_SUCCESS) continue;
		std::vector<std::pair<std::wstring, Json>> values;
		readAllValues(key, values);
		Json o = Json::obj();
		o.add(L"Name", Json::str(zone.name));
		addDate(o, L"KeyLastWrite", zone.lastWriteUtc);
		for (auto& [name, value] : values) o.add(name == L"Name" ? L"ValueName" : name, std::move(value));
		zones.push(std::move(o));
		std::wstring file;
		if (getRegSzValue(key, NULL, L"DatabaseFile", &file) == ERROR_SUCCESS && !file.empty())
			files[toLower(file)] = zone.name;
		ORCloseKey(key);
	}
	ORCloseKey(root);
}

} // namespace

Json DnsZoneRecord::toJson() const {
	Json o = Json::obj();
	o.add(L"Zone", Json::str(zone));
	o.add(L"Name", Json::str(name));
	if (ttl >= 0) o.add(L"Ttl", Json::num(ttl));
	o.add(L"Class", Json::str(dnsClass));
	o.add(L"Type", Json::str(type));
	o.add(L"Data", Json::str(data));
	o.add(L"File", Json::str(file));
	o.add(L"Line", Json::num(line));
	return o;
}

Json DnsLogEntry::toJson() const {
	Json o = Json::obj();
	o.add(L"TimeAsStored", Json::str(timeAsStored));
	o.add(L"Thread", Json::str(thread));
	o.add(L"Context", Json::str(context));
	o.add(L"Packet", Json::str(packet));
	o.add(L"Protocol", Json::str(protocol));
	o.add(L"Direction", Json::str(direction));
	o.add(L"RemoteAddress", Json::str(remoteAddress));
	o.add(L"TransactionId", Json::str(transactionId));
	if (!packet.empty()) o.add(L"Response", Json::boolean(response));
	o.add(L"Opcode", Json::str(opcode));
	o.add(L"Flags", Json::str(flags));
	o.add(L"FlagCodes", Json::str(flagCodes));
	o.add(L"ResponseCode", Json::str(responseCode));
	o.add(L"QuestionType", Json::str(questionType));
	o.add(L"QuestionName", Json::str(questionName));
	o.add(L"Text", Json::str(text));
	o.add(L"File", Json::str(file));
	o.add(L"Line", Json::num(line));
	return o;
}

std::vector<DnsZoneRecord> parseDnsZoneFile(const std::wstring& text, const std::wstring& zone, const std::wstring& file) {
	std::vector<DnsZoneRecord> records;
	std::wstring origin = zone, owner = zone;
	long long defaultTtl = -1;
	for (const std::vector<ZoneWord>& entry : zoneEntries(text)) {
		if (entry.empty()) continue;
		const std::wstring& head = entry[0].text;
		if (head == L"$ORIGIN") {
			if (entry.size() > 1) {
				const std::wstring next = absoluteName(entry[1].text, origin);
				if (next.size() <= ORIGIN_MAX) owner = origin = next;
			}
			continue;
		}
		if (head == L"$TTL") { if (entry.size() > 1 && isDecimal(entry[1].text)) defaultTtl = std::stoll(entry[1].text); continue; }
		if (!head.empty() && head[0] == L'$') continue;   // $INCLUDE names a file: what it holds is in that file
		size_t i = 1;
		if (!head.empty()) owner = absoluteName(head, origin);
		else if (entry.size() < 2) continue;
		DnsZoneRecord r;
		r.zone = zone; r.name = owner; r.file = file; r.line = entry[0].line;
		r.dnsClass = L"IN";
		// TTL and class, each optional, in either order.
		for (int optional = 0; optional < 2 && i < entry.size(); ++optional) {
			if (isDecimal(entry[i].text)) r.ttl = std::stoll(entry[i++].text);
			else if (isDnsClass(entry[i].text) && i + 1 < entry.size()) r.dnsClass = toUpper(entry[i++].text);
		}
		if (i >= entry.size() || isDecimal(entry[i].text)) continue;
		r.type = toUpper(entry[i++].text);
		for (; i < entry.size(); ++i) {
			if (!r.data.empty()) r.data += L' ';
			r.data += entry[i].text;
		}
		// Windows' default: the SOA's last field, its own record's TTL when written without one.
		if (r.type == L"SOA" && !entry.empty() && isDecimal(entry.back().text)) {
			if (defaultTtl < 0) defaultTtl = std::stoll(entry.back().text);
		}
		if (r.ttl < 0) r.ttl = defaultTtl;
		records.push_back(std::move(r));
	}
	return records;
}

std::vector<DnsLogEntry> parseDnsDebugLog(const std::wstring& text, const std::wstring& file) {
	std::vector<DnsLogEntry> entries;
	const std::vector<std::wstring> lines = splitLines(text);
	for (size_t n = 0; n < lines.size(); ++n) {
		if (lines[n].size() > LOG_LINE_MAX) continue;
		const std::vector<std::wstring> words = lineWords(lines[n]);
		if (words.size() < 3 || !looksLikeDate(words[0])) continue;
		DnsLogEntry e;
		e.file = file; e.line = n + 1;
		size_t i = 2;
		e.timeAsStored = words[0] + L" " + words[1];
		if (i < words.size() && (words[i] == L"AM" || words[i] == L"PM")) e.timeAsStored += L" " + words[i++];
		if (i < words.size()) e.thread = words[i++];
		if (i < words.size()) e.context = words[i++];
		if (e.context != L"PACKET" || !readPacket(words, i, e)) {
			// Left as written after the thread: a note, or a packet line of another layout.
			DnsLogEntry note;
			note.file = file; note.line = e.line; note.timeAsStored = e.timeAsStored; note.thread = e.thread;
			const size_t at = lines[n].find(e.thread, words[0].size());
			if (at != std::wstring::npos) {
				note.text = lines[n].substr(at + e.thread.size());
				const size_t first = note.text.find_first_not_of(L" \t");
				note.text = first == std::wstring::npos ? L"" : note.text.substr(first);
				while (!note.text.empty() && (note.text.back() == L'\r' || note.text.back() == L' ')) note.text.pop_back();
			}
			entries.push_back(std::move(note));
			continue;
		}
		entries.push_back(std::move(e));
	}
	return entries;
}

std::wstring dnsServerLogFile() {
	std::wstring path;
	if (conf.CurrentControlSet && getRegSzValue(conf.CurrentControlSet, PARAMETERS_KEY, L"LogFilePath", &path) == ERROR_SUCCESS && !path.empty()) {
		const std::wstring normalized = normalizeFilePath(path);
		if (!normalized.empty()) return normalized;
	}
	return conf.systemDrive.substr(0, 2) + DNS_FOLDER + L"\\dns.log";
}

HRESULT DnsServer::getData() {
	if (conf.CurrentControlSet) {
		ORHKEY key = NULL;
		if (OROpenKey(conf.CurrentControlSet, PARAMETERS_KEY, &key) == ERROR_SUCCESS) {
			std::vector<std::pair<std::wstring, Json>> values;
			readAllValues(key, values);
			Json o = Json::obj();
			o.add(L"Key", Json::str(PARAMETERS_KEY));
			addDate(o, L"KeyLastWrite", lastWrite(key));
			for (auto& [name, value] : values) o.add(name == L"Key" ? L"ValueKey" : name, std::move(value));
			configuration_.push(std::move(o));
			ORCloseKey(key);
		}
	}
	std::map<std::wstring, std::wstring> zoneOfFile;
	readZones(zones_, zoneOfFile);

	const std::wstring root = conf.systemDrive.substr(0, 2) + DNS_FOLDER;
	for (const std::wstring& folder : { root, root + L"\\backup" }) {
		std::error_code ec;
		for (std::filesystem::directory_iterator it(extractedPath(folder), ec), end; !ec && it != end; it.increment(ec)) {
			const std::wstring name = it->path().filename().wstring();
			if (!it->is_regular_file(ec) || toLower(it->path().extension().wstring()) != L".dns") continue;
			std::string bytes;
			if (!readWholeFile(it->path(), FILE_MAX, bytes)) { log(2, L"🔥Zone file not read: " + it->path().wstring()); continue; }
			const auto known = zoneOfFile.find(toLower(name));
			std::wstring zone = known != zoneOfFile.end() ? known->second : name.substr(0, name.size() - 4);
			if (toLower(name) == L"cache.dns") zone.clear();   // the root's hints
			std::vector<DnsZoneRecord> read = parseDnsZoneFile(decodeTextFile(bytes), zone, folder + L"\\" + name);
			log(2, L"❇️" + name + L" : " + std::to_wstring(read.size()) + L" record(s)");
			for (DnsZoneRecord& r : read) records_.push_back(std::move(r));
		}
	}

	const std::wstring logFile = dnsServerLogFile();
	std::error_code ec;
	const std::filesystem::path logPath = extractedPath(logFile);
	if (std::filesystem::is_regular_file(logPath, ec)) {
		std::string bytes;
		if (readWholeFile(logPath, FILE_MAX, bytes)) logEntries_ = parseDnsDebugLog(decodeTextFile(bytes), logFile);
		else log(2, L"🔥DNS debug log not read: " + logPath.wstring());
	}
	return ERROR_SUCCESS;
}

HRESULT DnsServer::toJson() {
	HRESULT failed = ERROR_SUCCESS;
	const auto note = [&failed](HRESULT written) { if (written != ERROR_SUCCESS) failed = written; };
	note(writeJsonFile("dns_server_configuration.json", configuration_));
	note(writeJsonFile("dns_server_zones.json", zones_));
	note(writeList("dns_server_records.json", records_));
	note(writeList("dns_server_log.json", logEntries_));
	return failed;
}

void DnsServer::clear() {
	configuration_ = Json::arr();
	zones_ = Json::arr();
	records_.clear();
	logEntries_.clear();
}
