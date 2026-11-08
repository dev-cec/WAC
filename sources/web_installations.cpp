/*! \file
 *  \brief Apache, nginx and the database engines (see web_installations.h).
 */
#include "web_installations.h"
#include "wildcard.h"
#include "registry_common.h"
#include <algorithm>
#include <filesystem>
#include <map>
#include <set>

namespace {

//! Includes followed, at most: far above a real configuration, a bound on one that includes itself through links.
const int INCLUDE_DEPTH = 16;
//! Largest configuration file read.
const uintmax_t CONFIGURATION_MAX = 16ULL * 1024 * 1024;
//! Folder depth an Apache `Include folder/` walks.
const int INCLUDE_FOLDER_DEPTH = 8;
//! Longest word once its variables are replaced: far above any path or name of a configuration.
const size_t EXPANDED_MAX = 64 * 1024;

const wchar_t* APACHE = L"Apache";
const wchar_t* NGINX = L"nginx";
const wchar_t* SERVICES = L"Services";

//! Forward slashes to backslashes, the final one removed.
std::wstring windowsPath(std::wstring path) {
	std::replace(path.begin(), path.end(), L'/', L'\\');
	while (path.size() > 3 && path.back() == L'\\') path.pop_back();
	return path;
}

//! Whether a path starts with its volume.
bool absolutePath(const std::wstring& path) {
	return path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
}

//! A path of the configuration as absolute, from the folder relative ones start in.
std::wstring fromRoot(const std::wstring& written, const std::wstring& root) {
	const std::wstring path = windowsPath(written);
	return absolutePath(path) ? path : root + L"\\" + path;
}

//! The folder of a path.
std::wstring parentOf(const std::wstring& path) {
	const size_t slash = path.rfind(L'\\');
	return slash == std::wstring::npos ? L"" : path.substr(0, slash);
}

//! The name of a path, lower case.
std::wstring nameOf(const std::wstring& path) {
	const size_t slash = path.rfind(L'\\');
	return toLower(slash == std::wstring::npos ? path : path.substr(slash + 1));
}

//! Adds a value once, case ignored.
void addOnce(std::vector<std::wstring>& list, const std::wstring& value) {
	const std::wstring lower = toLower(value);
	if (!value.empty() && std::none_of(list.begin(), list.end(), [&](const std::wstring& v) { return toLower(v) == lower; }))
		list.push_back(value);
}

//! A list of texts as a JSON array.
Json textList(const std::vector<std::wstring>& values) {
	Json out = Json::arr();
	for (const std::wstring& v : values) out.push(Json::str(v));
	return out;
}

//! The value of `--name=value`, or the word after `-n`, in a command.
std::wstring option(const std::vector<std::wstring>& words, const std::wstring& longName, const std::wstring& shortName) {
	for (size_t i = 1; i < words.size(); ++i) {
		if (!longName.empty() && toLower(words[i]).compare(0, longName.size() + 1, longName + L"=") == 0)
			return words[i].substr(longName.size() + 1);
		if (!shortName.empty() && words[i] == shortName && i + 1 < words.size()) return words[i + 1];
	}
	return L"";
}

//! A candidate from a service's binary, if it is httpd.exe or nginx.exe.
bool candidateOfService(const WebServiceEntry& service, WebCandidate& out) {
	const std::wstring command = service.application.empty() ? service.imagePath : service.application;
	const std::vector<std::wstring> words = commandWords(command);
	if (words.empty()) return false;
	const std::wstring binary = windowsPath(words[0]), name = nameOf(binary);
	if (!absolutePath(binary) || (name != L"httpd.exe" && name != L"nginx.exe")) return false;
	const bool apache = name == L"httpd.exe";
	const std::wstring folder = parentOf(binary);
	out.product = apache ? APACHE : NGINX;
	out.source = L"service " + service.name;
	if (apache) {
		out.root = nameOf(folder) == L"bin" ? parentOf(folder) : folder;
		const std::wstring server = option(words, L"", L"-d");
		if (!server.empty()) out.root = windowsPath(server);
	}
	else {
		const std::wstring prefix = option(words, L"", L"-p");
		out.root = prefix.empty() ? folder : windowsPath(prefix);
	}
	const std::wstring file = option(words, L"", apache ? L"-f" : L"-c");
	out.configFile = fromRoot(file.empty() ? (apache ? L"conf\\httpd.conf" : L"conf\\nginx.conf") : file, out.root);
	return true;
}

/*! Reads Apache's directives. A class for what the includes share: the
 *  variables, the host being read, the files seen. */
class ApacheReader {
public:
	ApacheReader(WebInstallation& out, const WebConfigFiles& files) : out_(out), files_(files), root_(out.root) {}

	void file(const std::wstring& path, int depth) {
		std::wstring text;
		if (depth > INCLUDE_DEPTH || !seen_.insert(toLower(path)).second) return;
		if (!files_.read(path, text)) { addOnce(out_.notRead, path); return; }
		std::wstring pending;
		for (std::wstring line : splitLines(text)) {
			if (!line.empty() && line.back() == L'\r') line.pop_back();
			if (!line.empty() && line.back() == L'\\') { line.pop_back(); pending += line; continue; }
			directive(pending + line, path, depth);
			pending.clear();
		}
	}

private:
	WebInstallation& out_;
	const WebConfigFiles& files_;
	std::wstring root_;
	std::map<std::wstring, std::wstring> defines_;
	std::set<std::wstring> seen_;
	size_t host_ = 0;   //!< the host being read: an index, the list grows

	/*! A word with its variables replaced. A chain of `Define`, each doubling the
	 *  one before, reaches any size from a few lines: past the bound, the rest of
	 *  the word stays as written. */
	std::wstring expanded(std::wstring value) const {
		for (const auto& [name, text] : defines_) {
			const std::wstring marker = L"${" + name + L"}";
			for (size_t at = value.find(marker); at != std::wstring::npos; at = value.find(marker, at + text.size())) {
				if (value.size() - marker.size() + text.size() > EXPANDED_MAX) return value;
				value.replace(at, marker.size(), text);
			}
		}
		return value;
	}

	void include(const std::wstring& written, int depth) {
		const std::wstring pattern = fromRoot(written, root_);
		const std::vector<std::wstring> found = files_.matches(pattern);
		if (found.empty() && pattern.find_first_of(L"*?") == std::wstring::npos) addOnce(out_.notRead, pattern);
		for (const std::wstring& f : found) file(f, depth + 1);
	}

	//! A log named by a directive, unless it is a pipe or syslog.
	void addLog(std::vector<std::wstring>& logs, const std::wstring& written) const {
		if (written.empty() || written[0] == L'|' || toLower(written).compare(0, 7, L"syslog:") == 0) return;
		addOnce(logs, fromRoot(written, root_));
	}

	void directive(const std::wstring& line, const std::wstring& path, int depth) {
		std::vector<std::wstring> w = commandWords(line);
		if (w.empty() || w[0][0] == L'#') return;
		const std::wstring name = toLower(w[0]);
		for (size_t i = 1; i < w.size(); ++i) w[i] = expanded(w[i]);
		if (name == L"<virtualhost") {
			out_.hosts.emplace_back();
			host_ = out_.hosts.size() - 1;
			out_.hosts[host_].file = path;
			if (w.size() > 1) {
				std::wstring address = w[1];
				if (!address.empty() && address.back() == L'>') address.pop_back();
				addOnce(out_.hosts[host_].listen, address);
			}
			return;
		}
		if (name == L"</virtualhost>") { host_ = 0; return; }
		if (w.size() < 2) return;
		WebHost& host = out_.hosts[host_];
		if (name == L"define") { if (w.size() > 2) defines_[w[1]] = w[2]; }
		else if (name == L"serverroot") { root_ = windowsPath(w[1]); out_.root = root_; }
		else if (name == L"documentroot") addOnce(host.documentRoots, fromRoot(w[1], root_));
		else if ((name == L"alias" || name == L"scriptalias") && w.size() > 2) addOnce(host.documentRoots, fromRoot(w[2], root_));
		else if (name == L"servername" || name == L"serveralias") { for (size_t i = 1; i < w.size(); ++i) addOnce(host.serverNames, w[i]); }
		else if (name == L"listen") addOnce(host.listen, w[1]);
		else if (name == L"errorlog") addLog(host.errorLogs, w[1]);
		else if (name == L"customlog" || name == L"transferlog") addLog(host.accessLogs, w[1]);
		else if (name == L"loadmodule" && w.size() > 2) out_.modules.emplace_back(w[1], fromRoot(w[2], root_));
		else if (name == L"include" || name == L"includeoptional") include(w[1], depth);
	}
};

/*! Reads nginx's blocks. Words, `;`, `{` and `}` are tokens of a file; an
 *  include is read in the block that names it. */
class NginxReader {
public:
	NginxReader(WebInstallation& out, const WebConfigFiles& files) : out_(out), files_(files), confFolder_(parentOf(out.configFile)) {}

	void file(const std::wstring& path, std::vector<std::wstring>& context, size_t host, int depth) {
		std::wstring text;
		if (depth > INCLUDE_DEPTH || !seen_.insert(toLower(path)).second) return;
		if (!files_.read(path, text)) { addOnce(out_.notRead, path); return; }
		statements(tokens(text), path, context, host, depth);
	}

private:
	WebInstallation& out_;
	const WebConfigFiles& files_;
	std::wstring confFolder_;
	std::set<std::wstring> seen_;

	static std::vector<std::wstring> tokens(const std::wstring& text) {
		std::vector<std::wstring> out;
		size_t i = 0;
		while (i < text.size()) {
			const wchar_t c = text[i];
			if (iswspace(c)) { ++i; continue; }
			if (c == L'#') { while (i < text.size() && text[i] != L'\n') ++i; continue; }
			if (c == L';' || c == L'{' || c == L'}') { out.emplace_back(1, c); ++i; continue; }
			std::wstring word;
			if (c == L'"' || c == L'\'') {
				const size_t close = text.find(c, i + 1);
				word = text.substr(i + 1, (close == std::wstring::npos ? text.size() : close) - i - 1);
				i = close == std::wstring::npos ? text.size() : close + 1;
			}
			else {
				while (i < text.size() && !iswspace(text[i]) && text[i] != L';' && text[i] != L'{' && text[i] != L'}') word += text[i++];
			}
			out.push_back(word);
		}
		return out;
	}

	void addLog(std::vector<std::wstring>& logs, const std::wstring& written) const {
		const std::wstring lower = toLower(written);
		if (lower == L"off" || lower == L"stderr" || lower.compare(0, 7, L"syslog:") == 0 || lower.compare(0, 7, L"memory:") == 0) return;
		addOnce(logs, fromRoot(written, out_.root));
	}

	void statements(const std::vector<std::wstring>& t, const std::wstring& path, std::vector<std::wstring>& context, size_t host, int depth) {
		std::vector<size_t> hosts;
		std::vector<std::wstring> words;
		for (const std::wstring& token : t) {
			if (token == L"{") {
				const std::wstring block = words.empty() ? L"" : toLower(words[0]);
				context.push_back(block);
				hosts.push_back(host);
				if (block == L"server" && std::find(context.begin(), context.end(), L"http") != context.end()) {
					out_.hosts.emplace_back();
					host = out_.hosts.size() - 1;
					out_.hosts[host].file = path;
				}
				words.clear();
			}
			else if (token == L"}") {
				if (!hosts.empty()) { host = hosts.back(); hosts.pop_back(); }
				if (!context.empty()) context.pop_back();
				words.clear();
			}
			else if (token == L";") {
				statement(words, context, host, depth);
				words.clear();
			}
			else words.push_back(token);
		}
	}

	void statement(const std::vector<std::wstring>& w, std::vector<std::wstring>& context, size_t host, int depth) {
		if (w.size() < 2) return;
		const std::wstring name = toLower(w[0]);
		WebHost& h = out_.hosts[host];
		if (name == L"root" || name == L"alias") addOnce(h.documentRoots, fromRoot(w[1], out_.root));
		else if (name == L"listen") addOnce(h.listen, w[1]);
		else if (name == L"server_name") { for (size_t i = 1; i < w.size(); ++i) addOnce(h.serverNames, w[i]); }
		else if (name == L"access_log") addLog(h.accessLogs, w[1]);
		else if (name == L"error_log") addLog(h.errorLogs, w[1]);
		else if (name == L"load_module") {
			const std::wstring module = fromRoot(w[1], out_.root);
			out_.modules.emplace_back(nameOf(module), module);
		}
		else if (name == L"include") {
			const std::wstring pattern = fromRoot(w[1], confFolder_);
			const std::vector<std::wstring> found = files_.matches(pattern);
			if (found.empty() && pattern.find_first_of(L"*?") == std::wstring::npos) addOnce(out_.notRead, pattern);
			for (const std::wstring& f : found) file(f, context, host, depth + 1);
		}
	}
};

//! The FILETIME of a date written as ISO 8601; 0 if it is impossible.
FILETIME dateOf(const std::wstring& iso) {
	FILETIME read = { 0, 0 };
	if (!iso8601UtcToFiletime(iso, read)) return FILETIME{ 0, 0 };
	return read;
}

//! A month's number from its English abbreviation, two digits; empty if none.
std::wstring monthNumber(const std::wstring& name) {
	static const wchar_t* MONTHS[] = { L"Jan", L"Feb", L"Mar", L"Apr", L"May", L"Jun", L"Jul", L"Aug", L"Sep", L"Oct", L"Nov", L"Dec" };
	for (int m = 0; m < 12; ++m)
		if (name == MONTHS[m]) return (m < 9 ? L"0" : L"") + std::to_wstring(m + 1);
	return L"";
}

//! An entry that is only its raw line: another format than the ones read.
W3cLogEntry rawEntry(const std::wstring& line, const std::wstring& file, unsigned long long number, W3cTime zone) {
	W3cLogEntry e;
	e.file = file;
	e.line = number;
	e.zone = zone;
	e.fields.emplace_back(L"Raw", line);
	return e;
}

/*! `10/Oct/2026:13:55:36 +0200` as UTC.
 *  @return false if it is not that form */
bool accessLogDate(const std::wstring& text, FILETIME& utc) {
	if (text.size() != 26 || text[2] != L'/' || text[6] != L'/' || text[11] != L':' || text[20] != L' ') return false;
	const std::wstring month = monthNumber(text.substr(3, 3)), offset = text.substr(21);
	if (month.empty() || (offset[0] != L'+' && offset[0] != L'-')
	    || offset.find_first_not_of(L"0123456789", 1) != std::wstring::npos) return false;
	const FILETIME local = dateOf(text.substr(7, 4) + L"-" + month + L"-" + text.substr(0, 2) + L"T" + text.substr(12, 8) + L"Z");
	if (!local.dwLowDateTime && !local.dwHighDateTime) return false;
	const long long minutes = std::stoi(offset.substr(1, 2)) * 60 + std::stoi(offset.substr(3, 2));
	const long long shift = (offset[0] == L'+' ? -minutes : minutes) * 60 * 10000000LL;
	ULARGE_INTEGER value;
	value.LowPart = local.dwLowDateTime;
	value.HighPart = local.dwHighDateTime;
	value.QuadPart += (unsigned long long)shift;
	utc.dwLowDateTime = value.LowPart;
	utc.dwHighDateTime = value.HighPart;
	return true;
}

//! The text of a quoted field starting at `at`, `\"` inside it; moves `at` past it. @return false if it is not there
bool quotedField(const std::wstring& line, size_t& at, std::wstring& out) {
	while (at < line.size() && line[at] == L' ') ++at;
	if (at >= line.size() || line[at] != L'"') return false;
	out.clear();
	for (++at; at < line.size() && line[at] != L'"'; ++at) {
		if (line[at] == L'\\' && at + 1 < line.size()) ++at;
		out += line[at];
	}
	if (at >= line.size()) return false;
	++at;
	return true;
}

//! The next word separated by spaces; moves `at` past it.
std::wstring nextWord(const std::wstring& line, size_t& at) {
	while (at < line.size() && line[at] == L' ') ++at;
	const size_t start = at;
	while (at < line.size() && line[at] != L' ') ++at;
	return line.substr(start, at - start);
}

//! Adds a field unless it is empty or "-", which says it has no value.
void addField(W3cLogEntry& e, const wchar_t* key, const std::wstring& value) {
	if (!value.empty() && value != L"-") e.fields.emplace_back(key, value);
}

//! The request of an access log: method, target split at its query, protocol.
void addRequest(W3cLogEntry& e, const std::wstring& request) {
	size_t at = 0;
	const std::wstring method = nextWord(request, at), target = nextWord(request, at), protocol = nextWord(request, at);
	if (target.empty()) { addField(e, L"Request", request); return; }  // a garbled request: as it came
	addField(e, L"Method", method);
	const size_t query = target.find(L'?');
	addField(e, L"UriStem", target.substr(0, query));
	if (query != std::wstring::npos) addField(e, L"UriQuery", target.substr(query + 1));
	addField(e, L"ProtocolVersion", protocol);
}

//! The bracket groups at the start of an Apache error line; `at` left on the message.
std::vector<std::wstring> bracketGroups(const std::wstring& line, size_t& at) {
	std::vector<std::wstring> groups;
	while (at < line.size() && line[at] == L'[') {
		const size_t close = line.find(L']', at);
		if (close == std::wstring::npos) break;
		groups.push_back(line.substr(at + 1, close - at - 1));
		at = close + 1;
		while (at < line.size() && line[at] == L' ') ++at;
	}
	return groups;
}

/*! `Fri Sep 09 10:42:29.902022 2011` as a FILETIME of that local time.
 *  @return zero if it is not that form */
FILETIME apacheErrorDate(const std::wstring& text) {
	size_t at = 0;
	nextWord(text, at);
	const std::wstring month = monthNumber(nextWord(text, at)), day = nextWord(text, at), time = nextWord(text, at), year = nextWord(text, at);
	if (month.empty() || day.size() != 2 || time.size() < 8 || year.size() != 4) return FILETIME{ 0, 0 };
	return dateOf(year + L"-" + month + L"-" + day + L"T" + time + L"Z");
}

/*! A message of Apache's error log as it was before Apache escaped it for
 *  the log (ap_escape_logitem): `\\\\` and `\\"`. A `\\xHH`, a byte it would not
 *  write raw, stays as written. */
std::wstring apacheMessage(const std::wstring& written) {
	std::wstring out;
	for (size_t i = 0; i < written.size(); ++i) {
		if (written[i] == L'\\' && i + 1 < written.size() && (written[i + 1] == L'\\' || written[i + 1] == L'"')) ++i;
		out += written[i];
	}
	return out;
}

//! A line of Apache's error log: its date, its groups, its message.
bool apacheErrorLine(const std::wstring& line, W3cLogEntry& e) {
	size_t at = 0;
	const std::vector<std::wstring> groups = bracketGroups(line, at);
	if (groups.size() < 2) return false;
	e.time = apacheErrorDate(groups[0]);
	if (!e.time.dwLowDateTime && !e.time.dwHighDateTime) return false;
	for (size_t g = 1; g < groups.size(); ++g) {
		const std::wstring& group = groups[g];
		if (group.compare(0, 4, L"pid ") == 0) {
			const size_t thread = group.find(L":tid ");
			addField(e, L"ProcessId", group.substr(4, thread == std::wstring::npos ? thread : thread - 4));
			if (thread != std::wstring::npos) addField(e, L"ThreadId", group.substr(thread + 5));
		}
		else if (group.compare(0, 7, L"client ") == 0) addField(e, L"ClientAddress", group.substr(7));
		else if (g == 1) {   // 2.4 "core:error", 2.2 "error"
			const size_t colon = group.find(L':');
			if (colon != std::wstring::npos) addField(e, L"Module", group.substr(0, colon));
			addField(e, L"Level", colon == std::wstring::npos ? group : group.substr(colon + 1));
		}
	}
	addField(e, L"Message", apacheMessage(line.substr(at)));
	return true;
}

//! A line of nginx's error log: `2026/11/01 10:42:29 [error] 12#34: *5 message`.
bool nginxErrorLine(const std::wstring& line, W3cLogEntry& e) {
	if (line.size() < 22 || line[4] != L'/' || line[7] != L'/' || line[10] != L' ' || line[19] != L' ' || line[20] != L'[') return false;
	e.time = dateOf(line.substr(0, 4) + L"-" + line.substr(5, 2) + L"-" + line.substr(8, 2) + L"T" + line.substr(11, 8) + L"Z");
	const size_t close = line.find(L']', 20);
	if ((!e.time.dwLowDateTime && !e.time.dwHighDateTime) || close == std::wstring::npos) return false;
	addField(e, L"Level", line.substr(21, close - 21));
	size_t at = close + 1;
	const std::wstring ids = nextWord(line, at);
	const size_t hash = ids.find(L'#');
	if (hash != std::wstring::npos && !ids.empty() && ids.back() == L':') {
		addField(e, L"ProcessId", ids.substr(0, hash));
		addField(e, L"ThreadId", ids.substr(hash + 1, ids.size() - hash - 2));
	}
	while (at < line.size() && line[at] == L' ') ++at;
	addField(e, L"Message", line.substr(at));
	return true;
}

} // namespace

bool folderHolds(const std::wstring& folder, const std::wstring& path) {
	const std::wstring p = toLower(path), f = toLower(folder);
	return p == f || (p.size() > f.size() && p.compare(0, f.size(), f) == 0 && p[f.size()] == L'\\');
}

std::vector<std::wstring> commandWords(const std::wstring& line) {
	std::vector<std::wstring> words;
	std::wstring word;
	bool quoted = false, any = false;
	for (const wchar_t c : line) {
		if (c == L'"') { quoted = !quoted; any = true; }
		else if (!quoted && (c == L' ' || c == L'\t')) {
			if (any) words.push_back(word);
			word.clear();
			any = false;
		}
		else { word += c; any = true; }
	}
	if (any) words.push_back(word);
	return words;
}

std::vector<WebCandidate> webCandidates(const std::vector<WebServiceEntry>& services, const WebFolderLister& folders,
                                        const std::wstring& drive) {
	std::vector<WebCandidate> found;
	std::set<std::wstring> roots;
	const auto add = [&](const WebCandidate& c) { if (roots.insert(toLower(c.root)).second) found.push_back(c); };
	for (const WebServiceEntry& s : services) {
		WebCandidate c;
		if (candidateOfService(s, c)) add(c);
	}
	const auto addFolder = [&](const std::wstring& root, bool apache) {
		WebCandidate c;
		c.product = apache ? APACHE : NGINX;
		c.root = root;
		c.configFile = root + (apache ? L"\\conf\\httpd.conf" : L"\\conf\\nginx.conf");
		c.source = L"folder";
		add(c);
	};
	for (const std::wstring& name : folders(drive + L"\\")) {
		const std::wstring lower = toLower(name);
		if (lower.compare(0, 6, L"apache") == 0 || lower.compare(0, 5, L"httpd") == 0) addFolder(drive + L"\\" + name, true);
		else if (lower.compare(0, 5, L"nginx") == 0) addFolder(drive + L"\\" + name, false);
		else if (lower == L"xampp") addFolder(drive + L"\\" + name + L"\\apache", true);
	}
	for (const wchar_t* programs : { L"\\Program Files", L"\\Program Files (x86)" }) {
		const std::wstring foundation = drive + programs + L"\\Apache Software Foundation";
		for (const std::wstring& name : folders(foundation)) addFolder(foundation + L"\\" + name, true);
	}
	return found;
}

std::vector<DatabaseEngine> databaseEngines(const std::vector<WebServiceEntry>& services) {
	std::vector<DatabaseEngine> found;
	for (const WebServiceEntry& s : services) {
		const std::vector<std::wstring> words = commandWords(s.application.empty() ? s.imagePath : s.application);
		if (words.empty()) continue;
		const std::wstring binary = windowsPath(words[0]), name = nameOf(binary);
		if (!absolutePath(binary)) continue;
		DatabaseEngine e;
		e.service = s.name;
		e.binary = binary;
		const std::wstring base = parentOf(parentOf(binary));
		if (name == L"mysqld.exe" || name == L"mariadbd.exe" || name == L"mysqld-nt.exe") {
			e.product = L"MySQL or MariaDB";
			const std::wstring file = option(words, L"--defaults-file", L"");
			if (!file.empty()) e.configFile = windowsPath(file);
			const std::wstring data = option(words, L"--datadir", L"");
			e.dataFolder = windowsPath(data.empty() ? (file.empty() ? base + L"\\data" : L"") : data);
		}
		else if (name == L"pg_ctl.exe" || name == L"postgres.exe") {
			e.product = L"PostgreSQL";
			const std::wstring data = option(words, L"", L"-D");
			if (data.empty()) continue;   // a pg_ctl without its folder names nothing to take
			e.dataFolder = windowsPath(data);
			e.configFile = e.dataFolder + L"\\postgresql.conf";
		}
		else continue;
		found.push_back(std::move(e));
	}
	return found;
}

std::wstring mysqlDataFolder(const std::wstring& ini) {
	bool section = false;
	for (std::wstring line : splitLines(ini)) {
		if (!line.empty() && line.back() == L'\r') line.pop_back();
		const size_t first = line.find_first_not_of(L" \t");
		if (first == std::wstring::npos || line[first] == L'#' || line[first] == L';') continue;
		line = line.substr(first);
		if (line[0] == L'[') {
			const std::wstring name = toLower(line.substr(1, line.find(L']') - 1));
			section = name == L"mysqld" || name == L"mariadb" || name == L"server";
			continue;
		}
		const size_t equal = line.find(L'=');
		if (!section || equal == std::wstring::npos) continue;
		std::wstring key = toLower(line.substr(0, equal));
		key.erase(key.find_last_not_of(L" \t") + 1);
		if (key != L"datadir") continue;
		const std::vector<std::wstring> value = commandWords(line.substr(equal + 1));
		// Backslashes doubled or forward slashes, as my.ini writes them.
		std::wstring path = value.empty() ? L"" : value[0];
		for (size_t at = path.find(L"\\\\"); at != std::wstring::npos; at = path.find(L"\\\\", at + 1)) path.erase(at, 1);
		return windowsPath(path);
	}
	return L"";
}

WebInstallation parseApacheConfiguration(const WebCandidate& candidate, const WebConfigFiles& files) {
	WebInstallation out;
	out.product = candidate.product;
	out.source = candidate.source;
	out.root = candidate.root;
	out.configFile = candidate.configFile;
	std::wstring probe;
	if (!files.read(candidate.configFile, probe)) return out;
	out.hosts.emplace_back();
	out.hosts[0].file = candidate.configFile;
	ApacheReader(out, files).file(candidate.configFile, 0);
	return out;
}

WebInstallation parseNginxConfiguration(const WebCandidate& candidate, const WebConfigFiles& files) {
	WebInstallation out;
	out.product = candidate.product;
	out.source = candidate.source;
	out.root = candidate.root;
	out.configFile = candidate.configFile;
	std::wstring probe;
	if (!files.read(candidate.configFile, probe)) return out;
	out.hosts.emplace_back();
	out.hosts[0].file = candidate.configFile;
	std::vector<std::wstring> context;
	NginxReader(out, files).file(candidate.configFile, context, 0, 0);
	// nginx's defaults, where nothing is named: its logs under its prefix, its pages in html.
	WebHost& main = out.hosts[0];
	if (main.accessLogs.empty()) main.accessLogs.push_back(candidate.root + L"\\logs\\access.log");
	if (main.errorLogs.empty()) main.errorLogs.push_back(candidate.root + L"\\logs\\error.log");
	for (WebHost& h : out.hosts) if (h.documentRoots.empty()) h.documentRoots.push_back(candidate.root + L"\\html");
	return out;
}

W3cLogEntry parseAccessLogLine(const std::wstring& line, const std::wstring& file, unsigned long long number) {
	W3cLogEntry e = rawEntry(line, file, number, W3cTime::Utc);
	size_t at = 0;
	const std::wstring client = nextWord(line, at), identity = nextWord(line, at), user = nextWord(line, at);
	while (at < line.size() && line[at] == L' ') ++at;
	if (at >= line.size() || line[at] != L'[') return e;
	const size_t close = line.find(L']', at);
	FILETIME utc;
	if (close == std::wstring::npos || !accessLogDate(line.substr(at + 1, close - at - 1), utc)) return e;
	at = close + 1;
	std::wstring request;
	if (!quotedField(line, at, request)) return e;
	const std::wstring status = nextWord(line, at), bytes = nextWord(line, at);
	if (status.empty() || status.find_first_not_of(L"0123456789") != std::wstring::npos) return e;
	e.fields.clear();
	e.time = utc;
	addField(e, L"ClientAddress", client);
	addField(e, L"Identity", identity);
	addField(e, L"UserName", user);
	addRequest(e, request);
	addField(e, L"Status", status);
	addField(e, L"BytesSent", bytes);
	std::wstring referer, agent;
	if (quotedField(line, at, referer)) {
		addField(e, L"Referer", referer);
		if (quotedField(line, at, agent)) addField(e, L"UserAgent", agent);
	}
	return e;
}

W3cLogEntry parseErrorLogLine(const std::wstring& line, const std::wstring& file, unsigned long long number) {
	W3cLogEntry e = rawEntry(line, file, number, W3cTime::Local);
	W3cLogEntry read = e;
	read.fields.clear();
	if (apacheErrorLine(line, read)) return read;
	read.fields.clear();
	read.time = FILETIME{ 0, 0 };
	if (nginxErrorLine(line, read)) return read;
	return e;
}

Json WebHost::toJson() const {
	Json o = Json::obj();
	o.add(L"ServerNames", textList(serverNames));
	o.add(L"Listen", textList(listen));
	o.add(L"DocumentRoots", textList(documentRoots));
	o.add(L"AccessLogs", textList(accessLogs));
	o.add(L"ErrorLogs", textList(errorLogs));
	o.add(L"File", Json::str(file));
	return o;
}

Json WebInstallation::toJson() const {
	Json o = Json::obj();
	o.add(L"Product", Json::str(product));
	o.add(L"Source", Json::str(source));
	o.add(L"Root", Json::str(root));
	o.add(L"ConfigFile", Json::str(configFile));
	Json moduleList = Json::arr();
	for (const auto& [name, moduleFile] : modules) {
		Json m = Json::obj();
		m.add(L"Name", Json::str(name));
		m.add(L"File", Json::str(moduleFile));
		moduleList.push(std::move(m));
	}
	o.add(L"Modules", std::move(moduleList));
	Json hostList = Json::arr();
	for (const WebHost& h : hosts) hostList.push(h.toJson());
	o.add(L"Hosts", std::move(hostList));
	if (!notRead.empty()) o.add(L"IncludesNotRead", textList(notRead));
	return o;
}

Json DatabaseEngine::toJson() const {
	Json o = Json::obj();
	o.add(L"Product", Json::str(product));
	o.add(L"Service", Json::str(service));
	o.add(L"Binary", Json::str(binary));
	o.add(L"ConfigFile", Json::str(configFile));
	o.add(L"DataFolder", Json::str(dataFolder));
	o.add(L"DataFolderCopied", Json::boolean(copied));
	return o;
}

std::vector<WebServiceEntry> examinedServices() {
	std::vector<WebServiceEntry> found;
	if (!conf.CurrentControlSet) return found;
	for (const std::wstring& name : subkeys(conf.CurrentControlSet, SERVICES)) {
		WebServiceEntry s;
		s.name = name;
		const std::wstring key = std::wstring(SERVICES) + L"\\" + name;
		if (getRegSzValue(conf.CurrentControlSet, key.c_str(), L"ImagePath", &s.imagePath) != ERROR_SUCCESS) s.imagePath.clear();
		const std::wstring parameters = key + L"\\Parameters";
		if (getRegSzValue(conf.CurrentControlSet, parameters.c_str(), L"Application", &s.application) != ERROR_SUCCESS) s.application.clear();
		if (!s.imagePath.empty() || !s.application.empty()) found.push_back(std::move(s));
	}
	return found;
}

std::vector<std::wstring> rotatedLogs(const std::vector<std::wstring>& named) {
	std::vector<std::wstring> found;
	for (const std::wstring& log_ : named) {
		const std::filesystem::path folder = extractedPath(parentOf(log_));
		const std::wstring stem = nameOf(log_);
		std::error_code ec;
		if (!std::filesystem::is_directory(folder, ec)) continue;
		for (std::filesystem::directory_iterator it(folder, ec), end; !ec && it != end; it.increment(ec)) {
			const std::wstring name = toLower(it->path().filename().wstring());
			if (it->is_regular_file(ec) && name.compare(0, stem.size(), stem) == 0)
				addOnce(found, parentOf(log_) + L"\\" + it->path().filename().wstring());
		}
	}
	std::sort(found.begin(), found.end());
	return found;
}

std::vector<DatabaseEngine> readDatabaseEngines() {
	std::vector<DatabaseEngine> engines = databaseEngines(examinedServices());
	for (DatabaseEngine& e : engines) {
		std::string bytes;
		std::error_code ec;
		if (e.dataFolder.empty() && !e.configFile.empty() && readWholeFile(extractedPath(e.configFile), CONFIGURATION_MAX, bytes))
			e.dataFolder = mysqlDataFolder(decodeTextFile(bytes));
		e.copied = !e.dataFolder.empty() && std::filesystem::is_directory(extractedPath(e.dataFolder), ec);
	}
	return engines;
}

WebInstallation readWebInstallation(const WebCandidate& candidate) {
	WebConfigFiles files;
	files.read = [](const std::wstring& path, std::wstring& text) {
		std::string bytes;
		const std::filesystem::path copy = extractedPath(path);
		std::error_code ec;
		if (!std::filesystem::is_regular_file(copy, ec) || !readWholeFile(copy, CONFIGURATION_MAX, bytes)) return false;
		text = decodeTextFile(bytes);
		return true;
	};
	files.matches = [](const std::wstring& pattern) {
		std::vector<std::wstring> found;
		std::error_code ec;
		const std::filesystem::path copy = extractedPath(pattern);
		if (pattern.find_first_of(L"*?") == std::wstring::npos) {
			if (std::filesystem::is_regular_file(copy, ec)) found.push_back(pattern);
			else if (std::filesystem::is_directory(copy, ec)) {
				for (std::filesystem::recursive_directory_iterator it(copy, ec), end; !ec && it != end; it.increment(ec)) {
					if (it.depth() >= INCLUDE_FOLDER_DEPTH) it.disable_recursion_pending();
					if (it->is_regular_file(ec)) found.push_back(pattern + L"\\" + std::filesystem::relative(it->path(), copy, ec).wstring());
				}
			}
		}
		else {
			const std::wstring folder = parentOf(pattern), mask = pattern.substr(folder.size() + 1);
			const std::filesystem::path folderCopy = extractedPath(folder);
			if (folder.find_first_of(L"*?") == std::wstring::npos && std::filesystem::is_directory(folderCopy, ec))
				for (std::filesystem::directory_iterator it(folderCopy, ec), end; !ec && it != end; it.increment(ec))
					if (it->is_regular_file(ec) && wildcardMatch(mask, it->path().filename().wstring()))
						found.push_back(folder + L"\\" + it->path().filename().wstring());
		}
		std::sort(found.begin(), found.end());
		return found;
	};
	return candidate.product == APACHE ? parseApacheConfiguration(candidate, files) : parseNginxConfiguration(candidate, files);
}
