/*! \file
 *  \brief The Windows Firewall's log (see firewall_log.h).
 */
#include "firewall_log.h"
#include "registry_common.h"
#include <algorithm>
#include <filesystem>
#include <set>

namespace {

//! Largest log read: Windows caps it at 32 MiB (LogFileSize), a forged one is refused.
const uintmax_t LOG_MAX = 256ULL * 1024 * 1024;

//! The JSON key of each field of "#Fields:"; another field keeps its name, in PascalCase.
const std::pair<const wchar_t*, const wchar_t*> FIELD_KEYS[] = {
	{ L"action", L"Action" }, { L"protocol", L"Protocol" }, { L"src-ip", L"SourceAddress" },
	{ L"dst-ip", L"DestinationAddress" }, { L"src-port", L"SourcePort" }, { L"dst-port", L"DestinationPort" },
	{ L"size", L"Size" }, { L"tcpflags", L"TcpFlags" }, { L"tcpsyn", L"TcpSyn" }, { L"tcpack", L"TcpAck" },
	{ L"tcpwin", L"TcpWindow" }, { L"icmptype", L"IcmpType" }, { L"icmpcode", L"IcmpCode" }, { L"info", L"Info" },
	{ L"path", L"Direction" }, { L"pid", L"ProcessId" } };

//! The JSON key of a field of "#Fields:".
std::wstring fieldKey(const std::wstring& field) {
	for (const auto& [name, key] : FIELD_KEYS)
		if (field == name) return key;
	return registryNameToJsonKey(field);
}

//! The words of a line, separated by spaces.
std::vector<std::wstring> words(const std::wstring& line) {
	std::vector<std::wstring> out;
	size_t i = 0;
	while (i < line.size()) {
		while (i < line.size() && line[i] == L' ') ++i;
		const size_t start = i;
		while (i < line.size() && line[i] != L' ') ++i;
		if (i > start) out.push_back(line.substr(start, i - start));
	}
	return out;
}

//! A value that is a decimal number, as a JSON number; anything else as text.
Json value(const std::wstring& text) {
	const bool digits = !text.empty() && text.size() < 19
	                    && text.find_first_not_of(L"0123456789") == std::wstring::npos;
	return digits ? Json::num(std::stoull(text)) : Json::str(text);
}

/*! Reads the LogFilePath of each profile under a key.
 *  @param root the hive's root (or the control set)
 *  @param base the key holding the profiles
 *  @param profiles their names
 *  @param out receives each path, normalized */
void readLogPaths(ORHKEY root, const std::wstring& base, std::initializer_list<const wchar_t*> profiles,
                  std::vector<std::wstring>& out) {
	if (!root) return;
	for (const wchar_t* profile : profiles) {
		std::wstring path;
		if (getRegSzValue(root, (base + L"\\" + profile + L"\\Logging").c_str(), L"LogFilePath", &path) != ERROR_SUCCESS)
			continue;
		const std::wstring normalized = normalizeFilePath(path);
		if (!normalized.empty()) out.push_back(normalized);
	}
}

} // namespace

std::vector<std::wstring> firewallLogFiles() {
	std::vector<std::wstring> candidates;
	readLogPaths(conf.CurrentControlSet, L"Services\\SharedAccess\\Parameters\\FirewallPolicy",
	             { L"DomainProfile", L"StandardProfile", L"PublicProfile" }, candidates);
	readLogPaths(conf.Software, L"Policies\\Microsoft\\WindowsFirewall",
	             { L"DomainProfile", L"PrivateProfile", L"PublicProfile" }, candidates);
	// The default, where a log may stay after its path was changed: XP's, or Vista's and later.
	const wchar_t* fallback = conf.examinedVersion.build && conf.examinedVersion.build < 6000
	                          ? L"\\Windows\\pfirewall.log" : L"\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log";
	candidates.push_back(conf.systemDrive.substr(0, 2) + fallback);
	std::vector<std::wstring> files;
	std::set<std::wstring> seen;
	for (const std::wstring& c : candidates)
		if (seen.insert(toLower(c)).second) files.push_back(c);
	return files;
}

std::vector<FirewallLogEntry> parseFirewallLog(const std::wstring& text, const std::wstring& file) {
	std::vector<FirewallLogEntry> entries;
	std::vector<std::wstring> fields;
	bool local = true;
	const std::vector<std::wstring> lines = splitLines(text);
	for (size_t i = 0; i < lines.size(); ++i) {
		std::wstring line = lines[i];
		if (!line.empty() && line.back() == L'\r') line.pop_back();
		/* Windows leaves zeros in the file where it reopened it (logging
		   switched back on): seen before the first line's date. */
		line.erase(std::remove(line.begin(), line.end(), L'\0'), line.end());
		if (line.compare(0, 8, L"#Fields:") == 0) { fields = words(line.substr(8)); continue; }
		if (line.compare(0, 13, L"#Time Format:") == 0) {
			const std::vector<std::wstring> format = words(line.substr(13));
			local = format.size() == 1 && toLower(format[0]) == L"local";
			continue;
		}
		if (line.empty() || line[0] == L'#' || fields.empty()) continue;
		const std::vector<std::wstring> values = words(line);
		FirewallLogEntry e;
		e.file = file;
		e.line = i + 1;
		e.timeIsLocal = local;
		std::wstring date, time;
		for (size_t f = 0; f < fields.size() && f < values.size(); ++f) {
			if (values[f] == L"-") continue;
			if (fields[f] == L"date") date = values[f];
			else if (fields[f] == L"time") time = values[f];
			else e.fields.emplace_back(fieldKey(fields[f]), values[f]);
		}
		if (!date.empty() && !time.empty()) {
			/* "2026-10-24" and "15:01:02": read as ISO 8601, which checks each
			   field; the instant obtained is the local one, as written. */
			FILETIME read;
			if (local && iso8601UtcToFiletime(date + L"T" + time + L"Z", read)) e.timeLocal = read;
			else e.timeAsStored = date + L" " + time;
		}
		entries.push_back(std::move(e));
	}
	return entries;
}

Json FirewallLogEntry::toJson() const {
	Json o = Json::obj();
	if (timeLocal.dwLowDateTime || timeLocal.dwHighDateTime) addDate(o, L"Time", suspectLocalToUtc(timeLocal));
	o.add(L"TimeAsStored", Json::str(timeAsStored));
	for (const auto& [key, text] : fields) o.add(key, value(text));
	o.add(L"File", Json::str(file));
	o.add(L"Line", Json::num(line));
	return o;
}

HRESULT FirewallLog::getData() {
	for (const std::wstring& file : firewallLogFiles())
		for (const std::wstring& name : { file, file + L".old" }) {
			// The working copy, as the collection took it.
			const std::filesystem::path path = extractedPath(name);
			std::error_code ec;
			if (!std::filesystem::is_regular_file(path, ec)) continue;
			std::string bytes;
			if (!readWholeFile(path, LOG_MAX, bytes)) {
				log(2, L"🔥Firewall log not read (unreadable or larger than 256 MiB): " + path.wstring());
				continue;
			}
			std::vector<FirewallLogEntry> read = parseFirewallLog(decodeTextFile(bytes), name);
			log(2, L"❇️" + name + L" : " + std::to_wstring(read.size()) + L" line(s)");
			for (FirewallLogEntry& e : read) entries_.push_back(std::move(e));
		}
	return ERROR_SUCCESS;
}

HRESULT FirewallLog::toJson() { return writeList("firewall_log.json", entries_); }
void FirewallLog::clear() { entries_.clear(); }
