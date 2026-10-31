/*! \file
 *  \brief The Windows Firewall's log (see firewall_log.h).
 */
#include "firewall_log.h"
#include "registry_common.h"
#include <filesystem>
#include <set>

namespace {

//! Largest log read: Windows caps it at 32 MiB (LogFileSize), a forged one is refused.
const uintmax_t LOG_MAX = 256ULL * 1024 * 1024;

//! The JSON key of each field of "#Fields:"; another field keeps its name, in PascalCase.
const std::vector<W3cFieldKey> FIELD_KEYS = {
	{ L"action", L"Action" }, { L"protocol", L"Protocol" }, { L"src-ip", L"SourceAddress" },
	{ L"dst-ip", L"DestinationAddress" }, { L"src-port", L"SourcePort" }, { L"dst-port", L"DestinationPort" },
	{ L"size", L"Size" }, { L"tcpflags", L"TcpFlags" }, { L"tcpsyn", L"TcpSyn" }, { L"tcpack", L"TcpAck" },
	{ L"tcpwin", L"TcpWindow" }, { L"icmptype", L"IcmpType" }, { L"icmpcode", L"IcmpCode" }, { L"info", L"Info" },
	{ L"path", L"Direction" }, { L"pid", L"ProcessId" } };

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

std::vector<W3cLogEntry> parseFirewallLog(const std::wstring& text, const std::wstring& file) {
	return parseW3cLog(text, file, FIELD_KEYS, W3cTime::Local);
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
			std::vector<W3cLogEntry> read = parseFirewallLog(decodeTextFile(bytes), name);
			log(2, L"❇️" + name + L" : " + std::to_wstring(read.size()) + L" line(s)");
			for (W3cLogEntry& e : read) entries_.push_back(std::move(e));
		}
	return ERROR_SUCCESS;
}

HRESULT FirewallLog::toJson() { return writeList("firewall_log.json", entries_); }
void FirewallLog::clear() { entries_.clear(); }
