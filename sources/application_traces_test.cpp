/*! \file
 *  \brief Tests of the applications' traces table: the wildcards it relies on, and
 *         the rules a line of it must keep (no private key taken, one key each).
 *         Portable: built natively and under MinGW.
 */
#include "application_traces.h"
#include <map>
#include <cstdio>
#include <set>

namespace {

int failures = 0;
int checks = 0;

//! Counts one check, and says which failed.
void check(bool ok, const std::string& what) {
	++checks;
	if (!ok) { ++failures; std::printf("FAILED: %s\n", what.c_str()); }
}

//! The wildcards: exact, case, runs, none, backtracking, and what must not match.
void testWildcards() {
	check(wildcardMatch(L"ERRORLOG", L"errorlog"), "a whole name, whatever its case");
	check(!wildcardMatch(L"ERRORLOG", L"ERRORLOG.1"), "a whole name is not a prefix");
	check(wildcardMatch(L"ERRORLOG.*", L"ERRORLOG.1"), "a star at the end");
	check(!wildcardMatch(L"ERRORLOG.*", L"ERRORLOG"), "the dot before the star is required");
	check(wildcardMatch(L"connections*.txt", L"connections.txt"), "a star stands for nothing too");
	check(wildcardMatch(L"connections*.txt", L"Connections_incoming.TXT"), "a star in the middle");
	check(wildcardMatch(L"TeamViewer*_Logfile*", L"TeamViewer15_Logfile_OLD.log"), "two stars");
	check(wildcardMatch(L"*a*b", L"xaybab"), "a star backtracks");
	check(!wildcardMatch(L"*a*b", L"xaybac"), "and still refuses");
	check(!wildcardMatch(L"Sophos *", L"Sophos"), "the space before the star is required");
	check(wildcardMatch(L"*", L""), "a star matches an empty name");
	check(!wildcardMatch(L"", L"x"), "no pattern matches no name but the empty one");
	check(isPasswordValue(L"ProxyPassword") && isPasswordValue(L"Password") && isPasswordValue(L"TUNNELPASSWORD"), "a password value, whatever its case or place");
	check(!isPasswordValue(L"HostName") && !isPasswordValue(L"UserName"), "the other values stay");
	check(wildcardMatch(std::wstring(200, L'*') + L"z", std::wstring(5000, L'a') + L"z"), "long patterns and names end");
	check(wildcardMatch(L"httpd-?.conf", L"HTTPD-a.conf") && !wildcardMatch(L"httpd-?.conf", L"httpd-.conf")
	      && !wildcardMatch(L"httpd-?.conf", L"httpd-ab.conf"), "a question mark stands for exactly one character");
}

//! The switches: a product's, its group's, a neighbour's, and the products off by default.
void testSwitches() {
	ProductSwitches switches;
	switches.off = { "messaging.telegram", "vpn" };
	switches.on = { "system_traces.minidumps" };
	check(!traceProductWanted(switches, "messaging", "telegram"), "a product switched off");
	check(traceProductWanted(switches, "messaging", "slack"), "its neighbour stays");
	check(!traceProductWanted(switches, "vpn", "openvpn"), "a group switched off takes its products");
	check(traceProductWanted(switches, "antivirus", "sophos"), "another group stays");
	check(!traceProductWanted(switches, "system_traces", "crash_dumps", false), "a product off by default stays off");
	check(traceProductWanted(switches, "system_traces", "minidumps", false), "a product off by default, switched on");
	// Off by default: what holds the user's data or memory (decision of 2026-11-08), nothing else.
	std::set<std::string> offByDefault;
	for (const TraceGroup& group : applicationTraces())
		for (const TraceProduct& product : group.products)
			if (!product.onByDefault) offByDefault.insert(group.key + "." + product.key);
	check(offByDefault == std::set<std::string>{ "system_traces.crash_dumps", "system_traces.minidumps", "system_traces.office_cache" },
	      "the products off by default are the crash dumps and Office's document cache");
}

//! The table: keys unique and lower case; no filter that would take an SSH private key.
void testTable() {
	std::set<std::string> groups;
	for (const TraceGroup& group : applicationTraces()) {
		check(groups.insert(group.key).second, "group twice: " + group.key);
		check(traceGroup(group.key) == &group, "group not found by its key: " + group.key);
		std::set<std::string> products;
		for (const TraceProduct& product : group.products) {
			check(products.insert(product.key).second, "product twice: " + group.key + "." + product.key);
			check(!product.pieces.empty(), "no folder: " + product.key);
			for (char c : product.key) check((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_', "key not in snake case: " + product.key);
			for (const TracePiece& piece : product.pieces) check(!piece.folder.empty() && (piece.folder[0] == L'\\' || piece.folder[0] == L'%'), "a folder's root: " + product.key);
		}
		check(!group.products.empty(), "an empty group: " + group.key);
	}
	check(traceGroup("no such group") == nullptr, "an unknown group");
	const TraceGroup* ssh = traceGroup("ssh");
	check(ssh != nullptr, "the ssh group");
	if (!ssh) return;
	for (const TraceProduct& product : ssh->products)
		for (const TracePiece& piece : product.pieces) {
			if (piece.folder.find(L"logs") != std::wstring::npos) continue;
			check(!piece.filter.empty(), "an SSH folder taken without filter would take its private keys");
			for (const wchar_t* name : { L"id_rsa", L"id_ed25519", L"id_ecdsa", L"id_dsa", L"ssh_host_rsa_key", L"ssh_host_ed25519_key" })
				for (const std::wstring& entry : piece.filter)
					check(!wildcardMatch(entry, name), "an SSH private key taken");
		}
}

} // namespace

//! The product a file of the examined machine belongs to, as the collection took it.
void testOwner() {
	auto owner = [](const wchar_t* path) {
		const TraceOwner o = traceOwnerOf(path);
		return o.group ? o.group->key + "." + o.product->key : std::string();
	};
	check(owner(L"C:\\Users\\bob\\AppData\\Roaming\\TeamViewer\\Connections_incoming.txt") == "remote_administration.teamviewer", "a product in a profile");
	check(owner(L"C:\\Program Files (x86)\\TeamViewer\\TeamViewer15_Logfile.log") == "remote_administration.teamviewer", "a folder with a star (Program Files*)");
	check(owner(L"C:\\Documents and Settings\\bob\\.ssh\\known_hosts") == "ssh.openssh_client", "a profile of Windows XP");
	check(owner(L"C:\\ProgramData\\ssh\\sshd_config") == "ssh.openssh_server", "a whole name of the filter");
	check(owner(L"C:\\Windows\\debug\\netlogon.log") == "server_logs.netlogon", "a server's log");
	check(owner(L"C:\\Users\\bob\\.ssh\\id_rsa").empty(), "a private key belongs to no product");
	check(owner(L"C:\\ProgramData\\ssh\\logs\\deeper\\sshd.log").empty(), "deeper than the line allows");
	const TraceOwner sshd = traceOwnerOf(L"C:\\ProgramData\\ssh\\logs\\sshd.log");
	check(sshd.product && sshd.product->layout.processIdFirst && !sshd.product->layout.monthFirst,
	      "sshd.log: its lines start with the process's identifier (measured)");
	const TraceOwner join = traceOwnerOf(L"C:\\Windows\\debug\\NetSetup.log");
	check(join.product && join.product->layout.monthFirst && !join.product->layout.processIdFirst, "NetSetup.log: month first");
	check(owner(L"C:\\Users\\bob\\AppData\\Roaming\\TeamViewer\\notes.txt").empty(), "a name the filter does not keep");
	check(owner(L"C:\\Windows\\System32\\cmd.exe").empty(), "a file of no product");
	check(isPasswordValue(L"Pass") && isPasswordValue(L"UserPwd") && isPasswordValue(L"client_secret") && isPasswordValue(L"Passwd"),
	      "every name of a secret is left out");
	check(!isPasswordValue(L"Passive") && !isPasswordValue(L"Port") && !isPasswordValue(L"Host"), "the other names stay");
}

//! The folders a pattern stands for, and a forged name that matched its own pattern without end.
void testExpansion() {
	std::map<std::wstring, std::vector<std::wstring>> disk = {
		{ L"\\", { L"Program Files", L"Program Files (x86)", L"Windows" } },
		{ L"\\Program Files", { L"TeamViewer" } },
		{ L"\\Program Files (x86)", { L"TeamViewer", L"Other" } } };
	size_t calls = 0;
	auto lister = [&](const std::wstring& folder) {
		++calls;
		const auto found = disk.find(folder);
		return found == disk.end() ? std::vector<std::wstring>() : found->second;
	};
	const std::vector<std::wstring> folders = expandFolderPattern(L"\\Program Files*\\TeamViewer", lister);
	check(folders == std::vector<std::wstring>{ L"\\Program Files\\TeamViewer", L"\\Program Files (x86)\\TeamViewer" },
	      "each folder the pattern stands for, its literal rest kept");
	check(expandFolderPattern(L"\\Windows\\Temp", lister) == std::vector<std::wstring>{ L"\\Windows\\Temp" }, "a path without a pattern is itself");
	// A forged index: a folder named like a pattern, which matches it.
	disk[L"\\"] = { L"Program Files*x", L"..", L"a\\..\\b" };
	calls = 0;
	const std::vector<std::wstring> forged = expandFolderPattern(L"\\Program Files*\\TeamViewer", lister);
	check(forged == std::vector<std::wstring>{ L"\\Program Files*x\\TeamViewer" } && calls == 1,
	      "a name found on the disk is taken literally, never expanded again");
	check(expandFolderPattern(L"\\*", lister) == std::vector<std::wstring>{ L"\\Program Files*x" }, "\"..\" and a name holding a separator left out");
}

int main() {
	testWildcards();
	testSwitches();
	testTable();
	testOwner();
	testExpansion();
	std::printf("%d checks, %d failed\n", checks, failures);
	return failures ? 1 : 0;
}
