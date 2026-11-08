/*! \file
 *  \brief Tests of the applications' traces table: the wildcards it relies on, and
 *         the rules a line of it must keep (no private key taken, one key each).
 *         Portable: built natively and under MinGW.
 */
#include "application_traces.h"
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
}

//! The switches: a product's, its group's, a neighbour's.
void testSwitches() {
	const std::set<std::string> off = { "messaging.telegram", "vpn" };
	check(!traceProductWanted(off, "messaging", "telegram"), "a product switched off");
	check(traceProductWanted(off, "messaging", "slack"), "its neighbour stays");
	check(!traceProductWanted(off, "vpn", "openvpn"), "a group switched off takes its products");
	check(traceProductWanted(off, "antivirus", "sophos"), "another group stays");
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

int main() {
	testWildcards();
	testSwitches();
	testTable();
	std::printf("%d checks, %d failed\n", checks, failures);
	return failures ? 1 : 0;
}
