/*! \file
 *  \brief Checks the decoders of the directory (active_directory.cpp) on values
 *         of known meaning, and the object ACEs of security descriptors.
 *
 *  The values are shaped on those measured in a real ntds.dit: the header of
 *  replPropertyMetaData and a 48-byte entry, a link_metadata, an objectSid whose
 *  RID 500 is big-endian. The reading of a whole database is confronted with
 *  the directory itself in the VM cycle (check-json.py, check_active_directory).
 *
 *  Usage: active_directory_test — built by `build-windows.sh --test`, runs under Wine.
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include "active_directory.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned g_checks = 0, g_failures = 0;

//! Records one check, printing a failure.
void check(bool ok, const char* what) {
	++g_checks;
	if (ok) return;
	++g_failures;
	printf("FAILED: %s\n", what);
}

//! Bytes from their hexadecimal text.
std::vector<uint8_t> fromHex(const std::string& text) {
	std::vector<uint8_t> out;
	for (size_t i = 0; i + 1 < text.size(); i += 2) out.push_back((uint8_t)std::stoul(text.substr(i, 2), nullptr, 16));
	return out;
}

const char ENTRY[] = "00000000" "01000000" "7f0cf82003000000" "387e79a9f277ca4688415e1a77215eec" "0420000000000000" "0520000000000000";

/*! replPropertyMetaData: an entry read, in bounds whatever the count announces. */
void replicationMetadata() {
	std::vector<uint8_t> value = fromHex(std::string("0100000000000000" "01000000" "00000000") + ENTRY);
	const std::vector<DirectoryChange> changes = parseReplicationMetadata(value.data(), value.size());
	check(changes.size() == 1, "one entry of metadata");
	if (changes.size() != 1) return;
	check(changes[0].attribute == 0 && changes[0].version == 1, "attribute and version of the entry");
	check(changes[0].changedSeconds == 0x320F80C7FULL, "date of the entry");
	check(changes[0].invocationId == L"{A9797E38-77F2-46CA-8841-5E1A77215EEC}", "controller of the entry");
	check(changes[0].originatingUsn == 0x2004 && changes[0].localUsn == 0x2005, "USNs of the entry");
	// A count larger than the value: bounded by the value, not by the count.
	std::vector<uint8_t> lying = fromHex(std::string("0100000000000000" "ffffff7f" "00000000") + ENTRY);
	check(parseReplicationMetadata(lying.data(), lying.size()).size() == 1, "an announced count does not leave the value");
	check(parseReplicationMetadata(lying.data(), 15).empty(), "a truncated header gives nothing");
	std::vector<uint8_t> otherVersion = fromHex(std::string("0200000000000000" "01000000" "00000000") + ENTRY);
	check(parseReplicationMetadata(otherVersion.data(), otherVersion.size()).empty(), "another version gives nothing");
}

/*! link_metadata: its fields, and only at its size. */
void linkMetadata() {
	std::vector<uint8_t> value = fromHex("800cf82003000000" "0100000000000000" "810cf82003000000" "387e79a9f277ca4688415e1a77215eec" "0920000000000000");
	DirectoryChange change;
	check(parseLinkMetadata(value.data(), value.size(), change), "link metadata read");
	check(change.createdSeconds == 0x320F80C80ULL && change.changedSeconds == 0x320F80C81ULL, "dates of the link");
	check(change.version == 1 && change.originatingUsn == 0x2009, "version and USN of the link");
	check(change.invocationId == L"{A9797E38-77F2-46CA-8841-5E1A77215EEC}", "controller of the link");
	check(!parseLinkMetadata(value.data(), value.size() - 1, change), "another size is refused");
}

/*! objectSid: its last sub-authority is big-endian in the directory. */
void sids() {
	const std::vector<uint8_t> administrator = fromHex("0105000000000005150000001887187674629b6c2e5da8ac000001f4");
	const std::wstring text = directorySidToText(administrator);
	check(text.size() > 4 && text.compare(text.size() - 4, 4, L"-500") == 0, "the RID reads 500");
	check(directorySidToText(std::vector<uint8_t>(administrator.begin(), administrator.end() - 1)).empty(), "a truncated SID gives nothing");
}

/*! A level of a name, as Get-ADObject writes it. */
void names() {
	check(distinguishedNameLevel(L"cn", L"Users") == L"CN=Users", "a plain level");
	check(distinguishedNameLevel(L"dc", L"wac") == L"DC=wac", "a domain level");
	check(distinguishedNameLevel(L"cn", L"Doe, John") == L"CN=Doe\\, John", "a reserved character");
	check(distinguishedNameLevel(L"cn", L"a\nDEL:1") == L"CN=a\\0ADEL:1", "the mark of a deleted object");
	check(distinguishedNameLevel(L"cn", L" a ") == L"CN=\\ a\\ ", "spaces at the edges");
}

/*! An object ACE: the replication right a DCSync needs is told by its GUID. */
void objectAce() {
	// A self-relative descriptor: header, then a DACL of one ACCESS_ALLOWED_OBJECT_ACE for S-1-5-18.
	std::string hex = "01000480000000000000000000000000140000000200300001000000" "05002800" "00010000" "01000000"
	                  "adf63111" "079c" "d111" "f79f00c04fc2dcd2" "0101000000000005" "12000000";
	const std::vector<uint8_t> sd = fromHex(hex);
	const Json json = securityDescriptorToJson(sd.data(), sd.size());
	const std::wstring text = json.dump();
	check(text.find(L"AllowObject") != std::wstring::npos, "an object ACE is named");
	check(text.find(L"{1131F6AD-9C07-11D1-F79F-00C04FC2DCD2}") != std::wstring::npos, "its right is given");
	check(text.find(L"S-1-5-18") != std::wstring::npos, "its trustee is given");
}

/*! userAccountControl: the bits' names, an unknown bit kept. */
void accountFlags() {
	const std::wstring text = userAccountControlFlags(0x00080202 | 0x08000000).dump();
	check(text.find(L"ACCOUNTDISABLE") != std::wstring::npos && text.find(L"NORMAL_ACCOUNT") != std::wstring::npos
	      && text.find(L"TRUSTED_FOR_DELEGATION") != std::wstring::npos, "the bits' names");
	check(text.find(L"0x08000000") != std::wstring::npos, "an unknown bit is said");
}

} // namespace

int wmain() {
	replicationMetadata();
	linkMetadata();
	sids();
	names();
	objectAce();
	accountFlags();
	printf("%u checks, %u failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
