/*! \file
 *  \brief Checks the shortcut and jump-list fields B-015 brought in, against
 *  the values Eric Zimmerman's JLECmd gives for the same exhibits of the test
 *  VM: the instant and hardware address of a version-1 DROID, the ExtraData
 *  blocks of a .lnk, and the end of a URI shell item.
 *
 *  Usage (runs under wine): link_tracking_test.exe
 */
#include "recent_docs.h"
#include "ip_address.h"
#include <cstdio>
#include <cstring>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const char* what) {
	++g_checks;
	if (!ok) { ++g_failures; std::fprintf(stderr, "  FAILED  %s\n", what); }
}

//! Writes a little-endian 32-bit value.
void put32(std::vector<BYTE>& b, size_t at, uint32_t v) { memcpy(b.data() + at, &v, 4); }

/*! The DROID of the test VM's Desktop in its Explorer jump list: JLECmd gives
 *  2026-09-12 11:32:36.6263407 and 52:54:00:73:e8:57 (the VM's network card). */
void droidTime() {
	const GUID droid = { 0xA75E346F, 0xAE9D, 0x11F1, { 0xAD, 0xB8, 0x52, 0x54, 0x00, 0x73, 0xE8, 0x57 } };
	const GuidV1 v = decodeGuidV1(droid);
	check(v.valid, "version-1 DROID recognised");
	check(timeToIso8601Utc(v.createdUtc) == L"2026-09-12T11:32:36.6263407Z", "DROID instant, to the 100 ns, as JLECmd");
	check(HardwareAddressText(v.node, sizeof v.node) == L"52-54-00-73-E8-57", "DROID hardware address, as JLECmd");
	const GUID random = { 0xA75E346F, 0xAE9D, 0x41F1, { 0xAD, 0xB8, 0x52, 0x54, 0x00, 0x73, 0xE8, 0x57 } };
	check(!decodeGuidV1(random).valid, "version-4 GUID: no date read from random bits");
}

/*! A minimal shortcut: header without ID list nor LinkInfo, then a tracker
 *  block, a known-folder block, a block of unknown signature and the
 *  terminal block. */
void extraData() {
	std::vector<BYTE> lnk(76 + 0x60 + 0x1C + 12 + 4, 0);
	put32(lnk, 0, 76);
	const GUID shellLink = { 0x00021401, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
	memcpy(lnk.data() + 4, &shellLink, sizeof shellLink);
	size_t at = 76;
	put32(lnk, at, 0x60); put32(lnk, at + 4, 0xA0000003); put32(lnk, at + 8, 0x58);
	memcpy(lnk.data() + at + 16, "wac-test", 8);
	const GUID droid = { 0xA75E346F, 0xAE9D, 0x11F1, { 0xAD, 0xB8, 0x52, 0x54, 0x00, 0x73, 0xE8, 0x57 } };
	for (int i = 0; i < 4; ++i) memcpy(lnk.data() + at + 32 + 16 * i, &droid, sizeof droid);
	at += 0x60;
	put32(lnk, at, 0x1C); put32(lnk, at + 4, 0xA000000B);
	const GUID desktop = { 0xB4BFCC3A, 0xDB2C, 0x424C, { 0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41 } };
	memcpy(lnk.data() + at + 8, &desktop, sizeof desktop);
	at += 0x1C;
	put32(lnk, at, 12); put32(lnk, at + 4, 0xA00000FF);
	RecentDoc doc(lnk.data(), lnk.size(), L"test.lnk", L"S-1-0-0");
	check(doc.extraDataBlocks.size() == 3, "three ExtraData blocks, up to the terminal one");
	check(doc.machineId == L"wac-test", "tracker: MachineID");
	check(doc.tracking.has_value(), "tracker: DROIDs read");
	check(doc.knownFolderId == L"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "known folder GUID");
	check(doc.extraDataBlocks.size() == 3 && doc.extraDataBlocks[2] == L"0xa00000ff", "unknown block named by its signature");
	// A block announcing more than the file holds stops the walk, nothing read past it.
	put32(lnk, 76, 0x6000);
	RecentDoc forged(lnk.data(), lnk.size(), L"test.lnk", L"S-1-0-0");
	check(forged.extraDataBlocks.empty() && !forged.tracking, "block larger than the file: refused");
}

/*! A URI shell item whose string is followed, within the item, by an
 *  extension block: the URI ends at its terminator (a jump list gave
 *  "ms-gamingoverlay:///" followed by "V…AppX5nebv…"). */
void uriEnd() {
	std::vector<BYTE> item(8 + 12 + 12, 0);
	const uint16_t size = (uint16_t)item.size();
	memcpy(item.data(), &size, 2);
	item[2] = 0x61;
	item[3] = 0x80;
	const wchar_t uri[] = L"ab:///";
	memcpy(item.data() + 8, uri, 12);                       // six characters, then the terminator
	const BYTE tail[] = { 0x1A, 0x00, 0xEF, 0xBE, 'X', 0, 'Y', 0 };
	memcpy(item.data() + 8 + 14, tail, sizeof tail);
	URIShellItem shell(item.data(), 0);
	check(shell.uri == L"ab:///", "URI cut at its terminator, not glued to what follows");
}

} // namespace

/*! Runs the checks.
 * @return 0 if all pass */
int wmain() {
	droidTime();
	extraData();
	uriEnd();
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
