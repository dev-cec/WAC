/*! \file
 *  \brief Checks the derivation of the SAM's hashed boot key
 *         (sam_secrets.cpp, hashedBootKeyFromF) on an F value built here.
 *
 *  WHY THIS TEST. A wrong constant in the RC4 scheme (revision 1, Windows 8.1
 *  and earlier, and accounts not rewritten since) gives a wrong hashed boot
 *  key, then wrong NT hashes for every account — in valid JSON, without any
 *  error: WAC salted it with thirteen 'Q' instead of twelve. The F value here
 *  is built with a synthetic boot key and hashed boot key, encrypted and
 *  checksummed by an independent computation (Python's hashlib and an RC4 of
 *  its own, with the constants of impacket); on the Windows 8.1 VM, only
 *  twelve 'Q' satisfy the checksum of the real value:
 *    - the hashed boot key comes back;
 *    - a checksum that does not match — a wrong boot key — is refused, and
 *      nothing is returned rather than a wrong key;
 *    - a truncated value or an unknown revision is refused.
 *
 *  Usage: sam_secrets_test — built by `build-windows.sh --test`, runs under Wine.
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include "sam_secrets.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok) { ++g_failures; std::printf("  FAILED  %s\n", what.c_str()); }
}

//! Bytes first, first + 1, … : the synthetic keys and salt.
std::vector<uint8_t> sequence(uint8_t first) {
	std::vector<uint8_t> v(16);
	for (size_t i = 0; i < v.size(); ++i) v[i] = (uint8_t)(first + i);
	return v;
}

/*! An F value of revision 1: boot key 00..0F, hashed boot key A0..AF, salt
 *  10..1F; Key and CheckSum encrypted by the independent computation. */
std::vector<uint8_t> revisionOneF() {
	static const uint8_t ENCRYPTED[32] = {
		0x68, 0x08, 0x8B, 0xEB, 0xAB, 0x5C, 0xFC, 0xA3, 0x12, 0x7C, 0xA7, 0xB7, 0x12, 0x2C, 0xDA, 0x25,
		0x3E, 0x5D, 0x59, 0x61, 0x49, 0x57, 0xDE, 0x15, 0x97, 0x68, 0x43, 0x4E, 0x25, 0x20, 0x04, 0x40 };
	std::vector<uint8_t> f(0x68, 0);
	const uint8_t header[8] = { 1, 0, 0, 0, 0x30, 0, 0, 0 };   // Revision 1, Length
	f.insert(f.end(), header, header + 8);
	const std::vector<uint8_t> salt = sequence(0x10);
	f.insert(f.end(), salt.begin(), salt.end());
	f.insert(f.end(), ENCRYPTED, ENCRYPTED + 32);
	return f;
}

} // namespace

int wmain() {
	const std::vector<uint8_t> f = revisionOneF();
	check(hashedBootKeyFromF(f, sequence(0x00)) == sequence(0xA0),
	      "revision 1: the hashed boot key of the independent computation");

	std::vector<uint8_t> otherBootKey = sequence(0x00);
	otherBootKey[0] ^= 1;
	check(hashedBootKeyFromF(f, otherBootKey).empty(), "revision 1: a wrong boot key refused by the checksum");

	std::vector<uint8_t> tampered = f;
	tampered.back() ^= 1;
	check(hashedBootKeyFromF(tampered, sequence(0x00)).empty(), "revision 1: a checksum that does not match refused");

	check(hashedBootKeyFromF(std::vector<uint8_t>(f.begin(), f.end() - 1), sequence(0x00)).empty(),
	      "revision 1: a truncated value refused");

	std::vector<uint8_t> unknown = f;
	unknown[0x68] = 3;
	check(hashedBootKeyFromF(unknown, sequence(0x00)).empty(), "an unknown revision refused");

	std::printf("%u check(s), %u failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
