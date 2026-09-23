/*! \file
 *  \brief Confronts sha.cpp with the public test vectors.
 *
 *  A wrong fingerprint is the worst of the silent defects: it produces an
 *  exhibit store that looks irreproachable and identifies nothing. Hence this
 *  test.
 *
 *  Two families of cases, for two different reasons:
 *    - the four vectors of FIPS 180-4 (empty, "abc", 448 bits, a million "a")
 *      validate the algorithm itself;
 *    - the lengths 55 to 128 validate the PADDING, the one place where an
 *      otherwise correct implementation goes wrong: at 56 bytes the length no
 *      longer fits in the block and must move to the next one. Their expected
 *      values come from an independent implementation.
 *
 *  Excluded from WAC's build by the "_test.cpp" pattern of build-windows.sh.
 *  Native build: g++ -std=c++17 -I. sha.cpp sha_test.cpp -o sha_test
 */
#include "sha.h"
#include <iostream>
#include <string>
#include <vector>

namespace {

std::string narrow(const std::wstring& w){
	std::string r;
	for (wchar_t c : w) r += (char)c;
	return r;
}
std::wstring sha1De(const std::string& m){
	Sha1Stream f; f.update((const uint8_t*)m.data(), m.size()); return f.hexDigest();
}
std::wstring sha256De(const std::string& m){
	Sha256Stream f; f.update((const uint8_t*)m.data(), m.size()); return f.hexDigest();
}

struct Case { std::string message; const char* sha1; const char* sha256; std::string name; };

} // namespace

int main(){
	std::vector<Case> case_ = {
		// FIPS 180-4
		{ "", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
		      "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", "empty" },
		{ "abc", "A9993E364706816ABA3E25717850C26C9CD0D89D",
		         "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", "abc" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		         "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
		         "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1", "448 bits" },
		{ std::string(1000000, 'a'), "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
		         "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0",
		         "un million de a" },
		// Remplissage
		{ std::string(55, 'x'), "CEF734BA81A024479E09EB5A75B6DDAE62E6ABF1",
		         "D5E285683CD4EFC02D021A5C62014694958901005D6F71E89E0989FAC77E4072", "55 bytes" },
		{ std::string(56, 'x'), "901305367C259952F4E7AF8323F480D59F81335B",
		         "04C26261370EE7541549D16DEE320C723E3FD14671E66A099AFE0A377C16888E",
		         "56 bytes (length in the next block)" },
		{ std::string(63, 'x'), "0DDC4E0CCCD9A12850DEB5ABB0853A4425559FEC",
		         "75220B47218278E656F2013BB8F0C455A25EAF01E86C64924E9D48D89776D6F2", "63 bytes" },
		{ std::string(64, 'x'), "BB2FA3EE7AFB9F54C6DFB5D021F14B1FFE40C163",
		         "7CE100971F64E7001E8FE5A51973ECDFE1CED42BEFE7EE8D5FD6219506B5393C",
		         "64 octets (multiple exact)" },
		{ std::string(65, 'x'), "78C741DDC482E4CDF8C474A0876347A0905B6233",
		         "9537C5FDF120482F7D58D25E9ED583F52C02B4E304EA814DB1633AD565AED7E9", "65 bytes" },
		{ std::string(119, 'x'), "4300320394F7EE239BCDCE7D3B8BCEE173A0CD5C",
		         "000B48D4EDF0FA7BEE3C6236ECD2785BAA5DB4EEB8BB54341B029E0D9FA5FB0C", "119 bytes" },
		{ std::string(120, 'x'), "CEB2821639C4B6DCB10BCE0E522CA2E608CE056D",
		         "13F05A0B594787F5ECD315EDC96141BD3243203D1B7D4F0836F37308B276BA98", "120 bytes" },
		{ std::string(128, 'x'), "150FA3FBDC899BD0B8F95A9FB6027F564D953762",
		         "24DA1B81D0B16DF6428EEE73C69FCB2A93C76BC6DF706F0C6670FE6BFE800464", "128 bytes" },
	};

	int failures = 0;
	for (const Case& c : case_){
		const std::string r1 = narrow(sha1De(c.message));
		const std::string r2 = narrow(sha256De(c.message));
		const bool ok = (r1 == c.sha1) && (r2 == c.sha256);
		if (!ok){
			++failures;
			std::cout << "  FAILED  " << c.name << "\n";
			if (r1 != c.sha1)   std::cout << "         sha1   expected " << c.sha1
			                              << "\n                got      " << r1 << "\n";
			if (r2 != c.sha256) std::cout << "         sha256 expected " << c.sha256
			                              << "\n                got      " << r2 << "\n";
		}
		else std::cout << "  ok     " << c.name << "\n";
	}

	/* Splitting the updates must change nothing: that is how WAC uses it, one
	   cluster at a time during the extraction. */
	Sha1Stream a; Sha256Stream b;
	for (char ch : std::string("abc")){
		a.update((const uint8_t*)&ch, 1);
		b.update((const uint8_t*)&ch, 1);
	}
	const bool chunks =
		narrow(a.hexDigest()) == "A9993E364706816ABA3E25717850C26C9CD0D89D" &&
		narrow(b.hexDigest()) == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
	if (!chunks) ++failures;
	std::cout << (chunks ? "  ok     " : "  FAILED  ")
	          << "byte-by-byte updates == one single block\n";

	std::cout << (failures ? "FAILURES: " : "all passed (failures: ") << failures
	          << (failures ? "\n" : ")\n");
	return failures ? 1 : 0;
}
