/*! \file
 *  \brief Confronts the reading of Microsoft's trust lists with independent
 *  references, then with altered lists.
 *
 *  WHY THIS TEST. --update-trust hands these lists to the signature check of
 *  third-party binaries: a root read as trusted for code signing when it is
 *  not, or a distrusted certificate not recognised, and a binary is judged
 *  authentic and left on the examined machine. Neither error shows at run
 *  time — the output stays valid. Hence:
 *    - authroot.stl: the counts of entries trusted for code signing and for
 *      time stamping, and of those for code signing not distrusted,
 *      computed apart by a DER reading of its own (Python,
 *      given as arguments), must be found again;
 *    - disallowedcert.stl: its identifiers are undocumented (see
 *      TrustList::identifier). The certificates Chromium blocks
 *      (net/data/ssl/blocklist), an independent set, must be recognised: at
 *      least as many as measured when the rule was established;
 *    - a list with one byte changed anywhere in its signed content must be
 *      refused: its signature no longer holds.
 *
 *  Usage: trust_list_test `<authroot.stl>` `<code-signing count>` `<time-stamping count>`
 *                         `<code-signing and not distrusted count>`
 *                         `<disallowedcert.stl>` `<blocklist folder>` `<minimum recognised>`
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. authenticode.cpp rsa.cpp sha.cpp quickdigest5.cpp trust_list_test.cpp -o trust_list_test
 */
#include "authenticode.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! @return the file's bytes; empty if it cannot be read
std::vector<uint8_t> readFile(const std::string& path) {
	std::ifstream f(path, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

//! @return the DER certificates of a PEM text
std::vector<std::vector<uint8_t>> pemCertificates(const std::string& text) {
	static const std::string BEGIN = "-----BEGIN CERTIFICATE-----", END = "-----END CERTIFICATE-----";
	std::vector<std::vector<uint8_t>> certificates;
	for (size_t at = text.find(BEGIN); at != std::string::npos; at = text.find(BEGIN, at)) {
		const size_t end = text.find(END, at);
		if (end == std::string::npos) break;
		certificates.push_back(DecodeBase64(text.substr(at + BEGIN.size(), end - at - BEGIN.size())));
		at = end;
	}
	return certificates;
}

//! The signed content altered at a few places, one at a time: each must be refused.
void checkAltered(const std::vector<uint8_t>& list, const std::string& name) {
	const size_t steps = 16;
	for (size_t k = 1; k < steps; ++k) {
		std::vector<uint8_t> altered = list;
		altered[altered.size() * k / steps / 2 + 64] ^= 0x01;    // within the content, which precedes the signature
		check(!ReadTrustList(altered.data(), altered.size()).valid, name + ": altered at byte "
		      + std::to_string(altered.size() * k / steps / 2 + 64) + " still read as valid");
	}
}

} // namespace

int main(int argc, char** argv) {
	if (argc != 8) {
		std::printf("usage: trust_list_test <authroot.stl> <code-signing> <time-stamping> "
		            "<usable> <disallowedcert.stl> <blocklist folder> <minimum recognised>\n");
		return 2;
	}
	const std::vector<uint8_t> authroot = readFile(argv[1]);
	const TrustList roots = ReadTrustList(authroot.data(), authroot.size());
	check(roots.valid, std::string("authroot.stl refused: ") + roots.reason);
	check(roots.identifier == 3, "authroot.stl: identifier " + std::to_string(roots.identifier) + ", 3 expected");
	check(roots.thisUpdate != 0, "authroot.stl: no issue date");
	size_t codeSigning = 0, timeStamping = 0, usable = 0;
	for (const TrustListEntry& e : roots.entries) {
		codeSigning += !e.codeSigningExcluded;
		timeStamping += !e.timeStampingExcluded;
		usable += !e.codeSigningExcluded && !e.distrusted;
	}
	check(usable == std::stoul(argv[4]), "authroot.stl: " + std::to_string(usable)
	      + " roots for code signing and not distrusted, " + argv[4] + " by the independent reading");
	check(codeSigning == std::stoul(argv[2]), "authroot.stl: " + std::to_string(codeSigning)
	      + " roots for code signing, " + argv[2] + " by the independent reading");
	check(timeStamping == std::stoul(argv[3]), "authroot.stl: " + std::to_string(timeStamping)
	      + " roots for time stamping, " + argv[3] + " by the independent reading");
	checkAltered(authroot, "authroot.stl");

	const std::vector<uint8_t> disallowed = readFile(argv[5]);
	const TrustList distrusted = ReadTrustList(disallowed.data(), disallowed.size());
	check(distrusted.valid, std::string("disallowedcert.stl refused: ") + distrusted.reason);
	check(distrusted.identifier == 15, "disallowedcert.stl: identifier " + std::to_string(distrusted.identifier));
	checkAltered(disallowed, "disallowedcert.stl");

	size_t certificates = 0, recognised = 0;
	for (const auto& file : std::filesystem::directory_iterator(argv[6])) {
		if (file.path().extension() != ".pem") continue;
		const std::vector<uint8_t> bytes = readFile(file.path().string());
		for (const std::vector<uint8_t>& certificate : pemCertificates(std::string(bytes.begin(), bytes.end()))) {
			++certificates;
			recognised += FindInTrustList(distrusted, certificate.data(), certificate.size()) != nullptr;
		}
	}
	std::printf("  %zu blocked certificate(s), %zu recognised by disallowedcert.stl\n", certificates, recognised);
	check(recognised >= std::stoul(argv[7]), std::to_string(recognised) + " blocked certificates recognised, at least "
	      + argv[7] + " expected");
	// Nothing is recognised by accident: a garbage certificate is not found.
	const uint8_t garbage[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
	check(FindInTrustList(distrusted, garbage, sizeof(garbage)) == nullptr, "a malformed certificate recognised");
	check(FindInTrustList(distrusted, nullptr, 0) == nullptr, "no certificate recognised");

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
