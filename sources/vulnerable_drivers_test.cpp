/*! \file
 *  \brief Checks each rule of VulnerableDrivers, one at a time.
 *
 *  WHY THIS TEST. A vulnerable driver not recognised is cleared, and left on
 *  the examined machine — the very tool of a kernel intrusion (BYOVD). Real
 *  samples of LOLDrivers prove the fingerprints (authenticode_test --trust:
 *  two drivers whose chain holds, refused by their fingerprint); they are
 *  listed by fingerprint only, and cannot prove the denied signers. Each rule
 *  is taken here alone, with made-up facts:
 *    - a fingerprint, Authenticode or of the file, listed; none listed;
 *    - a denied authority in the chain, or not;
 *    - narrowed by the signer's certificate name, by the WHQL manufacturer;
 *    - narrowed by files: original name (not the name on disk), product,
 *      version bounds; a binary whose version resource is absent does not
 *      match a file rule, one not read for it does.
 *
 *  Usage: vulnerable_drivers_test
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. authenticode.cpp rsa.cpp sha.cpp quickdigest5.cpp version_info.cpp vulnerable_drivers_test.cpp -o vulnerable_drivers_test
 */
#include "authenticode.h"
#include <cstdio>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! A version resource saying these names and version.
VersionInfo versionOf(const std::wstring& original, const std::wstring& product, const wchar_t* version) {
	VersionInfo v;
	v.strings[L"OriginalFilename"] = original;
	v.strings[L"ProductName"] = product;
	v.fixed = ParseFileVersion(version, v.fileVersion);
	return v;
}

} // namespace

int main() {
	const std::set<std::wstring> hashes = { L"AAAA1111", L"FFFF2222" };
	std::vector<DeniedSigner> signers;
	signers.push_back({ L"any file", L"TBS1", L"", L"", {} });
	signers.push_back({ L"a publisher", L"TBS2", L"Bad Vendor Ltd", L"", {} });
	signers.push_back({ L"a manufacturer", L"TBS3", L"", L"Cheat Engine", {} });
	DeniedFile evil;
	evil.fileName = L"evil.sys";
	ParseFileVersion(L"1.0.0.0", evil.minimumVersion);
	ParseFileVersion(L"1.2.0.0", evil.maximumVersion);
	DeniedFile product;
	product.productName = L"Bad Product";
	signers.push_back({ L"files", L"TBS4", L"", L"", { evil, product } });
	const VulnerableDrivers drivers(hashes, signers);

	auto listed = [&](const DriverFacts& f, const char* expected, const char* what) {
		const std::string why = drivers.match(f);
		if (!*expected) check(why.empty(), std::string(what) + ": listed: " + why);
		else check(why.find(expected) != std::string::npos, std::string(what) + ": " + (why.empty() ? "not listed" : why));
	};

	DriverFacts clean;
	clean.authenticodeSha256 = L"0000";
	clean.chainTbsHashes = { L"TBS9" };
	listed(clean, "", "nothing listed");

	DriverFacts f = clean;
	f.authenticodeSha256 = L"AAAA1111";
	listed(f, "fingerprint", "Authenticode fingerprint listed");
	f = clean;
	f.fileSha1 = L"FFFF2222";
	listed(f, "fingerprint", "file fingerprint listed");

	f = clean;
	f.chainTbsHashes = { L"tbs1" };                            // compared regardless of case
	listed(f, "any file", "denied authority in the chain");

	f = clean;
	f.chainTbsHashes = { L"TBS2" };
	f.signerName = L"bad vendor ltd";
	listed(f, "a publisher", "denied authority, signer named");
	f.signerName = L"Good Vendor";
	listed(f, "", "denied authority, another signer");

	f = clean;
	f.chainTbsHashes = { L"TBS3" };
	f.programName = L"Cheat Engine";
	listed(f, "a manufacturer", "denied authority, manufacturer named");
	f.programName = L"Red Hat, Inc.";
	listed(f, "", "denied authority, another manufacturer");

	f = clean;
	f.chainTbsHashes = { L"TBS4" };
	VersionInfo v = versionOf(L"EVIL.SYS", L"Some Product", L"1.1.0.0");
	f.version = &v;
	listed(f, "files", "denied file, original name and version within bounds");
	VersionInfo newer = versionOf(L"evil.sys", L"Some Product", L"1.3.0.0");
	f.version = &newer;
	listed(f, "", "denied file, version above the bound");
	VersionInfo older = versionOf(L"evil.sys", L"Some Product", L"0.9.0.0");
	f.version = &older;
	listed(f, "", "denied file, version below the bound");
	VersionInfo renamed = versionOf(L"sound.sys", L"Some Product", L"1.1.0.0");
	f.version = &renamed;
	listed(f, "", "another original name");
	VersionInfo byProduct = versionOf(L"sound.sys", L"bad product", L"9.0.0.0");
	f.version = &byProduct;
	listed(f, "files", "denied product, any version");
	f.version = nullptr;
	f.read = true;
	listed(f, "", "file rule, no version resource");
	f.read = false;
	listed(f, "files", "file rule, binary not read for its version");

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
