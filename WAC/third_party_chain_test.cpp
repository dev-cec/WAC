/*! \file
 *  \brief Checks each rule of ThirdPartyRoots on chains made to break it.
 *
 *  WHY THIS TEST. A chain accepted wrongly clears a third-party binary, and
 *  leaves it on the examined machine; nothing shows it. Real signatures
 *  (authenticode_test --trust, against openssl verify) prove that sound
 *  chains are accepted; they cannot prove that each rule refuses what it
 *  must. Here, chains built by openssl (third_party_chain_fixtures.sh) each
 *  break one rule, and must be refused for that rule's reason:
 *    - the sound chain, accepted;
 *    - the root absent from the list; excluded from code signing; distrusted;
 *    - the authority's key disallowed by Microsoft; the authority revoked
 *      according to the CCADB;
 *    - an issuer without cA; a signer certificate for the web only;
 *    - an authority with the right name and another key (a forger's);
 *    - an ECDSA authority: not verified, hence not accepted;
 *    - THE TIME a chain is judged at, with a real RFC 3161 token made by
 *      openssl ts over a signature value, the collection's time moved to
 *      2040: a signer valid 2020-2035 is accepted without time stamp in 2026,
 *      refused in 2040, accepted in 2040 when stamped in 2026 — by an RFC
 *      3161 token, or by a legacy counter-signature whose RSA block holds the
 *      bare digest, as old VeriSign services made them; a token over
 *      another signature, or altered, refused; its authority's root not
 *      trusted for time stamping, refused; a root distrusted after 2030
 *      accepted for a signature stamped before, refused otherwise;
 *    - REVOCATION, with real CRLs made by openssl ca: the sound chain
 *      accepted with its authority's and its root's CRLs; without them, or
 *      with the authority's missing, or forged — the right issuer name,
 *      another key —, refused as not verifiable; the CRL found through the
 *      CCADB when the certificate's address is not in the set, and the
 *      certificate's own prevailing over it; a signer
 *      revoked for a key compromise refused even when stamped before; one
 *      revoked as superseded after the time stamp accepted when stamped,
 *      refused otherwise.
 *  The trust lists are built here, entry by entry: what is tested is the
 *  chain, the lists' own reading being trust_list_test's.
 *
 *  Usage: trust fixtures made by `third_party_chain_fixtures.sh <folder>`, then
 *         third_party_chain_test `<folder>`
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. authenticode.cpp rsa.cpp sha.cpp quickdigest5.cpp third_party_chain_test.cpp -o third_party_chain_test
 */
#include "authenticode.h"
#include "quickdigest5.h"
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>

namespace {

unsigned long long g_checks = 0, g_failures = 0;
std::filesystem::path g_folder;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! A fixture certificate, DER.
std::vector<uint8_t> certificate(const char* name) {
	std::ifstream f(g_folder / (std::string(name) + ".der"), std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

//! Bytes as a string, the form of a list identifier.
std::string bytes(const uint8_t* p, size_t n) { return std::string((const char*)p, n); }

//! The MD5 of a certificate's public key: the 16-byte identifier of disallowedcert.stl.
std::string keyMd5(const std::vector<uint8_t>& der) {
	// Computed here, apart from WAC's FindInTrustList: Certificate > TBSCertificate > its fields,
	// the sixth after the optional version being the subjectPublicKeyInfo.
	auto header = [&](size_t at, size_t& length) {
		size_t n = der[at + 1];
		if (n < 0x80) { length = n; return at + 2; }
		length = 0;
		for (size_t k = 0; k < (n & 0x7F); ++k) length = (length << 8) | der[at + 2 + k];
		return at + 2 + (n & 0x7F);
	};
	size_t length = 0;
	const size_t tbs = header(0, length);
	size_t at = header(tbs, length);
	if (der[at] == 0xA0) at = header(at, length) + length;
	for (int field = 0; field < 5; ++field) at = header(at, length) + length;   // serial .. subject
	const size_t info = header(at, length);                   // SEQUENCE { algorithm, BIT STRING }
	const size_t algorithm = header(info, length);
	const size_t bits = algorithm + length;
	const size_t key = header(bits, length);
	Md5Stream md5;
	md5.update(der.data() + key + 1, length - 1);            // the unused-bits byte excluded
	const std::wstring hex = md5.hexDigest();
	std::string raw;
	for (size_t k = 0; k + 1 < hex.size(); k += 2)
		raw += (char)std::stoi(std::string(hex.begin() + k, hex.begin() + k + 2), nullptr, 16);
	return raw;
}

//! A fixture file, whole.
std::vector<uint8_t> fixture(const char* name) {
	std::ifstream f(g_folder / name, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

//! DER: `content` under `tag`, with its length.
std::vector<uint8_t> der(uint8_t tag, const std::vector<uint8_t>& content) {
	std::vector<uint8_t> out{ tag };
	const size_t n = content.size();
	if (n < 0x80) out.push_back((uint8_t)n);
	else if (n < 0x100) { out.push_back(0x81); out.push_back((uint8_t)n); }
	else { out.push_back(0x82); out.push_back((uint8_t)(n >> 8)); out.push_back((uint8_t)n); }
	out.insert(out.end(), content.begin(), content.end());
	return out;
}

/*! The unsigned attributes of a SignerInfo carrying a time stamp:
 *  [1] { SEQUENCE { OID, SET { value } } } — by default an RFC 3161 token
 *  (1.3.6.1.4.1.311.3.3.1). */
std::vector<uint8_t> stampAttributes(const std::vector<uint8_t>& token,
                                     const std::vector<uint8_t>& oid = { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01,
                                                                          0x82, 0x37, 0x03, 0x03, 0x01 }) {
	std::vector<uint8_t> attribute = oid;
	const std::vector<uint8_t> values = der(0x31, token);
	attribute.insert(attribute.end(), values.begin(), values.end());
	return der(0xA1, der(0x30, attribute));
}

//! A Unix time as a FILETIME.
uint64_t filetime(long long unixSeconds) { return (uint64_t)(unixSeconds + 11644473600LL) * 10000000ULL; }

//! A signature as VerifyPkcs7 would give it: intact, these certificates, the first the signer.
VerifiedSignature signatureOf(const std::vector<const std::vector<uint8_t>*>& pool) {
	VerifiedSignature s;
	s.intact = true;
	for (const std::vector<uint8_t>* c : pool) s.certificates.push_back({ c->data(), c->size() });
	s.signerIndex = 0;
	return s;
}

//! A chain, and what it must give: accepted, or refused for a reason.
struct Case {
	const char* what;
	std::vector<const std::vector<uint8_t>*> pool;
	const char* expected;            //!< "" for accepted, else a part of the reason
};

} // namespace

int main(int argc, char** argv) {
	if (argc != 2) { std::printf("usage: third_party_chain_test <fixtures folder>\n"); return 2; }
	g_folder = argv[1];
	const std::vector<uint8_t> root = certificate("root"), ca = certificate("ca"), leaf = certificate("leaf"),
	                           web = certificate("web"), noca = certificate("noca"), under = certificate("under"),
	                           forged = certificate("forged-ca"), ecca = certificate("ecca"), ecleaf = certificate("ecleaf");
	uint8_t sha1[20], sha256[32];
	sha1Bytes(root.data(), root.size(), sha1);

	// The list of roots: the test root, trusted for code signing.
	TrustList roots;
	roots.valid = true;
	roots.identifier = 3;
	roots.entries.push_back({ bytes(sha1, 20) });
	const std::map<std::string, std::vector<uint8_t>> certificates = { { bytes(sha1, 20), root } };
	TrustList disallowed;
	disallowed.valid = true;
	disallowed.identifier = 15;
	std::set<std::wstring> revoked;
	// Now: the fixtures, made just before, are valid from their making, for ten years.
	const uint64_t NOW = filetime((long long)std::time(nullptr) + 60);
	// The revocation lists, by the addresses the certificates name.
	RevocationLists lists;
	lists.byUrl["http://wac.test/ca.crl"] = fixture("ca-crl.crl");
	lists.byUrl["http://wac.test/root.crl"] = fixture("root-crl.crl");

	const Case sound[] = {
		{ "sound chain", { &leaf, &ca }, "" },
		{ "sound chain, root carried too", { &leaf, &ca, &root }, "" },
		{ "issuer without cA", { &under, &noca }, "issuer not an authority" },
		{ "signer for the web only", { &web, &ca }, "not for code signing" },
		{ "authority of a forger: same name, another key", { &leaf, &forged }, "chain not tied" },
		{ "ECDSA authority", { &ecleaf, &ecca }, "not RSA" },
	};
	for (const Case& c : sound) {
		const ThirdPartyRoots trust(roots, certificates, disallowed, revoked, lists, NOW);
		const ChainVerdict v = trust.verify(signatureOf(c.pool));
		if (!*c.expected) check(v.trusted && v.root == L"WAC Test Root", std::string(c.what) + ": refused: " + v.reason);
		else check(!v.trusted && v.reason.find(c.expected) != std::string::npos,
		           std::string(c.what) + ": " + (v.trusted ? "accepted" : "refused for \"" + v.reason + "\""));
	}

	// The same sound chain, each list changed to refuse it.
	auto expectRefused = [&](const TrustList& r, const TrustList& d, const std::set<std::wstring>& rv,
	                         const char* expected, const char* what) {
		const ThirdPartyRoots trust(r, certificates, d, rv, lists, NOW);
		const ChainVerdict v = trust.verify(signatureOf({ &leaf, &ca }));
		check(!v.trusted && v.reason.find(expected) != std::string::npos,
		      std::string(what) + ": " + (v.trusted ? "accepted" : "refused for \"" + v.reason + "\""));
	};
	TrustList absent = roots;
	absent.entries.clear();
	expectRefused(absent, disallowed, revoked, "chain not tied", "root not in the list");
	TrustList excluded = roots;
	excluded.entries[0].codeSigningExcluded = true;
	expectRefused(excluded, disallowed, revoked, "not trusted by Microsoft for code signing", "root excluded from code signing");
	TrustList distrusted = roots;
	distrusted.entries[0].distrusted = true;
	expectRefused(distrusted, disallowed, revoked, "root distrusted", "root distrusted");
	TrustList banned = disallowed;
	banned.entries.push_back({ keyMd5(ca) });
	expectRefused(roots, banned, revoked, "disallowed by Microsoft", "authority's key disallowed");
	sha256Bytes(ca.data(), ca.size(), sha256);
	expectRefused(roots, disallowed, { toHexadecimal(sha256, 32) }, "revoked (CCADB)", "authority revoked");

	// Not intact: nothing to check.
	VerifiedSignature broken = signatureOf({ &leaf, &ca });
	broken.intact = false;
	check(!ThirdPartyRoots(roots, certificates, disallowed, revoked, lists, NOW).verify(broken).trusted, "signature not intact: accepted");

	// THE TIME. A signer valid 2020-2035; a token made now over signature.bin.
	const std::vector<uint8_t> old = certificate("old");
	const std::vector<uint8_t> value = fixture("signature.bin"), other = fixture("other-signature.bin");
	const std::vector<uint8_t> token = fixture("token.bin");
	std::vector<uint8_t> altered = token;
	altered[altered.size() - 20] ^= 0x01;                     // within the token's RSA signature
	const std::vector<uint8_t> stamped = stampAttributes(token), stampedAltered = stampAttributes(altered);
	const uint64_t IN_2040 = filetime(2208988800);
	auto timed = [&](const std::vector<uint8_t>& signatureValue, const std::vector<uint8_t>* attributes) {
		VerifiedSignature v = signatureOf({ &old, &ca });
		v.signatureValue = signatureValue.data();
		v.signatureValueSize = signatureValue.size();
		if (attributes) { v.unsignedAttributes = attributes->data(); v.unsignedAttributesSize = attributes->size(); }
		return v;
	};
	auto judgeWith = [&](const TrustList& r, const RevocationLists& crls, uint64_t now, const VerifiedSignature& v,
	                     const char* expected, const char* what) {
		const ChainVerdict c = ThirdPartyRoots(r, certificates, disallowed, revoked, crls, now).verify(v);
		if (!*expected) check(c.trusted, std::string(what) + ": refused: " + c.reason);
		else check(!c.trusted && c.reason.find(expected) != std::string::npos,
		           std::string(what) + ": " + (c.trusted ? "accepted" : "refused for \"" + c.reason + "\""));
		return c;
	};
	auto judge = [&](const TrustList& r, uint64_t now, const VerifiedSignature& v, const char* expected, const char* what) {
		return judgeWith(r, lists, now, v, expected, what);
	};
	judge(roots, NOW, timed(value, nullptr), "", "valid signer, no time stamp, judged in 2026");
	judge(roots, IN_2040, timed(value, nullptr), "not valid at the collection time", "expired signer, no time stamp");
	const ChainVerdict ok = judge(roots, IN_2040, timed(value, &stamped), "", "expired signer, stamped while valid");
	// The token was made when the fixtures were, a moment ago.
	check(ok.signedAt > NOW - 86400ULL * 10000000ULL && ok.signedAt <= NOW && ok.timeStampAuthority == L"WAC Test Time Stamping",
	      "stamped: time or authority not recorded");
	judge(roots, IN_2040, timed(other, &stamped), "not over this signature", "time stamp over another signature");
	judge(roots, IN_2040, timed(value, &stampedAltered), "time stamp token", "time stamp token altered");
	// A legacy counter-signature (PKCS#9), its RSA block holding the bare SHA-1: its authority in the outer pool.
	const std::vector<uint8_t> counterSigned = stampAttributes(fixture("countersignature.bin"),
		{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06 });
	const std::vector<uint8_t> tsa = certificate("tsa");
	VerifiedSignature legacy = timed(value, &counterSigned);
	legacy.certificates.push_back({ tsa.data(), tsa.size() });
	const ChainVerdict countersigned = judge(roots, IN_2040, legacy, "", "expired signer, legacy counter-signature over a bare digest");
	check(countersigned.timeStampAuthority == L"WAC Test Time Stamping", "legacy counter-signature: authority not recorded");
	TrustList noStamping = roots;
	noStamping.entries[0].timeStampingExcluded = true;
	judge(noStamping, NOW, timed(value, &stamped), "root not trusted by Microsoft for time stamping",
	      "time stamping authority under a root not trusted for it");
	TrustList distrustedLater = roots;
	distrustedLater.entries[0].distrusted = true;
	distrustedLater.entries[0].distrustedAfter = filetime(1893456000);   // 2030
	judge(distrustedLater, IN_2040, timed(value, &stamped), "", "root distrusted after 2030, stamped before");
	judge(distrustedLater, NOW, timed(value, nullptr), "root distrusted", "root distrusted after 2030, not stamped");
	TrustList distrustedEarlier = distrustedLater;
	distrustedEarlier.entries[0].distrustedAfter = filetime(1577836800);  // 2020
	judge(distrustedEarlier, NOW, timed(value, &stamped), "before the signing time", "root distrusted before the time stamp");

	// REVOCATION.
	auto signedBy = [&](const std::vector<uint8_t>& signer, const std::vector<uint8_t>* attributes) {
		VerifiedSignature v = signatureOf({ &signer, &ca });
		v.signatureValue = value.data();
		v.signatureValueSize = value.size();
		if (attributes) { v.unsignedAttributes = attributes->data(); v.unsignedAttributesSize = attributes->size(); }
		return v;
	};
	const ChainVerdict checked = judge(roots, NOW, signedBy(leaf, nullptr), "", "sound chain, both CRLs");
	check(checked.revocationListsIssued > 0, "sound chain: date of the CRLs not recorded");
	judgeWith(roots, RevocationLists{}, NOW, signedBy(leaf, nullptr), "revocation not verifiable", "no revocation list");
	RevocationLists rootOnly;
	rootOnly.byUrl["http://wac.test/root.crl"] = lists.byUrl["http://wac.test/root.crl"];
	judgeWith(roots, rootOnly, NOW, signedBy(leaf, nullptr), "revocation not verifiable", "authority's CRL missing");
	RevocationLists forgedCrl = lists;
	forgedCrl.byUrl["http://wac.test/ca.crl"] = fixture("forged-crl.crl");
	judgeWith(roots, forgedCrl, NOW, signedBy(leaf, nullptr), "revocation not verifiable", "authority's CRL forged");
	RevocationLists throughCcadb = rootOnly;
	uint8_t caSha256[32];
	sha256Bytes(ca.data(), ca.size(), caSha256);
	throughCcadb.byUrl["http://elsewhere.test/full.crl"] = lists.byUrl["http://wac.test/ca.crl"];
	throughCcadb.byAuthority[toHexadecimal(caSha256, 32)] = { "http://elsewhere.test/full.crl" };
	judgeWith(roots, throughCcadb, NOW, signedBy(leaf, nullptr), "", "authority's CRL found through the CCADB");
	const std::vector<uint8_t> compromised = certificate("revkey"), superseded = certificate("revsup");
	// The list the certificate names prevails over the CCADB's, which here revokes nothing.
	RevocationLists named = lists;
	named.byUrl["http://elsewhere.test/empty.crl"] = fixture("ca-empty-crl.crl");
	named.byAuthority[toHexadecimal(caSha256, 32)] = { "http://elsewhere.test/empty.crl" };
	judgeWith(roots, named, NOW, signedBy(superseded, nullptr), "revoked before the signing time",
	          "the certificate's CRL prevails over the CCADB's");
	judge(roots, NOW, signedBy(compromised, &stamped), "compromise", "signer revoked for a key compromise, stamped before");
	judge(roots, NOW, signedBy(superseded, nullptr), "revoked before the signing time", "signer superseded, not stamped");
	judge(roots, NOW, signedBy(superseded, &stamped), "", "signer superseded after its time stamp");


	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
