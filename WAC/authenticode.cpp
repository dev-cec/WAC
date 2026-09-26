/*! \file
 *  \brief Authenticode digests, PKCS#7 verification and catalog index.
 *
 *  See authenticode.h.
 *
 *  Format references: RFC 2315 (PKCS#7), RFC 5280 (X.509), "Windows
 *  Authenticode Portable Executable Signature Format" (Microsoft), and the CTL
 *  structure of catalogs (Certificate Trust List, OID 1.3.6.1.4.1.311.10.1).
 */
#include "authenticode.h"
#include "rsa.h"
#include "racines_microsoft.h"
#include "quickdigest5.h"
#include "json.h"
#include <cstring>
#include <map>
#include <set>
#include <mutex>

namespace {

// ============================================================ DER

struct Tlv {
	uint8_t tag = 0;
	const uint8_t* start = nullptr;   //!< first byte (tag)
	size_t total = 0;                 //!< tag + length + value
	const uint8_t* val = nullptr;     //!< value
	size_t len = 0;
};

//! Reads a DER element at `p` (at most `n` bytes). Definite length only.
bool readTlv(const uint8_t* p, size_t n, Tlv& t) {
	if (n < 2 || (p[0] & 0x1F) == 0x1F) return false;         // long tag form: no
	size_t i = 1, len = 0;
	const uint8_t b = p[i++];
	if (b < 0x80) len = b;
	else {
		const size_t lengthSize = b & 0x7F;
		if (lengthSize == 0 || lengthSize > 4 || i + lengthSize > n) return false;     // indefinite or oversized
		for (size_t k = 0; k < lengthSize; ++k) len = (len << 8) | p[i++];
	}
	if (len > n - i) return false;
	t.tag = p[0]; t.start = p; t.val = p + i; t.len = len; t.total = i + len;
	return true;
}

//! Elements contained in a constructed element.
std::vector<Tlv> children(const Tlv& t) {
	std::vector<Tlv> r;
	size_t pos = 0;
	while (pos < t.len) {
		Tlv e;
		if (!readTlv(t.val + pos, t.len - pos, e)) break;
		r.push_back(e);
		pos += e.total;
	}
	return r;
}

bool isOid(const Tlv& t, const uint8_t* oid, size_t n) {
	return t.tag == 0x06 && t.len == n && std::memcmp(t.val, oid, n) == 0;
}
//! Declares an OID constant as its DER content bytes.
#define OID(name, ...) const uint8_t name[] = { __VA_ARGS__ }
OID(OID_SIGNED_DATA,  0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02);
OID(OID_RSA,          0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01);
OID(OID_SHA1_RSA,     0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05);
OID(OID_SHA256_RSA,   0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B);
OID(OID_SHA1,         0x2B,0x0E,0x03,0x02,0x1A);
OID(OID_SHA256,       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01);
OID(OID_SHA384,       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02);
OID(OID_SHA512,       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03);
OID(OID_SHA384_RSA,   0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0C);
OID(OID_SHA512_RSA,   0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0D);
OID(OID_MESSAGE_DIGEST, 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04);
OID(OID_CN,           0x55,0x04,0x03);
OID(OID_O,            0x55,0x04,0x0A);
OID(OID_SPC_INDIRECT, 0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x04);
OID(OID_CTL,          0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x01);
OID(OID_BASIC_CONSTRAINTS, 0x55,0x1D,0x13);
OID(OID_EXT_KEY_USAGE,  0x55,0x1D,0x25);
OID(OID_ANY_KEY_USAGE,  0x55,0x1D,0x25,0x00);
OID(OID_CODE_SIGNING,   0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x03);
OID(OID_TIME_STAMPING,  0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x08);
OID(OID_RFC3161_TIME_STAMP, 0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x03,0x03,0x01);
OID(OID_COUNTER_SIGNATURE, 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x06);
OID(OID_SIGNING_TIME,   0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x05);
OID(OID_CRL_DISTRIBUTION_POINTS, 0x55,0x1D,0x1F);
OID(OID_SPC_SP_OPUS_INFO, 0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x0C);
OID(OID_CRL_REASON,     0x55,0x1D,0x15);
OID(OID_TST_INFO,       0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x10,0x01,0x04);
//! True if the DER element `t` is the OID constant `o`.
#define IS_OID(t, o) isOid((t), (o), sizeof(o))

//! Digest algorithm of an AlgorithmIdentifier (digest alone or RSA+digest).
DigestAlgorithm algoDe(const Tlv& algId) {
	const std::vector<Tlv> e = children(algId);
	if (e.empty()) return DigestAlgorithm::Unknown;
	if (IS_OID(e[0], OID_SHA1) || IS_OID(e[0], OID_SHA1_RSA)) return DigestAlgorithm::Sha1;
	if (IS_OID(e[0], OID_SHA256) || IS_OID(e[0], OID_SHA256_RSA)) return DigestAlgorithm::Sha256;
	if (IS_OID(e[0], OID_SHA384) || IS_OID(e[0], OID_SHA384_RSA)) return DigestAlgorithm::Sha384;
	if (IS_OID(e[0], OID_SHA512) || IS_OID(e[0], OID_SHA512_RSA)) return DigestAlgorithm::Sha512;
	return DigestAlgorithm::Unknown;
}

size_t fingerprint(DigestAlgorithm a, const uint8_t* p, size_t n, uint8_t output[64]) {
	if (a == DigestAlgorithm::Sha1)   { sha1Bytes(p, n, output);   return 20; }
	if (a == DigestAlgorithm::Sha256) { sha256Bytes(p, n, output); return 32; }
	if (a == DigestAlgorithm::Sha384) { sha384Bytes(p, n, output); return 48; }
	if (a == DigestAlgorithm::Sha512) { sha512Bytes(p, n, output); return 64; }
	return 0;
}

//! String of a name attribute (PrintableString, UTF8String, BMPString…).
std::wstring text(const Tlv& v) {
	std::wstring r;
	if (v.tag == 0x1E) {                                       // BMPString: UTF-16BE
		for (size_t i = 0; i + 1 < v.len; i += 2) r += (wchar_t)((v.val[i] << 8) | v.val[i + 1]);
		return r;
	}
	for (size_t i = 0; i < v.len; ++i) {                       // UTF-8 (ASCII included)
		const uint8_t c = v.val[i];
		if (c < 0x80) r += (wchar_t)c;
		else if ((c & 0xE0) == 0xC0 && i + 1 < v.len) { r += (wchar_t)(((c & 0x1F) << 6) | (v.val[i + 1] & 0x3F)); ++i; }
		else if ((c & 0xF0) == 0xE0 && i + 2 < v.len) { r += (wchar_t)(((c & 0x0F) << 12) | ((v.val[i + 1] & 0x3F) << 6) | (v.val[i + 2] & 0x3F)); i += 2; }
		else r += L'?';
	}
	return r;
}

//! Value of an attribute (CN, O…) in a Name.
std::wstring attributeNameField(const Tlv& name, const uint8_t* oid, size_t n) {
	for (const Tlv& rdn : children(name))
		for (const Tlv& atv : children(rdn)) {
			const std::vector<Tlv> e = children(atv);
			if (e.size() >= 2 && isOid(e[0], oid, n)) return text(e[1]);
		}
	return std::wstring();
}

bool sameBytes(const Tlv& a, const Tlv& b) {
	return a.total == b.total && std::memcmp(a.start, b.start, a.total) == 0;
}

// ============================================================ X.509

/*! An ASN.1 time to a FILETIME in UTC: UTCTime "YYMMDDHHMMSSZ" (RFC 5280:
 *  years 50 to 99 are 19xx), or GeneralizedTime "YYYYMMDDHHMMSS[.f...]Z" —
 *  the time of an RFC 3161 time stamp, whose fraction is dropped. Computed
 *  here rather than by the system: the module is portable, and tested on
 *  Linux.
 *  @return false if the text is not such a time (filetime untouched) */
bool asn1TimeToFiletime(const Tlv& time, uint64_t& filetime) {
	const size_t yearDigits = time.tag == 0x17 ? 2 : time.tag == 0x18 ? 4 : 0;
	const size_t digitCount = yearDigits + 10;
	if (!yearDigits || time.len < digitCount + 1 || time.val[time.len - 1] != 'Z') return false;
	if (time.len > digitCount + 1 && (yearDigits == 2 || time.val[digitCount] != '.')) return false;
	int digits[14];
	for (size_t k = 0; k < digitCount; ++k) {
		if (time.val[k] < '0' || time.val[k] > '9') return false;
		digits[k] = time.val[k] - '0';
	}
	auto two = [&](size_t at) { return digits[at] * 10 + digits[at + 1]; };
	const int year = yearDigits == 4 ? two(0) * 100 + two(2) : two(0) + (two(0) >= 50 ? 1900 : 2000);
	const size_t m = yearDigits;
	const int month = two(m), day = two(m + 2), hour = two(m + 4), minute = two(m + 6), second = two(m + 8);
	if (year < 1601 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59)
		return false;
	// Days since 1601-01-01 (proleptic Gregorian): days from civil, H. Hinnant's method.
	const int y = year - (month <= 2);
	const int era = y / 400;
	const int yearOfEra = y - era * 400;
	const int dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	const int dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
	const long long daysSince1970 = (long long)era * 146097 + dayOfEra - 719468;
	const long long DAYS_1601_TO_1970 = 134774;
	const long long seconds = (daysSince1970 + DAYS_1601_TO_1970) * 86400 + hour * 3600 + minute * 60 + second;
	filetime = (uint64_t)seconds * 10000000ULL;
	return true;
}


struct Certificate {
	Tlv integer, tbs, issuer, subject, serial;
	Tlv module, exponent;          // RSA key
	DigestAlgorithm algoSignature = DigestAlgorithm::Unknown;
	const uint8_t* signature = nullptr;
	size_t signatureSize = 0;
	bool rsa = false;
	uint64_t notBefore = 0, notAfter = 0;   // FILETIME (UTC); 0 if unreadable
};

bool analyseCertificate(const Tlv& c, Certificate& r) {
	const std::vector<Tlv> e = children(c);
	if (c.tag != 0x30 || e.size() < 3 || e[0].tag != 0x30 || e[2].tag != 0x03 || e[2].len < 2) return false;
	r.integer = c;
	r.tbs = e[0];
	r.algoSignature = algoDe(e[1]);
	r.signature = e[2].val + 1;                               // unused-bits byte
	r.signatureSize = e[2].len - 1;
	std::vector<Tlv> t = children(e[0]);
	size_t i = 0;
	if (i < t.size() && t[i].tag == 0xA0) ++i;                // version
	if (i + 6 > t.size()) return false;
	r.serial = t[i];                                           // serialNumber
	r.issuer = t[i + 2];                                    // issuer
	r.subject = t[i + 4];                                       // subject
	const std::vector<Tlv> validity = children(t[i + 3]);
	if (validity.size() == 2 && (!asn1TimeToFiletime(validity[0], r.notBefore) || !asn1TimeToFiletime(validity[1], r.notAfter)))
		r.notBefore = r.notAfter = 0;
	const std::vector<Tlv> spki = children(t[i + 5]);
	if (spki.size() < 2 || spki[1].tag != 0x03 || spki[1].len < 2) return true;
	const std::vector<Tlv> alg = children(spki[0]);
	if (alg.empty() || !IS_OID(alg[0], OID_RSA)) return true;    // non-RSA key: cannot be verified
	Tlv key;
	if (!readTlv(spki[1].val + 1, spki[1].len - 1, key)) return true;
	const std::vector<Tlv> ne = children(key);
	if (ne.size() < 2 || ne[0].tag != 0x02 || ne[1].tag != 0x02) return true;
	r.module = ne[0];
	r.exponent = ne[1];
	r.rsa = true;
	return true;
}

//! Was the signature of `c` produced by the key of `issuer`?
bool signedBy(const Certificate& c, const Certificate& issuer) {
	if (!issuer.rsa || c.algoSignature == DigestAlgorithm::Unknown) return false;
	uint8_t h[64];
	const size_t lh = fingerprint(c.algoSignature, c.tbs.start, c.tbs.total, h);
	return RsaVerifyPkcs1(issuer.module.val, issuer.module.len,
	                        issuer.exponent.val, issuer.exponent.len,
	                        c.signature, c.signatureSize, c.algoSignature, h, lh);
}

//! Embedded roots, parsed once.
const std::vector<Certificate>& roots() {
	static std::vector<Certificate> r;
	static std::once_flag done;
	std::call_once(done, [] {
		for (const MicrosoftRoot& m : MICROSOFT_ROOTS) {
			Tlv t; Certificate c;
			if (readTlv(m.der, m.size, t) && analyseCertificate(t, c) && c.rsa) r.push_back(c);
		}
	});
	return r;
}

/*! Certificates already chained to a root, by SHA-256 of their DER.
 *  The 5,308 catalogs of a machine are signed by a handful of certificates:
 *  without this cache, the same chain would be verified again every time, the
 *  RSA-4096 root included. Shared by the analysis threads of --collect
 *  --binary, which verify signatures at once: hence its lock — a std::set
 *  written by two threads is undefined behaviour, which no test shows. */
class ChainCache {
public:
	//! @return true if `key` is known to chain to a root
	bool known(const std::string& key) {
		std::lock_guard<std::mutex> lock(mutex_);
		return keys_.count(key) != 0;
	}
	//! Records keys that chain to a root.
	void add(const std::vector<std::string>& keys) {
		std::lock_guard<std::mutex> lock(mutex_);
		keys_.insert(keys.begin(), keys.end());
	}
private:
	std::mutex mutex_;
	std::set<std::string> keys_;
};
ChainCache& validChains() { static ChainCache cache; return cache; }

std::string certKey(const Certificate& c) {
	uint8_t h[32];
	sha256Bytes(c.integer.start, c.integer.total, h);
	return std::string((const char*)h, 32);
}

/*! Chains `leaf` to an embedded Microsoft root, through the certificates
 *  supplied with the signature. At most 6 levels. */
bool attach(const Certificate& leaf, const std::vector<Certificate>& pool) {
	const Certificate* current = &leaf;
	std::vector<std::string> walked;
	for (int level = 0; level < 6; ++level) {
		const std::string key = certKey(*current);
		if (validChains().known(key)) {
			validChains().add(walked);
			return true;
		}
		walked.push_back(key);
		// Issued by an embedded root?
		for (const Certificate& r : roots()) {
			if (!sameBytes(current->issuer, r.subject)) continue;
			// The certificate IS the root (same key): nothing more to verify.
			if (current->rsa && current->module.len == r.module.len
			    && std::memcmp(current->module.val, r.module.val, r.module.len) == 0) {
				validChains().add(walked);
				return true;
			}
			if (signedBy(*current, r)) {
				validChains().add(walked);
				return true;
			}
		}
		// Otherwise, an intermediate supplied with the signature.
		const Certificate* next = nullptr;
		for (const Certificate& c : pool) {
			if (&c == current || !sameBytes(current->issuer, c.subject)) continue;
			if (signedBy(*current, c)) { next = &c; break; }
		}
		if (!next) return false;
		current = next;
	}
	return false;
}

/*! Signers whose binaries are authentic Microsoft ones, identical on every
 *  machine of the same build. ".NET": the runtime Microsoft ships with
 *  Windows and its applications (544 files of a plain Windows 11 were
 *  collected for want of it), and ".NET DAC", its data access component. Not accepted: "Microsoft Windows Hardware
 *  Compatibility Publisher" and "Microsoft 3rd Party Application Component",
 *  which Microsoft grants to OTHER vendors' drivers and components — a
 *  vulnerable third-party driver is a classic intrusion tool. */
bool signerAccepted(const std::wstring& cn, const std::wstring& o) {
	if (o != L"Microsoft Corporation") return false;
	return cn == L"Microsoft Windows" || cn == L"Microsoft Corporation"
	    || cn == L"Microsoft Windows Publisher" || cn == L".NET" || cn == L".NET DAC";
}

/*! What checkSignerInfo gives of a SignerInfo that holds. */
struct SignerInfoCheck {
	size_t signerIndex = SIZE_MAX;   //!< the signer's certificate, in the pool
	Tlv attributes;                  //!< its authenticated attributes ([0])
	Tlv signatureValue;              //!< its encryptedDigest
	Tlv unsignedAttributes;          //!< its unsigned attributes ([1]); start null if none
};

/*! A SignerInfo — of a signature, a counter-signature or a time stamp
 *  token: the messageDigest attribute must be the digest of `content`, and
 *  the signature over the attributes, re-encoded as a SET, must hold with
 *  the certificate of `pool` it names (RSA).
 *  @param encoding whether a bare digest is accepted (counter-signatures only)
 *  @return "" if it holds, otherwise why not */
std::string checkSignerInfo(const Tlv& signerInfo, const uint8_t* content, size_t contentSize,
                            const std::vector<Certificate>& pool, SignerInfoCheck& out,
                            DigestEncoding encoding = DigestEncoding::DigestInfo) {
	const std::vector<Tlv> si = children(signerInfo);
	// version, issuerAndSerialNumber, digestAlgorithm, [0] attributes, digestEncryptionAlgorithm, encryptedDigest, [1] unsigned
	if (si.size() < 5) return "SignerInfo incomplete";
	const std::vector<Tlv> ias = children(si[1]);
	if (ias.size() < 2) return "signer's issuer unreadable";
	const DigestAlgorithm algo = algoDe(si[2]);
	if (algo == DigestAlgorithm::Unknown) return "digest algorithm not supported";
	size_t k = 3;
	const Tlv* attributes = nullptr;
	if (si[k].tag == 0xA0) attributes = &si[k++];
	if (k + 1 >= si.size() || si[k + 1].tag != 0x04) return "signature absent";
	const Tlv& signature = si[k + 1];
	if (!attributes) return "authenticated attributes absent";
	if (k + 2 < si.size() && si[k + 2].tag == 0xA1) out.unsignedAttributes = si[k + 2];

	// 1. The content's digest must be the one announced in the attributes.
	uint8_t hc[64];
	const size_t lhc = fingerprint(algo, content, contentSize, hc);
	bool digestOk = false;
	for (const Tlv& a : children(*attributes)) {
		const std::vector<Tlv> av = children(a);
		if (av.size() < 2 || !IS_OID(av[0], OID_MESSAGE_DIGEST)) continue;
		const std::vector<Tlv> vals = children(av[1]);
		if (!vals.empty() && vals[0].tag == 0x04 && vals[0].len == lhc
		    && std::memcmp(vals[0].val, hc, lhc) == 0) digestOk = true;
	}
	if (!digestOk) return "content digest does not match";

	// 2. The signature covers the attributes, re-encoded as a SET (0x31).
	std::vector<uint8_t> signedBytes(attributes->start, attributes->start + attributes->total);
	signedBytes[0] = 0x31;
	uint8_t ha[64];
	const size_t lha = fingerprint(algo, signedBytes.data(), signedBytes.size(), ha);
	for (size_t c = 0; c < pool.size(); ++c)
		if (sameBytes(pool[c].issuer, ias[0]) && sameBytes(pool[c].serial, ias[1])) { out.signerIndex = c; break; }
	if (out.signerIndex == SIZE_MAX || !pool[out.signerIndex].rsa) return "signer certificate absent or not RSA";
	const Certificate& signer = pool[out.signerIndex];
	if (!RsaVerifyPkcs1(signer.module.val, signer.module.len, signer.exponent.val, signer.exponent.len,
	                    signature.val, signature.len, algo, ha, lha, encoding))
		return "RSA signature invalid";
	out.attributes = *attributes;
	out.signatureValue = signature;
	return std::string();
}

} // namespace

// ============================================================ PKCS#7

VerifiedSignature VerifyPkcs7(const uint8_t* data, size_t size) {
	VerifiedSignature r;
	Tlv ci;
	if (!readTlv(data, size, ci) || ci.tag != 0x30) { r.reason = "ContentInfo unreadable"; return r; }
	std::vector<Tlv> e = children(ci);
	if (e.size() < 2 || !IS_OID(e[0], OID_SIGNED_DATA) || e[1].tag != 0xA0) { r.reason = "not a SignedData"; return r; }
	std::vector<Tlv> w = children(e[1]);
	if (w.empty() || w[0].tag != 0x30) { r.reason = "SignedData unreadable"; return r; }
	const std::vector<Tlv> sd = children(w[0]);
	// version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
	if (sd.size() < 4) { r.reason = "SignedData incomplete"; return r; }
	const std::vector<Tlv> eci = children(sd[2]);
	if (eci.size() < 2 || eci[0].tag != 0x06 || eci[1].tag != 0xA0) { r.reason = "content absent"; return r; }
	r.contentOid.assign((const char*)eci[0].val, eci[0].len);
	const std::vector<Tlv> cc = children(eci[1]);
	if (cc.empty()) { r.reason = "content empty"; return r; }
	r.content = cc[0].val;
	r.contentSize = cc[0].len;

	std::vector<Certificate> pool;
	const Tlv* infos = nullptr;
	for (size_t i = 3; i < sd.size(); ++i) {
		if (sd[i].tag == 0xA0)
			for (const Tlv& c : children(sd[i])) {
				Certificate x;
				if (!analyseCertificate(c, x)) continue;
				pool.push_back(x);
				r.certificates.push_back({ c.start, c.total });
			}
		else if (sd[i].tag == 0x31) infos = &sd[i];
	}
	if (!infos) { r.reason = "no signer"; return r; }
	const std::vector<Tlv> signers = children(*infos);
	if (signers.empty()) { r.reason = "no signer"; return r; }
	SignerInfoCheck check;
	r.reason = checkSignerInfo(signers[0], r.content, r.contentSize, pool, check);
	if (!r.reason.empty()) return r;
	r.signerIndex = check.signerIndex;
	// SpcSpOpusInfo { [0] programName SpcString { [0] BMPString | [1] IA5String } } — the WHQL manufacturer.
	for (const Tlv& a : children(check.attributes)) {
		const std::vector<Tlv> av = children(a);
		if (av.size() < 2 || !IS_OID(av[0], OID_SPC_SP_OPUS_INFO)) continue;
		const std::vector<Tlv> values = children(av[1]);
		if (values.empty()) continue;
		for (const Tlv& field : children(values[0])) {
			if (field.tag != 0xA0) continue;
			const std::vector<Tlv> name = children(field);
			if (name.empty()) continue;
			if (name[0].tag == 0x80)
				for (size_t k = 0; k + 1 < name[0].len; k += 2) r.programName += (wchar_t)((name[0].val[k] << 8) | name[0].val[k + 1]);
			else if (name[0].tag == 0x81) r.programName.assign(name[0].val, name[0].val + name[0].len);
		}
	}
	r.signatureValue = check.signatureValue.val;
	r.signatureValueSize = check.signatureValue.len;
	if (check.unsignedAttributes.start) {
		r.unsignedAttributes = check.unsignedAttributes.start;
		r.unsignedAttributesSize = check.unsignedAttributes.total;
	}
	const Certificate* signer = &pool[check.signerIndex];
	// The signature holds, whoever signed: who, for the record.
	r.intact = true;
	r.signer = attributeNameField(signer->subject, OID_CN, sizeof(OID_CN));
	r.signerOrganization = attributeNameField(signer->subject, OID_O, sizeof(OID_O));
	// 3. The chain up to an embedded Microsoft root.
	if (!attach(*signer, pool)) { r.reason = "chain not tied to a Microsoft root"; return r; }

	r.valid = true;
	r.signerAccepted = signerAccepted(r.signer, r.signerOrganization);
	if (!r.signerAccepted) r.reason = "signer not accepted";
	return r;
}

// ============================================================ third-party chains

namespace {

/*! The value of an extension of a certificate (the content of its
 *  extnValue OCTET STRING), found by its OID.
 *  @return false if the certificate has no such extension */
bool extensionOf(const Certificate& c, const uint8_t* oid, size_t oidSize, Tlv& value) {
	for (const Tlv& field : children(c.tbs)) {
		if (field.tag != 0xA3) continue;                         // [3] extensions
		const std::vector<Tlv> wrapper = children(field);
		if (wrapper.empty()) return false;
		for (const Tlv& extension : children(wrapper[0])) {
			const std::vector<Tlv> e = children(extension);
			if (e.size() < 2 || e[0].tag != 0x06 || e[0].len != oidSize || std::memcmp(e[0].val, oid, oidSize) != 0)
				continue;
			const Tlv& octets = e.back();                        // critical flag optional, in between
			return octets.tag == 0x04 && readTlv(octets.val, octets.len, value);
		}
	}
	return false;
}

//! An authority: basic constraints present, cA true.
bool isAuthority(const Certificate& c) {
	Tlv constraints;
	if (!extensionOf(c, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS), constraints)) return false;
	const std::vector<Tlv> b = children(constraints);
	return !b.empty() && b[0].tag == 0x01 && b[0].len == 1 && b[0].val[0] != 0;
}

/*! The certificate allows a use (code signing, time stamping): no extended
 *  key usage, or one listing that use or any use. */
bool allowsUse(const Certificate& c, const uint8_t* use, size_t useSize) {
	Tlv usages;
	if (!extensionOf(c, OID_EXT_KEY_USAGE, sizeof(OID_EXT_KEY_USAGE), usages)) return true;
	for (const Tlv& oid : children(usages))
		if ((oid.tag == 0x06 && oid.len == useSize && std::memcmp(oid.val, use, useSize) == 0) || IS_OID(oid, OID_ANY_KEY_USAGE))
			return true;
	return false;
}

//! SHA-256 of a certificate, in uppercase hexadecimal: how the CCADB names it.
std::wstring certificateSha256(const Certificate& c) {
	uint8_t h[32];
	sha256Bytes(c.integer.start, c.integer.total, h);
	return toHexadecimal(h, sizeof(h));
}

//! Its CN, for a reason.
std::string narrowName(const Certificate& c) {
	const std::wstring cn = attributeNameField(c.subject, OID_CN, sizeof(OID_CN));
	return std::string(cn.begin(), cn.end());
}

//! The certificates of a signature, parsed.
std::vector<Certificate> parsePool(const std::vector<std::pair<const uint8_t*, size_t>>& certificates) {
	std::vector<Certificate> pool;
	for (const auto& [der, size] : certificates) {
		Tlv t;
		Certificate c;
		if (readTlv(der, size, t) && analyseCertificate(t, c)) pool.push_back(c);
	}
	return pool;
}

//! A root of the set: its certificate, and its entry in authroot.stl.
using SetRoot = std::pair<Certificate, const TrustListEntry*>;

//! A chain from a signer up to a root of the set, or why there is none.
struct Chain {
	std::vector<const Certificate*> certificates;   //!< signer first, the root excluded
	const SetRoot* root = nullptr;
	std::string reason;
};

//! The use a chain is built for: code signing, or time stamping — each with its own trust in authroot.stl.
struct Use {
	const uint8_t* oid;
	size_t oidSize;
	bool TrustListEntry::* excluded;
	const char* name;
};
const Use CODE_SIGNING_USE = { OID_CODE_SIGNING, sizeof(OID_CODE_SIGNING), &TrustListEntry::codeSigningExcluded, "code signing" };
const Use TIME_STAMPING_USE = { OID_TIME_STAMPING, sizeof(OID_TIME_STAMPING), &TrustListEntry::timeStampingExcluded, "time stamping" };

//! A time stamp of a signature: when it was made, by whom — or why it does not hold.
struct TimeStamp {
	bool present = false;            //!< the signature carries one
	bool verified = false;           //!< and it holds
	uint64_t at = 0;                 //!< FILETIME (UTC) it gives
	std::wstring authority;          //!< CN of the time stamping authority
	std::string reason;              //!< why it does not hold
};

//! A revocation list, read: what it says, and what its signature covers.
struct ParsedCrl {
	std::string url;
	Tlv tbs;                         //!< what the signature covers
	DigestAlgorithm algo = DigestAlgorithm::Unknown;
	const uint8_t* signature = nullptr;
	size_t signatureSize = 0;
	Tlv issuer;
	uint64_t thisUpdate = 0;
	//! Each revoked serial (the INTEGER's bytes): when, and why (RFC 5280 reason code; -1 when not given).
	std::map<std::string, std::pair<uint64_t, int>> revoked;
};

// RFC 5280 reason codes that undo a signature whatever its time.
const int REASON_UNSPECIFIED = 0, REASON_KEY_COMPROMISE = 1, REASON_CA_COMPROMISE = 2, REASON_AA_COMPROMISE = 10;

/*! Reads a CRL: CertificateList { tbsCertList, signatureAlgorithm, signature }.
 *  @return false if it is not one */
bool parseCrl(const uint8_t* data, size_t size, ParsedCrl& crl) {
	Tlv whole;
	if (!readTlv(data, size, whole) || whole.tag != 0x30) return false;
	const std::vector<Tlv> e = children(whole);
	if (e.size() != 3 || e[0].tag != 0x30 || e[2].tag != 0x03 || e[2].len < 2) return false;
	crl.tbs = e[0];
	crl.algo = algoDe(e[1]);
	crl.signature = e[2].val + 1;                            // unused-bits byte
	crl.signatureSize = e[2].len - 1;
	const std::vector<Tlv> t = children(e[0]);
	size_t i = !t.empty() && t[0].tag == 0x02 ? 1 : 0;       // version
	// signature, issuer, thisUpdate, [nextUpdate], [revokedCertificates], [0] extensions
	if (i + 3 > t.size()) return false;
	crl.issuer = t[i + 1];
	if (!asn1TimeToFiletime(t[i + 2], crl.thisUpdate)) return false;
	i += 3;
	if (i < t.size() && (t[i].tag == 0x17 || t[i].tag == 0x18)) ++i;   // nextUpdate
	if (i >= t.size() || t[i].tag != 0x30) return true;       // no revoked certificate
	for (const Tlv& entry : children(t[i])) {
		const std::vector<Tlv> f = children(entry);
		uint64_t date = 0;
		if (f.size() < 2 || f[0].tag != 0x02 || !asn1TimeToFiletime(f[1], date)) return false;
		int reason = -1;
		if (f.size() >= 3)
			for (const Tlv& extension : children(f[2])) {
				const std::vector<Tlv> x = children(extension);
				Tlv code;
				if (x.size() >= 2 && IS_OID(x[0], OID_CRL_REASON) && x.back().tag == 0x04
				    && readTlv(x.back().val, x.back().len, code) && code.tag == 0x0A && code.len == 1)
					reason = code.val[0];
			}
		crl.revoked[std::string((const char*)f[0].val, f[0].len)] = { date, reason };
	}
	return true;
}

/*! The addresses a certificate gives for its revocation list (CRL
 *  Distribution Points, full names, URIs). */
std::vector<std::string> crlAddressesOf(const Certificate& c) {
	std::vector<std::string> urls;
	Tlv points;
	if (!extensionOf(c, OID_CRL_DISTRIBUTION_POINTS, sizeof(OID_CRL_DISTRIBUTION_POINTS), points)) return urls;
	for (const Tlv& point : children(points)) {
		const std::vector<Tlv> p = children(point);
		if (p.empty() || p[0].tag != 0xA0) continue;            // [0] distributionPoint
		const std::vector<Tlv> name = children(p[0]);
		if (name.empty() || name[0].tag != 0xA0) continue;      // [0] fullName
		for (const Tlv& general : children(name[0]))
			if (general.tag == 0x86) urls.emplace_back((const char*)general.val, general.len);   // [6] URI
	}
	return urls;
}

} // namespace

//! The roots of the set, parsed once; the other lists as given.
struct ThirdPartyRoots::Impl {
	const TrustList& roots;
	const TrustList& disallowed;
	const std::set<std::wstring>& revoked;
	uint64_t now;                                    //!< the collection's time, for a signature without time stamp
	const RevocationLists& revocation;
	std::vector<SetRoot> parsed;
	std::vector<ParsedCrl> crls;                     //!< every CRL of the set that reads
	std::vector<std::vector<uint8_t>> decodedPem;    //!< CRLs served as PEM, decoded: what `crls` points into
	std::map<std::string, size_t> crlByUrl;
	//! A CRL's signature checked against an issuer, by (CRL, SHA-256 of the issuer): shared by the threads, hence locked.
	mutable std::mutex verifiedMutex;
	mutable std::map<std::pair<size_t, std::wstring>, bool> verified;

	//! Whether the CRL `k` is signed by `issuer`, checked once per pair.
	bool crlSignedBy(size_t k, const Certificate& issuer) const {
		const std::pair<size_t, std::wstring> key{ k, certificateSha256(issuer) };
		{
			std::lock_guard<std::mutex> lock(verifiedMutex);
			const auto found = verified.find(key);
			if (found != verified.end()) return found->second;
		}
		const ParsedCrl& crl = crls[k];
		bool ok = false;
		if (issuer.rsa && crl.algo != DigestAlgorithm::Unknown && sameBytes(crl.issuer, issuer.subject)) {
			uint8_t h[64];
			const size_t lh = fingerprint(crl.algo, crl.tbs.start, crl.tbs.total, h);
			ok = RsaVerifyPkcs1(issuer.module.val, issuer.module.len, issuer.exponent.val, issuer.exponent.len,
			                    crl.signature, crl.signatureSize, crl.algo, h, lh);
		}
		std::lock_guard<std::mutex> lock(verifiedMutex);
		verified[key] = ok;
		return ok;
	}

	/*! The revocation of `c`, issued by `issuer`, by the CRL it names — or,
	 *  naming none the set holds, the full CRL of its issuer per the CCADB —,
	 *  that CRL signed by the issuer. Revoked for a compromise, or without a
	 *  reason given: refused whatever the time — a compromised key signs
	 *  anything, at any date. Revoked for another reason: refused unless a
	 *  verified time stamp puts the signature before the revocation.
	 *  @param oldest receives the issue date of the CRL used, if older
	 *  @param missing receives the addresses `c` names, when none of its CRLs is in the set
	 *  @return why the chain must be refused, or "" */
	std::string revocationOf(const Certificate& c, const Certificate& issuer, const TimeStamp& stamp, uint64_t& oldest,
	                         std::vector<std::string>& missing) const {
		std::vector<std::string> urls;
		for (const std::string& url : crlAddressesOf(c))
			if (crlByUrl.count(url)) urls.push_back(url);
		if (urls.empty()) {
			const auto full = revocation.byAuthority.find(certificateSha256(issuer));
			if (full != revocation.byAuthority.end()) urls = full->second;
		}
		bool checked = false;
		for (const std::string& url : urls) {
			const auto k = crlByUrl.find(url);
			if (k == crlByUrl.end() || !crlSignedBy(k->second, issuer)) continue;
			checked = true;
			const ParsedCrl& crl = crls[k->second];
			if (!oldest || crl.thisUpdate < oldest) oldest = crl.thisUpdate;
			const auto entry = crl.revoked.find(std::string((const char*)c.serial.val, c.serial.len));
			if (entry == crl.revoked.end()) continue;
			const auto [date, reason] = entry->second;
			const bool compromise = reason < 0 || reason == REASON_UNSPECIFIED || reason == REASON_KEY_COMPROMISE
			                     || reason == REASON_CA_COMPROMISE || reason == REASON_AA_COMPROMISE;
			if (compromise) return "certificate revoked (compromise, or no reason given): " + narrowName(c);
			if (!stamp.verified || stamp.at >= date) return "certificate revoked before the signing time: " + narrowName(c);
		}
		if (!checked) {
			const std::vector<std::string> named = crlAddressesOf(c);
			missing.insert(missing.end(), named.begin(), named.end());
			return "revocation not verifiable, no signed revocation list: " + narrowName(c)
			     + (named.empty() ? std::string(" (names none)") : " (" + named[0] + ")");
		}
		return std::string();
	}

	/*! A certificate of the chain that must stop it: disallowed by Microsoft,
	 *  or an authority the CCADB says revoked.
	 *  @return why, or "" if none */
	std::string distrusted(const Certificate& c) const {
		if (FindInTrustList(disallowed, c.integer.start, c.integer.total))
			return "certificate disallowed by Microsoft: " + narrowName(c);
		if (revoked.count(certificateSha256(c))) return "authority revoked (CCADB): " + narrowName(c);
		return std::string();
	}
	/*! The root of the set that `c` is, or is issued by.
	 *  @return it, or nullptr */
	const SetRoot* rootOf(const Certificate& c) const {
		for (const SetRoot& root : parsed) {
			if (sameBytes(c.integer, root.first.integer)) return &root;        // the root itself, in the signature
			if (sameBytes(c.issuer, root.first.subject) && signedBy(c, root.first)) return &root;
		}
		return nullptr;
	}

	/*! From a signer up to a root of the set, for a use: each certificate
	 *  signed by the next, each issuer an authority, the signer allowing the
	 *  use, the root trusted by Microsoft for it, no certificate disallowed or
	 *  revoked. Neither dates nor the root's distrust: they depend on the
	 *  time the signature was made, see verify. */
	Chain build(const std::vector<Certificate>& pool, size_t signerIndex, const Use& use) const {
		Chain chain;
		if (signerIndex >= pool.size()) { chain.reason = "signer certificate absent"; return chain; }
		const Certificate* current = &pool[signerIndex];
		if (!allowsUse(*current, use.oid, use.oidSize)) { chain.reason = std::string("signer certificate not for ") + use.name; return chain; }
		const size_t MAX_DEPTH = 8;
		for (size_t depth = 0; depth < MAX_DEPTH; ++depth) {
			if (const std::string why = distrusted(*current); !why.empty()) { chain.reason = why; return chain; }
			if (const SetRoot* root = rootOf(*current)) {
				if (const std::string why = distrusted(root->first); !why.empty()) { chain.reason = why; return chain; }
				if (root->second->*use.excluded) { chain.reason = std::string("root not trusted by Microsoft for ") + use.name; return chain; }
				if (!sameBytes(current->integer, root->first.integer)) chain.certificates.push_back(current);
				chain.root = root;
				return chain;
			}
			chain.certificates.push_back(current);
			const Certificate* next = nullptr;
			bool issuerNotRsa = false;
			for (const Certificate& c : pool) {
				if (&c == current || !sameBytes(current->issuer, c.subject)) continue;
				issuerNotRsa |= !c.rsa;
				if (signedBy(*current, c)) { next = &c; break; }
			}
			for (const SetRoot& root : parsed) issuerNotRsa |= sameBytes(current->issuer, root.first.subject) && !root.first.rsa;
			if (!next) {
				// WAC verifies RSA signatures only: another algorithm is not a forgery, but not a proof either.
				if (issuerNotRsa) chain.reason = "issuer key not RSA: chain not verified";
				else if (current->algoSignature == DigestAlgorithm::Unknown) chain.reason = "certificate signed by an algorithm not verified";
				else chain.reason = "chain not tied to a root of the trust set";
				return chain;
			}
			if (!isAuthority(*next)) { chain.reason = "issuer not an authority: " + narrowName(*next); return chain; }
			current = next;
		}
		chain.reason = "chain longer than " + std::to_string(MAX_DEPTH) + " certificates";
		return chain;
	}

	/*! The time-dependent rules of a chain, at `at`: every certificate within
	 *  its validity, the root not distrusted — or distrusted only after a
	 *  date, and `at` a verified time stamp before it.
	 *  @return why not, or "" */
	static std::string holdsAt(const Chain& chain, uint64_t at, bool stamped, const char* when) {
		for (const Certificate* c : chain.certificates)
			if (!c->notBefore || at < c->notBefore || at > c->notAfter)
				return "certificate not valid at the " + std::string(when) + ": " + narrowName(*c);
		const TrustListEntry& root = *chain.root->second;
		if (root.distrusted && !(root.distrustedAfter && stamped && at < root.distrustedAfter)) {
			if (!root.distrustedAfter) return "root distrusted by Microsoft, no date given";
			return stamped ? "root distrusted by Microsoft before the signing time" : "root distrusted by Microsoft";
		}
		return std::string();
	}

	/*! The time stamp of a signature, RFC 3161 or counter-signature: its
	 *  signature over the signer's, and its authority's chain, for time
	 *  stamping, valid at the time it gives. */
	TimeStamp timeStampOf(const VerifiedSignature& signature, const std::vector<Certificate>& pool) const {
		TimeStamp stamp;
		Tlv unsignedAttributes;
		if (!signature.unsignedAttributes || !readTlv(signature.unsignedAttributes, signature.unsignedAttributesSize, unsignedAttributes))
			return stamp;
		for (const Tlv& attribute : children(unsignedAttributes)) {
			const std::vector<Tlv> av = children(attribute);
			if (av.size() < 2 || av[0].tag != 0x06) continue;
			const std::vector<Tlv> values = children(av[1]);
			if (values.empty()) continue;
			if (IS_OID(av[0], OID_RFC3161_TIME_STAMP)) stamp = rfc3161(signature, values[0]);
			else if (IS_OID(av[0], OID_COUNTER_SIGNATURE)) stamp = counterSignature(signature, values[0], pool);
			else continue;
			if (stamp.verified) return stamp;
		}
		return stamp;
	}

	//! An RFC 3161 token: a SignedData of a TSTInfo, whose imprint is the digest of the signer's signature.
	TimeStamp rfc3161(const VerifiedSignature& signature, const Tlv& token) const {
		TimeStamp stamp;
		stamp.present = true;
		const VerifiedSignature t = VerifyPkcs7(token.start, token.total);
		if (!t.intact) { stamp.reason = "time stamp token: " + t.reason; return stamp; }
		if (t.contentOid != std::string((const char*)OID_TST_INFO, sizeof(OID_TST_INFO))) { stamp.reason = "time stamp token without TSTInfo"; return stamp; }
		Tlv info;
		std::vector<Tlv> fields;
		if (readTlv(t.content, t.contentSize, info)) fields = children(info);
		// version, policy, messageImprint, serialNumber, genTime, ...
		if (fields.size() < 5) { stamp.reason = "TSTInfo incomplete"; return stamp; }
		const std::vector<Tlv> imprint = children(fields[2]);
		const DigestAlgorithm algo = imprint.size() == 2 ? algoDe(imprint[0]) : DigestAlgorithm::Unknown;
		uint8_t h[64];
		const size_t lh = fingerprint(algo, signature.signatureValue, signature.signatureValueSize, h);
		if (!lh || imprint[1].tag != 0x04 || imprint[1].len != lh || std::memcmp(imprint[1].val, h, lh) != 0) {
			stamp.reason = "time stamp not over this signature";
			return stamp;
		}
		if (!asn1TimeToFiletime(fields[4], stamp.at)) { stamp.reason = "time stamp without a readable time"; return stamp; }
		return authorityHolds(parsePool(t.certificates), t.signerIndex, stamp);
	}

	//! A counter-signature: a SignerInfo whose content is the signer's signature, dated by its signingTime.
	TimeStamp counterSignature(const VerifiedSignature& signature, const Tlv& signerInfo, const std::vector<Certificate>& pool) const {
		TimeStamp stamp;
		stamp.present = true;
		SignerInfoCheck check;
		// Old VeriSign and Symantec services signed the bare digest: accepted here, and here only.
		stamp.reason = checkSignerInfo(signerInfo, signature.signatureValue, signature.signatureValueSize, pool, check,
		                               DigestEncoding::DigestInfoOrBare);
		if (!stamp.reason.empty()) { stamp.reason = "counter-signature: " + stamp.reason; return stamp; }
		bool dated = false;
		for (const Tlv& a : children(check.attributes)) {
			const std::vector<Tlv> av = children(a);
			if (av.size() < 2 || !IS_OID(av[0], OID_SIGNING_TIME)) continue;
			const std::vector<Tlv> vals = children(av[1]);
			dated = !vals.empty() && asn1TimeToFiletime(vals[0], stamp.at);
		}
		if (!dated) { stamp.reason = "counter-signature without a readable signing time"; return stamp; }
		return authorityHolds(pool, check.signerIndex, stamp);
	}

	//! The authority of a time stamp: its chain for time stamping, holding at the time it gives.
	TimeStamp authorityHolds(const std::vector<Certificate>& pool, size_t signerIndex, TimeStamp stamp) const {
		const Chain chain = build(pool, signerIndex, TIME_STAMPING_USE);
		if (!chain.reason.empty()) { stamp.reason = "time stamping authority: " + chain.reason; return stamp; }
		if (const std::string why = holdsAt(chain, stamp.at, true, "time stamp"); !why.empty()) {
			stamp.reason = "time stamping authority: " + why;
			return stamp;
		}
		stamp.authority = attributeNameField(pool[signerIndex].subject, OID_CN, sizeof(OID_CN));
		stamp.verified = true;
		return stamp;
	}
};

ThirdPartyRoots::ThirdPartyRoots(const TrustList& roots, const std::map<std::string, std::vector<uint8_t>>& certificates,
                                 const TrustList& disallowed, const std::set<std::wstring>& revokedAuthorities,
                                 const RevocationLists& revocation, uint64_t now)
	: impl_(new Impl{ roots, disallowed, revokedAuthorities, now, revocation, {}, {}, {}, {}, {}, {} }) {
	static const char PEM[] = "-----BEGIN";
	impl_->decodedPem.reserve(revocation.byUrl.size());      // `crls` points into it: no reallocation
	for (const auto& [url, bytes] : revocation.byUrl) {
		const uint8_t* data = bytes.data();
		size_t size = bytes.size();
		if (size > sizeof(PEM) && std::memcmp(data, PEM, sizeof(PEM) - 1) == 0) {
			const std::string text(bytes.begin(), bytes.end());
			const size_t begin = text.find('\n'), end = text.find("-----END");
			if (begin == std::string::npos || end == std::string::npos || end < begin) continue;
			impl_->decodedPem.push_back(DecodeBase64(text.substr(begin, end - begin)));
			data = impl_->decodedPem.back().data();
			size = impl_->decodedPem.back().size();
		}
		ParsedCrl crl;
		if (!parseCrl(data, size, crl)) continue;
		crl.url = url;
		impl_->crlByUrl[url] = impl_->crls.size();
		impl_->crls.push_back(std::move(crl));
	}
	for (const auto& [sha1, der] : certificates) {
		Tlv t;
		Certificate c;
		const TrustListEntry* entry = FindInTrustList(roots, der.data(), der.size());
		if (entry && readTlv(der.data(), der.size(), t) && analyseCertificate(t, c)) impl_->parsed.push_back({ c, entry });
	}
}

ThirdPartyRoots::~ThirdPartyRoots() = default;

ChainVerdict ThirdPartyRoots::verify(const VerifiedSignature& signature) const {
	ChainVerdict v;
	if (!signature.intact) { v.reason = "signature not intact"; return v; }
	const std::vector<Certificate> pool = parsePool(signature.certificates);
	const Chain chain = impl_->build(pool, signature.signerIndex, CODE_SIGNING_USE);
	if (!chain.reason.empty()) { v.reason = chain.reason; return v; }
	/* THE TIME THE CHAIN IS JUDGED AT. Time-stamped by an authority that
	   holds: the signing time — a certificate expired since, a root
	   distrusted since, do not undo a signature made before. Otherwise: the
	   collection's time, as Windows judges a signature without time stamp. A
	   time stamp that does not hold is not ignored: it is refused. */
	const TimeStamp stamp = impl_->timeStampOf(signature, pool);
	if (stamp.present && !stamp.verified) { v.reason = stamp.reason; return v; }
	const uint64_t at = stamp.verified ? stamp.at : impl_->now;
	if (const std::string why = Impl::holdsAt(chain, at, stamp.verified, stamp.verified ? "signing time" : "collection time");
	    !why.empty()) {
		v.reason = why;
		return v;
	}
	// Revocation: each certificate below the root, by its issuer's signed CRL.
	uint64_t oldest = 0;
	for (size_t k = 0; k < chain.certificates.size(); ++k) {
		const Certificate& issuer = k + 1 < chain.certificates.size() ? *chain.certificates[k + 1] : chain.root->first;
		if (const std::string why = impl_->revocationOf(*chain.certificates[k], issuer, stamp, oldest, v.missingCrls);
		    !why.empty()) {
			v.reason = why;
			return v;
		}
	}
	v.revocationListsIssued = oldest;
	// For the lists of vulnerable drivers: the signed part of each certificate, by both digests the blocklist uses.
	std::vector<const Certificate*> all = chain.certificates;
	all.push_back(&chain.root->first);
	for (const Certificate* c : all) {
		uint8_t h1[20], h2[32];
		sha1Bytes(c->tbs.start, c->tbs.total, h1);
		sha256Bytes(c->tbs.start, c->tbs.total, h2);
		v.tbsHashes.push_back(toHexadecimal(h1, sizeof(h1)));
		v.tbsHashes.push_back(toHexadecimal(h2, sizeof(h2)));
	}
	if (!chain.certificates.empty()) v.signerName = attributeNameField(chain.certificates[0]->subject, OID_CN, sizeof(OID_CN));
	v.trusted = true;
	v.root = attributeNameField(chain.root->first.subject, OID_CN, sizeof(OID_CN));
	if (stamp.verified) {
		v.signedAt = stamp.at;
		v.timeStampAuthority = stamp.authority;
	}
	return v;
}

// ============================================================ catalogues

namespace {

/*! Digest carried by a SpcIndirectDataContent: SEQUENCE { data,
 *  messageDigest DigestInfo SEQUENCE { AlgorithmIdentifier, OCTET STRING } }.
 *  @param anyLength false: a SHA-1 or SHA-256 digest only (a file's); true:
 *         any length (the "APPX" digest of a package, a sequence of records) */
bool indirectDigest(const Tlv& spc, std::string& output, bool anyLength = false) {
	const std::vector<Tlv> e = children(spc);
	if (e.size() < 2) return false;
	const std::vector<Tlv> di = children(e[1]);
	if (di.size() < 2 || di[1].tag != 0x04) return false;
	if (!anyLength && di[1].len != 20 && di[1].len != 32) return false;
	output.assign((const char*)di[1].val, di[1].len);
	return true;
}

} // namespace

bool IndexCatalogues::add(const std::wstring& name, const uint8_t* bytes, size_t size) {
	const VerifiedSignature s = VerifyPkcs7(bytes, size);
	if (!s.valid || !s.signerAccepted
	    || s.contentOid != std::string((const char*)OID_CTL, sizeof(OID_CTL))) {
		++rejected_;
		return false;
	}
	// CertificateTrustList: look for the list of subjects — a SEQUENCE whose
	// elements are SEQUENCE { OCTET STRING, SET }.
	Tlv ctl;
	ctl.tag = 0x30; ctl.val = s.content; ctl.len = s.contentSize;
	const uint32_t rank = (uint32_t)names_.size();
	size_t indexed = 0;
	for (const Tlv& champ : children(ctl)) {
		if (champ.tag != 0x30) continue;
		for (const Tlv& subject : children(champ)) {
			const std::vector<Tlv> se = children(subject);
			if (se.size() < 2 || se[0].tag != 0x04 || se[1].tag != 0x31) continue;
			for (const Tlv& attribute : children(se[1])) {
				const std::vector<Tlv> av = children(attribute);
				if (av.size() < 2 || !IS_OID(av[0], OID_SPC_INDIRECT)) continue;
				for (const Tlv& v : children(av[1])) {
					std::string h;
					if (indirectDigest(v, h)) { index_.emplace(h, rank); ++indexed; }
				}
			}
		}
	}
	if (indexed == 0) { ++rejected_; return false; }
	names_.push_back(name);
	return true;
}

void IndexCatalogues::dump(std::ostream& o) const {
	static const char* hx = "0123456789abcdef";
	for (const auto& e : index_) {
		std::string h;
		for (unsigned char b : e.first) { h += hx[b >> 4]; h += hx[b & 15]; }
		o << h << "\n";
	}
}

const std::wstring* IndexCatalogues::find(const uint8_t* e, size_t n) const {
	const auto it = index_.find(std::string((const char*)e, n));
	return it == index_.end() ? nullptr : &names_[it->second];
}

// ============================================================ PE en stream

namespace {
inline uint16_t lu16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t lu32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
const size_t HEAD = 64 * 1024;                  // headers expected within the first 64 KiB
const size_t MAX_CERTIFICATES = 4 * 1024 * 1024; // certificate table: 4 MiB at most
}

int PeAnalyser::overflow(int c) {
	if (c != traits_type::eof()) { const uint8_t o = (uint8_t)c; receive(&o, 1); }
	return traits_type::not_eof(c);
}

std::streamsize PeAnalyser::xsputn(const char* s, std::streamsize n) {
	receive(reinterpret_cast<const uint8_t*>(s), (size_t)n);
	return n;
}

void PeAnalyser::receive(const uint8_t* p, size_t n) {
	if (finished_ || n == 0) return;
	if (!decide_) {
		const size_t take = std::min(n, HEAD - head_.size());
		head_.insert(head_.end(), p, p + take);
		p += take; n -= take;
		if (head_.size() < HEAD) return;
		decide_ = true;
		isPe_ = analyseHeaders();
		if (isPe_) process(head_.data(), head_.size());
		head_.clear(); head_.shrink_to_fit();
	}
	if (isPe_ && n) process(p, n);
}

bool PeAnalyser::analyseHeaders() {
	const uint8_t* t = head_.data();
	const size_t n = head_.size();
	if (n < 0x40 || t[0] != 'M' || t[1] != 'Z') return false;
	const uint32_t pe = lu32(t + 0x3C);
	if (pe > n - 24 || std::memcmp(t + pe, "PE\0\0", 4) != 0) return false;
	const uint32_t opt = pe + 24;
	const uint16_t optionalHeaderSize = lu16(t + pe + 20);
	if (opt + optionalHeaderSize > n || optionalHeaderSize < 2) return false;
	const uint16_t magic = lu16(t + opt);
	size_t directories;
	if (magic == 0x10B) directories = opt + 96;         // PE32
	else if (magic == 0x20B) directories = opt + 112;   // PE32+
	else return false;
	if (directories > opt + optionalHeaderSize) return false;
	timeDateStamp_ = lu32(t + pe + 8);                  // COFF header
	sizeOfImage_ = lu32(t + opt + 56);                 // same offset in PE32 and PE32+
	const uint32_t nbRep = lu32(t + directories - 4);   // NumberOfRvaAndSizes
	checksum_ = opt + 64;
	certEntry_ = directories + 4 * 8;                  // entry 4: certificate table
	if (nbRep <= 4 || certEntry_ + 8 > opt + optionalHeaderSize) { certEntry_ = 0; return true; }
	certStart_ = lu32(t + certEntry_);                 // position in the FILE
	finCert_ = certStart_ + lu32(t + certEntry_ + 4);
	if (finCert_ == certStart_) certStart_ = finCert_ = 0;
	return true;
}

void PeAnalyser::process(const uint8_t* p, size_t n) {
	// Splits [position_, position_ + n) along the three excluded ranges.
	while (n) {
		const uint64_t pos = position_;
		uint64_t until = pos + n;
		bool excluded = false;
		auto area = [&](uint64_t start, uint64_t end) {
			if (end <= start) return;
			if (pos >= start && pos < end) { excluded = true; until = std::min(until, end); }
			else if (pos < start) until = std::min(until, start);
		};
		area(checksum_, checksum_ + 4);
		if (certEntry_) area(certEntry_, certEntry_ + 8);
		const bool inCert = certStart_ && pos >= certStart_ && pos < finCert_;
		area(certStart_, finCert_);
		const size_t m = (size_t)(until - pos);
		if (!excluded) { h1_.update(p, m); h256_.update(p, m); }
		else if (inCert && certificates_.size() + m <= MAX_CERTIFICATES)
			certificates_.insert(certificates_.end(), p, p + m);
		p += m; n -= m; position_ += m;
	}
}

void PeAnalyser::finish() {
	if (finished_) return;
	if (!decide_) {                                     // file smaller than 64 KiB
		decide_ = true;
		isPe_ = analyseHeaders();
		if (isPe_) process(head_.data(), head_.size());
		head_.clear();
	}
	finished_ = true;
	if (!isPe_) return;
	// Two variants: as is, and padded with zeros to a multiple of 8
	// (the rule of some implementations for an unsigned file).
	Sha1Stream c1 = h1_;
	Sha256Stream c256 = h256_;
	const uint64_t hashed = position_ - (finCert_ - certStart_);
	static const uint8_t zeros[8] = { 0 };
	const size_t complement = (size_t)((8 - (hashed % 8)) % 8);
	c1.update(zeros, complement);
	c256.update(zeros, complement);
	h1_.digest(sha1_);
	h256_.digest(sha256_);
	c1.digest(sha1c_);
	c256.digest(sha256c_);
}

// ============================================================ verdict

VerdictMicrosoft EvaluatePe(const PeAnalyser& pe, const IndexCatalogues& catalogues, const ThirdPartyRoots* thirdParty) {
	VerdictMicrosoft v;
	if (!pe.isPe()) { v.reason = "not a PE"; return v; }

	// 1. Catalogs: is the digest, in one of its forms, listed there?
	for (const auto& e : { std::make_pair(pe.sha256(), 32), std::make_pair(pe.sha1(), 20),
	                       std::make_pair(pe.sha256Complete(), 32), std::make_pair(pe.sha1Complete(), 20) }) {
		if (const std::wstring* cat = catalogues.find(e.first, (size_t)e.second)) {
			v.microsoft = true;
			v.source = L"catalog " + *cat;
			v.catalog = *cat;
			return v;
		}
	}

	// 2. Embedded signature: WIN_CERTIFICATE { dwLength, wRevision, wCertificateType, bCertificate }.
	const std::vector<uint8_t>& t = pe.certificateTable();
	if (t.size() < 8) { v.reason = "not signed (neither catalog nor embedded signature)"; return v; }
	const uint32_t length = lu32(t.data());
	const uint16_t type = lu16(t.data() + 6);
	if (type != 0x0002 || length < 8 || length > t.size()) { v.reason = "unexpected certificate table"; return v; }
	const VerifiedSignature s = VerifyPkcs7(t.data() + 8, length - 8);
	/* Whoever signed, and whether the file is as signed: recorded for every
	   signed binary, a third party's included — for the analyst, not for the
	   decision, which only a Microsoft chain settles. */
	v.signer = s.signer;
	v.signerOrganization = s.signerOrganization;
	if (s.intact && s.contentOid == std::string((const char*)OID_SPC_INDIRECT, sizeof(OID_SPC_INDIRECT))) {
		Tlv signedContent;
		signedContent.tag = 0x30; signedContent.val = s.content; signedContent.len = s.contentSize;
		std::string digest;
		v.signatureIntact = indirectDigest(signedContent, digest)
			&& ((digest.size() == 32 && std::memcmp(digest.data(), pe.sha256(), 32) == 0)
			 || (digest.size() == 20 && std::memcmp(digest.data(), pe.sha1(), 20) == 0));
	}
	// A third-party signature, the file as signed: its chain, against the trust set.
	if (thirdParty && v.signatureIntact && !(s.valid && s.signerAccepted)) {
		const ChainVerdict chain = thirdParty->verify(s);
		v.chainChecked = true;
		v.chainTrusted = chain.trusted;
		v.chainRoot = chain.root;
		v.chainReason = chain.reason;
		v.chainSignedAt = chain.signedAt;
		v.chainTimeStampAuthority = chain.timeStampAuthority;
		v.chainRevocationListsIssued = chain.revocationListsIssued;
		v.chainMissingCrls = chain.missingCrls;
		v.chainTbsHashes = chain.tbsHashes;
		v.chainSignerName = chain.signerName;
		v.signerProgramName = s.programName;
	}
	if (!s.valid) { v.reason = s.reason; return v; }
	if (s.contentOid != std::string((const char*)OID_SPC_INDIRECT, sizeof(OID_SPC_INDIRECT))) {
		v.reason = "unexpected signed content"; return v;
	}
	// The signed content carries the file's Authenticode digest: it must be the
	// one computed here, otherwise the signature is authentic but covers ANOTHER
	// file.
	Tlv spc;
	spc.tag = 0x30; spc.val = s.content; spc.len = s.contentSize;
	std::string declared;
	if (!indirectDigest(spc, declared)) { v.reason = "signed digest unreadable"; return v; }
	const bool wellFormed =
		(declared.size() == 32 && std::memcmp(declared.data(), pe.sha256(), 32) == 0)
	 || (declared.size() == 20 && std::memcmp(declared.data(), pe.sha1(), 20) == 0);
	if (!wellFormed) { v.reason = "file modified since it was signed"; return v; }
	if (!s.signerAccepted) { v.reason = "signer not accepted: " + std::string(s.signer.begin(), s.signer.end()); return v; }
	v.microsoft = true;
	v.source = L"embedded signature";
	return v;
}

// ============================================================ scripts

VerdictMicrosoft EvaluateByCatalog(const uint8_t sha256[32], const IndexCatalogues& catalogues) {
	VerdictMicrosoft v;
	if (const std::wstring* cat = catalogues.find(sha256, 32)) {
		v.microsoft = true;
		v.source = L"catalog " + *cat;
		v.catalog = *cat;
	}
	else v.reason = "absent from the catalogs";
	return v;
}

namespace {

/*! Script text as code points: UTF-8 or UTF-16LE BOM, otherwise UTF-8 if
 *  valid, otherwise Windows-1252 (approximated by Latin-1). A decoding error
 *  only yields a different digest — the file is then collected. */
std::u32string decodeText(const uint8_t* p, size_t n) {
	std::u32string t;
	if (n >= 2 && p[0] == 0xFF && p[1] == 0xFE) {
		for (size_t i = 2; i + 1 < n; i += 2) {
			uint32_t c = p[i] | (p[i + 1] << 8);
			if (c >= 0xD800 && c < 0xDC00 && i + 3 < n) {
				const uint32_t d = p[i + 2] | (p[i + 3] << 8);
				if (d >= 0xDC00 && d < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00); i += 2; }
			}
			t += (char32_t)c;
		}
		return t;
	}
	size_t i = (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) ? 3 : 0;
	const size_t start = i;
	bool valid = true;
	while (i < n && valid) {
		const uint8_t b = p[i];
		size_t k = b < 0x80 ? 0 : (b & 0xE0) == 0xC0 ? 1 : (b & 0xF0) == 0xE0 ? 2 : (b & 0xF8) == 0xF0 ? 3 : 9;
		if (k == 9 || i + k >= n) { valid = false; break; }
		uint32_t c = k == 0 ? b : k == 1 ? (b & 0x1F) : k == 2 ? (b & 0x0F) : (b & 0x07);
		for (size_t j = 1; j <= k; ++j) {
			if (i + j >= n || (p[i + j] & 0xC0) != 0x80) { valid = false; break; }
			c = (c << 6) | (p[i + j] & 0x3F);
		}
		if (!valid) break;
		t += (char32_t)c;
		i += k + 1;
	}
	if (valid) return t;
	t.clear();
	for (i = start; i < n; ++i) t += (char32_t)p[i];
	return t;
}

std::vector<uint8_t> enUtf16(const std::u32string& t, size_t end) {
	std::vector<uint8_t> r;
	r.reserve(end * 2);
	for (size_t i = 0; i < end; ++i) {
		uint32_t c = t[i];
		if (c >= 0x10000) {
			c -= 0x10000;
			const uint32_t h = 0xD800 + (c >> 10), l = 0xDC00 + (c & 0x3FF);
			r.push_back((uint8_t)h); r.push_back((uint8_t)(h >> 8));
			r.push_back((uint8_t)l); r.push_back((uint8_t)(l >> 8));
		}
		else { r.push_back((uint8_t)c); r.push_back((uint8_t)(c >> 8)); }
	}
	return r;
}

size_t findText(const std::u32string& t, const char* reason, size_t since = 0) {
	std::u32string m;
	for (const char* q = reason; *q; ++q) m += (char32_t)(unsigned char)*q;
	return t.find(m, since);
}

int base64Value(char32_t c) {
	if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
	if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
	if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

} // namespace

TrustList ReadTrustList(const uint8_t* bytes, size_t size) {
	TrustList list;
	const VerifiedSignature s = VerifyPkcs7(bytes, size);
	if (!s.valid) { list.reason = s.reason; return list; }
	if (s.signer != L"Microsoft Certificate Trust List Publisher" || s.signerOrganization != L"Microsoft Corporation") {
		list.reason = "not signed by Microsoft's trust list publisher";
		return list;
	}
	if (s.contentOid != std::string((const char*)OID_CTL, sizeof(OID_CTL))) { list.reason = "not a trust list"; return list; }
	// Properties of a listed certificate: 1.3.6.1.4.1.311.10.11.<id>.
	static const uint8_t PROPERTY[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0A, 0x0B };
	static const uint8_t CODE_SIGNING[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03 };
	static const uint8_t TIME_STAMPING[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08 };
	// Whether a list of uses — a SEQUENCE OF OID, in an OCTET STRING — holds `use`.
	auto listsUse = [&](const Tlv& value, const uint8_t* use, size_t useSize) {
		Tlv sequence;
		if (value.tag != 0x04 || !readTlv(value.val, value.len, sequence)) return false;
		for (const Tlv& oid : children(sequence))
			if (oid.tag == 0x06 && oid.len == useSize && std::memcmp(oid.val, use, useSize) == 0)
				return true;
		return false;
	};
	Tlv ctl;
	ctl.tag = 0x30; ctl.val = s.content; ctl.len = s.contentSize;
	for (const Tlv& field : children(ctl)) {
		if (field.tag == 0x17 && list.thisUpdate == 0) {   // thisUpdate, the first time of the list
			asn1TimeToFiletime(field, list.thisUpdate);
			continue;
		}
		if (field.tag != 0x30) continue;
		const std::vector<Tlv> parts = children(field);
		// The subject algorithm: SEQUENCE { OID 1.3.6.1.4.1.311.10.11.<id> [, NULL] }.
		// authroot.stl names it by the SHA-1 OID, disallowedcert.stl by the property.
		if (!parts.empty() && parts[0].tag == 0x06) {
			if (parts[0].len == sizeof(PROPERTY) + 1 && std::memcmp(parts[0].val, PROPERTY, sizeof(PROPERTY)) == 0)
				list.identifier = parts[0].val[sizeof(PROPERTY)];
			else if (IS_OID(parts[0], OID_SHA1)) list.identifier = 3;
			continue;
		}
		// The sizes each kind of list holds (see TrustList::identifier); any other is skipped.
		auto sizeExpected = [&](size_t size) {
			return list.identifier == 3 ? size == 20 : list.identifier == 15 && (size == 16 || size == 48);
		};
		for (const Tlv& subject : parts) {
			const std::vector<Tlv> se = children(subject);
			if (se.size() < 1 || se[0].tag != 0x04 || !sizeExpected(se[0].len)) continue;
			TrustListEntry entry;
			entry.identifier.assign((const char*)se[0].val, se[0].len);
			if (se.size() >= 2 && se[1].tag == 0x31)
				for (const Tlv& attribute : children(se[1])) {
					const std::vector<Tlv> av = children(attribute);
					if (av.size() < 2 || av[0].tag != 0x06 || av[0].len != sizeof(PROPERTY) + 1
					    || std::memcmp(av[0].val, PROPERTY, sizeof(PROPERTY)) != 0) continue;
					const uint8_t id = av[0].val[sizeof(PROPERTY)];
					const std::vector<Tlv> values = children(av[1]);
					if (values.empty()) continue;
					// 9: the uses the root is trusted for; 122: the uses it is NOT trusted for.
					if (id == 9) {
						entry.codeSigningExcluded |= !listsUse(values[0], CODE_SIGNING, sizeof(CODE_SIGNING));
						entry.timeStampingExcluded |= !listsUse(values[0], TIME_STAMPING, sizeof(TIME_STAMPING));
					}
					if (id == 122) {
						entry.codeSigningExcluded |= listsUse(values[0], CODE_SIGNING, sizeof(CODE_SIGNING));
						entry.timeStampingExcluded |= listsUse(values[0], TIME_STAMPING, sizeof(TIME_STAMPING));
					}
					if (id == 104) entry.distrusted = true;
					if (id == 104 && values[0].tag == 0x04 && values[0].len == 8) {
						uint64_t filetime = 0;
						for (int k = 7; k >= 0; --k) filetime = (filetime << 8) | values[0].val[k];
						entry.distrustedAfter = filetime;
					}
				}
			list.entries.push_back(std::move(entry));
		}
	}
	if (list.entries.empty()) { list.reason = "trust list without entries"; return list; }
	list.valid = true;
	return list;
}

const TrustListEntry* FindInTrustList(const TrustList& list, const uint8_t* certificate, size_t size) {
	Tlv whole;
	if (!certificate || !readTlv(certificate, size, whole) || whole.tag != 0x30) return nullptr;
	std::vector<std::string> identifiers;
	if (list.identifier == 3) {
		uint8_t sha1[20];
		sha1Bytes(whole.start, whole.total, sha1);
		identifiers.emplace_back((const char*)sha1, sizeof(sha1));
	}
	else if (list.identifier == 15) {
		const std::vector<Tlv> e = children(whole);
		if (e.empty() || e[0].tag != 0x30) return nullptr;
		uint8_t sha384[48];
		sha384Bytes(e[0].start, e[0].total, sha384);           // of the TBSCertificate
		identifiers.emplace_back((const char*)sha384, sizeof(sha384));
		const std::vector<Tlv> t = children(e[0]);
		const size_t first = !t.empty() && t[0].tag == 0xA0 ? 1 : 0;   // version
		if (first + 6 <= t.size()) {
			const std::vector<Tlv> spki = children(t[first + 5]);
			if (spki.size() >= 2 && spki[1].tag == 0x03 && spki[1].len >= 1) {
				Md5Stream md5;                                  // of the key: the BIT STRING, unused-bits byte excluded
				md5.update(spki[1].val + 1, spki[1].len - 1);
				const std::wstring hex = md5.hexDigest();
				std::string bytes;
				for (size_t k = 0; k + 1 < hex.size(); k += 2)
					bytes += (char)std::stoi(std::string(hex.begin() + k, hex.begin() + k + 2), nullptr, 16);
				identifiers.push_back(bytes);
			}
		}
	}
	for (const TrustListEntry& entry : list.entries)
		for (const std::string& identifier : identifiers)
			if (entry.identifier == identifier) return &entry;
	return nullptr;
}

namespace {

//! Equal, ignoring the case of ASCII letters — how the blocklist compares names.
bool sameName(const std::wstring& a, const std::wstring& b) {
	if (a.size() != b.size()) return false;
	for (size_t k = 0; k < a.size(); ++k) {
		const wchar_t x = a[k] >= L'A' && a[k] <= L'Z' ? a[k] + 32 : a[k];
		const wchar_t y = b[k] >= L'A' && b[k] <= L'Z' ? b[k] + 32 : b[k];
		if (x != y) return false;
	}
	return true;
}

/*! A file rule against a version resource: every attribute given equal,
 *  the version within bounds. Not read: matched; read and absent: not (see
 *  VulnerableDrivers). */
bool fileMatches(const DeniedFile& rule, const VersionInfo* version, bool read) {
	if (!read) return true;
	if (!version) return false;
	auto text = [&](const wchar_t* key) {
		const auto found = version->strings.find(key);
		return found == version->strings.end() ? std::wstring() : found->second;
	};
	if (!rule.fileName.empty() && !sameName(rule.fileName, text(L"OriginalFilename"))) return false;
	if (!rule.internalName.empty() && !sameName(rule.internalName, text(L"InternalName"))) return false;
	if (!rule.productName.empty() && !sameName(rule.productName, text(L"ProductName"))) return false;
	if (!rule.fileDescription.empty() && !sameName(rule.fileDescription, text(L"FileDescription"))) return false;
	if (version->fixed && (version->fileVersion < rule.minimumVersion || version->fileVersion > rule.maximumVersion)) return false;
	return true;
}

std::string narrowText(const std::wstring& w) { return std::string(w.begin(), w.end()); }

} // namespace

void VulnerableDriversFromJson(const Json& file, std::set<std::wstring>& hashes, std::vector<DeniedSigner>& signers,
                               std::vector<std::wstring>& missing) {
	auto text = [](const Json& object, const wchar_t* key) {
		const Json* member = object.find(key);
		return member ? member->text() : std::wstring();
	};
	if (const Json* list = file.find(L"Hashes"))
		for (const auto& [unused, h] : list->members()) hashes.insert(text(h, L"Hash"));
	if (const Json* list = file.find(L"ListsMissing"))
		for (const auto& [unused, m] : list->members()) missing.push_back(text(m, L"List"));
	const Json* list = file.find(L"Signers");
	if (!list) return;
	for (const auto& [unused, s] : list->members()) {
		DeniedSigner signer;
		signer.name = text(s, L"Name");
		signer.tbsHash = text(s, L"TbsHash");
		signer.publisher = text(s, L"CertPublisher");
		signer.oemId = text(s, L"CertOemID");
		if (const Json* files = s.find(L"Files"))
			for (const auto& [unused2, f] : files->members()) {
				DeniedFile rule;
				rule.fileName = text(f, L"FileName");
				rule.internalName = text(f, L"InternalName");
				rule.productName = text(f, L"ProductName");
				rule.fileDescription = text(f, L"FileDescription");
				ParseFileVersion(text(f, L"MinimumFileVersion"), rule.minimumVersion);
				ParseFileVersion(text(f, L"MaximumFileVersion"), rule.maximumVersion);
				signer.files.push_back(rule);
			}
		signers.push_back(std::move(signer));
	}
}

std::string VulnerableDrivers::match(const DriverFacts& facts) const {
	for (const std::wstring* h : { &facts.authenticodeSha256, &facts.authenticodeSha1, &facts.fileSha256, &facts.fileSha1 })
		if (!h->empty() && hashes_.count(*h)) return "listed as a vulnerable or malicious driver (fingerprint " + narrowText(*h) + ")";
	for (const DeniedSigner& signer : signers_) {
		if (signer.tbsHash.empty()) continue;
		bool inChain = false;
		for (const std::wstring& h : facts.chainTbsHashes) inChain |= sameName(h, signer.tbsHash);
		if (!inChain) continue;
		if (!signer.publisher.empty() && !sameName(signer.publisher, facts.signerName)) continue;
		if (!signer.oemId.empty() && !sameName(signer.oemId, facts.programName)) continue;
		bool fileMatched = signer.files.empty();
		for (const DeniedFile& rule : signer.files) fileMatched |= fileMatches(rule, facts.version, facts.read);
		if (fileMatched) return "signer denied by Microsoft's vulnerable driver blocklist: " + narrowText(signer.name);
	}
	return std::string();
}

std::vector<std::string> CertificateCrlAddresses(const uint8_t* der, size_t size) {
	Tlv t;
	Certificate c;
	if (!der || !readTlv(der, size, t) || !analyseCertificate(t, c)) return {};
	return crlAddressesOf(c);
}

std::vector<uint8_t> DecodeBase64(const std::string& text) {
	std::vector<uint8_t> bytes;
	uint32_t acc = 0; int bits = 0;
	for (char c : text) {
		const int b = base64Value((char32_t)(unsigned char)c);
		if (b < 0) continue;                               // "=" padding, spaces
		acc = (acc << 6) | (uint32_t)b; bits += 6;
		if (bits >= 8) { bits -= 8; bytes.push_back((uint8_t)(acc >> bits)); }
	}
	return bytes;
}

std::string EncodeBase64(const uint8_t* bytes, size_t size, size_t lineLength) {
	static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string text;
	auto put = [&](char c) {
		text += c;
		if (lineLength && (text.size() + 1) % (lineLength + 1) == 0) text += '\n';
	};
	for (size_t i = 0; i < size; i += 3) {
		const uint32_t group = (uint32_t)bytes[i] << 16 | (i + 1 < size ? (uint32_t)bytes[i + 1] << 8 : 0)
		                     | (i + 2 < size ? bytes[i + 2] : 0);
		put(ALPHABET[group >> 18 & 63]);
		put(ALPHABET[group >> 12 & 63]);
		put(i + 1 < size ? ALPHABET[group >> 6 & 63] : '=');
		put(i + 2 < size ? ALPHABET[group & 63] : '=');
	}
	if (lineLength && !text.empty() && text.back() != '\n') text += '\n';
	return text;
}

PackageSignature VerifyPackageSignature(const uint8_t* bytes, size_t size) {
	PackageSignature p;
	if (size < 4 || memcmp(bytes, "PKCX", 4) != 0) { p.reason = "not a package signature (PKCX)"; return p; }
	const VerifiedSignature s = VerifyPkcs7(bytes + 4, size - 4);
	if (!s.valid) { p.reason = s.reason; return p; }
	if (s.contentOid != std::string((const char*)OID_SPC_INDIRECT, sizeof(OID_SPC_INDIRECT))) {
		p.reason = "unexpected signed content"; return p;
	}
	Tlv spc; spc.tag = 0x30; spc.val = s.content; spc.len = s.contentSize;
	std::string digest;
	if (!indirectDigest(spc, digest, true) || digest.compare(0, 4, "APPX") != 0) {
		p.reason = "signed digest is not an APPX one"; return p;
	}
	// "APPX", then records of a 4-byte tag and a SHA-256: AXPC, AXCD, AXCT, AXBM, AXCI…
	for (size_t at = 4; at + 36 <= digest.size(); at += 36)
		if (digest.compare(at, 4, "AXBM") == 0) p.blockMapSha256 = digest.substr(at + 4, 32);
	if (p.blockMapSha256.empty()) { p.reason = "no block map digest (AXBM) in the signature"; return p; }
	p.valid = true;
	p.signer = s.signer;
	return p;
}

VerdictMicrosoft EvaluatePowerShellScript(const uint8_t* bytes, size_t size) {
	VerdictMicrosoft v;
	const std::u32string t = decodeText(bytes, size);

	// Comment form ("#") or XML form ("<!-- … -->").
	bool xml = false;
	size_t start = findText(t, "# SIG # Begin signature block");
	if (start == std::u32string::npos) {
		start = findText(t, "<!-- SIG # Begin signature block -->");
		xml = true;
	}
	if (start == std::u32string::npos) { v.reason = "no embedded signature"; return v; }
	const size_t end = findText(t, xml ? "<!-- SIG # End signature block -->" : "# SIG # End signature block", start);
	if (end == std::u32string::npos) { v.reason = "signature block incomplete"; return v; }

	// Base64 of the block's lines, prefixes and suffixes removed.
	std::vector<uint8_t> der;
	uint32_t acc = 0; int bits = 0;
	size_t i = t.find(U'\n', start);
	while (i != std::u32string::npos && i < end) {
		size_t j = t.find(U'\n', i + 1);
		if (j == std::u32string::npos || j > end) j = end;
		std::u32string line = t.substr(i + 1, j - i - 1);
		while (!line.empty() && (line.back() == U'\r' || line.back() == U' ')) line.pop_back();
		const size_t pref = xml ? 5 : 2;                          // "<!--" or "#"
		if (line.size() > pref && (xml ? line.compare(0, 5, U"<!-- ") == 0 : line.compare(0, 2, U"# ") == 0)) {
			const size_t suff = (xml && line.size() >= 4 && line.compare(line.size() - 4, 4, U" -->") == 0) ? 4 : 0;
			for (size_t k = pref; k + suff < line.size(); ++k) {
				const int b = base64Value(line[k]);
				if (b < 0) continue;                               // trailing "=", spaces
				acc = (acc << 6) | (uint32_t)b; bits += 6;
				if (bits >= 8) { bits -= 8; der.push_back((uint8_t)(acc >> bits)); }
			}
		}
		i = j;
	}

	const VerifiedSignature s = VerifyPkcs7(der.data(), der.size());
	if (!s.valid) { v.reason = s.reason; return v; }
	if (s.contentOid != std::string((const char*)OID_SPC_INDIRECT, sizeof(OID_SPC_INDIRECT))) {
		v.reason = "unexpected signed content"; return v;
	}
	Tlv spc; spc.tag = 0x30; spc.val = s.content; spc.len = s.contentSize;
	std::string declared;
	if (!indirectDigest(spc, declared)) { v.reason = "signed digest unreadable"; return v; }

	// Text preceding the block, without its last line break, as UTF-16LE.
	size_t corps = start;
	if (corps >= 2 && t[corps - 2] == U'\r' && t[corps - 1] == U'\n') corps -= 2;
	else if (corps >= 1 && t[corps - 1] == U'\n') corps -= 1;
	const std::vector<uint8_t> u16 = enUtf16(t, corps);
	uint8_t h[64];
	size_t lh = 0;
	if (declared.size() == 32) { sha256Bytes(u16.data(), u16.size(), h); lh = 32; }
	else if (declared.size() == 20) { sha1Bytes(u16.data(), u16.size(), h); lh = 20; }
	if (!lh || std::memcmp(declared.data(), h, lh) != 0) { v.reason = "script modified since it was signed"; return v; }
	v.signer = s.signer;
	if (!s.signerAccepted) { v.reason = "signer not accepted"; return v; }
	v.microsoft = true;
	v.source = L"embedded signature";
	return v;
}
