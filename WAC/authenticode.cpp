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
		const size_t nb = b & 0x7F;
		if (nb == 0 || nb > 4 || i + nb > n) return false;     // indefinite or oversized
		for (size_t k = 0; k < nb; ++k) len = (len << 8) | p[i++];
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

struct Certificate {
	Tlv integer, tbs, issuer, subject, serial;
	Tlv module, exponent;          // RSA key
	DigestAlgorithm algoSignature = DigestAlgorithm::Unknown;
	const uint8_t* signature = nullptr;
	size_t signatureSize = 0;
	bool rsa = false;
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
 *  RSA-4096 root included. */
std::set<std::string>& validChains() { static std::set<std::string> s; return s; }

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
		if (validChains().count(key)) {
			for (const std::string& p : walked) validChains().insert(p);
			return true;
		}
		walked.push_back(key);
		// Issued by an embedded root?
		for (const Certificate& r : roots()) {
			if (!sameBytes(current->issuer, r.subject)) continue;
			// The certificate IS the root (same key): nothing more to verify.
			if (current->rsa && current->module.len == r.module.len
			    && std::memcmp(current->module.val, r.module.val, r.module.len) == 0) {
				for (const std::string& p : walked) validChains().insert(p);
				return true;
			}
			if (signedBy(*current, r)) {
				for (const std::string& p : walked) validChains().insert(p);
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

bool signerAccepted(const std::wstring& cn, const std::wstring& o) {
	if (o != L"Microsoft Corporation") return false;
	return cn == L"Microsoft Windows" || cn == L"Microsoft Corporation"
	    || cn == L"Microsoft Windows Publisher";
}

} // namespace

// ============================================================ PKCS#7

VerifiedSignature VerifyPkcs7(const uint8_t* data, size_t size) {
	VerifiedSignature r;
	Tlv ci;
	if (!readTlv(data, size, ci) || ci.tag != 0x30) { r.reason = "ContentInfo unreadable"; return r; }
	std::vector<Tlv> e = children(ci);
	if (e.size() < 2 || !IS_OID(e[0], OID_SIGNED_DATA) || e[1].tag != 0xA0) { r.reason = "pas un SignedData"; return r; }
	std::vector<Tlv> w = children(e[1]);
	if (w.empty() || w[0].tag != 0x30) { r.reason = "SignedData unreadable"; return r; }
	const std::vector<Tlv> sd = children(w[0]);
	// version, digestAlgorithms, encapContentInfo, [0] certificats, [1] crls, signerInfos
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
			for (const Tlv& c : children(sd[i])) { Certificate x; if (analyseCertificate(c, x)) pool.push_back(x); }
		else if (sd[i].tag == 0x31) infos = &sd[i];
	}
	if (!infos) { r.reason = "no signer"; return r; }
	const std::vector<Tlv> signers = children(*infos);
	if (signers.empty()) { r.reason = "no signer"; return r; }
	const std::vector<Tlv> si = children(signers[0]);
	// version, issuerAndSerialNumber, digestAlgorithm, [0] attributes, digestEncryptionAlgorithm, encryptedDigest
	if (si.size() < 5) { r.reason = "SignerInfo incomplete"; return r; }
	const std::vector<Tlv> ias = children(si[1]);
	if (ias.size() < 2) { r.reason = "signer's issuer unreadable"; return r; }
	const DigestAlgorithm algo = algoDe(si[2]);
	if (algo == DigestAlgorithm::Unknown) { r.reason = "digest algorithm not supported"; return r; }
	size_t k = 3;
	const Tlv* attributes = nullptr;
	if (si[k].tag == 0xA0) attributes = &si[k++];
	if (k + 1 >= si.size() || si[k + 1].tag != 0x04) { r.reason = "signature absent"; return r; }
	const Tlv& signature = si[k + 1];
	if (!attributes) { r.reason = "authenticated attributes absent"; return r; }

	// 1. The content's digest must be the one announced in the attributes.
	uint8_t hc[64];
	const size_t lhc = fingerprint(algo, r.content, r.contentSize, hc);
	bool digestOk = false;
	for (const Tlv& a : children(*attributes)) {
		const std::vector<Tlv> av = children(a);
		if (av.size() < 2 || !IS_OID(av[0], OID_MESSAGE_DIGEST)) continue;
		const std::vector<Tlv> vals = children(av[1]);
		if (!vals.empty() && vals[0].tag == 0x04 && vals[0].len == lhc
		    && std::memcmp(vals[0].val, hc, lhc) == 0) digestOk = true;
	}
	if (!digestOk) { r.reason = "content digest does not match"; return r; }

	// 2. The signature covers the attributes, re-encoded as a SET (0x31).
	std::vector<uint8_t> signedBytes(attributes->start, attributes->start + attributes->total);
	signedBytes[0] = 0x31;
	uint8_t ha[64];
	const size_t lha = fingerprint(algo, signedBytes.data(), signedBytes.size(), ha);

	const Certificate* signer = nullptr;
	for (const Certificate& c : pool)
		if (sameBytes(c.issuer, ias[0]) && sameBytes(c.serial, ias[1])) { signer = &c; break; }
	if (!signer || !signer->rsa) { r.reason = "signer certificate absent or not RSA"; return r; }
	if (!RsaVerifyPkcs1(signer->module.val, signer->module.len,
	                      signer->exponent.val, signer->exponent.len,
	                      signature.val, signature.len, algo, ha, lha)) {
		r.reason = "RSA signature invalid"; return r;
	}
	// 3. The chain up to an embedded Microsoft root.
	if (!attach(*signer, pool)) { r.reason = "chain not tied to a Microsoft root"; return r; }

	r.valid = true;
	r.signer = attributeNameField(signer->subject, OID_CN, sizeof(OID_CN));
	const std::wstring o = attributeNameField(signer->subject, OID_O, sizeof(OID_O));
	r.signerAccepted = signerAccepted(r.signer, o);
	if (!r.signerAccepted) r.reason = "signer not accepted";
	return r;
}

// ============================================================ catalogues

namespace {

/*! Digest carried by a SpcIndirectDataContent: SEQUENCE { data,
 *  messageDigest DigestInfo SEQUENCE { AlgorithmIdentifier, OCTET STRING } }. */
bool indirectDigest(const Tlv& spc, std::string& output) {
	const std::vector<Tlv> e = children(spc);
	if (e.size() < 2) return false;
	const std::vector<Tlv> di = children(e[1]);
	if (di.size() < 2 || di[1].tag != 0x04 || (di[1].len != 20 && di[1].len != 32)) return false;
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

VerdictMicrosoft EvaluatePe(const PeAnalyser& pe, const IndexCatalogues& catalogues) {
	VerdictMicrosoft v;
	if (!pe.isPe()) { v.reason = "pas un PE"; return v; }

	// 1. Catalogs: is the digest, in one of its forms, listed there?
	for (const auto& e : { std::make_pair(pe.sha256(), 32), std::make_pair(pe.sha1(), 20),
	                       std::make_pair(pe.sha256Complete(), 32), std::make_pair(pe.sha1Complete(), 20) }) {
		if (const std::wstring* cat = catalogues.find(e.first, (size_t)e.second)) {
			v.microsoft = true;
			v.source = L"catalog " + *cat;
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
	v.signer = s.signer;
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
	if (start == std::u32string::npos) { v.reason = "pas de embedded signature"; return v; }
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
