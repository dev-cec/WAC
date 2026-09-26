/*! \file
 *  \brief Microsoft authenticity of a binary, verified without any API.
 *
 *  WHAT IT IS FOR. With --binary, WAC collects the executables cited by the
 *  artefacts. Most are Windows components or Microsoft software, identical on
 *  every machine of the same build: copying them does not serve the
 *  investigation, and weighs gigabytes. These files carry a proof of origin
 *  that can be checked ON THE MACHINE ITSELF, with no embedded list:
 *    - Windows' CATALOGS (`System32\CatRoot\{F750E6C3…}\*.cat`), signed by
 *      Microsoft, which list the fingerprint of every system file;
 *    - the EMBEDDED SIGNATURE of individually signed binaries (Edge,
 *      OneDrive, Office…).
 *  A file whose Authenticode digest is listed in a catalog with a valid
 *  Microsoft signature, or whose embedded signature is a valid Microsoft
 *  signature, is hashed without being collected. Everything else is collected.
 *  A System32 binary replaced by an attacker no longer has the catalog's
 *  digest: it is collected.
 *
 *  NO TRACE. WinVerifyTrust and CryptCATAdmin solicit the CryptSvc service and
 *  its catalog database, read the certificate stores in the live registry, and
 *  check revocation over the network — which writes to CryptnetUrlCache. None
 *  of that here: catalogs and binaries are read raw from the volume, and the
 *  verification — ASN.1, X.509, PKCS#7, RSA — is done in memory, up to
 *  EMBEDDED Microsoft roots (racines_microsoft.h), without consulting the
 *  machine's store.
 *
 *  WHAT IS NOT CHECKED, and why that is acceptable here: revocation and
 *  validity dates. The question is not "should this code be trusted today" but
 *  "is this file the one Microsoft published"; an authentic Microsoft signature
 *  answers it. When in doubt — unsupported algorithm, unexpected structure —
 *  the answer is "not verified", and the file is collected.
 *
 *  ACCEPTED SIGNERS. Not every certificate chaining to a Microsoft root signs
 *  Microsoft code: "Microsoft Windows Hardware Compatibility Publisher" signs
 *  WHQL-certified THIRD-PARTY drivers, and "Early Launch Anti-malware
 *  Publisher" third-party antivirus ELAM drivers — the classic ground of
 *  abused vulnerable drivers. Only signers whose organisation is "Microsoft
 *  Corporation" and whose name is "Microsoft Windows", "Microsoft Corporation"
 *  or "Microsoft Windows Publisher" are accepted.
 */
#pragma once
#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <streambuf>
#include <ostream>
#include <unordered_map>
#include "sha.h"

/*! Analysis of a PE file fed as a stream: Authenticode digests and certificate
 *  table, computed while reading, without reading the file again.
 *
 *  The Authenticode digest covers the whole file EXCEPT the optional header's
 *  CheckSum field, the "certificate table" entry of the data directory, and
 *  the certificate table itself. */
class PeAnalyser : public std::streambuf {
public:
	/*! Ends the computation (to be called once the whole file has been fed). */
	void finish();
	//! Whether the headers read identify a PE file.
	bool isPe() const { return isPe_; }
	//! @return the Authenticode SHA-1 (valid after finish(), if isPe()).
	const uint8_t* sha1() const { return sha1_; }
	//! @return the Authenticode SHA-256 (same conditions).
	const uint8_t* sha256() const { return sha256_; }
	//! @return the SHA-1, file padded with zeros to a multiple of 8.
	const uint8_t* sha1Complete() const { return sha1c_; }
	//! @return the SHA-256, same padding.
	const uint8_t* sha256Complete() const { return sha256c_; }
	/*! @return TimeDateStamp of the COFF header (valid if isPe()). With
	 *  sizeOfImage(), the key under which Microsoft's symbol server keeps
	 *  every build of its binaries: an authentic Microsoft binary that was not
	 *  copied can be fetched again, identical, from it. */
	uint32_t timeDateStamp() const { return timeDateStamp_; }
	//! @return SizeOfImage of the optional header (valid if isPe()).
	uint32_t sizeOfImage() const { return sizeOfImage_; }
	//! @return the certificate table (WIN_CERTIFICATE…), empty if absent.
	const std::vector<uint8_t>& certificateTable() const { return certificates_; }

protected:
	/*! Receives one byte from the stream. @param c the byte. */
	int overflow(int c) override;
	/*! Receives a block from the stream. @param s,n the bytes. */
	std::streamsize xsputn(const char* s, std::streamsize n) override;

private:
	void receive(const uint8_t* p, size_t n);
	void process(const uint8_t* p, size_t n);   // once the headers are analysed
	bool analyseHeaders();

	std::vector<uint8_t> head_;         // headers, until analysed
	bool decide_ = false, isPe_ = false, finished_ = false;
	uint64_t position_ = 0;             // bytes already processed
	uint64_t checksum_ = 0, certEntry_ = 0, certStart_ = 0, finCert_ = 0;
	uint32_t timeDateStamp_ = 0, sizeOfImage_ = 0;
	Sha1Stream h1_;
	Sha256Stream h256_;
	std::vector<uint8_t> certificates_;
	uint8_t sha1_[20] = {}, sha256_[32] = {}, sha1c_[20] = {}, sha256c_[32] = {};
};

/*! Result of verifying a PKCS#7 signature. */
struct VerifiedSignature {
	bool valid = false;          //!< signature and chain verified up to a Microsoft root
	bool signerAccepted = false; //!< and signer compliant with the rule (see the header)
	std::wstring signer;      //!< name (CN) of the signing certificate
	std::wstring signerOrganization; //!< its organisation (O)
	/*! The signature itself holds: content digest and RSA signature verified,
	 *  WHATEVER the chain. Informative only for a third-party signer: the
	 *  chain is not verified up to a trusted root, and anyone can sign with a
	 *  certificate of their own. */
	bool intact = false;
	std::string reason;            //!< reason for a rejection, for the log
	std::string contentOid;       //!< type of the signed content (DER bytes of the OID)
	const uint8_t* content = nullptr; //!< signed content (value, without header)
	size_t contentSize = 0;     //!< size of `content`, in bytes
	//! The certificates the SignedData carries, DER (pointers into the data).
	std::vector<std::pair<const uint8_t*, size_t>> certificates;
	size_t signerIndex = SIZE_MAX; //!< the signer's among them; SIZE_MAX if not found
};

/*! Verifies a PKCS#7 SignedData (catalog or embedded signature): content
 *  digest, signer's signature, chain up to an embedded Microsoft root. The
 *  returned pointers point into `data`. */
VerifiedSignature VerifyPkcs7(const uint8_t* data, size_t size);

/*! Index of the Authenticode digests listed by the machine's valid Microsoft
 *  catalogs. */
class IndexCatalogues {
public:
	/*! Verifies a catalog and, if it is signed by an accepted signer, indexes its
	 *  digests.
	 *  @param name name of the catalog, kept to name it in the manifest.
	 *  @param bytes,size the catalog's bytes.
	 *  @return true if the catalog was kept. */
	bool add(const std::wstring& name, const uint8_t* bytes, size_t size);
	/*! Looks a digest up in the index.
	 *  @param fingerprint,size the raw digest (SHA-1 or SHA-256).
	 *  @return the name of the catalog listing it, or nullptr. */
	const std::wstring* find(const uint8_t* fingerprint, size_t size) const;
	//! @return the number of indexed catalogs.
	size_t catalogues() const { return names_.size(); }
	//! @return the number of digests they list.
	size_t fingerprints() const { return index_.size(); }
	//! @return the number of catalogs rejected by the verification.
	size_t rejected() const { return rejected_; }
	/*! Writes each indexed digest (hex) and its catalog — test tool.
	 *  @param o where to write. */
	void dump(std::ostream& o) const;
private:
	std::vector<std::wstring> names_;
	std::unordered_map<std::string, uint32_t> index_;   // raw digest -> catalog
	size_t rejected_ = 0;
};

/*! Microsoft authenticity verdict on an analysed PE. */
struct VerdictMicrosoft {
	bool microsoft = false;       //!< authentic: hash without collecting
	std::wstring source;          //!< "catalog <path>" or "embedded signature"
	std::wstring catalog;         //!< the catalog that listed the digest (its path); empty otherwise
	std::wstring signer;      //!< signer's CN (embedded signature), whoever it is
	std::wstring signerOrganization; //!< signer's organisation (O)
	/*! Embedded signature intact — RSA signature valid and the signed
	 *  Authenticode digest the file's: the file is as its signer signed it.
	 *  Says nothing about who the signer is (see VerifiedSignature::intact). */
	bool signatureIntact = false;
	std::string reason;            //!< why not, for the log
	/*! A third-party signature, intact, checked against the trust set (see
	 *  ThirdPartyRoots): whether it was, whether its chain holds, to which
	 *  root, or why not. */
	bool chainChecked = false;
	bool chainTrusted = false;
	std::wstring chainRoot;        //!< CN of the root reached, when trusted
	std::string chainReason;       //!< why not trusted
};

struct TrustList;

/*! Result of checking the chain of a third-party signature. */
struct ChainVerdict {
	bool trusted = false;
	std::wstring root;             //!< CN of the root reached
	std::string reason;            //!< why not trusted
};

/*! THE ROOTS A THIRD-PARTY SIGNATURE IS TIED TO: those of the trust set
 *  (trust_set.h), which Microsoft's root program trusts for code signing —
 *  never the examined machine's, which an attacker could have added to.
 *
 *  A chain holds when, from the signer up to a root of the set:
 *    - each certificate is signed by the next (RSA; another algorithm is not
 *      verified, and the chain does not hold);
 *    - each issuer is an authority (basic constraints, cA);
 *    - the signer's certificate allows code signing (extended key usage,
 *      when present);
 *    - the root is trusted by Microsoft for code signing, and not distrusted;
 *    - no certificate is disallowed by Microsoft (disallowedcert.stl), no
 *      authority revoked according to the CCADB.
 *  Not yet: the validity dates and the time stamp, the revocation lists.
 *
 *  Built once, then shared by the analysis threads (read only). */
class ThirdPartyRoots {
public:
	/*! @param roots authroot.stl
	 *  @param certificates the root certificates, DER, by their SHA-1
	 *  @param disallowed disallowedcert.stl
	 *  @param revokedAuthorities SHA-256 (uppercase hexadecimal) of the authorities the CCADB says revoked
	 *  All must outlive this object. */
	ThirdPartyRoots(const TrustList& roots, const std::map<std::string, std::vector<uint8_t>>& certificates,
	                const TrustList& disallowed, const std::set<std::wstring>& revokedAuthorities);
	~ThirdPartyRoots();
	ThirdPartyRoots(const ThirdPartyRoots&) = delete;
	ThirdPartyRoots& operator=(const ThirdPartyRoots&) = delete;

	/*! @param signature an intact signature, as VerifyPkcs7 returned it
	 *  @return whether its chain holds (see the class) */
	ChainVerdict verify(const VerifiedSignature& signature) const;

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

/*! Decides whether a PE is an authentic Microsoft binary; a third-party
 *  signature, intact, is checked against `thirdParty` when given. */
VerdictMicrosoft EvaluatePe(const PeAnalyser& pe, const IndexCatalogues& catalogues,
                            const ThirdPartyRoots* thirdParty = nullptr);

/*! Non-PE file (script, document) listed in a Microsoft catalog?
 *
 *  For these files, the catalogs' digest is the SHA-256 of the file's RAW
 *  BYTES, whatever its encoding — established on 463 PowerShell and WSH scripts
 *  of Windows 11, all found that way. */
VerdictMicrosoft EvaluateByCatalog(const uint8_t sha256[32], const IndexCatalogues& catalogues);

/*! A certificate listed by a Microsoft trust list, and what the list says
 *  of it. */
struct TrustListEntry {
	/*! What identifies the certificate, per the list's kind (TrustList::
	 *  identifier) and, for disallowedcert.stl, per its size (see there). */
	std::string identifier;
	/*! The list restricts its uses (property 9) and code signing is not among
	 *  them, or it disallows code signing (property 122): a root trusted for
	 *  the web only must not validate a code signature. */
	bool codeSigningExcluded = false;
	/*! The same for time stamping: a root the list does not trust for it
	 *  must not validate the time stamp of a signature. */
	bool timeStampingExcluded = false;
	/*! The list distrusts it after a date (property 104). Two roots of the
	 *  list of 2026-08-25 carry the property WITHOUT a date (VeriSign Class 3
	 *  G5, thawte Primary Root CA): the meaning is undocumented, hence taken
	 *  the prudent way — distrusted, as of always. */
	bool distrusted = false;
	uint64_t distrustedAfter = 0;     //!< FILETIME of that date; 0 when the list gives none
};

/*! A Microsoft trust list: authroot.stl (the roots of Microsoft's root
 *  program) or disallowedcert.stl (the certificates Microsoft distrusts). */
struct TrustList {
	bool valid = false;               //!< signed by Microsoft's trust list publisher, chain to a Microsoft root
	std::string reason;               //!< why not valid
	/*! How the list identifies a certificate — the property id of its
	 *  subject algorithm:
	 *    - 3 (authroot.stl): the SHA-1 of the certificate, 20 bytes;
	 *    - 15 (disallowedcert.stl), "signature hash" by its name, but in
	 *      fact two different digests, told apart by their size:
	 *        16 bytes, the MD5 of the PUBLIC KEY (the content of the
	 *          subjectPublicKeyInfo BIT STRING): a key is distrusted, with
	 *          every certificate that carries it;
	 *        48 bytes, the SHA-384 of the TBSCertificate.
	 *      Neither is documented: MEASURED against an independent set, the
	 *      certificates Chromium blocks (net/data/ssl/blocklist, 107 files):
	 *      26 of the 82 entries of 16 bytes found as MD5 of a key, 3 of the
	 *      6 entries of 48 bytes as SHA-384 of a TBSCertificate, and none as
	 *      MD5 of a TBSCertificate, the reading the property's name
	 *      suggests (see trust_list_test). */
	unsigned identifier = 0;
	uint64_t thisUpdate = 0;          //!< FILETIME (UTC) Microsoft issued this list at
	std::vector<TrustListEntry> entries;
};

/*! Reads a Microsoft trust list and checks its signature: valid, up to an
 *  embedded Microsoft root, by "Microsoft Certificate Trust List Publisher"
 *  of Microsoft Corporation — the only signer accepted for a trust list, and
 *  for nothing else.
 *  @param bytes,size the .stl file
 *  @return the list; `valid` false if its signature does not hold */
TrustList ReadTrustList(const uint8_t* bytes, size_t size);

/*! Looks a certificate up in a trust list, by the identifiers the list's
 *  kind uses (see TrustList::identifier).
 *  @param list the list, as ReadTrustList returned it
 *  @param certificate,size the certificate, DER
 *  @return its entry; nullptr if the list does not name it, or if the
 *          certificate cannot be read */
const TrustListEntry* FindInTrustList(const TrustList& list, const uint8_t* certificate, size_t size);

/*! Base64 (the standard alphabet) to bytes; padding and characters outside
 *  the alphabet are skipped.
 *  @param text the encoded text
 *  @return the bytes */
std::vector<uint8_t> DecodeBase64(const std::string& text);

/*! Bytes to Base64 (the standard alphabet, padded), for the PEM files
 *  --update-trust writes.
 *  @param bytes,size the bytes
 *  @param lineLength characters per line, a line feed after each; 0: one line
 *  @return the encoded text */
std::string EncodeBase64(const uint8_t* bytes, size_t size, size_t lineLength = 0);

/*! Signature of an AppX / MSIX package (AppxSignature.p7x) and what it
 *  guarantees: the SHA-256 of the package's block map, which gives in turn
 *  the SHA-256 of every 64 KiB block of every file of the package. */
struct PackageSignature {
	bool valid = false;          //!< PKCS#7 verified, chain up to a Microsoft root
	/*! CN of the signing certificate. The Store signs, under its Microsoft
	 *  chain, the packages of other publishers: the name is theirs. */
	std::wstring signer;
	std::string reason;          //!< why not valid, for the log
	std::string blockMapSha256;  //!< AppxBlockMap.xml's SHA-256, as signed (32 bytes)
};

/*! Verifies a package signature: the "PKCX" header, then a PKCS#7 whose
 *  chain reaches an embedded Microsoft root — the Store's signature, or
 *  Microsoft's own; a package signed under another root is not valid here —,
 *  whose signed content is an "APPX" digest carrying the block map's.
 *  @param bytes,size the content of AppxSignature.p7x
 *  @return the verdict */
PackageSignature VerifyPackageSignature(const uint8_t* bytes, size_t size);

/*! EMBEDDED signature of a PowerShell script (.ps1, .psm1, .psd1, .ps1xml…).
 *
 *  The "# SIG # Begin signature block" block (or its XML form
 *  "<!-- SIG # … -->") carries a base64 PKCS#7. The signed digest is that of the
 *  TEXT preceding the block, without its last line break, re-encoded as
 *  UTF-16LE without BOM — established on the 10 scripts signed this way on a
 *  Windows 11 installation (Defender), .ps1xml included.
 *
 *  Windows Script Host scripts (.vbs, .js, .wsf) are authenticated by catalog
 *  only: their embedded digest covers a normalised form of the text that could
 *  not be established with certainty. Such a script signed outside a catalog is
 *  therefore collected — erring on the cautious side. */
VerdictMicrosoft EvaluatePowerShellScript(const uint8_t* bytes, size_t size);
