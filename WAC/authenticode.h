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
	//! @return the Authenticode SHA-1 (valid after terminer(), if isPe()).
	const uint8_t* sha1() const { return sha1_; }
	//! @return the Authenticode SHA-256 (same conditions).
	const uint8_t* sha256() const { return sha256_; }
	//! @return the SHA-1, file padded with zeros to a multiple of 8.
	const uint8_t* sha1Complete() const { return sha1c_; }
	//! @return the SHA-256, same padding.
	const uint8_t* sha256Complete() const { return sha256c_; }
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
	std::string reason;            //!< reason for a rejection, for the log
	std::string contentOid;       //!< type of the signed content (DER bytes of the OID)
	const uint8_t* content = nullptr; //!< signed content (value, without header)
	size_t contentSize = 0;     //!< size of `content`, in bytes
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
	std::wstring source;          //!< "catalog <name>" or "embedded signature"
	std::wstring signer;      //!< signer's CN (embedded signature)
	std::string reason;            //!< why not, for the log
};

/*! Decides whether a PE is an authentic Microsoft binary. */
VerdictMicrosoft EvaluatePe(const PeAnalyser& pe, const IndexCatalogues& catalogues);

/*! Non-PE file (script, document) listed in a Microsoft catalog?
 *
 *  For these files, the catalogs' digest is the SHA-256 of the file's RAW
 *  BYTES, whatever its encoding — established on 463 PowerShell and WSH scripts
 *  of Windows 11, all found that way. */
VerdictMicrosoft EvaluateByCatalog(const uint8_t sha256[32], const IndexCatalogues& catalogues);

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
