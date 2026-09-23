/*  authenticode.h — Microsoft authenticity of a binary, verified without any API.
 *
 *  WHAT IT IS FOR. With --binary, WAC collects the executables cited by the
 *  artefacts. Most are Windows components or Microsoft software, identical on
 *  every machine of the same build: copying them does not serve the
 *  investigation, and weighs gigabytes. These files carry a proof of origin
 *  that can be checked ON THE MACHINE ITSELF, with no embedded list:
 *    - Windows' CATALOGS (System32\CatRoot\{F750E6C3…}\*.cat), signed by
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
class AnalyseurPe : public std::streambuf {
public:
	/*! Ends the computation (to be called once the whole file has been fed). */
	void terminer();
	//! Whether the headers read identify a PE file.
	bool estPe() const { return estPe_; }
	//! @return the Authenticode SHA-1 (valid after terminer(), if estPe()).
	const uint8_t* sha1() const { return sha1_; }
	//! @return the Authenticode SHA-256 (same conditions).
	const uint8_t* sha256() const { return sha256_; }
	//! @return the SHA-1, file padded with zeros to a multiple of 8.
	const uint8_t* sha1Complete() const { return sha1c_; }
	//! @return the SHA-256, same padding.
	const uint8_t* sha256Complete() const { return sha256c_; }
	//! @return the certificate table (WIN_CERTIFICATE…), empty if absent.
	const std::vector<uint8_t>& tableCertificats() const { return certificats_; }

protected:
	/*! Receives one byte from the stream. @param c the byte. */
	int overflow(int c) override;
	/*! Receives a block from the stream. @param s,n the bytes. */
	std::streamsize xsputn(const char* s, std::streamsize n) override;

private:
	void recevoir(const uint8_t* p, size_t n);
	void traiter(const uint8_t* p, size_t n);   // once the headers are analysed
	bool analyserEntetes();

	std::vector<uint8_t> tete_;         // headers, until analysed
	bool decide_ = false, estPe_ = false, termine_ = false;
	uint64_t position_ = 0;             // bytes already processed
	uint64_t checksum_ = 0, entreeCert_ = 0, debutCert_ = 0, finCert_ = 0;
	Sha1Stream h1_;
	Sha256Stream h256_;
	std::vector<uint8_t> certificats_;
	uint8_t sha1_[20] = {}, sha256_[32] = {}, sha1c_[20] = {}, sha256c_[32] = {};
};

/*! Result of verifying a PKCS#7 signature. */
struct SignatureVerifiee {
	bool valide = false;          //!< signature and chain verified up to a Microsoft root
	bool signataireAccepte = false; //!< and signer compliant with the rule (see the header)
	std::wstring signataire;      //!< name (CN) of the signing certificate
	std::string motif;            //!< reason for a rejection, for the log
	std::string oidContenu;       //!< type of the signed content (DER bytes of the OID)
	const uint8_t* contenu = nullptr; //!< signed content (value, without header)
	size_t tailleContenu = 0;     //!< size of `contenu`, in bytes
};

/*! Verifies a PKCS#7 SignedData (catalog or embedded signature): content
 *  digest, signer's signature, chain up to an embedded Microsoft root. The
 *  returned pointers point into `donnees`. */
SignatureVerifiee VerifierPkcs7(const uint8_t* donnees, size_t taille);

/*! Index of the Authenticode digests listed by the machine's valid Microsoft
 *  catalogs. */
class IndexCatalogues {
public:
	/*! Verifies a catalog and, if it is signed by an accepted signer, indexes its
	 *  digests.
	 *  @param nom name of the catalog, kept to name it in the manifest.
	 *  @param octets,taille the catalog's bytes.
	 *  @return true if the catalog was kept. */
	bool ajouter(const std::wstring& nom, const uint8_t* octets, size_t taille);
	/*! Looks a digest up in the index.
	 *  @param empreinte,taille the raw digest (SHA-1 or SHA-256).
	 *  @return the name of the catalog listing it, or nullptr. */
	const std::wstring* chercher(const uint8_t* empreinte, size_t taille) const;
	//! @return the number of indexed catalogs.
	size_t catalogues() const { return noms_.size(); }
	//! @return the number of digests they list.
	size_t empreintes() const { return index_.size(); }
	//! @return the number of catalogs rejected by the verification.
	size_t refuses() const { return refuses_; }
	/*! Writes each indexed digest (hex) and its catalog — test tool.
	 *  @param o where to write. */
	void vider(std::ostream& o) const;
private:
	std::vector<std::wstring> noms_;
	std::unordered_map<std::string, uint32_t> index_;   // raw digest -> catalog
	size_t refuses_ = 0;
};

/*! Microsoft authenticity verdict on an analysed PE. */
struct VerdictMicrosoft {
	bool microsoft = false;       //!< authentic: hash without collecting
	std::wstring source;          //!< "catalogue <name>" or "signature intégrée"
	std::wstring signataire;      //!< signer's CN (embedded signature)
	std::string motif;            //!< why not, for the log
};

/*! Decides whether a PE is an authentic Microsoft binary. */
VerdictMicrosoft EvaluerPe(const AnalyseurPe& pe, const IndexCatalogues& catalogues);

/*! Non-PE file (script, document) listed in a Microsoft catalog?
 *
 *  For these files, the catalogs' digest is the SHA-256 of the file's RAW
 *  BYTES, whatever its encoding — established on 463 PowerShell and WSH scripts
 *  of Windows 11, all found that way. */
VerdictMicrosoft EvaluerParCatalogue(const uint8_t sha256[32], const IndexCatalogues& catalogues);

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
VerdictMicrosoft EvaluerScriptPowerShell(const uint8_t* octets, size_t taille);
