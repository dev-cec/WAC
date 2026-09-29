/*! \file
 *  \brief RSA PKCS#1 v1.5 signature verification, in memory, with no API.
 *
 *  WHY NOT CryptoAPI OR CNG. Windows signature verification (WinVerifyTrust)
 *  solicits the CryptSvc service, reads the certificate stores in the live
 *  registry and checks revocation over the network — which writes to
 *  CryptnetUrlCache, a forensic artefact in its own right. Even CNG's
 *  primitives read their configuration from the registry. To leave NO trace,
 *  the operation is done here, on bytes in memory: a modular exponentiation,
 *  nothing else.
 *
 *  SCOPE. Only VERIFICATION is implemented (public key, public exponent): no
 *  private key, no secret to protect, hence no constant-time requirement.
 *  SHA-1, SHA-256, SHA-384 (Microsoft "PCA 2023" chain) and SHA-512 digests.
 */
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

/*! Digest algorithm named by a signature (its DigestInfo). */
enum class DigestAlgorithm {
	Unknown, //!< not recognised: the signature is not verified
	Sha1,    //!< SHA-1
	Sha256,  //!< SHA-256
	Sha384,  //!< SHA-384
	Sha512   //!< SHA-512
};

/*! How the digest is wrapped in the signed block. */
enum class DigestEncoding {
	DigestInfo,      //!< PKCS#1 v1.5 proper: the digest within a DigestInfo naming its algorithm
	/*! Also the bare digest, without DigestInfo: what the time stamping
	 *  services of VeriSign and Symantec produced for Authenticode
	 *  counter-signatures (measured on LOLDrivers samples: the decrypted block
	 *  is 00 01 FF… 00 then the SHA-1 alone), and Windows accepts. For those
	 *  counter-signatures only. */
	DigestInfoOrBare
};

/*! Verifies an RSA PKCS#1 v1.5 signature.
 *
 *  @param module, modulusSize  modulus n, big-endian (as in DER, possible
 *         leading zero included)
 *  @param exponent, exponentSize  public exponent e, big-endian
 *  @param signature, signatureSize  signature, big-endian
 *  @param algo  algorithm of the signed digest
 *  @param fingerprint, digestSize  expected digest
 *  @param encoding  whether a bare digest is accepted too (see DigestEncoding)
 *  @return true if the signature is valid for this digest
 */
bool RsaVerifyPkcs1(const uint8_t* module, size_t modulusSize,
                      const uint8_t* exponent, size_t exponentSize,
                      const uint8_t* signature, size_t signatureSize,
                      DigestAlgorithm algo,
                      const uint8_t* fingerprint, size_t digestSize,
                      DigestEncoding encoding = DigestEncoding::DigestInfo);
