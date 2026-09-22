/*  rsa.h — RSA PKCS#1 v1.5 signature verification, in memory, with no API.
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

enum class AlgoEmpreinte { Inconnu, Sha1, Sha256, Sha384, Sha512 };

/*! Verifies an RSA PKCS#1 v1.5 signature.
 *
 *  @param module, tailleModule  modulus n, big-endian (as in DER, possible
 *         leading zero included)
 *  @param exposant, tailleExposant  public exponent e, big-endian
 *  @param signature, tailleSignature  signature, big-endian
 *  @param algo  algorithm of the signed digest
 *  @param empreinte, tailleEmpreinte  expected digest
 *  @return true if the signature is valid for this digest
 */
bool RsaVerifierPkcs1(const uint8_t* module, size_t tailleModule,
                      const uint8_t* exposant, size_t tailleExposant,
                      const uint8_t* signature, size_t tailleSignature,
                      AlgoEmpreinte algo,
                      const uint8_t* empreinte, size_t tailleEmpreinte);
