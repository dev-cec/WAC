/*  rsa.h — vérification de signature RSA PKCS#1 v1.5, en mémoire, sans API.
 *
 *  POURQUOI PAS CryptoAPI NI CNG. La vérification de signature Windows
 *  (WinVerifyTrust) sollicite le service CryptSvc, lit les magasins de
 *  certificats dans le registre vivant et contrôle la révocation par le réseau —
 *  ce qui écrit dans CryptnetUrlCache, un artefact forensique à part entière.
 *  Même les primitives de CNG consultent leur configuration dans le registre.
 *  Pour ne laisser AUCUNE trace, l'opération se fait ici, sur des octets en
 *  mémoire : une exponentiation modulaire, rien d'autre.
 *
 *  PÉRIMÈTRE. Seule la VÉRIFICATION est implémentée (clé publique, exposant
 *  public) : pas de clé privée, pas de secret à protéger, donc pas d'exigence de
 *  temps constant. Empreintes SHA-1, SHA-256, SHA-384 (chaîne Microsoft « PCA
 *  2023 ») et SHA-512.
 */
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

enum class AlgoEmpreinte { Inconnu, Sha1, Sha256, Sha384, Sha512 };

/*! Vérifie une signature RSA PKCS#1 v1.5.
 *
 *  @param module, tailleModule  module n, grand-boutien (tel qu'en DER, zéro de
 *         tête éventuel compris)
 *  @param exposant, tailleExposant  exposant public e, grand-boutien
 *  @param signature, tailleSignature  signature, grand-boutien
 *  @param algo  algorithme de l'empreinte signée
 *  @param empreinte, tailleEmpreinte  empreinte attendue
 *  @return true si la signature est valide pour cette empreinte
 */
bool RsaVerifierPkcs1(const uint8_t* module, size_t tailleModule,
                      const uint8_t* exposant, size_t tailleExposant,
                      const uint8_t* signature, size_t tailleSignature,
                      AlgoEmpreinte algo,
                      const uint8_t* empreinte, size_t tailleEmpreinte);
