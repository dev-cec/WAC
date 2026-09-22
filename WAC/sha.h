#pragma once

/*  sha.h — EMPREINTES SHA-1 ET SHA-256, calculées au fil de l'écriture.
 *
 *  POURQUOI DEUX ALGORITHMES DE PLUS. La consigne d'une pièce numérique doit
 *  porter une empreinte qui l'identifie sans discussion possible. MD5 seul ne
 *  suffit plus : des collisions sont produites à volonté depuis 2008, et une
 *  défense peut donc soutenir qu'un fichier de même empreinte n'est pas le
 *  fichier saisi. SHA-1 est l'empreinte que les procédures et les outils du
 *  domaine réclament encore, mais il est lui aussi cassé en collision depuis
 *  2017 (SHAttered). D'où les trois, dont SHA-256, seul non contesté :
 *  fabriquer un fichier qui coïncide sur les trois à la fois n'est pas au
 *  pouvoir de l'état de l'art.
 *
 *  POURQUOI PAS L'API DU SYSTÈME. `bcrypt.dll` ferait le calcul, mais WAC
 *  s'interdit d'ajouter une dépendance à une bibliothèque du système examiné
 *  quand un algorithme public de trente lignes suffit : l'exécutable reste
 *  autonome, et l'empreinte reste calculable à l'identique par un tiers.
 *
 *  POURQUOI « AU FIL DE L'ÉCRITURE ». Les octets de la pièce transitent déjà en
 *  mémoire pendant l'extraction. Les hacher à ce moment évite de relire la copie
 *  depuis le support de collecte — sur clé USB, cette relecture coûtait près de
 *  la moitié du temps d'extraction. Et l'empreinte porte alors sur ce qui a
 *  effectivement été lu du volume, non sur une relecture qui pourrait différer.
 *
 *  Même interface que Md5Stream (cf. quickdigest5.h), pour que les trois
 *  empreintes se calculent dans la même boucle.
 *
 *  C++ portable, aucune dépendance : vérifiable hors Windows, et confronté aux
 *  vecteurs de test publics des deux algorithmes (cf. sha_test).
 */

#include <cstdint>
#include <cstddef>
#include <string>

/*! SHA-1, calculé par ajouts successifs. */
class Sha1Stream final {
public:
	/*! Ajoute des octets au calcul. */
	void update(const uint8_t* data, size_t length);
	/*! Clôt le calcul et rend l'empreinte en hexadécimal majuscule.
	 *  À n'appeler qu'une fois : le calcul est terminé ensuite. */
	std::wstring hexDigest();
	/*! Clôt le calcul et écrit l'empreinte brute (20 octets). Même contrainte :
	 *  une seule fois, et exclusif de hexDigest. */
	void digest(uint8_t sortie[20]);
private:
	uint32_t etat_[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };
	uint8_t  bloc_[64] = { 0 };
	size_t   dansBloc_ = 0;
	uint64_t octets_ = 0;
	void comprimer(const uint8_t* bloc);
};

/*! SHA-256, calculé par ajouts successifs. */
class Sha256Stream final {
public:
	/*! Ajoute des octets au calcul. */
	void update(const uint8_t* data, size_t length);
	/*! Clôt le calcul et rend l'empreinte en hexadécimal majuscule.
	 *  À n'appeler qu'une fois : le calcul est terminé ensuite. */
	std::wstring hexDigest();
	/*! Clôt le calcul et écrit l'empreinte brute (32 octets). Même contrainte :
	 *  une seule fois, et exclusif de hexDigest. */
	void digest(uint8_t sortie[32]);
private:
	uint32_t etat_[8] = { 0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
	                      0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u };
	uint8_t  bloc_[64] = { 0 };
	size_t   dansBloc_ = 0;
	uint64_t octets_ = 0;
	void comprimer(const uint8_t* bloc);
};

/*! SHA-512, et SHA-384 qui en est la variante tronquée (autres constantes
 *  initiales, 48 octets rendus).
 *
 *  POURQUOI. Microsoft signe désormais avec la chaîne « Windows Production PCA
 *  2023 », en sha384WithRSAEncryption : relevé sur le catalogue de Defender
 *  (wd_mpextdeps.cat) d'une installation Windows 11. Sans SHA-384, un fichier
 *  signé par cette chaîne ne peut pas être authentifié — et la migration de
 *  Microsoft vers cette chaîne en rendra la part croissante. */
class Sha512Stream final {
public:
	explicit Sha512Stream(bool variante384 = false);
	void update(const uint8_t* data, size_t length);
	/*! Clôt le calcul et écrit l'empreinte : 64 octets, ou 48 pour SHA-384. */
	void digest(uint8_t* sortie);
	size_t taille() const { return variante384_ ? 48 : 64; }
private:
	uint64_t etat_[8];
	uint8_t  bloc_[128] = { 0 };
	size_t   dansBloc_ = 0;
	uint64_t octets_ = 0;
	bool     variante384_;
	void comprimer(const uint8_t* bloc);
};

/*! Empreintes brutes d'un tampon en une passe. */
void sha1Octets(const uint8_t* data, size_t length, uint8_t sortie[20]);
void sha256Octets(const uint8_t* data, size_t length, uint8_t sortie[32]);
void sha384Octets(const uint8_t* data, size_t length, uint8_t sortie[48]);
void sha512Octets(const uint8_t* data, size_t length, uint8_t sortie[64]);

/*! Empreinte SHA-256 d'un fichier, lue par blocs.
 *  Sert à sceller le manifeste de consigne, qui ne peut pas se hacher lui-même.
 *  @param chemin fichier à lire
 *  @return empreinte en hexadécimal majuscule, ou chaîne vide si illisible
 */
std::wstring sha256Fichier(const std::wstring& chemin);
