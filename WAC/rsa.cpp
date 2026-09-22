/*  rsa.cpp — voir rsa.h.
 *
 *  Nombres représentés en mots de 32 bits, poids faible d'abord.
 *  Exponentiation par multiplication de Montgomery (variante CIOS) : elle évite
 *  toute division longue, la seule partie délicate d'une arithmétique
 *  multiprécision. Le module RSA est impair, condition de Montgomery.
 */
#include "rsa.h"
#include <cstring>

namespace {

using Mot = uint32_t;
using Nombre = std::vector<Mot>;

//! Grand-boutien -> mots de 32 bits poids faible d'abord, sur `k` mots.
Nombre depuisOctets(const uint8_t* p, size_t n, size_t k) {
	Nombre r(k, 0);
	for (size_t i = 0; i < n; ++i) {
		const size_t rang = n - 1 - i;              // rang de l'octet depuis la fin
		if (rang / 4 < k) r[rang / 4] |= (Mot)p[i] << (8 * (rang % 4));
	}
	return r;
}

//! a >= b ?
bool superieurOuEgal(const Nombre& a, const Nombre& b) {
	for (size_t i = a.size(); i-- > 0;) {
		if (a[i] != b[i]) return a[i] > b[i];
	}
	return true;
}

//! a -= b (a >= b)
void soustraire(Nombre& a, const Nombre& b) {
	uint64_t emprunt = 0;
	for (size_t i = 0; i < a.size(); ++i) {
		const uint64_t d = (uint64_t)a[i] - b[i] - emprunt;
		a[i] = (Mot)d;
		emprunt = (d >> 63) & 1;
	}
}

/*! Montgomery : r = a·b·R⁻¹ mod n, avec R = 2^(32k). `ninv` = −n⁻¹ mod 2³². */
void montgomery(const Nombre& a, const Nombre& b, const Nombre& n, Mot ninv, Nombre& r) {
	const size_t k = n.size();
	std::vector<Mot> t(k + 2, 0);
	for (size_t i = 0; i < k; ++i) {
		uint64_t retenue = 0;
		for (size_t j = 0; j < k; ++j) {
			const uint64_t s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + retenue;
			t[j] = (Mot)s;
			retenue = s >> 32;
		}
		uint64_t s = (uint64_t)t[k] + retenue;
		t[k] = (Mot)s;
		t[k + 1] = (Mot)(s >> 32);

		const Mot m = t[0] * ninv;
		retenue = ((uint64_t)t[0] + (uint64_t)m * n[0]) >> 32;
		for (size_t j = 1; j < k; ++j) {
			const uint64_t v = (uint64_t)t[j] + (uint64_t)m * n[j] + retenue;
			t[j - 1] = (Mot)v;
			retenue = v >> 32;
		}
		s = (uint64_t)t[k] + retenue;
		t[k - 1] = (Mot)s;
		t[k] = t[k + 1] + (Mot)(s >> 32);
	}
	r.assign(t.begin(), t.begin() + k);
	if (t[k] != 0 || superieurOuEgal(r, n)) soustraire(r, n);
}

//! −n⁻¹ mod 2³², par la méthode de Newton (n impair).
Mot inverseNegatif(Mot n0) {
	Mot x = 1;
	for (int i = 0; i < 5; ++i) x *= 2 - n0 * x;   // x = n0⁻¹ mod 2³²
	return (Mot)(0u - x);
}

//! R² mod n, par doublements successifs de 1 : 2·32k doublements réduits.
Nombre rCarre(const Nombre& n) {
	const size_t k = n.size();
	Nombre r(k, 0);
	r[0] = 1;
	for (size_t i = 0; i < 64 * k; ++i) {
		Mot haut = 0;
		for (size_t j = 0; j < k; ++j) {                // r <<= 1
			const Mot suivant = r[j] >> 31;
			r[j] = (r[j] << 1) | haut;
			haut = suivant;
		}
		if (haut || superieurOuEgal(r, n)) soustraire(r, n);
	}
	return r;
}

// Préfixes DigestInfo (DER) : AlgorithmIdentifier + en-tête de l'OCTET STRING.
const uint8_t PREFIXE_SHA1[]   = { 0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14 };
const uint8_t PREFIXE_SHA1_SANS_NULL[] = { 0x30,0x1F,0x30,0x07,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x04,0x14 };
const uint8_t PREFIXE_SHA256[] = { 0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20 };
const uint8_t PREFIXE_SHA256_SANS_NULL[] = { 0x30,0x2F,0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x04,0x20 };
const uint8_t PREFIXE_SHA384[] = { 0x30,0x41,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30 };
const uint8_t PREFIXE_SHA384_SANS_NULL[] = { 0x30,0x3F,0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x04,0x30 };
const uint8_t PREFIXE_SHA512[] = { 0x30,0x51,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40 };
const uint8_t PREFIXE_SHA512_SANS_NULL[] = { 0x30,0x4F,0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x04,0x40 };

/*! Le bloc déchiffré doit être EXACTEMENT 00 01 FF…FF 00 ‖ DigestInfo : toute
 *  autre forme est refusée. Une comparaison laxiste (DigestInfo cherché au lieu
 *  d'être reconstruit) est la faille classique qui permet de forger une
 *  signature quand l'exposant est petit. */
bool blocConforme(const std::vector<uint8_t>& em, const uint8_t* prefixe, size_t lp,
                  const uint8_t* h, size_t lh) {
	const size_t k = em.size();
	if (k < lp + lh + 11) return false;
	const size_t remplissage = k - 3 - lp - lh;
	if (em[0] != 0x00 || em[1] != 0x01) return false;
	for (size_t i = 0; i < remplissage; ++i) if (em[2 + i] != 0xFF) return false;
	if (em[2 + remplissage] != 0x00) return false;
	if (std::memcmp(em.data() + 3 + remplissage, prefixe, lp) != 0) return false;
	return std::memcmp(em.data() + 3 + remplissage + lp, h, lh) == 0;
}

} // namespace

bool RsaVerifierPkcs1(const uint8_t* module, size_t tailleModule,
                      const uint8_t* exposant, size_t tailleExposant,
                      const uint8_t* signature, size_t tailleSignature,
                      AlgoEmpreinte algo,
                      const uint8_t* empreinte, size_t tailleEmpreinte) {
	// Zéros de tête du module (INTEGER DER positif).
	while (tailleModule > 0 && *module == 0) { ++module; --tailleModule; }
	if (tailleModule < 64 || tailleModule > 1024) return false;   // 512 à 8192 bits
	if ((module[tailleModule - 1] & 1) == 0) return false;        // module pair : invalide
	if (tailleExposant == 0 || tailleExposant > 8) return false;
	while (tailleSignature > tailleModule && *signature == 0) { ++signature; --tailleSignature; }
	if (tailleSignature > tailleModule) return false;

	const size_t k = (tailleModule + 3) / 4;
	const Nombre n = depuisOctets(module, tailleModule, k);
	const Nombre s = depuisOctets(signature, tailleSignature, k);
	if (superieurOuEgal(s, n)) return false;                      // signature hors intervalle

	uint64_t e = 0;
	for (size_t i = 0; i < tailleExposant; ++i) e = (e << 8) | exposant[i];
	if (e < 3) return false;

	const Mot ninv = inverseNegatif(n[0]);
	const Nombre r2 = rCarre(n);
	Nombre base;
	montgomery(s, r2, n, ninv, base);                             // s·R mod n
	Nombre res = base;
	int bit = 63;
	while (bit >= 0 && !((e >> bit) & 1)) --bit;
	for (--bit; bit >= 0; --bit) {                                // carré et multiplication
		Nombre t;
		montgomery(res, res, n, ninv, t);
		res.swap(t);
		if ((e >> bit) & 1) { montgomery(res, base, n, ninv, t); res.swap(t); }
	}
	Nombre un(k, 0);
	un[0] = 1;
	Nombre m;
	montgomery(res, un, n, ninv, m);                              // sortie du domaine

	std::vector<uint8_t> em(tailleModule);
	for (size_t i = 0; i < tailleModule; ++i) {
		const size_t rang = tailleModule - 1 - i;
		em[i] = (uint8_t)(m[rang / 4] >> (8 * (rang % 4)));
	}
	switch (algo) {
	case AlgoEmpreinte::Sha1:
		if (tailleEmpreinte != 20) return false;
		return blocConforme(em, PREFIXE_SHA1, sizeof(PREFIXE_SHA1), empreinte, 20)
		    || blocConforme(em, PREFIXE_SHA1_SANS_NULL, sizeof(PREFIXE_SHA1_SANS_NULL), empreinte, 20);
	case AlgoEmpreinte::Sha256:
		if (tailleEmpreinte != 32) return false;
		return blocConforme(em, PREFIXE_SHA256, sizeof(PREFIXE_SHA256), empreinte, 32)
		    || blocConforme(em, PREFIXE_SHA256_SANS_NULL, sizeof(PREFIXE_SHA256_SANS_NULL), empreinte, 32);
	case AlgoEmpreinte::Sha384:
		if (tailleEmpreinte != 48) return false;
		return blocConforme(em, PREFIXE_SHA384, sizeof(PREFIXE_SHA384), empreinte, 48)
		    || blocConforme(em, PREFIXE_SHA384_SANS_NULL, sizeof(PREFIXE_SHA384_SANS_NULL), empreinte, 48);
	case AlgoEmpreinte::Sha512:
		if (tailleEmpreinte != 64) return false;
		return blocConforme(em, PREFIXE_SHA512, sizeof(PREFIXE_SHA512), empreinte, 64)
		    || blocConforme(em, PREFIXE_SHA512_SANS_NULL, sizeof(PREFIXE_SHA512_SANS_NULL), empreinte, 64);
	default:
		return false;
	}
}
