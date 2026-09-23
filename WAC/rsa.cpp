/*  rsa.cpp — see rsa.h.
 *
 *  Numbers are held in 32-bit words, least significant first.
 *  Exponentiation by Montgomery multiplication (CIOS variant): it avoids any
 *  long division, the only tricky part of multi-precision arithmetic. The RSA
 *  modulus is odd, which Montgomery requires.
 */
#include "rsa.h"
#include <cstring>

namespace {

using Word = uint32_t;
using Count = std::vector<Word>;

//! Big-endian -> 32-bit words, least significant first, over `k` words.
Count fromBytes(const uint8_t* p, size_t n, size_t k) {
	Count r(k, 0);
	for (size_t i = 0; i < n; ++i) {
		const size_t rank = n - 1 - i;              // rank of the byte counted from the end
		if (rank / 4 < k) r[rank / 4] |= (Word)p[i] << (8 * (rank % 4));
	}
	return r;
}

//! a >= b ?
bool greaterOrEqual(const Count& a, const Count& b) {
	for (size_t i = a.size(); i-- > 0;) {
		if (a[i] != b[i]) return a[i] > b[i];
	}
	return true;
}

//! a -= b (a >= b)
void subtract(Count& a, const Count& b) {
	uint64_t borrow = 0;
	for (size_t i = 0; i < a.size(); ++i) {
		const uint64_t d = (uint64_t)a[i] - b[i] - borrow;
		a[i] = (Word)d;
		borrow = (d >> 63) & 1;
	}
}

/*! Montgomery: r = a·b·R⁻¹ mod n, with R = 2^(32k). `ninv` = −n⁻¹ mod 2³². */
void montgomery(const Count& a, const Count& b, const Count& n, Word ninv, Count& r) {
	const size_t k = n.size();
	std::vector<Word> t(k + 2, 0);
	for (size_t i = 0; i < k; ++i) {
		uint64_t kept = 0;
		for (size_t j = 0; j < k; ++j) {
			const uint64_t s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + kept;
			t[j] = (Word)s;
			kept = s >> 32;
		}
		uint64_t s = (uint64_t)t[k] + kept;
		t[k] = (Word)s;
		t[k + 1] = (Word)(s >> 32);

		const Word m = t[0] * ninv;
		kept = ((uint64_t)t[0] + (uint64_t)m * n[0]) >> 32;
		for (size_t j = 1; j < k; ++j) {
			const uint64_t v = (uint64_t)t[j] + (uint64_t)m * n[j] + kept;
			t[j - 1] = (Word)v;
			kept = v >> 32;
		}
		s = (uint64_t)t[k] + kept;
		t[k - 1] = (Word)s;
		t[k] = t[k + 1] + (Word)(s >> 32);
	}
	r.assign(t.begin(), t.begin() + k);
	if (t[k] != 0 || greaterOrEqual(r, n)) subtract(r, n);
}

//! −n⁻¹ mod 2³², by Newton's method (n odd).
Word negativeInverse(Word n0) {
	Word x = 1;
	for (int i = 0; i < 5; ++i) x *= 2 - n0 * x;   // x = n0⁻¹ mod 2³²
	return (Word)(0u - x);
}

//! R² mod n, by successive doublings of 1: 2·32k reduced doublings.
Count rSquared(const Count& n) {
	const size_t k = n.size();
	Count r(k, 0);
	r[0] = 1;
	for (size_t i = 0; i < 64 * k; ++i) {
		Word high = 0;
		for (size_t j = 0; j < k; ++j) {                // r <<= 1
			const Word next = r[j] >> 31;
			r[j] = (r[j] << 1) | high;
			high = next;
		}
		if (high || greaterOrEqual(r, n)) subtract(r, n);
	}
	return r;
}

// DigestInfo prefixes (DER): AlgorithmIdentifier + OCTET STRING header.
const uint8_t PREFIX_SHA1[]   = { 0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14 };
const uint8_t PREFIX_SHA1_WITHOUT_NULL[] = { 0x30,0x1F,0x30,0x07,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x04,0x14 };
const uint8_t PREFIX_SHA256[] = { 0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20 };
const uint8_t PREFIX_SHA256_WITHOUT_NULL[] = { 0x30,0x2F,0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x04,0x20 };
const uint8_t PREFIX_SHA384[] = { 0x30,0x41,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30 };
const uint8_t PREFIX_SHA384_WITHOUT_NULL[] = { 0x30,0x3F,0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x04,0x30 };
const uint8_t PREFIX_SHA512[] = { 0x30,0x51,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40 };
const uint8_t PREFIX_SHA512_WITHOUT_NULL[] = { 0x30,0x4F,0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x04,0x40 };

/*! The decrypted block must be EXACTLY 00 01 FF…FF 00 ‖ DigestInfo: any other
 *  form is rejected. A lax comparison (DigestInfo searched for instead of
 *  rebuilt) is the classic flaw that allows forging a signature when the
 *  exponent is small. */
bool blockIsWellFormed(const std::vector<uint8_t>& em, const uint8_t* prefix, size_t lp,
                  const uint8_t* h, size_t lh) {
	const size_t k = em.size();
	if (k < lp + lh + 11) return false;
	const size_t padding = k - 3 - lp - lh;
	if (em[0] != 0x00 || em[1] != 0x01) return false;
	for (size_t i = 0; i < padding; ++i) if (em[2 + i] != 0xFF) return false;
	if (em[2 + padding] != 0x00) return false;
	if (std::memcmp(em.data() + 3 + padding, prefix, lp) != 0) return false;
	return std::memcmp(em.data() + 3 + padding + lp, h, lh) == 0;
}

} // namespace

bool RsaVerifyPkcs1(const uint8_t* module, size_t modulusSize,
                      const uint8_t* exponent, size_t exponentSize,
                      const uint8_t* signature, size_t signatureSize,
                      DigestAlgorithm algo,
                      const uint8_t* fingerprint, size_t digestSize) {
	// Leading zeros of the modulus (positive DER INTEGER).
	while (modulusSize > 0 && *module == 0) { ++module; --modulusSize; }
	if (modulusSize < 64 || modulusSize > 1024) return false;   // 512 to 8192 bits
	if ((module[modulusSize - 1] & 1) == 0) return false;        // even modulus: invalid
	if (exponentSize == 0 || exponentSize > 8) return false;
	while (signatureSize > modulusSize && *signature == 0) { ++signature; --signatureSize; }
	if (signatureSize > modulusSize) return false;

	const size_t k = (modulusSize + 3) / 4;
	const Count n = fromBytes(module, modulusSize, k);
	const Count s = fromBytes(signature, signatureSize, k);
	if (greaterOrEqual(s, n)) return false;                      // signature hors intervalle

	uint64_t e = 0;
	for (size_t i = 0; i < exponentSize; ++i) e = (e << 8) | exponent[i];
	if (e < 3) return false;

	const Word ninv = negativeInverse(n[0]);
	const Count r2 = rSquared(n);
	Count base;
	montgomery(s, r2, n, ninv, base);                             // s·R mod n
	Count res = base;
	int bit = 63;
	while (bit >= 0 && !((e >> bit) & 1)) --bit;
	for (--bit; bit >= 0; --bit) {                                // square and multiply
		Count t;
		montgomery(res, res, n, ninv, t);
		res.swap(t);
		if ((e >> bit) & 1) { montgomery(res, base, n, ninv, t); res.swap(t); }
	}
	Count un(k, 0);
	un[0] = 1;
	Count m;
	montgomery(res, un, n, ninv, m);                              // out of the Montgomery domain

	std::vector<uint8_t> em(modulusSize);
	for (size_t i = 0; i < modulusSize; ++i) {
		const size_t rank = modulusSize - 1 - i;
		em[i] = (uint8_t)(m[rank / 4] >> (8 * (rank % 4)));
	}
	switch (algo) {
	case DigestAlgorithm::Sha1:
		if (digestSize != 20) return false;
		return blockIsWellFormed(em, PREFIX_SHA1, sizeof(PREFIX_SHA1), fingerprint, 20)
		    || blockIsWellFormed(em, PREFIX_SHA1_WITHOUT_NULL, sizeof(PREFIX_SHA1_WITHOUT_NULL), fingerprint, 20);
	case DigestAlgorithm::Sha256:
		if (digestSize != 32) return false;
		return blockIsWellFormed(em, PREFIX_SHA256, sizeof(PREFIX_SHA256), fingerprint, 32)
		    || blockIsWellFormed(em, PREFIX_SHA256_WITHOUT_NULL, sizeof(PREFIX_SHA256_WITHOUT_NULL), fingerprint, 32);
	case DigestAlgorithm::Sha384:
		if (digestSize != 48) return false;
		return blockIsWellFormed(em, PREFIX_SHA384, sizeof(PREFIX_SHA384), fingerprint, 48)
		    || blockIsWellFormed(em, PREFIX_SHA384_WITHOUT_NULL, sizeof(PREFIX_SHA384_WITHOUT_NULL), fingerprint, 48);
	case DigestAlgorithm::Sha512:
		if (digestSize != 64) return false;
		return blockIsWellFormed(em, PREFIX_SHA512, sizeof(PREFIX_SHA512), fingerprint, 64)
		    || blockIsWellFormed(em, PREFIX_SHA512_WITHOUT_NULL, sizeof(PREFIX_SHA512_WITHOUT_NULL), fingerprint, 64);
	default:
		return false;
	}
}
