/*! \file
 *  \brief DES, one block in decryption: see des.h.
 *
 *  The tables are those of FIPS 46-3; their bit positions count from 1, the
 *  most significant bit of the block first, as the standard writes them.
 */
#include "des.h"

namespace {

const uint8_t IP[64] = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                         62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                         57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                         61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
const uint8_t FP[64] = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                         38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                         36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                         34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
const uint8_t E[48] = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
const uint8_t P[32] = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
const uint8_t PC1[56] = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                          10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                          63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                          14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
const uint8_t PC2[48] = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
                          26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
                          51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
const uint8_t SHIFTS[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
const uint8_t S[8][64] = {
	{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	  4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
	{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	  0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
	{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	  13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
	{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	  10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
	{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	  4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
	{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	  9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
	{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	  1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
	{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	  7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

/*! The bits of `in` (its `inBits` low bits, the first the most significant)
 *  taken in the order of `table`. */
uint64_t permute(uint64_t in, unsigned inBits, const uint8_t* table, unsigned outBits) {
	uint64_t out = 0;
	for (unsigned i = 0; i < outBits; ++i) out = (out << 1) | ((in >> (inBits - table[i])) & 1);
	return out;
}

//! The cipher function f: expansion, key mixing, S-boxes, permutation.
uint32_t feistel(uint32_t half, uint64_t subkey) {
	const uint64_t mixed = permute(half, 32, E, 48) ^ subkey;
	uint32_t sboxes = 0;
	for (int box = 0; box < 8; ++box) {
		const unsigned six = (unsigned)((mixed >> (42 - 6 * box)) & 0x3F);
		const unsigned row = ((six & 0x20) >> 4) | (six & 1), column = (six >> 1) & 0xF;
		sboxes = (sboxes << 4) | S[box][row * 16 + column];
	}
	return (uint32_t)permute(sboxes, 32, P, 32);
}

} // namespace

std::array<uint8_t, 8> desDecryptBlock(const std::array<uint8_t, 8>& key, const std::array<uint8_t, 8>& block) {
	uint64_t k = 0, b = 0;
	for (int i = 0; i < 8; ++i) { k = (k << 8) | key[i]; b = (b << 8) | block[i]; }
	// The sixteen subkeys, from the key's 56 bits rotated in two halves.
	uint64_t subkeys[16];
	const uint64_t cd = permute(k, 64, PC1, 56);
	uint32_t c = (uint32_t)(cd >> 28) & 0x0FFFFFFF, d = (uint32_t)cd & 0x0FFFFFFF;
	for (int round = 0; round < 16; ++round) {
		for (int s = 0; s < SHIFTS[round]; ++s) {
			c = ((c << 1) | (c >> 27)) & 0x0FFFFFFF;
			d = ((d << 1) | (d >> 27)) & 0x0FFFFFFF;
		}
		subkeys[round] = permute(((uint64_t)c << 28) | d, 56, PC2, 48);
	}
	// Decryption: the rounds of encryption, their subkeys in reverse order.
	const uint64_t ip = permute(b, 64, IP, 64);
	uint32_t left = (uint32_t)(ip >> 32), right = (uint32_t)ip;
	for (int round = 15; round >= 0; --round) {
		const uint32_t next = left ^ feistel(right, subkeys[round]);
		left = right;
		right = next;
	}
	const uint64_t out = permute(((uint64_t)right << 32) | left, 64, FP, 64);
	std::array<uint8_t, 8> plain{};
	for (int i = 0; i < 8; ++i) plain[i] = (uint8_t)(out >> (56 - 8 * i));
	return plain;
}
