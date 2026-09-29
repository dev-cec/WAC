#include "sha.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <vector>
#include <filesystem>

/*! \file
 *  \brief SHA-1, SHA-256, SHA-384 and SHA-512, computed incrementally.
 *
 *  See sha.h. Both algorithms follow FIPS 180-4; the comments do not
 *  restate the standard, they point out the only places where an
 *  implementation goes wrong: the final padding and the bit length, written
 *  BIG-endian while the rest of the project reads little-endian.
 */

namespace {

inline uint32_t rotl(uint32_t v, int n){ return (uint32_t)((v << n) | (v >> (32 - n))); }
inline uint32_t rotr(uint32_t v, int n){ return (uint32_t)((v >> n) | (v << (32 - n))); }

//! Big-endian 32-bit word, the byte order of both algorithms.
inline uint32_t be32(const uint8_t* p){
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
	     | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

const uint32_t K256[64] = {
	0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
	0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
	0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
	0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
	0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
	0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
	0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
	0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};


/*! Padding shared by both algorithms: a 0x80 byte, zeros, then the message
 *  length IN BITS on 8 big-endian bytes.
 *  @param inBlock bytes already in the current block
 *  @param block 64-byte working block
 *  @param bytes total message length, in bytes
 *  @param compress compression function of a block
 */
template <typename F>
void finish(size_t& inBlock, uint8_t* block, uint64_t bytes, F compress){
	block[inBlock++] = 0x80;
	// The length takes the last 8 bytes: if there is no room left, this block is
	// closed and the length goes into the next one.
	if (inBlock > 56){
		std::memset(block + inBlock, 0, 64 - inBlock);
		compress(block);
		inBlock = 0;
	}
	std::memset(block + inBlock, 0, 56 - inBlock);
	const uint64_t bits = bytes * 8;
	for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
	compress(block);
}

/*! Accumulation by 64-byte blocks, shared by both algorithms. */
template <typename F>
void add(const uint8_t* data, size_t length, uint8_t* block, size_t& inBlock,
             uint64_t& bytes, F compress){
	if (!data) return;
	bytes += length;
	while (length){
		const size_t place = 64 - inBlock;
		const size_t n = length < place ? length : place;
		std::memcpy(block + inBlock, data, n);
		inBlock += n; data += n; length -= n;
		if (inBlock == 64){ compress(block); inBlock = 0; }
	}
}

} // namespace

std::wstring toHexadecimal(const uint8_t* bytes, size_t n){
	static const wchar_t* d = L"0123456789ABCDEF";
	std::wstring r;
	r.reserve(n * 2);
	for (size_t i = 0; i < n; ++i){
		r.push_back(d[bytes[i] >> 4]);
		r.push_back(d[bytes[i] & 0x0F]);
	}
	return r;
}

// ---------------------------------------------------------------------------
//  SHA-1
// ---------------------------------------------------------------------------

void Sha1Stream::compress(const uint8_t* block){
	uint32_t w[80];
	for (int i = 0; i < 16; ++i) w[i] = be32(block + 4 * i);
	for (int i = 16; i < 80; ++i) w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

	uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3], e = state_[4];
	for (int i = 0; i < 80; ++i){
		uint32_t f, k;
		if      (i < 20){ f = (b & c) | (~b & d);            k = 0x5A827999u; }
		else if (i < 40){ f = b ^ c ^ d;                     k = 0x6ED9EBA1u; }
		else if (i < 60){ f = (b & c) | (b & d) | (c & d);    k = 0x8F1BBCDCu; }
		else            { f = b ^ c ^ d;                     k = 0xCA62C1D6u; }
		const uint32_t t = rotl(a, 5) + f + e + k + w[i];
		e = d; d = c; c = rotl(b, 30); b = a; a = t;
	}
	state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d; state_[4] += e;
}

void Sha1Stream::update(const uint8_t* data, size_t length){
	add(data, length, block_, inBlock_, bytes_,
	        [this](const uint8_t* b){ compress(b); });
}

void Sha1Stream::digest(uint8_t d[20]){
	finish(inBlock_, block_, bytes_, [this](const uint8_t* b){ compress(b); });
	for (int i = 0; i < 5; ++i)
		for (int j = 0; j < 4; ++j) d[4 * i + j] = (uint8_t)(state_[i] >> (24 - 8 * j));
}

std::wstring Sha1Stream::hexDigest(){
	uint8_t d[20];
	digest(d);
	return toHexadecimal(d, 20);
}

void sha1Bytes(const uint8_t* data, size_t length, uint8_t output[20]){
	Sha1Stream s; s.update(data, length); s.digest(output);
}

// ---------------------------------------------------------------------------
//  SHA-256
// ---------------------------------------------------------------------------

void Sha256Stream::compress(const uint8_t* block){
	uint32_t w[64];
	for (int i = 0; i < 16; ++i) w[i] = be32(block + 4 * i);
	for (int i = 16; i < 64; ++i){
		const uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
		const uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19)  ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
	uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
	for (int i = 0; i < 64; ++i){
		const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
		const uint32_t ch = (e & f) ^ (~e & g);
		const uint32_t t1 = h + S1 + ch + K256[i] + w[i];
		const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
		const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
		const uint32_t t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
	state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256Stream::update(const uint8_t* data, size_t length){
	add(data, length, block_, inBlock_, bytes_,
	        [this](const uint8_t* b){ compress(b); });
}

void Sha256Stream::digest(uint8_t d[32]){
	finish(inBlock_, block_, bytes_, [this](const uint8_t* b){ compress(b); });
	for (int i = 0; i < 8; ++i)
		for (int j = 0; j < 4; ++j) d[4 * i + j] = (uint8_t)(state_[i] >> (24 - 8 * j));
}

std::wstring Sha256Stream::hexDigest(){
	uint8_t d[32];
	digest(d);
	return toHexadecimal(d, 32);
}

void sha256Bytes(const uint8_t* data, size_t length, uint8_t output[32]){
	Sha256Stream s; s.update(data, length); s.digest(output);
}

std::wstring sha256OfFile(const std::wstring& path){
	std::ifstream f(std::filesystem::path(path), std::ios::binary);
	if (!f) return L"";
	Sha256Stream stream;
	std::vector<char> buffer(1 << 16);
	while (f.read(buffer.data(), (std::streamsize)buffer.size()) || f.gcount())
		stream.update(reinterpret_cast<const uint8_t*>(buffer.data()), (size_t)f.gcount());
	return stream.hexDigest();
}

// ---------------------------------------------------------------------------
//  SHA-512 / SHA-384 (FIPS 180-4, section 6.4)
// ---------------------------------------------------------------------------

namespace {
const uint64_t K512[80] = {
	0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,0x3956c25bf348b538ULL,
	0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,0xd807aa98a3030242ULL,0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL,0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,0x983e5152ee66dfabULL,
	0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL,0x142929670a0e6e70ULL,0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,
	0x53380d139d95b3dfULL,0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,
	0x682e6ff3d6b2b8a3ULL,0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,0xca273eceea26619cULL,
	0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL,0x1b710b35131c471bULL,0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL,0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL };
inline uint64_t rotr64(uint64_t v, int n){ return (v >> n) | (v << (64 - n)); }
inline uint64_t be64(const uint8_t* p){ uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | p[i]; return v; }
} // namespace

Sha512Stream::Sha512Stream(bool variant384) : variant384_(variant384) {
	static const uint64_t H512[8] = { 0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
	                                  0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL };
	static const uint64_t H384[8] = { 0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,
	                                  0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL };
	for (int i = 0; i < 8; ++i) state_[i] = variant384 ? H384[i] : H512[i];
}

void Sha512Stream::compress(const uint8_t* block){
	uint64_t w[80];
	for (int i = 0; i < 16; ++i) w[i] = be64(block + 8 * i);
	for (int i = 16; i < 80; ++i){
		const uint64_t s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
		const uint64_t s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	uint64_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
	uint64_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
	for (int i = 0; i < 80; ++i){
		const uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
		const uint64_t ch = (e & f) ^ (~e & g);
		const uint64_t t1 = h + S1 + ch + K512[i] + w[i];
		const uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
		const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
		const uint64_t t2 = S0 + maj;
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
	state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha512Stream::update(const uint8_t* data, size_t length){
	bytes_ += length;
	while (length){
		const size_t n = std::min(length, sizeof(block_) - inBlock_);
		std::memcpy(block_ + inBlock_, data, n);
		inBlock_ += n; data += n; length -= n;
		if (inBlock_ == sizeof(block_)){ compress(block_); inBlock_ = 0; }
	}
}

void Sha512Stream::digest(uint8_t* output){
	// Padding: 0x80, zeros, then the bit length on 128 bits.
	const uint64_t bits = bytes_ * 8;
	block_[inBlock_++] = 0x80;
	if (inBlock_ > 112){
		std::memset(block_ + inBlock_, 0, 128 - inBlock_);
		compress(block_);
		inBlock_ = 0;
	}
	std::memset(block_ + inBlock_, 0, 120 - inBlock_);
	for (int i = 0; i < 8; ++i) block_[120 + i] = (uint8_t)(bits >> (56 - 8 * i));
	compress(block_);
	const size_t n = size();
	for (size_t i = 0; i < n; ++i) output[i] = (uint8_t)(state_[i / 8] >> (56 - 8 * (i % 8)));
}

void sha384Bytes(const uint8_t* data, size_t length, uint8_t output[48]){
	Sha512Stream s(true); s.update(data, length); s.digest(output);
}

void sha512Bytes(const uint8_t* data, size_t length, uint8_t output[64]){
	Sha512Stream s(false); s.update(data, length); s.digest(output);
}
