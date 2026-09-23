/*! \file
 *  \brief SHA-1 AND SHA-256 FINGERPRINTS, computed while writing.
 *
 *  WHY TWO MORE ALGORITHMS. An exhibit must carry a fingerprint that identifies
 *  it beyond dispute. MD5 alone no longer does: collisions have been producible
 *  at will since 2008, so a defence can argue that a file with the same
 *  fingerprint is not the seized file. SHA-1 is the fingerprint the field's
 *  procedures and tools still ask for, but it too has been broken for
 *  collisions since 2017 (SHAttered). Hence all three, SHA-256 being the only
 *  undisputed one: crafting a file that matches all three at once is beyond the
 *  state of the art.
 *
 *  WHY NOT THE SYSTEM'S API. `bcrypt.dll` would do the computation, but WAC
 *  refuses to depend on a library of the examined system when a thirty-line
 *  public algorithm is enough: the executable stays standalone, and the
 *  fingerprint stays reproducible by a third party.
 *
 *  WHY "WHILE WRITING". The exhibit's bytes already pass through memory during
 *  extraction. Hashing them at that point avoids reading the copy back from the
 *  collection medium — on a USB stick, that re-read took almost half the
 *  extraction time. And the fingerprint then bears on what was actually read
 *  from the volume, not on a re-read that could differ.
 *
 *  Same interface as Md5Stream (see quickdigest5.h), so that the three
 *  fingerprints are computed in the same loop.
 *
 *  Portable C++, no dependency: verifiable outside Windows, and checked against
 *  the public test vectors of both algorithms (see sha_test).
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

/*! SHA-1, computed incrementally. */
class Sha1Stream final {
public:
	/*! Adds bytes to the computation.
	 *  @param data,length the bytes. */
	void update(const uint8_t* data, size_t length);
	/*! Ends the computation.
	 *  Call only once: the computation is over afterwards.
	 *  @return the digest in uppercase hexadecimal. */
	std::wstring hexDigest();
	/*! Ends the computation and writes the raw digest. Same constraint: only
	 *  once, and exclusive of hexDigest.
	 *  @param output the 20 bytes of the digest. */
	void digest(uint8_t output[20]);
private:
	uint32_t state_[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };
	uint8_t  block_[64] = { 0 };
	size_t   inBlock_ = 0;
	uint64_t bytes_ = 0;
	void compress(const uint8_t* block);
};

/*! SHA-256, computed incrementally. */
class Sha256Stream final {
public:
	/*! Adds bytes to the computation.
	 *  @param data,length the bytes. */
	void update(const uint8_t* data, size_t length);
	/*! Ends the computation.
	 *  Call only once: the computation is over afterwards.
	 *  @return the digest in uppercase hexadecimal. */
	std::wstring hexDigest();
	/*! Ends the computation and writes the raw digest. Same constraint: only
	 *  once, and exclusive of hexDigest.
	 *  @param output the 32 bytes of the digest. */
	void digest(uint8_t output[32]);
private:
	uint32_t state_[8] = { 0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
	                      0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u };
	uint8_t  block_[64] = { 0 };
	size_t   inBlock_ = 0;
	uint64_t bytes_ = 0;
	void compress(const uint8_t* block);
};

/*! SHA-512, and SHA-384, its truncated variant (other initial constants,
 *  48 bytes returned).
 *
 *  WHY. Microsoft now signs with the "Windows Production PCA 2023" chain, in
 *  sha384WithRSAEncryption: seen on Defender's catalog (wd_mpextdeps.cat) of a
 *  Windows 11 installation. Without SHA-384, a file signed by that chain cannot
 *  be authenticated — and Microsoft's move to that chain will make that share
 *  grow. */
class Sha512Stream final {
public:
	/*! @param variant384 computes SHA-384 instead of SHA-512. */
	explicit Sha512Stream(bool variant384 = false);
	/*! Adds bytes to the computation. */
	void update(const uint8_t* data, size_t length);
	/*! Ends the computation and writes the digest: 64 bytes, or 48 for SHA-384.
	 *  @param output buffer of at least size() bytes. */
	void digest(uint8_t* output);
	/*! Digest size in bytes: 48 for SHA-384, 64 for SHA-512. */
	size_t size() const { return variant384_ ? 48 : 64; }
private:
	uint64_t state_[8];
	uint8_t  block_[128] = { 0 };
	size_t   inBlock_ = 0;
	uint64_t bytes_ = 0;
	bool     variant384_;
	void compress(const uint8_t* block);
};

/*! Raw digests of a buffer in one pass. */
void sha1Bytes(const uint8_t* data, size_t length, uint8_t output[20]);
void sha256Bytes(const uint8_t* data, size_t length, uint8_t output[32]);
void sha384Bytes(const uint8_t* data, size_t length, uint8_t output[48]);
void sha512Bytes(const uint8_t* data, size_t length, uint8_t output[64]);

/*! SHA-256 fingerprint of a file, read by blocks.
 *  Used to seal the exhibit store manifest, which cannot hash itself.
 *  @param path file to read
 *  @return uppercase hexadecimal digest, or an empty string if unreadable
 */
std::wstring sha256OfFile(const std::wstring& path);
