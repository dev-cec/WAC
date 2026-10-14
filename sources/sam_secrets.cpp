/*! \file
 *  \brief Implementation of the SAM hash decryption (see sam_secrets.h).
 */
#include "sam_secrets.h"

#include <array>
#include <cstring>
#include <windows.h>
#include <bcrypt.h>
#include "tools.h"
#include "sha.h"
#include "quickdigest5.h"

namespace {

// --- small helpers ----------------------------------------------------------

//! MD5 of a byte buffer, raw 16 bytes.
std::vector<uint8_t> md5(const std::vector<uint8_t>& data) {
	return QuickDigest5::digestString(std::string(reinterpret_cast<const char*>(data.data()), data.size()));
}

//! Concatenates byte buffers into one.
std::vector<uint8_t> join(std::initializer_list<std::vector<uint8_t>> parts) {
	std::vector<uint8_t> out;
	for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
	return out;
}

//! A 32-bit value as 4 little-endian bytes.
std::vector<uint8_t> le32(uint32_t v) {
	return { uint8_t(v), uint8_t(v >> 8), uint8_t(v >> 16), uint8_t(v >> 24) };
}

//! Turns a class name such as "a1b2c3d4" into its 4 bytes; empty if not hex.
std::vector<uint8_t> hexToBytes(const std::wstring& hex) {
	if (hex.size() % 2 != 0) return {};
	std::vector<uint8_t> out;
	out.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2) {
		auto nibble = [](wchar_t c) -> int {
			if (c >= L'0' && c <= L'9') return c - L'0';
			if (c >= L'a' && c <= L'f') return c - L'a' + 10;
			if (c >= L'A' && c <= L'F') return c - L'A' + 10;
			return -1;
		};
		const int hi = nibble(hex[i]), lo = nibble(hex[i + 1]);
		if (hi < 0 || lo < 0) return {};
		out.push_back(uint8_t((hi << 4) | lo));
	}
	return out;
}

//! The class name of a subkey (used for the boot key); empty on failure.
std::wstring readClass(ORHKEY controlSet, const std::wstring& subKey) {
	ORHKEY key = NULL;
	if (OROpenKey(controlSet, subKey.c_str(), &key) != ERROR_SUCCESS) return {};
	wchar_t cls[64] = L"";
	DWORD clsLen = (DWORD)(sizeof(cls) / sizeof(cls[0]));
	const DWORD r = ORQueryInfoKey(key, cls, &clsLen, NULL, NULL, NULL, NULL,
	                               NULL, NULL, NULL, NULL);
	ORCloseKey(key);
	if (r != ERROR_SUCCESS) return {};
	return std::wstring(cls, clsLen);
}

// --- keyed stream and block ciphers (BCrypt for AES and DES) ----------------

/*! RC4 with a given key (the quarantine RC4 in defender_history.cpp uses a
 *  fixed key and cannot be reused here). */
std::vector<uint8_t> rc4(const std::vector<uint8_t>& key, const uint8_t* data, size_t size) {
	uint8_t s[256];
	for (int n = 0; n < 256; ++n) s[n] = (uint8_t)n;
	uint8_t j = 0;
	for (int n = 0; n < 256; ++n) {
		j = (uint8_t)(j + s[n] + key[n % key.size()]);
		std::swap(s[n], s[j]);
	}
	std::vector<uint8_t> out(size);
	uint8_t a = 0, b = 0;
	for (size_t n = 0; n < size; ++n) {
		a = (uint8_t)(a + 1);
		b = (uint8_t)(b + s[a]);
		std::swap(s[a], s[b]);
		out[n] = data[n] ^ s[(uint8_t)(s[a] + s[b])];
	}
	return out;
}

/*! One pass of a BCrypt block cipher in decryption, no padding.
 *  @param algo BCRYPT_AES_ALGORITHM or BCRYPT_DES_ALGORITHM
 *  @param chaining BCRYPT_CHAIN_MODE_CBC or BCRYPT_CHAIN_MODE_ECB
 *  @param key the symmetric key
 *  @param iv the initialisation vector (copied; CBC only), or empty for ECB
 *  @param data the ciphertext (a multiple of the block size)
 *  @return the plaintext, or an empty vector on any failure */
std::vector<uint8_t> blockDecrypt(const wchar_t* algo, const wchar_t* chaining,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& iv,
                                  const std::vector<uint8_t>& data) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, algo, NULL, 0))) return {};
	std::vector<uint8_t> out;
	BCRYPT_KEY_HANDLE hKey = NULL;
	do {
		if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
		        (PUCHAR)chaining, (ULONG)((wcslen(chaining) + 1) * sizeof(wchar_t)), 0))) break;
		if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
		        (PUCHAR)key.data(), (ULONG)key.size(), 0))) break;
		std::vector<uint8_t> ivCopy = iv;   // BCryptDecrypt overwrites the IV
		out.resize(data.size());
		ULONG written = 0;
		const NTSTATUS r = BCryptDecrypt(hKey, (PUCHAR)data.data(), (ULONG)data.size(),
		        NULL, ivCopy.empty() ? NULL : ivCopy.data(), (ULONG)ivCopy.size(),
		        out.data(), (ULONG)out.size(), &written, 0);
		if (!BCRYPT_SUCCESS(r)) { out.clear(); break; }
		out.resize(written);
	} while (false);
	if (hKey) BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	return out;
}

std::vector<uint8_t> aesCbcDecrypt(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv,
                                   const std::vector<uint8_t>& data) {
	return blockDecrypt(BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_CBC, key, iv, data);
}

// --- the DES layer keyed on the RID -----------------------------------------

//! Spreads 7 bytes into an 8-byte DES key, each byte shifted left by one.
std::array<uint8_t, 8> transformKey(const std::array<uint8_t, 7>& in) {
	std::array<uint8_t, 8> out{};
	out[0] = in[0] >> 1;
	out[1] = ((in[0] & 0x01) << 6) | (in[1] >> 2);
	out[2] = ((in[1] & 0x03) << 5) | (in[2] >> 3);
	out[3] = ((in[2] & 0x07) << 4) | (in[3] >> 4);
	out[4] = ((in[3] & 0x0F) << 3) | (in[4] >> 5);
	out[5] = ((in[4] & 0x1F) << 2) | (in[5] >> 6);
	out[6] = ((in[5] & 0x3F) << 1) | (in[6] >> 7);
	out[7] = in[6] & 0x7F;
	for (auto& b : out) b = (uint8_t)((b << 1) & 0xFE);
	return out;
}

//! The two DES keys derived from a RID (the last layer over NT and LM hashes).
void ridKeys(uint32_t rid, std::vector<uint8_t>& key1, std::vector<uint8_t>& key2) {
	const uint8_t r[4] = { uint8_t(rid), uint8_t(rid >> 8), uint8_t(rid >> 16), uint8_t(rid >> 24) };
	const std::array<uint8_t, 7> a = { r[0], r[1], r[2], r[3], r[0], r[1], r[2] };
	const std::array<uint8_t, 7> b = { r[3], r[0], r[1], r[2], r[3], r[0], r[1] };
	const auto k1 = transformKey(a), k2 = transformKey(b);
	key1.assign(k1.begin(), k1.end());
	key2.assign(k2.begin(), k2.end());
}

/*! Removes the RID-keyed DES layer from a 16-byte block: the two halves are DES
 *  decrypted with the two RID keys. Gives the final NT or LM hash.
 *  @return the 16-byte hash, or an empty vector on failure */
std::vector<uint8_t> removeDes(uint32_t rid, const std::vector<uint8_t>& block) {
	if (block.size() < 16) return {};
	std::vector<uint8_t> key1, key2;
	ridKeys(rid, key1, key2);
	const std::vector<uint8_t> a = blockDecrypt(BCRYPT_DES_ALGORITHM, BCRYPT_CHAIN_MODE_ECB,
	        key1, {}, std::vector<uint8_t>(block.begin(), block.begin() + 8));
	const std::vector<uint8_t> b = blockDecrypt(BCRYPT_DES_ALGORITHM, BCRYPT_CHAIN_MODE_ECB,
	        key2, {}, std::vector<uint8_t>(block.begin() + 8, block.begin() + 16));
	if (a.size() != 8 || b.size() != 8) return {};
	return join({ a, b });
}

// --- the SAM structures -----------------------------------------------------

// Offsets, in the account's V value, of the (offset, length) entry of each
// hash field (relative to 0xCC, documented in impacket and confirmed in the VM).
const size_t V_BASE = 0xCC;
const size_t V_LM_HASH = 0x9C, V_NT_HASH = 0xA8, V_NT_HISTORY = 0xB4, V_LM_HISTORY = 0xC0;

// The per-account RC4 salts (revision 1): "NTPASSWORD\0" and "LMPASSWORD\0".
const std::vector<uint8_t> NT_SALT = { 'N','T','P','A','S','S','W','O','R','D',0 };
const std::vector<uint8_t> LM_SALT = { 'L','M','P','A','S','S','W','O','R','D',0 };
// ... and those of the history, which differ: with the current hash's salts,
// the history of a Windows 8.1 account did not hold its previous password's
// hash (measured in the VM against MD4 of that password).
const std::vector<uint8_t> NT_HISTORY_SALT = { 'N','T','P','A','S','S','W','O','R','D','H','I','S','T','O','R','Y',0 };
const std::vector<uint8_t> LM_HISTORY_SALT = { 'L','M','P','A','S','S','W','O','R','D','H','I','S','T','O','R','Y',0 };

//! The bytes of a V field, from its (offset, length) entry; empty if out of range.
std::vector<uint8_t> field(const std::vector<uint8_t>& v, size_t entry) {
	if (v.size() < entry + 8) return {};
	uint32_t off = 0, len = 0;
	memcpy(&off, v.data() + entry, 4);
	memcpy(&len, v.data() + entry + 4, 4);
	const size_t start = V_BASE + off;
	if (len == 0 || start + len > v.size()) return {};
	return std::vector<uint8_t>(v.begin() + start, v.begin() + start + len);
}

/*! Decrypts one encrypted hash blob (RC4 revision 1, or AES revision 2) to the
 *  block still under the RID-keyed DES layer.
 *  @param blob the field, as `field` returns it
 *  @param rid the account RID
 *  @param hashedBootKey the hashed boot key
 *  @param rc4Salt NT_SALT or LM_SALT, for the RC4 revision only
 *  @return the 16-byte block before DES, or empty if no hash is present */
std::vector<uint8_t> decryptBlob(const std::vector<uint8_t>& blob, uint32_t rid,
                                 const std::vector<uint8_t>& hashedBootKey,
                                 const std::vector<uint8_t>& rc4Salt) {
	if (blob.size() < 4) return {};
	const uint16_t revision = uint16_t(blob[2] | (blob[3] << 8));
	if (revision == 1) {
		// SAM_HASH: 4-byte header, then a 16-byte RC4-encrypted hash.
		if (blob.size() < 4 + 16) return {};
		const std::vector<uint8_t> key = md5(join({ hashedBootKey, le32(rid), rc4Salt }));
		return rc4(key, blob.data() + 4, 16);
	}
	if (revision == 2) {
		// SAM_HASH_AES: PekID(2), Revision(2), DataOffset(4), Salt(16), data.
		if (blob.size() < 24 + 16) return {};
		const std::vector<uint8_t> salt(blob.begin() + 8, blob.begin() + 24);
		const std::vector<uint8_t> data(blob.begin() + 24, blob.end());
		const std::vector<uint8_t> plain = aesCbcDecrypt(hashedBootKey, salt, data);
		if (plain.size() < 16) return {};
		return std::vector<uint8_t>(plain.begin(), plain.begin() + 16);
	}
	return {};
}

//! One decrypted hash as uppercase hex, or empty on failure.
std::wstring hashHex(const std::vector<uint8_t>& blob, uint32_t rid,
                     const std::vector<uint8_t>& hashedBootKey,
                     const std::vector<uint8_t>& rc4Salt) {
	const std::vector<uint8_t> block = decryptBlob(blob, rid, hashedBootKey, rc4Salt);
	if (block.size() < 16) return {};
	const std::vector<uint8_t> hash = removeDes(rid, block);
	if (hash.size() != 16) return {};
	return toHexadecimal(hash.data(), hash.size());
}

/*! The history of hashes: a header, then N encrypted 16-byte blocks sharing one
 *  blob. Each block, once the blob layer is off, keeps its own DES layer.
 *  @return each previous hash as hex, newest first */
std::vector<std::wstring> historyHex(const std::vector<uint8_t>& blob, uint32_t rid,
                                     const std::vector<uint8_t>& hashedBootKey,
                                     const std::vector<uint8_t>& rc4Salt) {
	std::vector<std::wstring> out;
	if (blob.size() < 4) return out;
	const uint16_t revision = uint16_t(blob[2] | (blob[3] << 8));
	std::vector<uint8_t> blocks;
	if (revision == 1) {
		if (blob.size() <= 4) return out;
		const std::vector<uint8_t> key = md5(join({ hashedBootKey, le32(rid), rc4Salt }));
		blocks = rc4(key, blob.data() + 4, blob.size() - 4);
	}
	else if (revision == 2) {
		if (blob.size() <= 24) return out;
		const std::vector<uint8_t> salt(blob.begin() + 8, blob.begin() + 24);
		blocks = aesCbcDecrypt(hashedBootKey, salt, std::vector<uint8_t>(blob.begin() + 24, blob.end()));
	}
	else return out;
	for (size_t at = 0; at + 16 <= blocks.size(); at += 16) {
		const std::vector<uint8_t> hash = removeDes(rid, std::vector<uint8_t>(blocks.begin() + at, blocks.begin() + at + 16));
		if (hash.size() == 16) out.push_back(toHexadecimal(hash.data(), hash.size()));
	}
	return out;
}

} // namespace

std::vector<uint8_t> readBootKey(ORHKEY controlSet) {
	// The boot key is scrambled across the class names of these four subkeys of
	// Control\Lsa, then permuted. Each class name is 8 hex digits = 4 bytes.
	const wchar_t* NAMES[] = { L"JD", L"Skew1", L"GBG", L"Data" };
	std::vector<uint8_t> scrambled;
	for (const wchar_t* name : NAMES) {
		const std::vector<uint8_t> part = hexToBytes(readClass(controlSet, std::wstring(L"Control\\Lsa\\") + name));
		if (part.size() != 4) {
			log(2, std::wstring(L"🔥boot key: class of Control\\Lsa\\") + name + L" missing or malformed");
			return {};
		}
		scrambled.insert(scrambled.end(), part.begin(), part.end());
	}
	static const int PERM[16] = { 0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
	                              0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7 };
	std::vector<uint8_t> bootKey(16);
	for (int i = 0; i < 16; ++i) bootKey[i] = scrambled[PERM[i]];
	return bootKey;
}

std::vector<uint8_t> readHashedBootKey(ORHKEY hSam, const std::wstring& base,
                                       const std::vector<uint8_t>& bootKey) {
	if (bootKey.size() != 16) return {};
	ORHKEY account = NULL;
	if (OROpenKey(hSam, (base + L"Domains\\Account").c_str(), &account) != ERROR_SUCCESS) {
		log(2, L"🔥hashed boot key: Domains\\Account not found");
		return {};
	}
	std::vector<uint8_t> f;
	const bool read = getRegBinaryValue(account, nullptr, L"F", f) == ERROR_SUCCESS;
	ORCloseKey(account);
	if (!read || f.size() < 0x70) {
		log(2, L"🔥hashed boot key: value F missing or too short");
		return {};
	}
	return hashedBootKeyFromF(f, bootKey);
}

std::vector<uint8_t> hashedBootKeyFromF(const std::vector<uint8_t>& f, const std::vector<uint8_t>& bootKey) {
	if (bootKey.size() != 16 || f.size() < 0x70) return {};
	// The key structure starts at offset 0x68; its revision (a DWORD) says how.
	const uint8_t* k = f.data() + 0x68;
	uint32_t revision = 0;
	memcpy(&revision, k, 4);
	/* QWERTY/DIGITS are the fixed constants that salt the RC4 scheme: twelve
	   'Q', no more — a thirteenth gave a wrong hashed boot key, hence wrong
	   hashes for every account of Windows 8.1, in valid JSON. The checksum the
	   structure carries now refuses such a key (measured on the Windows 8.1
	   VM: only twelve 'Q' satisfy it). */
	static const std::vector<uint8_t> QWERTY = {
		'!','@','#','$','%','^','&','*','(',')','q','w','e','r','t','y','U','I','O','P','A','z','x',
		'c','v','b','n','m','Q','Q','Q','Q','Q','Q','Q','Q','Q','Q','Q','Q',')','(','*','@','&','%',0 };
	static const std::vector<uint8_t> DIGITS = {
		'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9',
		'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9',0 };
	if (revision == 1) {
		// SAM_KEY_DATA: Revision(4), Length(4), Salt(16), Key(16), CheckSum(16).
		if (f.size() < 0x68 + 8 + 16 + 16 + 16) return {};
		const std::vector<uint8_t> salt(k + 8, k + 24);
		const std::vector<uint8_t> enc(k + 24, k + 24 + 32);   // Key + CheckSum
		const std::vector<uint8_t> rc4Key = md5(join({ salt, QWERTY, bootKey, DIGITS }));
		std::vector<uint8_t> clear = rc4(rc4Key, enc.data(), enc.size());
		// CheckSum = MD5(Key, DIGITS, Key, QWERTY): a wrong boot key or constant shows here.
		const std::vector<uint8_t> key(clear.begin(), clear.begin() + 16);
		if (md5(join({ key, DIGITS, key, QWERTY })) != std::vector<uint8_t>(clear.begin() + 16, clear.end())) {
			log(2, L"🔥hashed boot key: the checksum of the F value does not match (wrong boot key?)");
			return {};
		}
		return key;
	}
	if (revision == 2) {
		// SAM_KEY_DATA_AES: Revision(4), Length(4), CheckLen(4), DataLen(4), Salt(16), Data.
		if (f.size() < 0x68 + 16 + 16) return {};
		uint32_t dataLen = 0;
		memcpy(&dataLen, k + 12, 4);
		const std::vector<uint8_t> salt(k + 16, k + 32);
		const size_t available = f.size() - (0x68 + 32);
		if (dataLen > available) return {};
		const std::vector<uint8_t> data(k + 32, k + 32 + dataLen);
		std::vector<uint8_t> clear = aesCbcDecrypt(bootKey, salt, data);
		if (clear.size() < 16) return {};
		clear.resize(16);
		return clear;
	}
	log(2, L"🔥hashed boot key: unknown F revision " + std::to_wstring(revision));
	return {};
}

AccountSecrets readAccountSecrets(const std::vector<uint8_t>& valueV, uint32_t rid,
                                  const std::vector<uint8_t>& hashedBootKey) {
	AccountSecrets s;
	if (hashedBootKey.size() != 16 || valueV.size() < V_LM_HISTORY + 8) return s;
	s.lmHash   = hashHex(field(valueV, V_LM_HASH), rid, hashedBootKey, LM_SALT);
	s.ntHash   = hashHex(field(valueV, V_NT_HASH), rid, hashedBootKey, NT_SALT);
	s.ntHistory = historyHex(field(valueV, V_NT_HISTORY), rid, hashedBootKey, NT_HISTORY_SALT);
	s.lmHistory = historyHex(field(valueV, V_LM_HISTORY), rid, hashedBootKey, LM_HISTORY_SALT);
	return s;
}
