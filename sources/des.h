/*! \file
 *  \brief DES, one 64-bit block, in decryption: the cipher of the layer that
 *         keys a SAM password hash on its account's RID.
 *
 *  WHY WAC'S OWN. The SAM's hashes keep, under their RC4 or AES layer, a DES
 *  layer of two blocks keyed on the RID. Windows' BCrypt is absent from
 *  Windows XP, and on Vista BCryptGenerateSymmetricKey wants the key object's
 *  memory from its caller (only Windows 7 accepts none): through BCrypt, the
 *  hashes of XP and Vista came out empty, without a word (measured on both
 *  VMs). DES is a public standard (FIPS 46-3) of a few tables; written here,
 *  it decrypts the same on every Windows, and adds no import.
 *
 *  Checked against the standard's own example (key 133457799BBCDFF1,
 *  0123456789ABCDEF <-> 85E813540F0AB405) and against the hashes of the
 *  test VMs' accounts, whose passwords are known.
 */
#pragma once

#include <array>
#include <cstdint>

/*! Decrypts one DES block (ECB).
 *  @param key the 8-byte key, its parity bits ignored
 *  @param block the 8-byte ciphertext
 *  @return the 8-byte plaintext */
std::array<uint8_t, 8> desDecryptBlock(const std::array<uint8_t, 8>& key, const std::array<uint8_t, 8>& block);
