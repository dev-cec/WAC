/*! \file
 *  \brief Decryption of the SAM password hashes, for an offline investigation.
 *
 *  WHY. A weak or empty password used by an attacker makes the intrusion look
 *  like a legitimate logon. WAC converts the hashes to JSON so that WAE can
 *  confront them, after the fact and offline, with the hashes of empty or
 *  common passwords. WAC itself judges nothing: it only converts.
 *
 *  THE CHAIN. The hashes are not stored in the clear. Three layers come off:
 *    1. the machine's boot key (syskey), scrambled across four class names of
 *       `SYSTEM\\CurrentControlSet\\Control\\Lsa` (JD, Skew1, GBG, Data);
 *    2. the SAM's hashed boot key, in `SAM\\Domains\\Account` value `F`,
 *       protected by the boot key — RC4 on older systems, AES-CBC since
 *       Windows 10;
 *    3. each account's NT and LM hash, in its `V` value, protected by the
 *       hashed boot key (RC4 or AES), then by a last DES layer keyed on the RID.
 *
 *  The password hashes themselves are one-way: they are condensates, not the
 *  passwords. They identify a password without revealing it, which is exactly
 *  what WAE needs to flag a weak one.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "offline_registry.h"

/*! The decrypted password hashes of one local account. Every field is hex, and
 *  empty where the SAM carries no such hash (an LM hash is unusual on a modern
 *  system). */
struct AccountSecrets {
	std::wstring ntHash;                   //!< current NT hash (MD4 of the password)
	std::wstring lmHash;                   //!< current LM hash
	std::vector<std::wstring> ntHistory;   //!< previous NT hashes, newest first
	std::vector<std::wstring> lmHistory;   //!< previous LM hashes, newest first
};

/*! Derives the machine's 16-byte boot key from the extracted SYSTEM hive.
 *  @param controlSet the selected control set (conf.CurrentControlSet)
 *  @return the boot key, or an empty vector if a class name is missing */
std::vector<uint8_t> readBootKey(ORHKEY controlSet);

/*! The SAM's hashed boot key, from `SAM\Domains\Account` value `F`.
 *  @param hSam the open SAM hive
 *  @param base key prefix, as openSam gives it ("SAM\\" or "")
 *  @param bootKey the boot key, as readBootKey gives it
 *  @return the 16-byte hashed boot key, or an empty vector on failure */
std::vector<uint8_t> readHashedBootKey(ORHKEY hSam, const std::wstring& base,
                                       const std::vector<uint8_t>& bootKey);

/*! The hashed boot key, from the bytes of the `F` value: revision 1 (RC4,
 *  its checksum verified) or 2 (AES).
 *  @param f the value `F` of `SAM\Domains\Account`
 *  @param bootKey the boot key, as readBootKey gives it
 *  @return the 16-byte hashed boot key, or an empty vector if the value is
 *          too short, of another revision, or its checksum does not match */
std::vector<uint8_t> hashedBootKeyFromF(const std::vector<uint8_t>& f, const std::vector<uint8_t>& bootKey);

/*! Decrypts the NT and LM hashes, and their history, of one account.
 *  @param valueV the account's `V` value
 *  @param rid the account's relative identifier
 *  @param hashedBootKey as readHashedBootKey gives it
 *  @return the hashes, empty strings where the account carries none */
AccountSecrets readAccountSecrets(const std::vector<uint8_t>& valueV, uint32_t rid,
                                  const std::vector<uint8_t>& hashedBootKey);
