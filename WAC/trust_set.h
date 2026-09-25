/*! \file
 *  \brief THE TRUST SET, read at the collection: the one --update-trust
 *         prepared on the analysis workstation (see trust_update.h).
 *
 *  WHY IT IS CHECKED AGAIN HERE. The set travelled on a key, and the
 *  collection is where it is believed: a root added on the way would make an
 *  attacker's binary pass for clean, and leave it on the examined machine.
 *  Nothing of the manifest is taken on its word:
 *    - each file must have the size and SHA-256 the manifest gives — which
 *      only proves the set is the one written;
 *    - authroot.stl and disallowedcert.stl must carry a valid signature of
 *      Microsoft's trust list publisher, up to a Microsoft root embedded in
 *      WAC — the real anchor: a set forged whole, manifest included, fails
 *      here;
 *    - each root certificate must have the SHA-1 the signed list names.
 *  One failure and the set is REFUSED, as a whole: treated as absent.
 *
 *  ABSENT OR REFUSED, the collection applies the rules of a set-less run: a
 *  third-party binary cannot be cleared, and is collected. The investigation
 *  log says which case applied, and why.
 */
#pragma once

#include "authenticode.h"
#include <map>
#include <set>
#include <string>
#include <vector>

/*! The trust set, as checked. */
struct TrustSet {
	bool usable = false;          //!< present and every check passed
	std::wstring folder;          //!< where it was looked for
	std::string reason;           //!< why not usable: absent, or the check that failed
	std::wstring createdUtc;      //!< when --update-trust wrote it
	std::wstring manifestSha256;  //!< fingerprint of its manifest, for the log
	TrustList roots;              //!< authroot.stl
	TrustList disallowed;         //!< disallowedcert.stl
	//! The root certificates, DER, by the identifier of their entry in `roots` (SHA-1).
	std::map<std::string, std::vector<uint8_t>> rootCertificates;
	std::set<std::wstring> driverHashes;          //!< vulnerable drivers: fingerprints, uppercase hexadecimal
	std::vector<std::wstring> driverListsMissing; //!< driver lists --update-trust could not obtain
	std::set<std::wstring> revokedAuthorities;    //!< SHA-256 of the authorities the CCADB says revoked
	//! Revocation lists, by the SHA-256 of an authority that issues them: their files.
	std::map<std::wstring, std::vector<std::wstring>> crlsByAuthority;
};

/*! Loads and checks the trust set.
 *  @param folder where it lies
 *  @return the set; `usable` false with `reason` if absent or refused */
TrustSet LoadTrustSet(const std::wstring& folder);

/*! The trust set of this collection: the one next to WAC.exe, loaded and
 *  checked once, on first use — from any thread.
 *  @return the set; `usable` false if absent or refused */
const TrustSet& CollectionTrustSet();

/*! @return the default folder of the trust set: `trust`, next to WAC.exe —
 *  where --update-trust writes it, and where the collection reads it */
std::wstring DefaultTrustFolder();
