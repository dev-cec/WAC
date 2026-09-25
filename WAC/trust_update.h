/*! \file
 *  \brief --update-trust: THE TRUST SET, prepared on the analysis workstation
 *         BEFORE the collection.
 *
 *  WHY. Checking the signature of a third-party binary means tying it to a
 *  root that is trusted, and to none that is distrusted. Taken from the
 *  examined machine, those roots would be the attacker's to choose: a root he
 *  added validates his binaries. They are therefore taken from Microsoft, on a
 *  controlled workstation, and carried to the examined machine on the WAC
 *  key, next to WAC.exe.
 *
 *  WHAT THE SET HOLDS, in the folder given (by default `trust`, next to
 *  WAC.exe):
 *    - authroot.stl: the roots of Microsoft's root program, with the uses each
 *      is trusted for and the date after which it no longer is;
 *    - disallowedcert.stl: the keys and certificates Microsoft distrusts;
 *    - roots\<SHA-1>.crt: every root authroot.stl names, as downloaded;
 *    - roots.pem: those trusted for code signing, for osslsigncode or openssl
 *      on a Linux workstation;
 *    - trust-manifest.json: date, sources, counts, SHA-256 of every file.
 *
 *  WHY IT CAN BE CARRIED WITHOUT BEING TRUSTED. Both lists are signed by
 *  Microsoft's trust list publisher, checked up to a Microsoft root embedded
 *  in WAC; every root certificate must have the SHA-1 the signed list names.
 *  The set is checked again where it is used: altered on the key, it is
 *  refused, not believed.
 *
 *  WRITTEN IN AN ORDER THAT SAYS WHETHER IT IS COMPLETE: the manifest goes
 *  last and is removed first. A set without its manifest — interrupted
 *  download, full medium — is treated as absent: the current rules apply,
 *  every third-party binary is collected.
 */
#pragma once

#include <string>

/*! Runs --update-trust.
 *  @param folder where to write the set; refused if it holds anything but a
 *         previous set
 *  @return the process exit code: 0 on success */
int UpdateTrust(const std::wstring& folder);

/*! @return the default folder of the trust set: `trust`, next to WAC.exe */
std::wstring DefaultTrustFolder();
