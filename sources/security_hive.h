/*! \file
 *  \brief The SECURITY hive: LSA secrets (names and dates only), cached domain
 *         logons, audit policy.
 *
 *  WHAT THE ARTEFACT PROVES.
 *   - LSA secrets (`Policy\\Secrets\\<name>`): their NAMES alone are evidence —
 *     `DefaultPassword` (an automatic logon's password stored), `_SC_<service>`
 *     (a service running under an account whose password is kept), `NL$KM`
 *     (cached logons in use), a name no product uses (a tool storing its own).
 *     The dates their current and previous values were set (`CupdTime`,
 *     `OupdTime`) date the change of a password.
 *   - Cached domain logons (`Cache\\NL$1…`): how many domain accounts could log
 *     on without the domain controller — which accounts is in the encrypted
 *     part, not read.
 *   - Audit policy (`Policy\\PolAdtEv`): what the machine logs. Its layout is
 *     not published: the value is kept as its bytes, undecoded.
 *   - Account rights (`Policy\\Accounts\\<SID>`): the privileges
 *     (`Privilgs`, a list of well-known LUIDs) and the logon rights
 *     (`ActSysAc`, a bitmask) held by each account or group. SeDebugPrivilege,
 *     SeBackupPrivilege or a remote-logon right granted to an unexpected
 *     account is a persistence an attacker leaves here.
 *
 *  WHAT IS NEVER READ. No secret's value, no cached credential: WAC reads
 *  names, dates and counts, never what the encryption protects — the same
 *  line as for LSASS, which WAC does not dump.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One LSA secret: its name and the dates of its values, never the values. */
struct LsaSecret {
	std::wstring name;                   //!< the secret's name
	FILETIME keyLastWriteUtc = { 0 };    //!< last write of its key, UTC
	FILETIME currentSetUtc = { 0 };      //!< when the current value was set (CupdTime), UTC
	FILETIME previousSetUtc = { 0 };     //!< when the previous value was set (OupdTime), UTC
	//! @return the secret as a JSON object
	Json toJson() const;
};

/*! The rights held by one account or group, from Policy\Accounts\<SID>. */
struct AccountRight {
	std::wstring sid;                        //!< the account or group SID
	std::vector<std::wstring> privileges;    //!< privilege names (Privilgs LUIDs)
	std::vector<std::wstring> logonRights;    //!< logon rights (ActSysAc bitmask)
	FILETIME keyLastWriteUtc = { 0 };        //!< last write of its key, UTC
	//! @return the account's rights as a JSON object
	Json toJson() const;
};

/*! What the SECURITY hive says (security.json). */
class SecurityHive {
public:
	/*! Opens the SECURITY hive of the working copy and reads it.
	 *  @return ERROR_SUCCESS, or why the hive could not be opened */
	HRESULT getData();
	/*! Writes security.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases what was read.
	void clear();
private:
	std::vector<LsaSecret> secrets_;        //!< Policy\Secrets, one per subkey
	unsigned cacheSlots_ = 0;               //!< NL$n values of Cache: slots for cached logons
	unsigned cacheUsed_ = 0;                //!< of which hold a logon (user name length not zero)
	bool cacheRead_ = false;                //!< the Cache key was found
	FILETIME cacheLastWriteUtc_ = { 0 };    //!< last write of Cache, UTC: the last cached logon, at the latest
	std::vector<BYTE> auditPolicy_;         //!< PolAdtEv, as its bytes
	FILETIME auditPolicyLastWriteUtc_ = { 0 };   //!< last write of PolAdtEv's key, UTC
	std::vector<AccountRight> accountRights_;     //!< Policy\Accounts, one per SID
};
