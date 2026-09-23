/*! \file
 *  \brief Local accounts of the examined machine, read from the SAM hive.
 *
 *  WHAT IT SHOWS. Who can log on to the machine, since when, how many times
 *  they did, and how many times they failed. An account created shortly before
 *  the events, an account whose password was changed, a disabled account that
 *  logged on: those are the facts this artefact settles, and it names them by
 *  the SID the other artefacts use.
 *
 *  WHY THE HIVE RATHER THAN netapi32. The original version called `NetUserEnum`
 *  then `NetUserGetInfo` for each account: as many RPC round trips to LSASS.
 *  The profile list, itself once read from the live registry, now comes from
 *  the extracted SOFTWARE hive (see tools.h, loadProfileList). The same
 *  information is written in `SAM\\Domains\\Account\\Users`, now extracted raw.
 *
 *  WHAT THE HIVE ADDS
 *    - the account key's `LastWriteTime`: when the account was created or
 *      modified — a piece of data no netapi32 API returns;
 *    - the accounts LSASS would refuse to enumerate if the service answered
 *      badly;
 *    - a reading that remains possible on a dead image.
 *
 *  STRUCTURE OF THE SAM
 *  Each account is a subkey named after its RID in hexadecimal on 8 digits,
 *  carrying two binary values:
 *    - `F`: the fixed-size fields — timestamps, RID, account flags, logon
 *      counters (offsets documented below);
 *    - `V`: the variable-size fields — name, full name, comment, paths,
 *      preceded by a table of offsets relative to 0xCC.
 *  The password hashes (`V`, offsets 0x9C and 0xA8) are DELIBERATELY IGNORED:
 *  they establish no fact useful to the investigation, and their presence in an
 *  output file would create a risk for nothing in return.
 *
 *  The full SID is rebuilt from the machine SID, read in the `V` value of
 *  `SAM\\Domains\\Account`, and the account's RID.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <offreg.h>
#include "tools.h"
#include "trans_id.h"
#include "json.h"

/*! One local account of the examined machine. */
struct User {
	std::wstring name;                   //!< logon name
	std::wstring fullName;               //!< full name of the account holder
	std::wstring comment;                //!< comment attached to the account
	std::wstring SID;                    //!< full SID, rebuilt from the machine SID and the RID
	DWORD        rid = 0;                //!< relative identifier, which names the subkey
	std::wstring profile;                //!< path of the profile (ProfileList)
	DWORD        flags = 0;              //!< account flags (ACB)
	std::wstring flagLabels;          //!< those flags spelled out
	unsigned     logonCount = 0;         //!< number of successful logons
	unsigned     badPasswordCount = 0;   //!< number of failed authentications
	FILETIME     lastLogonUtc = { 0, 0 };        //!< last logon, in UTC
	FILETIME     passwordLastSetUtc = { 0, 0 };  //!< last password change, in UTC
	FILETIME     accountExpiresUtc = { 0, 0 };   //!< expiry of the account, in UTC
	FILETIME     lastBadPasswordUtc = { 0, 0 };  //!< last failed authentication, in UTC
	FILETIME     keyLastWriteUtc = { 0, 0 };     //!< creation / modification of the account

	/*! Converts the account to JSON.
	 *  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the account.
	void clear();
};

/*! All the local accounts of the examined machine. */
struct Users {
	std::vector<User> users;   //!< the accounts, as the SAM lists them

	/*! Reads the accounts from the extracted SAM hive.
	* Requires that `ExtractSystemHivesRaw()` has extracted
	* `\Windows\System32\config\SAM`.
	* @return S_OK, or the failure of the hive read.
	*/
	HRESULT getData();

	/*! Writes `users.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the accounts.
	void clear();
};
