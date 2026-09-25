/*! \file
 *  \brief Logon sessions open on the machine while the collection runs.
 *
 *  WHAT IT SHOWS. Who is logged on AT THIS INSTANT, how they authenticated
 *  (password, certificate, network, service), from which domain, and since when.
 *  It is volatile: the session list disappears with the power, so it is read on
 *  the live machine, unlike the artefacts collected from the disk.
 *
 *  It also documents the collection itself — the operator's own session is
 *  among them, which shows what was open on the examined machine at the time.
 *
 *  WHERE IT IS READ. Through `LsaEnumerateLogonSessions` and
 *  `LsaGetLogonSessionData`, the only source for this information: it exists
 *  nowhere on the disk.
 */
#pragma once

#include <iostream>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include <Sddl.h>
#include <wtsapi32.h>
#include <winternl.h>
#define _NTDEF_ // avoids the type conflicts between ntsecapi.h and winternl.h
#include <ntsecapi.h>
#include "tools.h"
#include "json.h"
#include "trans_id.h"



/*! One logon session open on the machine. */
struct Session {

	FILETIME startTimeUtc = { 0 }; //!< start of the session, UTC (the local time is derived at output)
	std::wstring authenticationPackage = L""; //!< package that authenticated it (Kerberos, NTLM…)
	std::wstring logonName = L"";       //!< name of the account logged on
	std::wstring logonDomainName = L"";	//!< domain of that account
	std::wstring logonTypeName = L"";   //!< `logonType` spelled out
	ULONG logonType = 0;                //!< kind of logon: interactive, network, service…
	/*! SID of the account, converted to TEXT as soon as it is read.
	*
	* WHY NOT A `PSID`. The member used to be a pointer copied from the structure
	* returned by `LsaGetLogonSessionData`, which `LsaFreeReturnBuffer` releases
	* at the end of the constructor. `toJson()` running later, it therefore read
	* memory already given back: a SID that was right only by chance, for as long
	* as the block had not been reused. The conversion is now done while the
	* structure is still valid. */
	std::wstring sid;
	/*! Role of the session when its LUID is a value Windows reserves.
	*
	* The LUIDs 0x3E7 (999), 0x3E6 (998), 0x3E5 (997) and 0x3E4 (996) always
	* designate the same service sessions. Naming them keeps the analyst from
	* reading their null `LogonType` — legitimate for those — as a failed read. */
	std::wstring knownRole;
	LONGLONG sessionId = 0;  //!< LUID of the session, as Windows numbers it
	/*! Reads a session from its identifier.
	 *  @param id LUID of the session, as `LsaEnumerateLogonSessions` gives it. */
	Session(LUID* id);

	/*! Converts the session to JSON.
	 *  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the session.
	void clear();
};

/*! All the logon sessions open while the collection runs. */
struct Sessions {
	std::vector<Session> sessions; //!< the sessions, in the order LSA listed them


	/*! Enumerates the sessions and reads each one's data.
	 *  @return S_OK, or the failure of the enumeration. */
	HRESULT getData();
	/*! Records the sessions as a live snapshot (live_snapshot.h), which
	 *  writeSessionsFromSnapshot publishes.
	 *  @return the result of the write. */
	HRESULT snapshot();

	//! Releases the memory held by the sessions.
	void clear();

};

/*! Publishes `Sessions.json` from the live snapshot of the collection.
 *  @return ERROR_SUCCESS, or the reason the snapshot could not be read or written */
HRESULT writeSessionsFromSnapshot();
