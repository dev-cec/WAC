/*! \file
 *  \brief User Access Logging: `\Windows\System32\LogFiles\Sum` (user_access_log.json).
 *
 *  WHAT IT PROVES. Since Server 2012, a server keeps by itself, per role (file
 *  server, DNS, DHCP, Active Directory, web, remote access…), per account and
 *  per client address, the first and last access and a count for every day of
 *  the year, for up to three years: who reached this server, from where, on
 *  which days, well beyond the event logs. It is on by default and exists on no
 *  client edition.
 *
 *  WHERE, measured on Server 2022. ESE databases, opened by the service UALSVC:
 *    - SystemIdentity.mdb: SYSTEM_IDENTITY (the machine), ROLE_IDS (each role's
 *      GUID and name), CHAINED_DATABASES (the file of each past year);
 *    - Current.mdb, and <GUID>.mdb for a past year: CLIENTS, ROLE_ACCESS, DNS,
 *      VIRTUALMACHINES.
 *  The folder holds three log bases (Api, Prv, Svc), which is why the replay
 *  tries each one (eseLogBaseNames).
 *
 *  WHAT IS WRITTEN. One element per row of every table: its Database and Table,
 *  then its columns by name, as srum.json. Three things differ from the raw
 *  columns: the dates are FILETIMEs although the columns are declared DateTime;
 *  the binary Address of CLIENTS is given as text; the columns Day1 to Day366 are
 *  gathered in Days, each with its date. A RoleGuid is completed with RoleName
 *  and ProductName from ROLE_IDS. An all-zero TenantId, the case of every row
 *  outside a hosted server, is left out.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! The Address column of CLIENTS.
 *  @param address its bytes
 *  @return IPv4 for four bytes, IPv6 for sixteen; hexadecimal for any other size,
 *          which a forged database can hold */
std::wstring userAccessAddressText(const std::vector<uint8_t>& address);

/*! The date a column DayN stands for.
 *  @param year the year of the row
 *  @param day N, 1 for 1 January
 *  @return yyyy-MM-dd, or empty if the year has no such day */
std::wstring userAccessDayDate(unsigned year, unsigned day);

//! User Access Logging (user_access_log.json).
class UserAccessLog {
public:
	HRESULT getData();  //!< @return ERROR_SUCCESS, even where the folder is absent
	HRESULT toJson();   //!< @return the result of the write
	void clear();       //!< releases what was read
private:
	Json rows_ = Json::arr();
};
