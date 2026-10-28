/*! \file
 *  \brief System Resource Usage Monitor: `\Windows\System32\sru\SRUDB.dat` (srum.json).
 *
 *  WHAT IT PROVES. Every hour, Windows records per application and per user
 *  what it used: bytes sent and received on each network interface (an
 *  exfiltration shows there, with the program that made it), CPU cycles,
 *  bytes read and written on disk, time in the foreground, network
 *  connections and their duration. Thirty to sixty days are kept, well
 *  beyond the event logs.
 *
 *  WHAT IS WRITTEN. One element per row of every table of the database: its
 *  table (a provider's GUID for most) and that table's documented name when
 *  known, then its columns by name — a name keeps only its letters and
 *  digits ("Energy Data" gives EnergyData). AppId and UserId are resolved
 *  through SruDbIdMapTable: App (a path, a service, a package), UserSID and
 *  UserName are added. The FILETIME columns SRUM keeps as 64-bit numbers
 *  (ConnectStartTime, EndTime…) stay numbers. Rows are written as they are
 *  read: a database of sixty days holds hundreds of thousands.
 *
 *  THE DATABASE IS COPIED LIVE (dirty shutdown): the last hour is still in
 *  the service's transaction logs SRU*.log, collected with it and replayed
 *  into the working copy before it is read (ese_recovery.h); a replay not
 *  applied is said in the log.
 */
#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "ese_database.h"
#include "tools.h"

/*! The documented name of a provider's table (NetworkUsage…), or empty. */
std::wstring srumProviderName(const std::wstring& table);

/*! A column's name as a JSON key: its letters and digits only. */
std::wstring srumKey(const std::wstring& column);

/*! An entry of SruDbIdMapTable, as text: a SID for type 3, the UTF-16
 *  string of the others (an application's path, a service, a package).
 *  @param type IdType
 *  @param blob IdBlob */
std::wstring srumIdentity(unsigned type, const std::vector<uint8_t>& blob);

//! SRUM (srum.json).
class Srum {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why SRUDB.dat cannot be read
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the identities read; the database closes with the object
private:
	EseDatabase database_;
	std::map<int32_t, std::pair<unsigned, std::wstring>> identities_;   //!< IdIndex → (IdType, text)
};
