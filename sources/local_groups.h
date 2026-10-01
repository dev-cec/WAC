/*! \file
 *  \brief Local groups (aliases) of the examined machine, read from the SAM.
 *
 *  WHAT IT SHOWS. Which accounts hold which rights by membership: who is in
 *  Administrators, who in Remote Desktop Users, who in Backup Operators. An
 *  attacker who adds an account to a privileged group leaves it here, and the
 *  membership is a fact the account list alone does not give.
 *
 *  SOURCE. `SAM\Domains\Builtin\Aliases` (the built-in groups, S-1-5-32-…) and
 *  `SAM\Domains\Account\Aliases` (the groups created on the machine). Each alias
 *  key carries a `C` value: a 13-DWORD header (data at offset 0x34) with the
 *  offset and length of the name, of the description, and of the member list —
 *  a packed sequence of binary SIDs. The member SIDs are resolved offline
 *  (getNameFromSid), never by asking the system.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "json.h"

/*! One local group and its members. */
struct LocalGroup {
	std::wstring scope;         //!< "Builtin" (S-1-5-32) or "Local" (machine domain)
	DWORD        rid = 0;       //!< the alias RID (the subkey name, in hex)
	std::wstring sid;           //!< the group's own SID (S-1-5-32-<rid> or machine-<rid>)
	std::wstring name;          //!< the group name, as the machine knows it
	std::wstring description;   //!< its description
	std::vector<std::wstring> members;   //!< member SIDs, as text
	FILETIME     keyLastWriteUtc = { 0, 0 };   //!< last change of the group's key
	Json toJson() const;        //!< @return the group as a JSON object
};

//! The local groups of the examined machine (local_groups.json).
class LocalGroups {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or the SAM read failure
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the groups
private:
	std::vector<LocalGroup> groups_;
};
