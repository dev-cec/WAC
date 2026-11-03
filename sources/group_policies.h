/*! \file
 *  \brief The group policies a domain controller distributes, read in the copy
 *         of SYSVOL (group_policies.json).
 *
 *  WHAT THE ARTEFACT PROVES. A policy is how an intruder holding the domain
 *  reaches every machine at once: a startup script, an immediate scheduled task,
 *  a registry value turning a protection off, a right granted, all pushed from
 *  one folder. The directory (active_directory.h) says which policies exist and
 *  where they are linked; what they do is here.
 *
 *  WHAT IS WRITTEN. One element per policy folder (Policies\{GUID}): its version
 *  and name from GPT.INI, its registry values (Registry.pol, machine and user),
 *  its scripts (scripts.ini, psscripts.ini), the tasks of its preferences
 *  (ScheduledTasks.xml), its security template (GptTmpl.inf: rights, group
 *  memberships) and the list of its files. One more element per other folder of
 *  SYSVOL (scripts, the NETLOGON share; DfsrPrivate, where replication keeps what
 *  it deleted), with its files. Each file's content is in the exhibit store.
 *
 *  A PASSWORD IN A PREFERENCE IS NOT READ. A preference file may carry a
 *  `cpassword`: its presence is reported (StoredPasswords: the file and the
 *  element), a finding by itself, and its value is not written.
 *
 *  THE FOLDER. Services\Netlogon\Parameters\SysVol names SYSVOL\sysvol, where
 *  each domain is a junction to SYSVOL\domain: the real folder is the one read,
 *  a junction giving nothing when listed raw.
 */
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One value of a Registry.pol. */
struct PolicyRegistryEntry {
	std::wstring key;       //!< the key
	std::wstring value;     //!< the value's name; "**del." and the like are as written, they say the action
	uint32_t type = 0;      //!< its REG_ type
	std::vector<uint8_t> data;  //!< its data
	//! @return the entry in JSON, its data by its type
	Json toJson() const;
};

/*! Decodes a Registry.pol: "PReg", version 1, then entries in UTF-16
 *  `[key;value;type;size;data]`, delimiters included. Bounded by the file's real
 *  size, whatever a size says; a malformed entry ends the reading.
 *  @param data the file
 *  @param size its size
 *  @return the entries read; none for another signature or version */
std::vector<PolicyRegistryEntry> parseRegistryPol(const uint8_t* data, size_t size);

//! An INI file's content: section → its `key=value` lines, in order; names as written.
using IniSections = std::map<std::wstring, std::vector<std::pair<std::wstring, std::wstring>>>;

/*! Reads an INI text: GPT.INI, scripts.ini, GptTmpl.inf.
 *  @param text the text
 *  @return its sections; a line with no `=` is kept with an empty value (a
 *          template's [Unicode] and [Version] have none, other sections may) */
IniSections parseIniText(const std::wstring& text);

/*! The scripts of a scripts.ini: `0CmdLine=` and `0Parameters=` in sections
 *  Startup, Shutdown, Logon, Logoff, numbered in order.
 *  @param text the file's text
 *  @param scope Machine or User
 *  @param engine "Script" for scripts.ini, "PowerShell" for psscripts.ini
 *  @return one object per script */
std::vector<Json> parsePolicyScripts(const std::wstring& text, const std::wstring& scope, const std::wstring& engine);

/*! The tasks of a ScheduledTasks.xml of the preferences.
 *  @param text the file's text
 *  @param scope Machine or User
 *  @return one object per task, immediate or not */
std::vector<Json> parsePolicyTasks(const std::wstring& text, const std::wstring& scope);

/*! The elements of a preference file that hold a cpassword, by their name: never
 *  the value.
 *  @param text the file's text
 *  @return the names; an element without a name gives its own tag */
std::vector<std::wstring> storedPasswordElements(const std::wstring& text);

/*! Where SYSVOL's real folder is, in the SYSTEM hive opened.
 *  @param folder receives it, absolute
 *  @return false on a machine that is no controller */
bool sysvolDomainFolder(std::wstring& folder);

//! The group policies (group_policies.json).
class GroupPolicies {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, also on a machine that is no controller
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases what was read
private:
	std::vector<Json> rows_;
};
