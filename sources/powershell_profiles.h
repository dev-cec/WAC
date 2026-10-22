/*! \file
 *  \brief PowerShell profiles: the scripts PowerShell runs at each start,
 *         for every user or for one (powershell_profiles.json).
 *
 *  WHY. A profile runs, unseen, each time PowerShell starts — a persistence
 *  that goes through neither the registry, nor a task, nor a service. An
 *  intruder writes one line there; the defender looks at Run keys.
 *
 *  WHERE. For every user, in PowerShell's own folder ($PSHOME): Windows
 *  PowerShell 1 to 5.1 in System32\WindowsPowerShell\v1.0 — and in
 *  SysWOW64's on a 64-bit Windows, the 32-bit PowerShell having its own —,
 *  PowerShell 6 and 7 in Program Files\PowerShell\<version> (and
 *  Program Files (x86)). For one user, in their documents: WindowsPowerShell
 *  for Windows PowerShell, PowerShell for 6 and 7 — the documents where
 *  User Shell Folders puts them (Personal: OneDrive, another disk) as well
 *  as the profile's default ones. Windows XP and Vista run PowerShell only
 *  once installed (absent by default): looked for on every version.
 *
 *  WHICH FILES. profile.ps1 (every host) and <host>_profile.ps1:
 *  Microsoft.PowerShell (the console), Microsoft.PowerShellISE,
 *  Microsoft.VSCode — every name ending in "profile.ps1" in those folders.
 */
#pragma once

#include <functional>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! A folder that may hold profiles: where, for whom, of which PowerShell. */
struct PowerShellProfileFolder {
	std::wstring path;      //!< the folder on the examined machine ("C:\…")
	std::wstring sid;       //!< the profile's SID; empty for every user's
	std::wstring edition;   //!< "Windows PowerShell" or "PowerShell" (6 and 7)
};

/*! The profile folders of the examined machine, fixed or read in the
 *  profiles' User Shell Folders.
 *  @param listFolder lists a folder's subfolders by absolute path (the raw
 *         volume at collection, the working copy at conversion): PowerShell
 *         7's folders are named after their version
 *  @return the folders, machine's first */
std::vector<PowerShellProfileFolder> powerShellProfileFolders(
	const std::function<std::vector<std::wstring>(const std::wstring&)>& listFolder);

/*! Whether a file name is a profile's: ends in "profile.ps1", whatever the case. */
bool isPowerShellProfile(const std::wstring& name);

/*! The host a profile serves, from its name: "AllHosts" for profile.ps1,
 *  else the part before "_profile.ps1" (Microsoft.PowerShell…). */
std::wstring powerShellProfileHost(const std::wstring& name);

/*! One profile found. */
struct PowerShellProfile {
	PowerShellProfileFolder folder;            //!< where it is, for whom
	std::wstring path;                         //!< the file on the examined machine
	std::wstring host;                         //!< AllHosts, Microsoft.PowerShell, Microsoft.PowerShellISE…
	FILETIME sourceCreatedUtc = { 0 };         //!< creation of the file, UTC
	FILETIME sourceModifiedUtc = { 0 };        //!< last write, UTC: when the profile was last changed
	FILETIME sourceAccessedUtc = { 0 };        //!< last access, UTC
	unsigned long long size = 0;               //!< bytes
	std::wstring sha256;                       //!< of its bytes
	std::wstring content;                      //!< its text; empty if larger than the bound
	//! @return the profile as a JSON object
	Json toJson() const;
};

/*! The PowerShell profiles of the machine and of every user. */
class PowerShellProfiles {
public:
	/*! Reads the profiles extracted from every folder.
	 *  @return ERROR_SUCCESS, even without any: none is an answer */
	HRESULT getData();
	/*! Writes powershell_profiles.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the profiles read.
	void clear();
private:
	std::vector<PowerShellProfile> profiles_;   //!< one per file found
};
