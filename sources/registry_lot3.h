/*! \file
 *  \brief Registry artefacts of the third lot (B-031): the keys RECmd's Kroll
 *         batch reads and WAC did not.
 *
 *  Each is read in the copied hives and shares the structure of the second
 *  lot (registry_lot2.h): one struct per element with toJson(), one class with
 *  getData(), toJson(), clear().
 *
 *  WHAT THEY PROVE.
 *   - Installed programs (Uninstall): what was installed, by whom (machine or
 *     user), when, where — a remote access tool, a miner — and what was
 *     removed since leaves the key's last write.
 *   - Defender configuration: the exclusions (paths, extensions, processes,
 *     addresses) an intruder adds so that their tools are not scanned, and the
 *     values that switch protection off — set in Defender's own settings or
 *     by a policy.
 *   - Explorer's RecentDocs: the files each user opened, by extension, most
 *     recent first — the names survive the files and the shortcuts of Recent.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "registry_common.h"

// ------------------------------------------------------------ Installed programs

/*! One program of an Uninstall key: every value of its subkey. */
struct InstalledProgram {
	std::wstring scope;         //!< "Machine", "Machine (32-bit)" or "User"
	std::wstring sid;           //!< the user, for a per-user installation
	std::wstring keyName;       //!< the subkey's name: a product code or a name
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the subkey
	std::vector<std::pair<std::wstring, Json>> values; //!< every value, as stored (DisplayName, Publisher, InstallDate…)
	Json toJson() const;        //!< @return the program as a JSON object
};

//! Programs of the machine's and of each user's Uninstall keys (installed_programs.json).
class InstalledPrograms {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any program
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the programs
private:
	std::vector<InstalledProgram> programs_;
};

// ------------------------------------------------------------ Defender configuration

/*! One Defender exclusion: a path, an extension, a process or an address
 *  Defender does not scan. */
struct DefenderExclusion {
	std::wstring source;        //!< "Settings" (Defender's key) or "Policy" (Policies\\Microsoft\\Windows Defender)
	std::wstring kind;          //!< the subkey: Paths, Extensions, Processes, IpAddresses, TemporaryPaths
	std::wstring value;         //!< what is excluded (the value's name)
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the kind's key: the latest exclusion of that kind
	Json toJson() const;        //!< @return the exclusion as a JSON object
};

/*! The values of one Defender settings key. */
struct DefenderSettings {
	std::wstring source;        //!< "Settings" or "Policy"
	std::wstring key;           //!< the key, under SOFTWARE ("Microsoft\\Windows Defender\\Real-Time Protection")
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the key
	std::vector<std::pair<std::wstring, Json>> values; //!< every value, as stored (DisableRealtimeMonitoring, TamperProtection…)
	Json toJson() const;        //!< @return the key as a JSON object
};

//! Defender's exclusions and protection settings (defender_configuration.json).
class DefenderConfiguration {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why SOFTWARE is missing
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases what was read
private:
	std::vector<DefenderExclusion> exclusions_;
	std::vector<DefenderSettings> settings_;
};

// ------------------------------------------------------------ Explorer RecentDocs

/*! One file of a user's RecentDocs list. */
struct ExplorerRecentDoc {
	std::wstring sid;
	std::wstring extension;     //!< the subkey (".docx", "Folder"); empty for the list of every extension
	unsigned mruPosition = 0;   //!< position in its list, 0 for the most recent (MRUListEx)
	std::wstring name;          //!< the file's name, as Explorer recorded it
	Json shortcut = Json::obj();//!< the shell item that follows: the shortcut created in Recent
	FILETIME keyLastWriteUtc = { 0 };   //!< the list key's last write: when the file at position 0 was opened
	Json toJson() const;        //!< @return the entry as a JSON object
};

//! RecentDocs of every user (explorer_recent_docs.json).
class ExplorerRecentDocs {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any entry
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<ExplorerRecentDoc> entries_;
};
