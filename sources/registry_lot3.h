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
