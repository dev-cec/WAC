/*! \file
 *  \brief Startup folders: what Windows runs at each logon, for every user and for each profile.
 *
 *  WHAT THE ARTEFACT PROVES. A file dropped in
 *  `\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp` runs at
 *  every logon of every user; one in a profile's
 *  `AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup`, at
 *  that user's. It is the simplest persistence, and still used: a shortcut, a
 *  script, an executable. Everything found there is listed — except
 *  `desktop.ini`, which Windows puts in every folder — with its dates and
 *  fingerprints; a shortcut is also decoded (target, arguments), as in
 *  recentdocs.json.
 */
#pragma once

#include <memory>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "recent_docs.h"

/*! One file of a startup folder. */
struct StartupItem {
	std::wstring sid;                   //!< SID of the profile; empty for the folder of all users
	std::wstring path;                  //!< the file on the examined machine
	FILETIME sourceCreatedUtc = { 0 };  //!< creation of the file, UTC: when it was dropped there
	FILETIME sourceModifiedUtc = { 0 }; //!< last write, UTC
	FILETIME sourceAccessedUtc = { 0 }; //!< last access, UTC
	std::wstring md5, sha1, sha256;     //!< fingerprints, from the manifest
	std::unique_ptr<RecentDoc> shortcut;   //!< the shortcut decoded, for a .lnk
	//! @return the file as a JSON object
	Json toJson() const;
};

/*! The startup folders (startup_folders.json). */
class StartupFolders {
public:
	/*! Reads the files extracted from the folder of all users and of each profile.
	 *  @return ERROR_SUCCESS, even without any file */
	HRESULT getData();
	/*! Writes startup_folders.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the files read.
	void clear();
private:
	std::vector<StartupItem> items_;   //!< one per file
};

//! The startup folder of all users, relative to the system volume.
extern const wchar_t STARTUP_ALL_USERS[];
//! The startup folder of a user, relative to the profile.
extern const wchar_t STARTUP_PROFILE[];
