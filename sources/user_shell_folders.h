/*! \file
 *  \brief Each user's shell folders (User Shell Folders): where the desktop, the documents, the downloads really are.
 *
 *  WHAT THE ARTEFACT PROVES. Explorer finds a user's desktop, documents,
 *  downloads and AppData through `Software\\Microsoft\\Windows\\CurrentVersion\\
 *  Explorer\\User Shell Folders` of the user's NTUSER.DAT, not at a fixed place.
 *  OneDrive moves the desktop and the documents into `OneDrive\\`, a company
 *  redirects them to a share, a user puts them on D:. The key traces no
 *  activity, but it says WHERE to look for the user's files — and a desktop
 *  quietly redirected to a share is itself a trace; the key's last write
 *  dates the change.
 *
 *  WAC FOLLOWS IT. The shortcuts of a desktop redirected to a local folder are
 *  collected there too (shortcuts.json), not only at `<profile>\\Desktop`.
 *  A folder on a share cannot be read raw: it is listed, not followed.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! A shell folder value of User Shell Folders, made a path of the examined machine.
 *  `%USERPROFILE%` is the profile's path; the other variables are those
 *  normalizeFilePath knows.
 *  @param raw the value as written (REG_EXPAND_SZ)
 *  @param profilePath the profile's absolute path
 *  @return the local absolute path, or "" for a share, a relative path or an unknown variable */
std::wstring resolveUserShellFolder(const std::wstring& raw, const std::wstring& profilePath);

/*! Where a profile's shell folder is, when it is not its default one —
 *  a desktop or documents moved to OneDrive or another disk. Read in the
 *  working copy of the profile's NTUSER.DAT, once per profile and folder.
 *  @param sid the profile's SID
 *  @param profilePath its absolute path
 *  @param name the value of User Shell Folders: L"Desktop", L"Personal"…
 *  @param defaultFolder the folder's default place in the profile: L"Desktop", L"Documents"…
 *  @return the redirected folder's local absolute path, or "" when it is the
 *          default one, on a share, or the value cannot be read */
std::wstring redirectedShellFolder(const std::wstring& sid, const std::wstring& profilePath,
                                  const std::wstring& name, const std::wstring& defaultFolder);

/*! One value of User Shell Folders. */
struct UserShellFolder {
	std::wstring sid;            //!< the profile
	std::wstring name;           //!< the value's name: Desktop, Personal, {374DE290-…} (Downloads)…
	std::wstring value;          //!< as written
	std::wstring path;           //!< resolved, empty when not a local path
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the key: when a folder was last moved
	//! @return the value as a JSON object
	Json toJson() const;
};

/*! Every profile's shell folders (user_shell_folders.json). */
class UserShellFolders {
public:
	/*! Reads User Shell Folders in each profile's NTUSER.DAT.
	 *  @return ERROR_SUCCESS, even without any value */
	HRESULT getData();
	/*! Writes user_shell_folders.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases what was read.
	void clear();
private:
	std::vector<UserShellFolder> folders_;   //!< one per value
};
