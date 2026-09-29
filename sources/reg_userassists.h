/*! \file
 *  \brief UserAssist: what the user launched from the shell, how often, and when.
 *
 *  WHAT IT SHOWS. Explorer counts, for each user, the programs and shortcuts
 *  started FROM THE GRAPHICAL INTERFACE, with a run count, a focus count and
 *  the last run. It is the artefact that shows a human at the keyboard: a
 *  program started by a service, a script or a task is not counted here. A run
 *  count that stays at zero while the last-run date is set, or the reverse,
 *  says the entry was written by something other than an ordinary launch.
 *
 *  WHERE IT IS READ. In each NTUSER.DAT, under
 *  `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\count`,
 *  for two GUIDs: `{CEBFF5CD-…}` for shortcuts and `{F4E57C4B-…}` for
 *  executables. Value names are ROT13-encoded — which hides nothing, but keeps
 *  them out of a plain search of the hive.
 */
#pragma once

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include "offline_registry.h"
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <regex>
#include "tools.h"
#include "trans_id.h"
#include "usb.h"
#include "users.h"



/*! One UserAssist entry: something the user started from the shell. */
struct UserAssist {
public:
	std::wstring Sid = L"";      //!< SID of the user who started it
	std::wstring SidName = L"";  //!< name of that user
	std::wstring Class = L"";    //!< GUID of the subkey: shortcuts, or executables
	std::wstring Name = L"";     //!< what was started, ROT13-decoded and its
	                             //!< known folder GUIDs resolved to paths
	int Count = 0;               //!< number of runs counted by Explorer
	int FocusCount = 0;          //!< number of times the window received the focus
	FILETIME lastRunUtc = { 0, 0 };   //!< last run, in UTC as the value stores it

	/*! Size of an entry of Windows 7 and later: session (4), run count (4),
	 *  focus count (4), focus time (4), 10 usage ratios, last run FILETIME at
	 *  offset 60, then 4 bytes. A value of another size is not a program
	 *  entry: "UEME_CTLSESSION" holds session statistics, and read at the
	 *  same offsets it gave a last run in 1691. */
	static const size_t ENTRY_SIZE = 72;

	/*! Builds the entry from a registry value of ENTRY_SIZE bytes.
	 *  @param hKey name of the GUID subkey the value comes from.
	 *  @param valueName name of the value, ROT13-encoded.
	 *  @param data the value's bytes: run count, focus count and last run.
	 *  @param _sid SID of the user whose hive holds the value. */
	UserAssist(std::wstring hKey, const std::wstring& valueName, const std::vector<BYTE>& data, std::wstring _sid);

	/*! Converts the entry to JSON.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the entry.
	void clear();
};

/*! All the UserAssist entries collected, for every user of the machine. */
struct UserAssists {
public:
	std::vector<UserAssist> userassists;  //!< the entries, in the order they were read

	/*! Reads both GUID subkeys in each user's NTUSER.DAT.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `userassists.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();
};