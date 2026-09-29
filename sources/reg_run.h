/*! \file
 *  \brief Programs started automatically at logon: Run and RunOnce keys.
 *
 *  WHAT IT SHOWS. These four keys are the first place a program installs itself
 *  to survive a reboot, and the most-used persistence of commodity malware.
 *  `Run` starts its values at every logon; `RunOnce` starts them once, then
 *  Windows deletes the value — so a RunOnce value still present was written
 *  since the last logon, or never ran.
 *
 *  WHERE IT IS READ. Machine-wide in SOFTWARE
 *  (`Microsoft\Windows\CurrentVersion\Run` and `RunOnce`), and per user in
 *  each NTUSER.DAT (`Software\Microsoft\Windows\CurrentVersion\Run`,
 *  `RunOnce`), which tells whose logon starts the program.
 *
 *  The key's last write time dates the last change to the whole key, not to one
 *  value: it bounds when the entry appeared, it does not date it.
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
#include "tools.h"
#include "usb.h"



/*! One autostart entry: a command Windows runs at logon. */
struct Run {
public:
	std::wstring Sid = L"";     //!< SID of the user the entry belongs to, empty if machine-wide
	std::wstring SidName = L"";	//!< name of that user
	std::wstring Key = L"";     //!< the key it comes from: `Run` or `RunOnce`
	std::wstring Name = L"";    //!< name of the value, which the entry chooses freely
	std::wstring Value = L"";   //!< the command line started
	FILETIME lastWriteTimeUtc = { 0 }; //!< last write to the KEY, UTC (the local time is derived at output)

	/*! Converts the entry to JSON.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the entry.
	void clear();
};

/*! All the autostart entries collected, machine-wide and per user. */
struct Runs {
public:
	std::vector<Run> runs;  //!< the entries, in the order they were read

	/*! Reads the four keys: SOFTWARE, then each user's NTUSER.DAT.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `run.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();
};