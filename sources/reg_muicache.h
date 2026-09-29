/*! \file
 *  \brief MUICache: executables run through the shell, and their display name.
 *
 *  WHAT IT SHOWS. When the shell displays an application's name, it caches the
 *  name read from the binary's resources, keyed by the binary's path. An entry
 *  therefore means the executable was PRESENT and shown by the shell — it is a
 *  weaker execution indicator than BAM or Prefetch, but it survives the
 *  deletion of the binary, and it carries the name the program gave itself,
 *  which a renamed executable contradicts.
 *
 *  WHERE IT IS READ. In each user's UsrClass.dat
 *  (`Local Settings\Software\Microsoft\Windows\Shell\MuiCache`), so the
 *  entries are attributed to the user whose hive holds them. The keys carry no
 *  timestamp of their own: only the key's last write time bounds the cache.
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

/*! One MUICache entry: an executable, and the name the shell displayed. */
struct Muicache {
public:
	std::wstring sid = L"";      //!< SID of the user whose hive holds the entry
	std::wstring sidName = L"";  //!< name of that user
	std::wstring name = L"";     //!< path and file name of the executable
	std::wstring data = L"";     //!< display name, as read from the binary's resources

	/*! Builds the entry from a registry value.
	 *  @param hKey the MuiCache key, already open.
	 *  @param valueName name of the value, that is the executable's path.
	 *  @param profile profile of the user the hive belongs to. */
	Muicache(ORHKEY hKey, std::wstring valueName, std::wstring profile);

	/*! Converts the entry to JSON.
	 *  @return its JSON object. */
	Json toJson();
	//! Releases the memory held by the entry.
	void clear();
};

/*! All the MUICache entries collected, for every user of the machine. */
struct Muicaches {
public:
	std::vector<Muicache> muicaches;  //!< the entries, in the order they were read

	/*! Reads the MuiCache key of each user's UsrClass.dat.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `muicache.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();
};