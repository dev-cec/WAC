/*! \file
 *  \brief Shellbags: the folders the user browsed, and how they were displayed.
 *
 *  WHAT IT SHOWS. Explorer remembers the position, size and view of every
 *  window a user opened, keyed by folder. Writing that preference proves the
 *  folder WAS BROWSED — including folders on a USB stick, a network share, or
 *  inside a zip archive, and folders that have since been deleted. The key
 *  hierarchy reproduces the tree that was browsed, which is why the entries are
 *  collected as a tree and not as a flat list.
 *
 *  WHERE IT IS READ. In each user's UsrClass.dat, under
 *  `Local Settings\Software\Microsoft\Windows\Shell\BagMRU`. Each key holds
 *  a PIDL parsed by idList.h, so the folder keeps the name and the timestamps
 *  it had when it was browsed.
 *
 *  The dates are the KEYS' last write times: they date the last change to the
 *  display preference, which is the last visit, not the folder's creation.
 */
#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include "offline_registry.h"
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <fstream>
#include "tools.h"
#include "usb.h"
#include "idList.h"

/*! One shellbag: a folder that was browsed, and the folders browsed under it. */
struct Shellbag {
public:
	unsigned int id = 0;      //!< identifier of this shellbag, unique in the collection
	unsigned int Parent = 0;  //!< `id` of the folder it was browsed from, 0 at the root
	unsigned int level = 0;  //!< depth in the tree, which the output JSON reproduces
	std::wstring sid = L"";      //!< SID of the user who browsed the folder
	std::wstring sidName = L"";  //!< name of that user
	std::wstring source = L"";   //!< the key the shellbag comes from
	std::vector<std::unique_ptr<IdList>> shellitems; //!< the folder's PIDL, item by item
	std::vector<Shellbag> childs;    //!< the folders browsed below this one
	FILETIME lastWriteTime = { 0 };    //!< last write to the KEY, suspect's local time
	FILETIME lastWriteTimeUtc = { 0 }; //!< the same instant in UTC

	/*! Converts the shellbag and its children to JSON.
	 *  @return its JSON object. */
	Json toJson() const;


};

/*! The whole browsing tree, for every user of the machine. */
struct Shellbags {
public:
	std::vector<Shellbag> shellbags;  //!< the roots of the tree, one per key read
	unsigned int level = 0;  //!< depth reached in the tree, for the output JSON
	/*! Number of shellbags walked, for the progress display.
	* `parse` being recursive, the total cannot be known in advance: a running
	* count is displayed rather than a percentage. */
	unsigned long long nWalked = 0;


	/*! Reads the BagMRU key of each user's UsrClass.dat.
	 *  @param _level depth to start from, used to lay out the hierarchy in the
	 *         output JSON.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData(int _level = 0);

	/*! Parses a BagMRU key, and recurses into its subkeys — that is, into the
	 *  folders browsed below it.
	 *  @param hKey the key to parse, already open.
	 *  @param sid SID of the user whose hive holds it.
	 *  @param source the key the shellbags come from.
	 *  @param out receives the parsed shellbags.
	 *  @param level depth of this key, for the output JSON.
	 *  @param _Parentiszip whether the parent item is a zip archive, which
	 *         changes how the shell items below it are read.
	 *  @param Parent `id` of the parent shellbag, if there is one.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Shellbag>* out, unsigned int level, bool _Parentiszip, unsigned int Parent = NULL);

	/*! Writes `shellbags.json` into the output directory.
	 *  @return the result of the write. */
	virtual HRESULT toJson();


	/*! Releases the memory held by the shellbags (the unique_ptr are destroyed). */
	void clear();
};