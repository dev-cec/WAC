/*! \file
 *  \brief OpenSaveMRU: the files the user opened or saved through a dialog box.
 *
 *  WHAT IT SHOWS. Every Open and Save dialog leaves the chosen file in a
 *  per-extension list. That documents the handling of a document whatever the
 *  application, including files that have since been deleted, and files on a
 *  removable device or a network share which left no other trace on the disk.
 *  The entries are ordered by MRUListEx, most recent first.
 *
 *  WHERE IT IS READ. In each NTUSER.DAT, under
 *  `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`:
 *  `OpenSavePidlMRU` (shell items, the current form) and `OpenSaveMRU` (plain
 *  paths, older systems).
 *
 *  Each entry is a PIDL — a chain of shell items parsed by idList.h — and not a
 *  text path: it carries the target's name, size and timestamps AS THEY WERE
 *  when the dialog was used, which the file itself no longer holds.
 */
#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <fstream>
#include "tools.h"
#include "usb.h"
#include "idList.h"

/*! One MRU entry: a file chosen in an Open or Save dialog. */
struct Mru {
public:
	unsigned int id = 0;      //!< rank in MRUListEx: 0 is the most recent
	unsigned int niveau = 0;  //!< depth in the tree, which the output JSON reproduces
	std::wstring extension = L"";  //!< extension of the list the entry belongs to
	std::wstring sid = L"";        //!< SID of the user who opened the file
	std::wstring sidName = L"";    //!< name of that user
	std::wstring source = L"";     //!< the key it comes from: `OpenSavePidlMRU` or `OpenSaveMRU`
	FILETIME lastWriteTime = { 0 };    //!< last write to the KEY, suspect's local time
	FILETIME lastWriteTimeUtc = { 0 }; //!< the same instant in UTC
	std::vector<std::unique_ptr<IdList>> shellitems; //!< the PIDL, item by item

	/*! Converts the entry to JSON, shell items included.
	 *  @return its JSON object. */
	Json toJson() const;

};

/*! All the MRU entries collected, for every user of the machine. */
struct Mrus {
public:
	std::vector<Mru> mrus;  //!< the entries, in the order they were read
	/*! Number of entries walked, for the progress display: `parse` being
	* recursive, the total is not known in advance. */
	unsigned long long nbParcourus = 0;
	unsigned int niveau = 0; //!< depth reached in the tree, for the output JSON

	/*! Reads both ComDlg32 keys in each user's NTUSER.DAT.
	 *  @param _niveau depth to start from, used to lay out the hierarchy in the
	 *         output JSON.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData(int _niveau = 0);

	/*! Parses a key ordered by MRUListEx, and recurses into its subkeys.
	 *  @param hKey the key to parse, already open.
	 *  @param sid SID of the user whose hive holds it.
	 *  @param source the key the entries come from.
	 *  @param out receives the parsed entries.
	 *  @param niveau depth of this key, for the output JSON.
	 *  @param _Parentiszip whether the parent item is a zip archive, which
	 *         changes how the shell items below it are read.
	 *  @param extension extension of the list, that is the name of the subkey.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Mru>* out, unsigned int niveau, bool _Parentiszip, std::wstring extension);

	/*! Writes `mrus.json` into the output directory.
	 *  @return the result of the write. */
	virtual HRESULT toJson();


	/*! Releases the memory held by the entries (the unique_ptr are destroyed). */
	void clear();
};