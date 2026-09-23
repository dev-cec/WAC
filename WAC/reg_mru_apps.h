/*! \file
 *  \brief LastVisitedMRU: the applications that opened a dialog, and where they pointed.
 *
 *  WHAT IT SHOWS. The companion of OpenSaveMRU: where that key lists the files
 *  chosen, this one lists the EXECUTABLES that opened a dialog box, each with
 *  the folder it last pointed to. So it names the application used to handle a
 *  document — which the file lists alone do not say — and the folder it worked
 *  in, even if that folder has since disappeared.
 *
 *  WHERE IT IS READ. In each NTUSER.DAT, under
 *  `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`:
 *  `LastVisitedMRU`, `LastVisitedPidlMRU` and `LastVisitedPidlMRULegacy`, in
 *  MRUListEx order, most recent first.
 *
 *  The folder is stored as a PIDL, parsed by idList.h.
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



/*! One entry: an application that opened a dialog, and the folder it pointed to. */
struct MruApp {
public:
	unsigned int id = 0;      //!< rank in MRUListEx: 0 is the most recent
	unsigned int niveau = 0;  //!< depth in the tree, which the output JSON reproduces
	std::wstring name = L"";  //!< name of the application's executable
	std::wstring sid = L"";   //!< SID of the user who used it
	std::wstring sidName = L"";  //!< name of that user
	std::wstring source = L"";   //!< the key it comes from, of the three read
	FILETIME lastWriteTime = { 0 };    //!< last write to the KEY, suspect's local time
	FILETIME lastWriteTimeUtc = { 0 }; //!< the same instant in UTC
	std::vector<std::unique_ptr<IdList>> shellitems; //!< the folder's PIDL, item by item

	/*! Converts the entry to JSON, shell items included.
	 *  @return its JSON object. */
	Json toJson() const;


};

/*! All the entries collected, for every user of the machine. */
struct MruApps {
public:
	std::vector<MruApp> mruApps;  //!< the entries, in the order they were read
	/*! Number of entries walked, for the progress display: `parse` being
	* recursive, the total is not known in advance. */
	unsigned long long nbParcourus = 0;
	unsigned int niveau = 0;  //!< depth reached in the tree, for the output JSON

	/*! Reads the three LastVisited keys in each user's NTUSER.DAT.
	 *  @param _niveau depth to start from, used to lay out the hierarchy in the
	 *         output JSON.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData(int _niveau = 0);

	/*! Parses one of those keys, and recurses into its subkeys.
	 *  @param hKey the key to parse, already open.
	 *  @param sid SID of the user whose hive holds it.
	 *  @param source the key the entries come from.
	 *  @param out receives the parsed entries.
	 *  @param niveau depth of this key, for the output JSON.
	 *  @param _Parentiszip whether the parent item is a zip archive, which
	 *         changes how the shell items below it are read.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<MruApp>* out, unsigned int niveau, bool _Parentiszip);

	/*! Writes `mruApps.json` into the output directory.
	 *  @return the result of the write. */
	virtual HRESULT toJson();


	/*! Releases the memory held by the entries (the unique_ptr are destroyed). */
	void clear();
};