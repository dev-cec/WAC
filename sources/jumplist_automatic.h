/*! \file
 *  \brief Automatic jump lists: the files each application opened, per user.
 *
 *  WHAT THE ARTEFACT PROVES. Windows keeps, for each application and each user,
 *  the list of files recently opened WITH THAT APPLICATION — what the task bar
 *  shows on a right click. So it does not merely say that a document was
 *  opened, as the Recent folder does: it says WHICH PROGRAM opened it. And the
 *  list is kept per application identifier, so it survives the application
 *  being uninstalled.
 *
 *  WHERE IT IS READ.
 *  `%AppData%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\<AppID>.automaticDestinations-ms`.
 *  The file is an OLE compound document (parsed by oleparser.h) whose streams
 *  each hold a complete .lnk shortcut, parsed by recent_docs.h. The AppID is a
 *  hash of the executable's path: the same program installed in two places
 *  gives two files.
 *
 *  Documentation:
 *   - https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
 *   - https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
 *   - https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
 */
#pragma once
#include <optional>

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include "tools.h"
#include "recent_docs.h"
#include "oleparser.h"

/*! One automatic jump list: an application, and the files it opened. */
struct AutomaticDestination {
	std::wstring path = L"";         //!< path of the file in the working directory
	std::wstring pathOriginal = L"";	//!< path it was read from on the examined volume
	std::wstring Sid = L"";     //!< SID of the user the jump list belongs to
	std::wstring SidName = L"";	//!< name of that user
	std::wstring application = L"";//!< the application, resolved from the AppID when known

	/*! One DestList entry and the shortcut its number points to. */
	struct JumplistEntry {
		DestFile destList;               //!< the DestList entry: last access, host, droid GUIDs, pin
		std::optional<RecentDoc> lnk;    //!< its shortcut; empty if the stream is missing or unreadable
	};

	oleParser ole; //!< reader of the OLE compound document the file is
	std::vector<JumplistEntry> entries; //!< one per opened file, in DestList order
	FILETIME createdUtc = { 0 };  //!< creation of the jump list FILE, UTC (the local time is derived at output)
	FILETIME modifiedUtc = { 0 };	//!< last modification of that file, UTC
	FILETIME accessedUtc = { 0 };	//!< last access to that file, UTC

	/*! Reads a jump list and every shortcut in it.
	* @param _path path of the .automaticDestinations-ms file.
	* @param _sid SID of the user it belongs to.
	*/
	AutomaticDestination(std::filesystem::path _path, std::wstring _sid);

	/*! Parses the content of a jump list: the OLE container, its DestList and
	*  the shortcut of each entry. Separate from the file reading so that it can
	*  be tested on a buffer (see parsers_test.cpp).
	* @param buffer the file's bytes
	* @param size their number: no read goes beyond
	*/
	void parse(LPBYTE buffer, size_t size);

	/*! Converts the jump list to JSON, shortcuts included.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the jump list.
	void clear();
};

/*! All the automatic jump lists of every user of the machine. */
struct JumplistAutomatics {
	std::vector<AutomaticDestination> automaticDestinations; //!< the jump lists read

	/*! Lists each user's AutomaticDestinations folder and reads every file.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `jumplistAutomaticDestinations.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the jump lists.
	void clear();
};