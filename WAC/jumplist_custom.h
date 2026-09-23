/*! \file
 *  \brief Custom jump lists: the entries an application pins itself.
 *
 *  WHAT THE ARTEFACT PROVES. Beside the automatic list, an application may
 *  declare its OWN task-bar entries, grouped in named categories — pinned
 *  files, recent projects, its own commands. The categories are the
 *  application's own words, and a pinned entry stays until the user removes it:
 *  it therefore documents a lasting interest in a document, where the automatic
 *  list only keeps the most recent ones.
 *
 *  WHERE IT IS READ.
 *  `%AppData%\\Microsoft\\Windows\\Recent\\CustomDestinations\\<AppID>.customDestinations-ms`.
 *  Unlike the automatic lists, the file is not an OLE document: it is a
 *  concatenation of complete .lnk shortcuts, each parsed by recent_docs.h.
 *
 *  Documentation:
 *   - https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
 *   - https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
 *   - https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
 */
#pragma once
#include <memory>

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include "tools.h"
#include "idList.h"
#include "recent_docs.h"

/*! One category of a custom jump list, as the application names it. */
struct CustomDestinationCategory {
	unsigned short int nameSize = 0; //!< length of the category's name, as declared
	std::wstring name = L"";    //!< name of the category, in the application's own words
	unsigned int nbentries = 0; //!< number of entries the category declares
	std::vector<RecentDoc> recentDocs; //!< its entries, each a complete shortcut

	//! Builds an empty category.
	CustomDestinationCategory() {};

	/*! Reads a category from the file's bytes.
	* @param buffer the category's bytes.
	* @param buffersize size of that buffer, in bytes.
	* @param _path path of the .customDestinations-ms file.
	* @param _sid SID of the user it belongs to.
	*/
	CustomDestinationCategory(LPBYTE buffer, size_t buffersize, std::wstring _path, std::wstring _sid);

	/*! Virtual destructor.
	* `toJson()` being virtual, destroying the object through a base pointer
	* would be undefined behaviour without it. No derived class exists yet, but
	* the class is declared polymorphic and must be so completely.
	*/
	virtual ~CustomDestinationCategory() = default;

	/*! Converts the category to JSON, entries included.
	 *  @return its JSON object. */
	virtual Json toJson();

	//! Releases the memory held by the category.
	void clear();
};

/*! One custom jump list: an application, and the entries it pinned. */
struct CustomDestination {
	std::wstring Sid = L"";     //!< SID of the user the jump list belongs to
	std::wstring SidName = L"";	//!< name of that user
	std::wstring application = L"";//!< the application, resolved from the AppID when known
	std::wstring path = L"";       //!< path of the file in the working directory
	std::wstring pathOriginal = L"";//!< path it was read from on the examined volume
	unsigned int typeInt = 0;//!< kind of list, as the file numbers it
	std::wstring type = L"";	//!< that kind spelled out
	/*! Category of the jump list, absent if the file carries no shortcut.
	*
	* WHY A `unique_ptr`. The pointer was raw, and was released only by
	* `CustomDestination::clear()` — which nothing called: `JumplistCustoms::clear()`
	* empties the vector, which destroys the elements without going through that
	* method. Every Custom Destination therefore leaked its whole category, with
	* its vector of `RecentDoc` and the ID lists they hold. Ownership is now
	* carried by the type. */
	std::unique_ptr<CustomDestinationCategory> category;
	FILETIME created = { 0 };     //!< creation of the jump list FILE, local time
	FILETIME createdUtc = { 0 };  //!< the same instant in UTC
	FILETIME modified = { 0 };    //!< last modification of that file, local time
	FILETIME modifiedUtc = { 0 };	//!< the same instant in UTC
	FILETIME accessed = { 0 };    //!< last access to that file, local time
	FILETIME accessedUtc = { 0 };	//!< the same instant in UTC

	//! Builds an empty jump list.
	CustomDestination() {};

	/*! Reads a jump list, its category and every shortcut in it.
	* @param _path path of the .customDestinations-ms file.
	* @param _sid SID of the user it belongs to.
	*/
	CustomDestination(std::filesystem::path _path, std::wstring _sid);

	/*! Converts the jump list to JSON, category included.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the jump list.
	void clear();
};

/*! All the custom jump lists of every user of the machine. */
struct JumplistCustoms {
	std::vector<CustomDestination> customDestinations; //!< the jump lists read
	

	/*! Lists each user's CustomDestinations folder and reads every file.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `jumplistCustomDestinations.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the jump lists.
	void clear();
};