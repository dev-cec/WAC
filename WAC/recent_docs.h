/*! \file
 *  \brief Recent documents: the .lnk shortcuts of `\\Recent`.
 *
 *  WHAT THE ARTEFACT PROVES. Windows creates a shortcut in
 *  `%AppData%\\Microsoft\\Windows\\Recent` every time a document is opened. The
 *  shortcut outlives the document's deletion and keeps the original path, the
 *  size and the timestamps of the TARGET as they were when it was opened: it
 *  therefore attests that a file existed and was opened, even if it is no
 *  longer on the disk — including on a removable volume long since unplugged.
 *
 *  TWO SETS OF TIMESTAMPS, NOT TO BE CONFUSED
 *    - `target*`: the target's dates, copied into the .lnk header;
 *    - `source*`: the dates of the .lnk file itself, that is the instant of the
 *      opening.
 *  The first date the document, the second date the user's ACTIVITY.
 *
 *  A TIME TRAP. The three timestamps of the .lnk header (offsets 28, 36, 44)
 *  are in UTC — MS-SHLLINK — despite field names that do not say so. Treating
 *  them as local times shifted the dates by the time-zone offset, where no
 *  format check could see it.
 *
 *  The structured content of the shortcut (ID list, extension blocks,
 *  properties) is parsed by `idList.h`.
 */
#pragma once

#include "binaires.h"
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <regex>
#include "tools.h"
#include "trans_id.h"
#include "idList.h"
#include "quickdigest5.h"

/*! One recent document: a .lnk shortcut, and the file it points to. */
struct RecentDoc {
public:
	// Holds unique_ptr (through IdList): movable type, not copyable.
	// Copying is forbidden explicitly, to get a clear error at the offending
	// site rather than a template error.
	RecentDoc(const RecentDoc&) = delete;
	RecentDoc& operator=(const RecentDoc&) = delete;
	RecentDoc(RecentDoc&&) = default;
	RecentDoc& operator=(RecentDoc&&) = default;

	std::wstring Sid = L"";      //!< SID of the user whose Recent folder holds it
	std::wstring path_original = L"";//!< path of the .lnk file on the examined volume
	std::wstring path = L"";     //!< path of the .lnk file in the working directory
	std::wstring md5Source=L"";  //!< MD5 of the .lnk file itself
	std::wstring target = L"";   //!< path of the document the shortcut points to
	EmpreinteBinaire empreinteCible; //!< fingerprints of that target, if `--binary` was given
	std::wstring description = L""; //!< description carried by the shortcut
	std::wstring relativePath = L"";//!< path of the target, relative to the shortcut
	std::wstring workingDirectory = L"";//!< working directory declared for the target
	std::wstring arguments = L"";//!< command-line arguments passed to the target
	std::wstring iconLocation = L"";//!< file the shortcut's icon is taken from
	unsigned int fileSize = 0;   //!< size of the target, as the .lnk header records it
	unsigned int iconIndex = 0;  //!< index of the icon in that file
	std::wstring commandOption = L"";//!< how the target is to be shown when opened
	GUID guid = { 0 };           //!< GUID of the shortcut, when it carries one
	FILETIME sourceCreated = { 0 };     //!< creation of the .lnk FILE, local time
	FILETIME sourceCreatedUtc = { 0 };  //!< the same instant in UTC
	FILETIME sourceModified = { 0 };    //!< last modification of the .lnk file, local time
	FILETIME sourceModifiedUtc = { 0 };	//!< the same instant in UTC
	FILETIME sourceAccessed = { 0 };    //!< last access to the .lnk file, local time
	FILETIME sourceAccessedUtc = { 0 };	//!< the same instant in UTC
	FILETIME targetCreated = { 0 };     //!< creation of the TARGET, local time
	FILETIME targetCreatedUtc = { 0 };  //!< the same instant, as the header stores it
	FILETIME targetModified = { 0 };    //!< last modification of the target, local time
	FILETIME targetModifiedUtc = { 0 };	//!< the same instant, as the header stores it
	FILETIME targetAccessed = { 0 };    //!< last access to the target, local time
	FILETIME targetAccessedUtc = { 0 };	//!< the same instant, as the header stores it
	LinkFlags flags = { 0 };            //!< flags of the shortcut: which parts it carries
	FileAttributes attributes = { 0 };  //!< attributes of the target file
	std::wstring volumeDriveType = L""; //!< kind of volume the target was on
	std::wstring volumeSerial = L"";    //!< serial number of that volume
	std::wstring volumeLabel = L"";     //!< label of that volume
	std::wstring netName = L"";         //!< network share the target was on
	std::wstring netDeviceName = L"";   //!< device name that share was mapped to
	std::wstring netProviderType = L"";	//!< kind of network provider
	std::vector<IdList> idLists;        //!< the target's PIDL, item by item

	/*! Parses a LNK file.
	*
	* The SIZE is indispensable, and was missing: without it no read could be
	* bounded, and the StringData fields — whose length is announced in the file
	* itself — were read up to the first zero met, hence possibly past the end of
	* the buffer on a truncated or forged shortcut.
	*
	* @param buffer the bytes of the shortcut.
	* @param taille size of that buffer, in bytes.
	*/
	void parseLNK(LPBYTE buffer, size_t taille);


	/*! Reads a shortcut from a file.
	* @param _path path of the .lnk file to parse.
	* @param _sid SID of the user whose Recent folder holds it.
	*/
	RecentDoc(std::filesystem::path _path, std::wstring _sid);

	/*! Reads a shortcut already in memory — a jump list holds its shortcuts
	* inside a single file.
	* @param buffer the bytes of the shortcut.
	* @param size size of that buffer, in bytes.
	* @param _path path of the file the buffer comes from.
	* @param _sid SID of the user that file belongs to.
	*/
	RecentDoc(LPBYTE buffer, size_t size, std::wstring _path, std::wstring _sid);

	/*! Converts the shortcut to JSON, shell items included.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the shortcut.
	void clear();
};

/*! All the recent documents of every user of the machine. */
struct RecentDocs {
	std::vector<RecentDoc> recentdocs; //!< the shortcuts, in the order they were listed

	/*! Lists each user's Recent folder and parses every .lnk file in it.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `recentdocs.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the shortcuts.
	void clear();

};