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
 *  them as local times shifted the dates by the time-area offset, where no
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
#include "link_tracking.h"
#include <optional>
#include "quickdigest5.h"

/*! One recent document: a .lnk shortcut, and the file it points to. */
struct RecentDoc {
public:
	// Holds unique_ptr (through IdList): movable type, not copyable.
	// Copying is forbidden explicitly, to get a clear error at the offending
	// site rather than a template error.
	RecentDoc(const RecentDoc&) = delete;
	RecentDoc& operator=(const RecentDoc&) = delete;
	//! Moves a shortcut (its unique_ptr go along).
	RecentDoc(RecentDoc&&) = default;
	//! Moves a shortcut (its unique_ptr go along).
	RecentDoc& operator=(RecentDoc&&) = default;

	std::wstring Sid = L"";      //!< SID of the user whose Recent folder holds it
	std::wstring path_original = L"";//!< path of the .lnk file on the examined volume
	std::wstring path = L"";     //!< path of the .lnk file in the working directory
	std::wstring md5Source=L"";  //!< MD5 of the .lnk file itself
	std::wstring target = L"";   //!< path of the document the shortcut points to
	BinaryFingerprint targetFingerprint; //!< fingerprints of that target, if `--binary` was given
	std::wstring description = L""; //!< description carried by the shortcut
	std::wstring relativePath = L"";//!< path of the target, relative to the shortcut
	std::wstring workingDirectory = L"";//!< working directory declared for the target
	std::wstring arguments = L"";//!< command-line arguments passed to the target
	std::wstring iconLocation = L"";//!< file the shortcut's icon is taken from
	unsigned int fileSize = 0;   //!< size of the target, as the .lnk header records it
	unsigned int iconIndex = 0;  //!< index of the icon in that file
	std::wstring commandOption = L"";//!< how the target is to be shown when opened
	GUID guid = { 0 };           //!< GUID of the shortcut, when it carries one
	FILETIME sourceCreatedUtc = { 0 };  //!< creation of the .lnk FILE, UTC (the local times are derived at output)
	FILETIME sourceModifiedUtc = { 0 };	//!< last modification of the .lnk file, UTC
	FILETIME sourceAccessedUtc = { 0 };	//!< last access to the .lnk file, UTC
	FILETIME targetCreatedUtc = { 0 };  //!< creation of the TARGET, UTC, as the header stores it
	FILETIME targetModifiedUtc = { 0 };	//!< last modification of the target, UTC
	FILETIME targetAccessedUtc = { 0 };	//!< last access to the target, UTC
	LinkFlags flags = { 0 };            //!< flags of the shortcut: which parts it carries
	FileAttributes attributes = { 0 };  //!< attributes of the target file
	std::wstring volumeDriveType = L""; //!< kind of volume the target was on
	std::wstring volumeSerial = L"";    //!< serial number of that volume
	std::wstring volumeLabel = L"";     //!< label of that volume
	std::wstring netName = L"";         //!< network share the target was on
	std::wstring netDeviceName = L"";   //!< device name that share was mapped to
	std::wstring netProviderType = L"";	//!< kind of network provider
	std::vector<IdList> idLists;        //!< the target's PIDL, item by item

	/*  EXTRA DATA (MS-SHLLINK 2.5): the blocks after the StringData. They were
	    not read at all — among them the tracker block, which names the machine
	    the target was on. */
	std::vector<std::wstring> extraDataBlocks; //!< names of the blocks present, in order (unknown ones by signature)
	std::optional<LinkTracking> tracking;      //!< TrackerDataBlock: DROID and birth DROID of the target
	std::wstring machineId = L"";       //!< TrackerDataBlock: NetBIOS name of the machine the target was on
	std::wstring targetEnvironment = L"";//!< EnvironmentVariableDataBlock: target path with its variables (%USERPROFILE%…)
	std::wstring iconEnvironment = L""; //!< IconEnvironmentDataBlock: icon path with its variables
	std::wstring darwinData = L"";      //!< DarwinDataBlock: Windows Installer descriptor of the target
	std::wstring shimLayer = L"";       //!< ShimDataBlock: compatibility layer applied to the target
	std::wstring knownFolderId = L"";   //!< KnownFolderDataBlock: GUID of the known folder of the target
	std::optional<unsigned int> specialFolderId; //!< SpecialFolderDataBlock: CSIDL of the target's folder
	std::optional<unsigned int> consoleCodePage; //!< ConsoleFEDataBlock: code page of the console
	std::vector<SPS> propertyStores;    //!< PropertyStoreDataBlock: the target's properties

	/*! Parses a LNK file.
	*
	* The SIZE is indispensable, and was missing: without it no read could be
	* bounded, and the StringData fields — whose length is announced in the file
	* itself — were read up to the first zero met, hence possibly past the end of
	* the buffer on a truncated or forged shortcut.
	*
	* @param buffer the bytes of the shortcut.
	* @param size size of that buffer, in bytes.
	*/
	void parseLNK(LPBYTE buffer, size_t size);

	/*! Reads the ExtraData blocks, up to the terminal block.
	* @param buffer the bytes of the shortcut
	* @param size size of that buffer
	* @param at offset of the first block, just after the StringData
	*/
	void parseExtraData(LPBYTE buffer, size_t size, size_t at);


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

	/*! Adds the ExtraData fields to the shortcut's JSON: nothing if it has none.
	 *  @param o the shortcut's object */
	void addExtraData(Json& o);

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