#pragma once
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <vector>
#include <memory>
#include <variant>
#include <string>
#include <filesystem>
#include <regex>
#include "tools.h"
#include "json.h"
#include "trans_id.h"



/*! \file
* \brief Shell items, ID lists and extension blocks: the structures behind
* shortcuts, shellbags, MRU lists and jump lists.
*
* This file cannot be split into several ones: cyclic references between the
* types prevent it.
*/

/***************************************************************************************************
* STRUCUTRES VRTUELLES
****************************************************************************************************/
/*! Virtual base type of the shell items.
*  Every shell item inherits from it, which lets the other classes hold a shell
*  item of any kind.
*/
struct IShellItem {
public:
	/*! Virtual destructor: indispensable to destroy a derived object through a base
	* pointer (undefined behaviour otherwise). */
	virtual ~IShellItem() = default;

	int level = 0; //!< depth in the tree of shell items, used to lay out the JSON
	bool is_zip = false; //!< for the shellbags: says that the children are archive contents

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	virtual Json toJson() = 0;

};

/*! Virtual base type of the extension blocks.
*  Every extension block inherits from it, which lets the other classes hold an
*  extension block of any kind.
*/
struct IExtensionBlock {
public:
	/*! Virtual destructor: indispensable to destroy a derived object through a base
	* pointer (undefined behaviour otherwise). */
	virtual ~IExtensionBlock() = default;

	int level = 0;//!< depth in the tree of shell items, used to lay out the JSON
	bool isPresent = false;//!< true if an extension block is present, false otherwise
	std::wstring signature = L"";//!< signature of the extension block, which identifies its structure

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	virtual Json toJson() = 0;

};

/*! User Property View Delegate Shell Item
*/
struct UserPropertyViewDelegate {
	/*! Virtual destructor: indispensable to destroy a derived object through a base
	* pointer (undefined behaviour otherwise). */
	virtual ~UserPropertyViewDelegate() = default;


	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	virtual Json toJson() = 0;

};

/***************************************************************************************************
* Fonctions
****************************************************************************************************/

/*! Extracts the extension blocks of a buffer, according to their signature.
* @param buffer the bytes of the extension blocks to parse
* @param extensionBlocks vector receiving the extension blocks extracted from the buffer
* @param _level depth in the tree of elements, used to lay out the output JSON
* @param is_zip whether the shell item is a zip file: the children of a zip (or
*        similar) have a special format. Concerns only files — some zips are
*        identified as directories, and then there is no special format — and
*        only the beef0004 extension blocks
* @param is_file whether the parent shell item is a file
*/
void getExtensionBlock(LPBYTE buffer, std::vector<std::unique_ptr<IExtensionBlock>>* extensionBlocks, int _level, bool* is_zip, bool is_file);

/***************************************************************************************************
* FLAGS
****************************************************************************************************/

/*! The FileAttributesFlags structure defines bits that specify the file
* attributes of the link target, if the target is a file system item. The file
* attributes can be used if the link target is not available, or if accessing
* the target would be inefficient. The target's attributes may not be in sync
* with this value.
* Documentation: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/378f485c-0be9-47a4-a261-7df467c3c9c6
*/
struct FileAttributes {
	bool ReadOnly = false; //!< The file is read-only.
	bool Hidden = false; //!< The file is hidden, and so not included in an ordinary directory listing.
	bool System = false; //!< The file is a system file.
	bool Directory = false; //!< The file is a directory.
	bool Archive = false; //!< The file is marked to be included in an incremental backup operation.
	bool Normal = false; //!< The file is a standard file with no special attribute. Valid only when used alone.
	bool Temporary = false; //!< The file is temporary: it holds data needed while an application runs, and no longer once it has finished.
	bool SparseFile = false; //!< The file is a sparse file. Sparse files are usually large files whose data are mostly zeros.
	bool ReparsePoint = false; //!< The file holds a reparse point, a block of user-defined data attached to a file or a directory.
	bool Compressed = false; //!< The file is compressed.
	bool Offline = false; //!< The file is offline. Its data are not immediately available.
	bool NotContentIndexed = false; //!< The file will not be indexed by the operating system's content indexing service.
	bool Encrypted = false; //!< The file or directory is encrypted. For a file, all its data are encrypted; for a directory, every file and directory created in it is encrypted by default.


	/*! Decodes the attributes.
	* @param attr integer holding the file's attributes; the constructor extracts
	*        them from it with bit masks.
	*/
	FileAttributes(unsigned int attr);

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	std::wstring to_wstring();

};

/*! The LinkFlags structure defines bits that specify which shell link
* structures are present in the file format after the ShellLinkHeader structure.
* Documentation: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af
*/
struct LinkFlags {
	bool HasLinkTargetIDList = false; //!< The shell link is saved with an item ID list (IDList). If this bit is set, a LinkTargetIDList structure MUST follow the ShellLinkHeader. If it is not set, that structure MUST NOT be present.
	bool HasLinkInfo = false; //!< The shell link is saved with link information. If this bit is set, a LinkInfo structure MUST be present. If it is not set, that structure MUST NOT be present.
	bool HasName = false; //!< The shell link is saved with a name string. If this bit is set, a NAME_STRING StringData structure MUST be present. If it is not set, that structure MUST NOT be present.
	bool HasRelativePath = false; //!< The shell link is saved with a relative path string. If this bit is set, a RELATIVE_PATH StringData structure MUST be present. If this bit is not set, this structure MUST NOT be present.
	bool HasWorkingDir = false; //!< The shell link is saved with a working directory. If this bit is set, a WORKING_DIR StringData structure MUST be present. If it is not set, that structure MUST NOT be present.
	bool HasArguments = false;  //!< The shell link is saved with command-line arguments. If this bit is set, a COMMAND_LINE_ARGUMENTS StringData structure MUST be present. If it is not set, that structure MUST NOT be present.
	bool HasIconLocation = false; //!< The shell link is saved with an icon location string. If this bit is set, an ICON_LOCATION StringData structure MUST be present. If it is not set, that structure MUST NOT be present.
	bool IsUnicode = false; //!< The shell link holds Unicode-encoded strings. This bit SHOULD be set. If it is, the StringData section holds Unicode strings; otherwise it holds strings encoded with the system's default code page.
	bool ForceNoLinkInfo = false; //!< The LinkInfo structure is ignored.
	bool HasExpString = false; //!< The shell link is saved with an EnvironmentVariableDataBlock.
	bool RunInSeparateProcess = false; //!< The target is run in a separate virtual machine when launching a link target that is a 16-bit application.
	bool Unused1 = false; //!< A bit that is undefined and MUST be ignored.
	bool HasDarwinID = false; //!< The shell link is saved with a DarwinDataBlock.
	bool RunAsUser = false; //!< The application is run as a different user when the target of the shell link is activated.
	bool HasExpIcon = false; //!< The shell link is saved with an IconEnvironmentDataBlock.
	bool NoPidlAlias = false; //! The file system location is represented in the shell namespace when the path to an item is parsed into an IDList.
	bool Unused2 = false; //!< A bit that is undefined and MUST be ignored.
	bool RunWithShimLayer = false; //!< The shell link is saved with a ShimDataBlock.
	bool ForceNoLinkTrack = false; //!< The TrackerDataBlock is ignored.
	bool EnableTargetMetadata = false; //!< The shell link attempts to collect the target's properties and store them in the PropertyStoreDataBlock when the link target is set.
	bool DisableLinkPathTracking = false; //!< The EnvironmentVariableDataBlock is ignored.
	bool DisableKnownFolderTracking = false; //!< The SpecialFolderDataBlock and the KnownFolderDataBlock are ignored when loading the shell link. If this bit is set, those extra data blocks SHOULD NOT be saved when saving the shell link.
	bool DisableKnownFolderAlias = false; //!< If the link has a KnownFolderDataBlock, the unaliased form of the known folder IDList SHOULD be used when translating the target IDList at the time the link is loaded.
	bool AllowLinkToLink = false; //!< Creating a link that references another link is enabled. Otherwise, specifying a link as the target IDList SHOULD NOT be allowed.
	bool UnaliasOnSave = false; //!< When saving a link for which the target IDList is under a known folder, either the unaliased form of that known folder or the target IDList SHOULD be used.
	bool PreferEnvironmentPath = false; //!< The target IDList SHOULD NOT be stored; instead, the path specified in the EnvironmentVariableDataBlock SHOULD be used to refer to the target.
	bool KeepLocalIDListForUNCTarget = false; //!< When the target is a UNC name that refers to a location on a local machine, the local path IDList in the PropertyStoreDataBlock SHOULD be stored, so that it can be used when the link is loaded on the local machine.

	/*! Decodes the link flags.
	* @param _flags integer holding the link's flags; the constructor extracts
	*        them from it with bit masks.
	*/
	LinkFlags(unsigned int _flags);

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	std::wstring to_wstring();

};


/*! The ShellVolumeFlags structure defines bits that specify the kind of shell
* volume.
*/
struct ShellVolumeFlags {
	bool None = false; //!< No information on the volume
	bool SystemFolder = false; //!< the volume is a system directory
	bool LocalDisk = false; //!< the volume is a local disk

	/*! Decodes the flags.
	* @param i byte holding the data; the constructor extracts them from it with
	*        bit masks.
	*/
	ShellVolumeFlags(unsigned char i);

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	std::wstring to_wstring();

};

/*! The FsFlags structure defines bits that specify the kind of link.
*/
struct FsFlags {
	bool IS_DIRECTORY = false; //!< it is a directory
	bool IS_FILE = false; //!< it is a file
	bool IS_UNICODE = false; //!< the link's strings are in UNICODE
	bool UNKNOWN = false; //!< the kind of link is unknown
	bool HAS_CLSID = false; //!< the link has a class GUID

	/*! Decodes the flags.
	* @param i byte holding the data; the constructor extracts them from it with
	*        bit masks.
	*/
	FsFlags(unsigned char i);

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	std::wstring to_wstring();

};


/***************************************************************************************************
* SPS
****************************************************************************************************/

/*! One of the values of an SPS (serialized property set).
*/
struct SPSValue {
	int level = 0; //!< depth in the tree of shell items, used to lay out the JSON
	unsigned int size = 0; //! size of the object
	unsigned short int valueType = 0; //! identifies the kind of value
	std::wstring guid = L""; //! GUID of the value
	std::wstring id = L""; // id of the value
	std::wstring name = L""; // name of the value
	Json value = Json::str(L""); // the value itself; it may be an object, in which case it is kept as JSON to fit the output format.

	/*! Reads one value of an SPS.
	* @param buffer the bytes to parse
	* @param _guid GUID of the SPS the value belongs to
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	SPSValue(LPBYTE buffer, std::wstring _guid, int _level);

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();

};

/*! A Serialized Property Set.
*/
struct SPS {
	int level = 0; //!< depth in the tree of shell items, used to lay out the JSON
	unsigned int size = 0; //!< size of the object, in bytes
	unsigned int version = 0; //!< version of the object, which decides its internal structure
	std::wstring guid = L""; //!< GUID of the object
	std::wstring FriendlyName = L"";//!< name attached to the GUID
	std::vector<SPSValue> values; //!< the SPSVALUEs of the SPS

	/*! Builds an empty object.
	*/
	SPS() {};

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	SPS(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();

};

std::unique_ptr<IShellItem> makeShellItem(LPBYTE buffer, int _level, bool Parentiszip = false);

/***************************************************************************************************
* ID LIST
****************************************************************************************************/
/*! A list of shell items.
*/
struct IdList {
	int level = 0;//!< depth in the tree of shell items, used to lay out the JSON
	unsigned int item_size = 0; //!< size of the object, in bytes
	unsigned char type_char = NULL; //!< kind of the object
	std::wstring type_hex = L""; //!< kind of the object, in hexadecimal
	std::wstring type = L""; //!< name of the object's kind
	std::wstring data = L""; //!< hexadecimal dump of the object, when it must be included in the output JSON
	std::unique_ptr<IShellItem> shellItem; //!< pointer to the shell item object matching the kind

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	* @param Parentiszip true if the parent element is an archive: the content of
	*        a ZIP has a format of its own, which cannot be guessed from the item
	*/
	IdList(LPBYTE buffer, int _level, bool Parentiszip = false);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();

};

/***************************************************************************************************
* EXTENSION BLOCKS
****************************************************************************************************/
/*!  Related to CMergedFolder object
*/
struct Beef0000 : IExtensionBlock {
	std::wstring guid1 = L""; //!< identifiant GUID
	std::wstring identifier1 = L"";//!< name matching the GUID
	std::wstring guid2 = L""; //!< identifiant GUID
	std::wstring identifier2 = L""; //!< name matching the GUID

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0000(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*!  Extension block related to CFileUrlStub object. Used for display name?
*/
struct Beef0001 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0001(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to CFileUrlStub object. Used for display name?
*/
struct Beef0002 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0002(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to CFSFolder and CFileSysItemString object. Used for junction information?
*/
struct Beef0003 : IExtensionBlock {
	std::wstring guid = L""; //!< identifiant GUID
	std::wstring identifier = L"";//!< name attached to the GUID

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0003(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to the CFSFolder and CFileSysItem objects.
	* For the shellbags, if the parent is a zip or similar, the children have a
	* special format, so whether the parent is a zip must be known. Concerns only
	* files — some zips are identified as directories, and then there is no
	* special format — and only the beef0004 extension blocks.
*/
struct Beef0004 : IExtensionBlock {
	FILETIME creationDate = { 0 }; //!< creation date
	FILETIME creationDateUtc = { 0 };//!< creation date in UTC
	FILETIME accessedDate = { 0 }; //!< access date
	FILETIME accessedDateUtc = { 0 }; //!< access date in UTC
	unsigned short int ExtensionVersion=0;
	/*! Internal identifier of the block (offset 16), read but never emitted before. */
	unsigned short int identifier = 0;
	/*! NTFS file reference: `$MFT` entry number on 48 bits and sequence number on
	* 16, present from version 7 of the block on.
	*
	* WHY IT MATTERS. This reference names the EXACT `$MFT` entry of the file: it
	* ties a shellbag or shortcut entry to its record in the file table, hence
	* makes it possible to find the file again even renamed or deleted, and to
	* cross-check its dates. WAC did not read it, while the raw reading of the
	* volume already uses those references elsewhere.
	* Null if the block is of a version older than 7, or if the item does not
	* come from an NTFS volume. */
	unsigned long long mftEntryNumber = 0;
	unsigned short int mftSequenceNumber = 0;
	/*! Nature deduced from the reference: "NTFS", "FAT" or "Network/special item". */
	std::wstring mftNote;
	std::wstring longName = L"";
	std::wstring localizedName = L"";

	/*! Reads the extension block.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	* @param is_zip whether the object is a compressed archive
	* @param is_file whether the object is a file
	*/
	Beef0004(LPBYTE buffer, int _level, bool* is_zip, bool is_file);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to CFSFolder and CFileSysItem object. Used for personalized name?
*/
struct Beef0006 : IExtensionBlock {
	std::wstring username = L"";

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0006(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to CBitBucket object.
*/
struct Beef0008 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0008(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to CBitBucket object. Used for original path?
*/
struct Beef0009 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0009(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to CMergedFolder object. Used for source count or sub shell item list?
*/
struct Beef000a : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef000a(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block  related to CControlPanelFolder object. Used for display name/CPL category?
*/
struct Beef000c : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef000c(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef000e : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message to display in the JSON
	std::wstring guid = L"";//!< Identifiant GUID
	std::wstring identifier = L"";//!< name matching the GUID
	std::vector<std::unique_ptr<IExtensionBlock>> extensionblocks; //!< tableau d'extension blocks
	std::vector<SPS> SPSs; //! array of SPS
	std::vector<std::unique_ptr<IShellItem>> ishellitems;//!< array of shell items

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef000e(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0010 : IExtensionBlock {
	SPS sps;

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0010(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0013 : IExtensionBlock {
	std::wstring message = L"The purpose of this extension block is unknown"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0013(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! The extension block has seen to be used with the CUri class identifier which is the GUID "df2fce13-25ec-45bb-9d4c-cecd47c2430c". The CUri data could be a Vista and/or MSIE 7 specific extension.
*/
struct Beef0014 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block";//!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0014(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0016 : IExtensionBlock {
	std::wstring value = L"";

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0016(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*!  Extension block  related to Shell item from Windows 7 BagMRU (Search Home).
*/
struct Beef0017 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block";//!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0017(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block seen in
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\\{0B2BAAEB-0042-4DCA-AA4D-3EE8648D03E5}`
*
* The path is written as a literal (backquotes): outside of that frame, doxygen
* reads "\\{" as the opening of a member group, never closed.
*/
struct Beef0019 : IExtensionBlock {
	std::wstring guid1 = L""; //!< identifiant GUID
	std::wstring identifier1 = L"";//!< name matching the GUID
	std::wstring guid2 = L"";//!< identifiant GUID
	std::wstring identifier2 = L"";//!< name matching the GUID

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0019(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001a : IExtensionBlock {
	std::wstring fileDocumentTypeString = L"";

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef001a(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001b : IExtensionBlock {
	std::wstring fileDocumentTypeString = L""; //!< string giving the kind of document

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef001b(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001d : IExtensionBlock {
	std::wstring executable = L"";

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef001d(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001e : IExtensionBlock {
	std::wstring pinType = L"";

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef001e(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0021 : IExtensionBlock {
	SPS sps;  //!< an SPS object

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0021(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0024 : IExtensionBlock {
	SPS sps;  //!< an SPS object

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0024(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0025 : IExtensionBlock {
	FILETIME filetime1 = { 0 }; //!< date as a FILETIME
	FILETIME filetime2 = { 0 };//!< date as a FILETIME

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0025(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0026 : IExtensionBlock {
	FILETIME ctimeUtc = { 0 }; //!< creation date
	FILETIME ctime = { 0 };//!< creation date in UTC
	FILETIME mtimeUtc = { 0 };//!< modification date
	FILETIME mtime = { 0 };//!< modification date in UTC
	FILETIME atimeUtc = { 0 };//!< access date
	FILETIME atime = { 0 };//!< access date in UTC
	std::unique_ptr<IdList> idlist;// pointer to a list of shell items (idlist)
	std::unique_ptr<IShellItem> shellitem;// pointer to a shell item
	std::unique_ptr<SPS> sps;// pointer to an SPS

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0026(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0027 : IExtensionBlock {
	SPS sps; //!< an SPS object

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0027(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
/*! Extension block with an unrecognised signature.
*
*  WHY THIS CLASS. The factory merely wrote the dump into the LOG and added
*  NOTHING to the list of blocks: an unknown extension block was therefore
*  absent from the JSON, and invisible unless the collection was run again with
*  `--loglevel=2`. At the default log level, the data was lost without a trace.
*
*  An object whose structure cannot be read must return its BYTES: it is the
*  only way an analyst can decode it later, and the only one that tells "WAC
*  cannot decode this" from "there was nothing". `UnknownShellItem` already does
*  so; this class restores the symmetry.
*/
struct BeefUnknown : IExtensionBlock {
	std::wstring data;        //!< raw content of the block, in hexadecimal
	unsigned short size = 0;  //!< size declared by the block

	/*! Reads the extension block.
	* @param buffer the bytes to parse
	* @param _level depth in the tree, used to lay out the JSON
	*/
	BeefUnknown(LPBYTE buffer, int _level);

	//! Converts the object to JSON.
	Json toJson() override;
};

struct Beef0029 : IExtensionBlock {
	std::wstring message = L"The purpose of this extension block is unknown"; //!< message to display in the JSON

	/*! Reads the object.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Beef0029(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/********************************************************************************************************************
* shell items
*********************************************************************************************************************/

/*! Volume Shell Item
*/
struct VolumeShellItem : IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	ShellVolumeFlags flags = { 0 }; //!< flags matching the options of the volume type
	std::wstring name = L""; //!< name of the volume
	std::wstring guid = L""; //!< GUID of the volume
	std::wstring identifier = L""; //!< name attached to the GUID

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param type_char kind of the object, as a character
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	VolumeShellItem(LPBYTE buffer, unsigned char type_char, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();

};

/*! Control panel Shell Item
*/
struct ControlPanel : IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	std::wstring guid = L"";//!< identifiant GUID
	std::wstring identifier = L""; //!< name attached to the GUID
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< tableau d'Extension Block


	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param itemSize total size of the object
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	ControlPanel(LPBYTE buffer, unsigned short int itemSize, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Control Panel Category Shell Item
*/
struct ControlPanelCategory :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	std::wstring id = L""; //!< identifiant
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< tableau d'Extension Block


	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	ControlPanelCategory(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Returns the kind of value of the SPSVALUE from its hexadecimal code.
*/
std::wstring getType(unsigned int type);

/*! Returns the value of the SPSVALUE according to its kind.
*/
/*! Reads a typed value of a property store.
*
* @param buffer start of the entry
* @param pos reading position in the entry, advanced as the decoding goes
* @param valueType VT_ type of the value
* @param level depth, for the layout
* @param inputSize total size of the entry, used to return the raw bytes when
*        the type is not decoded. Zero if the caller does not know it: the value
*        then comes out without a dump.
* @param typeNotDecoded set to true if the type could not be decoded. The caller
*        must then stop its walk when the entry's size is not declared,
*        otherwise the next entry would be read in the wrong place.
* @return the value, or an object describing the type not supported
*/
Json getValue(LPBYTE buffer, unsigned int* pos, unsigned short valueType, unsigned int level,
              unsigned int inputSize = 0, bool* typeNotDecoded = nullptr);

/*! Format of a Property inside the UserPropertyViews.
*/
struct Property {
	int level = 0;//!< depth in the tree of shell items, used to lay out the JSON
	unsigned int id = 0; //!< identifier of the property
	unsigned short int type = 0; //!< type of the property
	unsigned int size = 0; //!< size of the property
	/*! True if the value's type could not be decoded.
	*
	* The size of a `Property` is not declared: it is DEDUCED from the progress
	* of the decoding. An unknown type therefore leaves the position where it
	* was, and the next property would be read in the wrong place — producing
	* properties that look normal and are wrong. The loops that chain properties
	* stop on that flag: a truncated and reported list is better than a complete
	* and invented one. */
	bool typeNotDecoded = false;
	std::wstring guid = L""; //! identifiant GUID
	std::wstring FriendlyName = L""; //!< name attached to the GUID
	Json value = Json::str(L"");//!< value of the property
	
	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	Property(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();

};

/*! Format of a UserPropertyView of signature 0xC01.
*/
struct UserPropertyView0xC01 : UserPropertyViewDelegate {
	unsigned int level = 0;//!< depth in the tree of shell items, used to lay out the JSON
	std::wstring folder = L""; //!< name of the directory
	std::wstring fullurl = L""; //! url correspondante

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	UserPropertyView0xC01(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();


};

/*! Format of a UserPropertyView of type 0x23febee.
*/
struct UserPropertyView0x23febbee : UserPropertyViewDelegate {
	unsigned int level = 0;//!< depth in the tree of shell items, used to lay out the JSON
	std::wstring guid = L""; //!< identifiant GUID
	std::wstring FriendlyName = L""; //!< name attached to the GUID

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	UserPropertyView0x23febbee(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();

};

/*! Format of a UserPropertyView of type 0x7192006.
*/
struct UserPropertyView0x07192006 : UserPropertyViewDelegate {
	unsigned int level = 0;//!< depth in the tree of shell items, used to lay out the JSON
	FILETIME modified = { 0 }; //!< modification date
	FILETIME modifiedUtc = { 0 };//!< modification date in UTC
	FILETIME created = { 0 }; //!< creation date
	FILETIME createdUtc = { 0 }; //!< creation date in UTC
	std::wstring folderName1 = L""; //!< name of the directory
	std::wstring folderName2 = L""; //!< name of the directory
	std::wstring folderIdentifier = L""; //!< identifier of the directory
	std::wstring guidClass = L""; //!< GUID of the class
	std::wstring FriendlyName = L""; //!< name attached to the class GUID
	std::vector<Property> properties; //!< array of Property

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	UserPropertyView0x07192006(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson();

};

/*! Format of a UserPropertyView of type 0x10312005.
*/
struct UserPropertyView0x10312005 : UserPropertyViewDelegate {
	unsigned int level = 0;//!< depth in the tree of shell items, used to lay out the JSON
	std::wstring name = L"";//!< name of the property
	std::wstring identifier = L""; //!< identifier of the property
	std::wstring filesystem = L"";//!< name of the file system
	std::wstring guidClass = L""; //!< class GUID
	std::wstring FriendlyName = L""; //!< name attached to the class GUID
	std::vector<std::wstring> guidstrings; //!< array of GUID
	std::vector<Property> properties;//!< array of Property

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	UserPropertyView0x10312005(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of a UserPropertyView shell item.
*/
struct UsersPropertyView :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	unsigned short int totalsize = 0; //!< total size of the object
	unsigned short int dataSize = 0; //!< size of the data
	unsigned int signature = 0; //!< signature of the object
	unsigned short int SPSDataSize = 0; //!< size of the SPS data
	unsigned short int identifierSize = 0;//!< size of the identifier
	unsigned int dataOffset = 0; //!< offset of the data
	unsigned short int extensionOffset = 0; //!< offset of the extension blocks
	unsigned short int spsOffset = 0;//!< offset of the SPS
	std::vector<SPS> SPSs; //!< the SPS
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< the extension blocks
	/*! Nature of the item, deduced from its signature.
	*
	* The signature does not only choose a decoder: at libyal (libfwsi) it
	* IDENTIFIES the type. Two of the signatures handled here do not name "users
	* property views" but MTP devices — a volume and a file entry —, that is the
	* trace that a phone or a camera was plugged in and browsed. The generic class
	* name hid that fact. */
	std::wstring itemType;
	/*! 32-bit identifier of the signatures that carry one (a 4-byte identifier),
	* read as libfwsi does. */
	unsigned int identifier32 = 0;
	bool identifier32Lu = false;
	// `guid` and `identifier` removed: the constructor never filled them.
	// The identification goes through the signature, `itemType` and the delegate.
	std::unique_ptr<UserPropertyViewDelegate> delegate; //! the delegated UsersPropertyView

	/*! Raw content, in hexadecimal, when the signature is not recognised.
	*
	* MEASURED ON A REAL COLLECTION (2026-09-15): 75 of the 89
	* `USERS_PROPERTY_VIEW` carried an unknown signature (`0xc1ec0c9`) and came
	* out with nothing but their type and that signature as content. The dump
	* existed, but went only into the LOG: at the default log level, 75 objects
	* therefore vanished entirely from the output.
	* See the quality bar: an object that is not decoded returns its bytes. */
	std::wstring data;

	/*! Builds an empty object.
	*/
	UsersPropertyView() {};

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	UsersPropertyView(LPBYTE buffer, int _level);

	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of a RootFolder shell item.
*/
struct RootFolder :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	std::wstring sortIndex = L""; //!< sort index
	std::wstring guid = L"";//!< identifiant GUID
	std::wstring identifier = L"";//!< name attached to the GUID
	std::vector<SPS> SPSs; //!< array of SPS
	//std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; // TODO: extension blocks are present with the GUID type, but the same data are found in the SPS, so they are skipped

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	RootFolder(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of a Network shell item.
*/
struct NetworkShellItem :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	std::wstring subtypename = L"";//!< name of the subtype
	std::wstring location = L"";//!< emplacement 
	std::wstring description = L"";//!< description of the object
	std::wstring comments = L"";//!< comments of the object
	FILETIME modifiedUtc = { 0 };//!< modification date in UTC
	FILETIME modified = { 0 };//!< modification date

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	NetworkShellItem(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of an Archive File shell item.
*/
struct ArchiveFileContent :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	// `subtypename` and `location` removed: declared here but never filled
	// (they belong to NetworkShellItem, which carries the same names).
	std::wstring name = L"";//!< name of the archive
	FILETIME modifiedUtc = { 0 };//!< modification date in UTC
	FILETIME modified = { 0 };//!< modification date

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	ArchiveFileContent(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of a URL shell item.
*/
struct URIShellItem :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	std::wstring uri = L""; //!< URI 

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	URIShellItem(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of a File Entry shell item.
*/
struct FileEntryShellItem :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	unsigned short int fsFileSize = 0; //!< size of the file
	FILETIME fsFileModificationUtc = { 0 };//!< modification date in UTC
	FILETIME fsFileModification = { 0 };//!< modification date
	std::wstring fsPrimaryName = L"";//!< primary name
	FsFlags fsFlags = { 0 }; //!< flags describing the options of the entry
	FileAttributes fsFileAttributes = { 0 }; //!< flags describing the attributes of the entry
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< the extension blocks

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param itemSize size of the object
	* @param shell_item_type_char kind of shell item, as a character
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	FileEntryShellItem(LPBYTE buffer, unsigned short int itemSize, unsigned char shell_item_type_char, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of a Users Files Folder shell item.
*/
struct UsersFilesFolder :IShellItem {
public:
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	std::wstring primaryName = L"";//!< primary name
	FILETIME modifiedUtc = { 0 };//!< modification date in UTC
	FILETIME modified = { 0 };//!< modification date
	std::unique_ptr<IExtensionBlock> extensionBlock; //!< block d'extension

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	UsersFilesFolder(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of a Favorites shell item.
*/

/*! Shell item of the "favorite" kind.
*
* NOT COVERED BY THE TESTS (checked on 2026-09-15): the validation VM produces no
* shell item of this kind, so the parsing is never exercised. High forensic
* relevance if met — a favorite expresses a resource deliberately marked by the
* user, hence an intent — which is why it is worth validating rather than
* leaving as it is.
* To exercise it: shellbags from an interactive session that browsed the
* Favorites, or a reference set of hives.
*/
struct FavoriteShellitem :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	UsersPropertyView UPV; //! Objet UsersPropertyView

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	FavoriteShellitem(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};

/*! Format of an UNKNOWN shell item.
*/
/*! Shell item of a type recognised by its signature, but without a dedicated
*  decoder.
*
*  WHY. A shell item is not identified by its class byte alone: several types are
*  recognised by a signature placed in the data (libfwsi_item.c tries every
*  decoder, and each checks its own). WAC tested only the class byte, so that
*  six documented types fell into "UNKNOWN": CD burner, games folder, web site,
*  Acronis file, control panel .cpl file.
*
*  Naming them is better than "unknown", even without decoding all their fields:
*  the analyst knows what is in front of them, and the bytes stay attached.
*/
struct TypedShellItem : IShellItem {
	bool isPresent = false;   //!< presence, to lay out the JSON
	std::wstring typeName;    //!< type reconnu, ex. "CD Burn", "Game Folder"
	std::wstring data;        //!< raw content, in hexadecimal

	/*! Reads the item.
	* @param buffer data of the item
	* @param size size of the item
	* @param _typeName label of the recognised type
	* @param _level depth in the tree
	*/
	TypedShellItem(LPBYTE buffer, unsigned short size, const std::wstring& _typeName,
	               int _level);

	Json toJson() override;
};

/*! Delegate folder.
*
*  This container wraps ONE COMPLETE SHELL ITEM, placed at offset 6, and is
*  recognised by the delegation GUID written 32 bytes before the end
*  ({5E591A74-DF96-48D3-8D67-1733BCEE28BA}). The GUID of the delegating class
*  occupies the last 16 bytes.
*
*  It was not recognised at all: the whole item — hence the shell item it holds,
*  with its path, its dates and its property stores — was reduced to an
*  "UNKNOWN" object. It was the missing type that cost the most, because it is
*  common in the shellbags and it hides a decodable item.
*/
struct DelegateFolder : IShellItem {
	bool isPresent = false;                      //!< presence, for the JSON
	std::wstring classGuid;                      //!< GUID of the delegated class
	std::wstring classFriendlyName;               //!< label of that GUID
	std::unique_ptr<IShellItem> innerItem;        //!< nested shell item
	std::wstring data;                            //!< raw content if not decoded

	/*! Reads the item.
	* @param buffer data of the item
	* @param size size of the item
	* @param _level depth in the tree
	*/
	DelegateFolder(LPBYTE buffer, unsigned short size, int _level);

	Json toJson() override;
};

struct UnknownShellItem :IShellItem {
	bool isPresent = false; //!< whether the object is present, used to lay out the JSON
	std::wstring data = L"";//!< string holding the data

	/*! Reads the item.
	* @param buffer the bytes to parse
	* @param _level depth in the tree of elements, used to lay out the output JSON
	*/
	UnknownShellItem(LPBYTE buffer, int _level);
	/*! Converts the object to JSON.
	* @return its JSON value
	*/
	Json toJson() override;

};


