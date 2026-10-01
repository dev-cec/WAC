/*! \file
 *  \brief DPAPI master keys: which keys each user and the system hold, and since when — never the key.
 *
 *  WHAT THE ARTEFACT PROVES. Every secret Windows keeps for a user — saved
 *  passwords of the browsers, Wi-Fi keys, the credential manager, cookies —
 *  is encrypted with one of that user's DPAPI master keys, themselves
 *  encrypted by the user's password (or, for the system, by the DPAPI_SYSTEM
 *  secret of the SECURITY hive). The key files are COPIED AS THEY ARE, still
 *  encrypted, into the exhibit store: with the password or the system secret,
 *  the analysis can decrypt those secrets later (decision of 2026-10-01, B-032).
 *
 *  WHAT THE JSON GIVES. For each key file: the owner (SID, from its folder),
 *  the key's GUID, its version and policy, the sizes of its blocks — a domain
 *  backup block says the account belonged to a domain — and the file's dates:
 *  a key created at an odd hour is a new password, or a new account. The
 *  `Preferred` file names the key in use and when it expires. Nothing of the
 *  key material is decoded or emitted.
 *
 *  A CHECK OF ITS OWN. The GUID written in the header must be the file's name;
 *  a file whose header does not say so is listed without its fields.
 *
 *  Sources: `<profile>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>\\` and
 *  `\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\` (machine keys, and
 *  `User\\` for the system account's own); CREDHIST, the history of the
 *  user's previous passwords, is copied raw beside them, not converted.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

//! The DPAPI folder of a profile, relative to the profile.
extern const wchar_t DPAPI_PROFILE_FOLDER[];
//! The DPAPI folder of the system, relative to the system volume.
extern const wchar_t DPAPI_SYSTEM_FOLDER[];

/*! The header of a master key file (the fields before the encrypted blocks). */
struct DpapiMasterKeyHeader {
	uint32_t version = 0;
	std::wstring guid;              //!< the key's GUID, as written in the header (36 characters)
	uint32_t policy = 0;
	uint64_t masterKeyLength = 0;   //!< the user's copy, encrypted by the password
	uint64_t backupKeyLength = 0;   //!< the local backup copy
	uint64_t credHistLength = 0;    //!< the link to CREDHIST
	uint64_t domainKeyLength = 0;   //!< the copy encrypted by the domain's backup key: 0 off a domain
};

/*! Decodes the header of a master key file.
 *  @param data the file's bytes
 *  @param size their number
 *  @param header receives the fields
 *  @return false if the file is shorter than its 128-byte header, or its
 *          block sizes exceed the file */
bool parseDpapiMasterKeyHeader(const uint8_t* data, size_t size, DpapiMasterKeyHeader& header);

/*! The `Preferred` file: the GUID of the key in use, and when it expires.
 *  @param data the file's bytes
 *  @param size their number (24)
 *  @param guid receives the GUID, in the form of the key files' names
 *  @param expiresUtc receives the expiry
 *  @return false if the file is not 24 bytes long */
bool parseDpapiPreferred(const uint8_t* data, size_t size, std::wstring& guid, FILETIME& expiresUtc);

/*! One master key file. */
struct DpapiMasterKey {
	std::wstring scope;               //!< "User" (a profile's) or "System"
	std::wstring sid;                 //!< the owner, from the folder's name
	std::wstring path;                //!< the file on the examined machine
	FILETIME sourceCreatedUtc = { 0 }, sourceModifiedUtc = { 0 }, sourceAccessedUtc = { 0 };
	std::optional<DpapiMasterKeyHeader> header;   //!< empty if the header is unreadable or names another key
	bool preferred = false;           //!< the key `Preferred` names
	FILETIME preferredExpiresUtc = { 0 };   //!< …and its expiry
	//! @return the key file as a JSON object, without any key material
	Json toJson() const;
};

/*! The DPAPI master keys of every profile and of the system (dpapi_master_keys.json). */
class DpapiMasterKeys {
public:
	/*! Reads the key files extracted from each profile's and the system's Protect folder.
	 *  @return ERROR_SUCCESS, even without any key */
	HRESULT getData();
	/*! Writes dpapi_master_keys.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases what was read.
	void clear();
private:
	std::vector<DpapiMasterKey> keys_;   //!< one per key file
};
