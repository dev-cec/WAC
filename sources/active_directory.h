/*! \file
 *  \brief The Active Directory database of a domain controller, read in the
 *         copy of `ntds.dit` (active_directory_*.json).
 *
 *  WHAT THE ARTEFACT PROVES. A compromise of a domain is written in its
 *  directory: an account added to a privileged group, a delegation or a
 *  service principal name set on it, a SID injected in its history, the
 *  replication rights granted on the domain that a DCSync needs. Each attribute
 *  keeps when it last changed and from which controller; each membership, when
 *  it was added or removed; a deleted object stays as a tombstone, its last name
 *  and parent kept.
 *
 *  WHAT IS WRITTEN.
 *   - active_directory_objects.json: one element per object, its name rebuilt
 *     up to the root, each attribute under its LDAP name in PascalCase;
 *   - active_directory_links.json: one element per value of a linked attribute
 *     (member…), removed ones included, with its dates and origin;
 *   - active_directory_replication.json: one element per object and attribute,
 *     from replPropertyMetaData: version, date, controller of origin, USNs;
 *   - active_directory_security_descriptors.json: each distinct descriptor
 *     once, which objects name by its SdId (the replication rights are the
 *     object ACEs of the domain's root).
 *
 *  THE SECRETS ARE NOT READ. Only the columns of a list of attributes are
 *  decoded (ATTRIBUTES, in the source): passwords and keys are never among
 *  them, and a new attribute of the schema stays unread until named there. The
 *  list is an allowance rather than a refusal because the secrets are many and
 *  extensible. The copy of the database itself is a piece of the collection, as
 *  a hive is: it holds them encrypted, and is protected as such.
 *
 *  THE FORMAT. `datatable` holds one row per object (DNT_col its number, PDNT_col
 *  its parent's, RDNtyp_col the attribute naming it, OBJ_col false for a phantom)
 *  and one column per attribute: "ATT", a letter for its syntax, then its internal
 *  identifier. Names are not assumed: the schema in the database itself gives each
 *  identifier its LDAP name (attributeSchema) and each class its name (classSchema).
 *   - a date ("l" syntax) is in seconds since 1601, a "q" one a FILETIME;
 *   - objectSid and sIDHistory keep their last sub-authority big-endian, so that
 *     SIDs sort by RID (measured on objectSid; no controller of the harness holds
 *     a sIDHistory, which is written the same way in the published descriptions);
 *   - a distinguished-name attribute holds the DNT of the object it names;
 *   - nTSecurityDescriptor holds a number in `sd_table`, 8 bytes.
 *  `link_table` holds the linked attributes: link_DNT the object bearing the link,
 *  backlink_DNT the object named, link_base the attribute (linkID / 2).
 *
 *  THE DATABASE IS COPIED LIVE: the latest changes are only in its logs,
 *  collected with it and replayed into the working copy (ese_recovery.h). Measured:
 *  without that, objects made after the last checkpoint are absent.
 *
 *  NOT A CONTROLLER: Services\NTDS\Parameters is absent from the SYSTEM hive,
 *  nothing was taken, and the files are empty.
 */
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>
#include <windows.h>
#include "ese_database.h"
#include "tools.h"

//! How a value of an attribute reads.
enum class DirectoryValueKind { Text, Int32, Int64, Flag, Seconds, FileTime, Sid, ObjectName, ClassName, Guid, Descriptor };

/*! One attribute's entry of replPropertyMetaData, or the metadata of a linked
 *  value: the state of the last change the controller knows. */
struct DirectoryChange {
	uint32_t attribute = 0;         //!< the attribute's internal identifier (replPropertyMetaData only)
	uint32_t version = 0;           //!< how many times it changed
	uint64_t createdSeconds = 0;    //!< a linked value: when it was added, seconds since 1601
	uint64_t changedSeconds = 0;    //!< when it last changed, seconds since 1601
	std::wstring invocationId;      //!< the controller of origin, by its database's identity
	uint64_t originatingUsn = 0;    //!< the update's number on that controller
	uint64_t localUsn = 0;          //!< its number on this controller
};

/*! Decodes replPropertyMetaData: a header of 16 bytes (version, reserved, number
 *  of entries, reserved) then 48-byte entries. Bounded by the value's real size,
 *  whatever the count it announces.
 *  @param value the value
 *  @param size its size
 *  @return the entries; none if the header is truncated or of another version */
std::vector<DirectoryChange> parseReplicationMetadata(const uint8_t* value, size_t size);

/*! Decodes link_metadata, 48 bytes: created (8), version (8), changed (8),
 *  controller (16), originating USN (8). Measured against
 *  Get-ADReplicationAttributeMetadata -ShowAllLinkedValues.
 *  @param value the value
 *  @param size its size
 *  @param change receives it; its localUsn is in another column
 *  @return false if the size is not this format's */
bool parseLinkMetadata(const uint8_t* value, size_t size, DirectoryChange& change);

/*! A SID as the directory stores it, in text: its last sub-authority big-endian.
 *  @param value the value
 *  @return the text, empty if this is no SID */
std::wstring directorySidToText(const std::vector<uint8_t>& value);

/*! One level of a distinguished name, as Get-ADObject writes it: "CN=" then the
 *  name with what LDAP reserves escaped (RFC 4514), a line feed — the mark of a
 *  deleted object — as \0A.
 *  @param type the naming attribute's name (cn, dc, ou)
 *  @param name the object's name
 *  @return the level */
std::wstring distinguishedNameLevel(const std::wstring& type, const std::wstring& name);

/*! The names of the bits set in userAccountControl (ADS_USER_FLAG_ENUM).
 *  @param value the attribute
 *  @return a JSON array; unknown bits as hexadecimal */
Json userAccountControlFlags(uint32_t value);

//! The directory (active_directory_*.json).
class ActiveDirectory {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, also on a machine that is no controller
	HRESULT toJson();           //!< @return the result of the writes
	void clear();               //!< releases the names read; the database closes with the object

private:
	//! A row's place in the tree.
	struct TreeNode {
		uint32_t parent = 0, namingAttribute = 0;
		std::wstring name;
	};
	void readNames(const EseTable& table);
	HRESULT writeObjects(const EseTable& table);
	HRESULT writeLinks();
	HRESULT writeSecurityDescriptors();
	Json valueToJson(DirectoryValueKind kind, const std::vector<uint8_t>& value) const;
	std::wstring distinguishedName(uint32_t dnt) const;
	std::wstring serverOf(const std::wstring& invocationId) const;  //!< a controller's name, empty if unknown (retired)

	bool opened_ = false;       //!< a database was found and opened
	EseDatabase database_;
	std::map<uint32_t, TreeNode> tree_;                 //!< DNT → place
	std::map<uint32_t, std::wstring> attributeNames_;   //!< internal identifier → LDAP name
	std::map<uint32_t, std::wstring> classNames_;       //!< governsID → LDAP name
	std::map<uint32_t, std::wstring> linkNames_;        //!< link_base → LDAP name of the forward link
	std::map<std::wstring, uint32_t> invocationIds_;    //!< a controller's invocationId → the DNT of its nTDSDSA
};

/*! Where the directory's database is, in the SYSTEM hive opened.
 *  @param database receives the file (DSA Database file)
 *  @param logFolder receives its logs' folder (Database log files path)
 *  @return false on a machine that is no controller */
bool directoryDatabaseLocation(std::wstring& database, std::wstring& logFolder);
