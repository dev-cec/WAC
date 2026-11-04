/*! \file
 *  \brief The Active Directory database of a domain controller (see active_directory.h).
 */
#include "active_directory.h"
#include "conversions.h"
#include "ese_recovery.h"
#include "consigne.h"
#include <algorithm>
#include <cstring>
#include <cwctype>
#include <set>

namespace {

const wchar_t NTDS_PARAMETERS[] = L"Services\\NTDS\\Parameters";

// The bootstrap: the only identifiers assumed, those that say all the others.
const uint32_t ATTRIBUTE_ID = 131102;       //!< attributeID of an attributeSchema
const uint32_t GOVERNS_ID = 131094;         //!< governsID of a classSchema
const uint32_t LDAP_DISPLAY_NAME = 131532;  //!< lDAPDisplayName of both
const uint32_t LINK_ID = 131122;            //!< linkID of a linked attributeSchema
const uint32_t OBJECT_NAME = 589825;        //!< name, the RDN's value
const uint32_t INVOCATION_ID = 131187;      //!< invocationId of a controller's nTDSDSA

const uint32_t REPL_PROPERTY_METADATA = 589827;

const size_t GUID_SIZE = 16;
const uint64_t FILETIME_TICKS_PER_SECOND = 10000000;
const uint64_t FILETIME_NEVER = 0x7FFFFFFFFFFFFFFFull;   //!< accountExpires: never

//! An attribute converted: nothing else of the row is decoded (see the header).
struct Attribute {
	const wchar_t* name;
	DirectoryValueKind kind;
};

using K = DirectoryValueKind;

const Attribute ATTRIBUTES[] = {
	// Identity
	{ L"name", K::Text }, { L"objectGUID", K::Guid }, { L"objectSid", K::Sid }, { L"sIDHistory", K::Sid },
	{ L"objectClass", K::ClassName }, { L"objectCategory", K::ObjectName }, { L"sAMAccountName", K::Text },
	{ L"sAMAccountType", K::Int32 }, { L"userPrincipalName", K::Text }, { L"displayName", K::Text }, { L"description", K::Text },
	{ L"info", K::Text }, { L"dNSHostName", K::Text }, { L"operatingSystem", K::Text }, { L"operatingSystemVersion", K::Text },
	// Dates and state
	{ L"whenCreated", K::Seconds }, { L"whenChanged", K::Seconds }, { L"uSNCreated", K::Int64 }, { L"uSNChanged", K::Int64 },
	{ L"pwdLastSet", K::FileTime }, { L"accountExpires", K::FileTime }, { L"lastLogon", K::FileTime },
	{ L"lastLogonTimestamp", K::FileTime }, { L"badPasswordTime", K::FileTime }, { L"badPwdCount", K::Int32 },
	{ L"logonCount", K::Int32 }, { L"isDeleted", K::Flag }, { L"isRecycled", K::Flag }, { L"lastKnownParent", K::ObjectName },
	{ L"msDS-LastKnownRDN", K::Text },
	// What a compromise changes
	{ L"userAccountControl", K::Int32 }, { L"primaryGroupID", K::Int32 }, { L"groupType", K::Int32 }, { L"adminCount", K::Int32 },
	{ L"servicePrincipalName", K::Text }, { L"msDS-AllowedToDelegateTo", K::Text },
	{ L"msDS-AllowedToActOnBehalfOfOtherIdentity", K::Descriptor }, { L"msDS-GroupMSAMembership", K::Descriptor },
	{ L"nTSecurityDescriptor", K::Descriptor }, { L"msDS-SupportedEncryptionTypes", K::Int32 }, { L"altSecurityIdentities", K::Text },
	{ L"scriptPath", K::Text }, { L"profilePath", K::Text }, { L"homeDirectory", K::Text },
	// Group policies, trusts, the controllers
	{ L"gPLink", K::Text }, { L"gPOptions", K::Int32 }, { L"gPCFileSysPath", K::Text }, { L"versionNumber", K::Int32 },
	{ L"gPCMachineExtensionNames", K::Text }, { L"gPCUserExtensionNames", K::Text }, { L"trustPartner", K::Text },
	{ L"flatName", K::Text }, { L"trustDirection", K::Int32 }, { L"trustType", K::Int32 }, { L"trustAttributes", K::Int32 },
	{ L"invocationId", K::Guid }, { L"tombstoneLifetime", K::Int32 }, { L"dSHeuristics", K::Text },
};

/*! A column's attribute: "ATTm589825" gives 589825.
 *  @param name the column's name
 *  @param attribute receives the identifier
 *  @return false for a column of the engine (DNT_col…) */
bool attributeOfColumn(const std::wstring& name, uint32_t& attribute) {
	if (name.size() < 5 || name.compare(0, 3, L"ATT") != 0) return false;
	try { attribute = (uint32_t)std::stoul(name.substr(4)); }
	catch (const std::exception&) { return false; }
	return true;
}

//! The cell of a column, or nullptr.
const EseCell* cellOf(const EseRecord& record, const EseColumn* column) {
	if (!column) return nullptr;
	for (const EseCell& c : record) if (c.columnId == column->id && !c.values.empty()) return &c;
	return nullptr;
}

//! The number in a column of a record, or the default.
uint64_t numberIn(const EseRecord& record, const EseColumn* column, uint64_t otherwise = 0) {
	const EseCell* cell = cellOf(record, column);
	return cell ? eseCellInteger(*cell).value_or(otherwise) : otherwise;
}

//! The text a value holds, UTF-16 as the directory stores it.
std::wstring textOf(const std::vector<uint8_t>& value) {
	return readWideZ(value.data(), value.size() & ~(size_t)1, 0);
}

/*! The column of a table by its name.
 *  @return the column, or nullptr */
const EseColumn* columnNamed(const EseTable& table, const wchar_t* name) {
	for (const EseColumn& c : table.columns) if (c.name == name) return &c;
	return nullptr;
}

/*! The table reduced to some of its columns: the only ones the reader decodes,
 *  whatever else the rows hold.
 *  @param table the table
 *  @param wanted whether a column is taken
 *  @return the table, its other columns gone */
EseTable reducedTo(const EseTable& table, const std::function<bool(const EseColumn&)>& wanted) {
	EseTable reduced = table;
	reduced.columns.clear();
	for (const EseColumn& c : table.columns) if (wanted(c)) reduced.columns.push_back(c);
	return reduced;
}

/*! An attribute's LDAP name as a JSON key, in the PascalCase of every output:
 *  its letters and digits, the first in capital. sAMAccountName gives
 *  SAMAccountName, msDS-LastKnownRDN gives MsDSLastKnownRDN: still found by
 *  whoever searches the attribute, its case ignored.
 *  @param name the LDAP name
 *  @return the key */
std::wstring fieldOf(const std::wstring& name) {
	std::wstring field;
	for (wchar_t c : name) if (std::iswalnum(c) && c < 128) field.push_back(c);
	if (!field.empty()) field[0] = (wchar_t)std::towupper(field[0]);
	return field;
}

/*! Adds a date, UTC then local, as every artefact does. A null date, or the
 *  "never" of accountExpires, is not one.
 *  @param object the object
 *  @param name the field
 *  @param ticks 100 ns since 1601 */
void addDate(Json& object, const std::wstring& name, uint64_t ticks) {
	if (ticks == 0 || ticks >= FILETIME_NEVER) return;
	const FILETIME utc = filetimeFromTicks(ticks);
	object.add(name + L"Utc", Json::str(timeToIso8601Utc(utc)));
	object.add(name, Json::str(utcTimeToIso8601Local(utc)));
}

//! The same, from seconds since 1601.
void addSeconds(Json& object, const std::wstring& name, uint64_t seconds) {
	if (seconds < FILETIME_NEVER / FILETIME_TICKS_PER_SECOND) addDate(object, name, seconds * FILETIME_TICKS_PER_SECOND);
}

//! The name of an attribute in a table of names, or nothing.
void addNameOf(Json& object, const wchar_t* field, const std::map<uint32_t, std::wstring>& names, uint32_t id) {
	const auto found = names.find(id);
	if (found != names.end()) object.add(field, Json::str(found->second));
}

} // namespace

std::vector<DirectoryChange> parseReplicationMetadata(const uint8_t* value, size_t size) {
	std::vector<DirectoryChange> changes;
	const size_t HEADER = 16, ENTRY = 48;
	if (size < HEADER || readLittleEndian<uint32_t>(value) != 1) return changes;
	const size_t announced = readLittleEndian<uint32_t>(value + 8);
	const size_t entries = std::min(announced, (size - HEADER) / ENTRY);
	for (size_t i = 0; i < entries; ++i) {
		const uint8_t* e = value + HEADER + i * ENTRY;
		DirectoryChange c;
		c.attribute = readLittleEndian<uint32_t>(e);
		c.version = readLittleEndian<uint32_t>(e + 4);
		c.changedSeconds = readLittleEndian<uint64_t>(e + 8);
		c.invocationId = guid_to_wstring(e + 16);
		c.originatingUsn = readLittleEndian<uint64_t>(e + 32);
		c.localUsn = readLittleEndian<uint64_t>(e + 40);
		changes.push_back(std::move(c));
	}
	return changes;
}

bool parseLinkMetadata(const uint8_t* value, size_t size, DirectoryChange& change) {
	if (size != 48) return false;
	change.createdSeconds = readLittleEndian<uint64_t>(value);
	change.version = (uint32_t)readLittleEndian<uint64_t>(value + 8);
	change.changedSeconds = readLittleEndian<uint64_t>(value + 16);
	change.invocationId = guid_to_wstring(value + 24);
	change.originatingUsn = readLittleEndian<uint64_t>(value + 40);
	return true;
}

std::wstring directorySidToText(const std::vector<uint8_t>& value) {
	const size_t HEADER = 8, SUB_AUTHORITY = 4;
	if (value.size() < HEADER + SUB_AUTHORITY || value.size() != HEADER + SUB_AUTHORITY * value[1]) return L"";
	std::vector<uint8_t> sid = value;
	std::reverse(sid.end() - SUB_AUTHORITY, sid.end());
	return sidToText(sid.data(), sid.size());
}

std::wstring distinguishedNameLevel(const std::wstring& type, const std::wstring& name) {
	std::wstring level;
	for (wchar_t c : type) level.push_back((wchar_t)towupper(c));
	level.push_back(L'=');
	for (size_t i = 0; i < name.size(); ++i) {
		const wchar_t c = name[i];
		if (c == L'\n') { level += L"\\0A"; continue; }
		const bool reserved = wcschr(L",+\"\\<>;=", c) != nullptr && c != 0;
		const bool atEdge = (c == L' ' && (i == 0 || i + 1 == name.size())) || (c == L'#' && i == 0);
		if (reserved || atEdge) level.push_back(L'\\');
		level.push_back(c);
	}
	return level;
}

Json userAccountControlFlags(uint32_t value) {
	static const struct { uint32_t bit; const wchar_t* name; } FLAGS[] = {
		{ 0x00000001, L"SCRIPT" }, { 0x00000002, L"ACCOUNTDISABLE" }, { 0x00000008, L"HOMEDIR_REQUIRED" },
		{ 0x00000010, L"LOCKOUT" }, { 0x00000020, L"PASSWD_NOTREQD" }, { 0x00000040, L"PASSWD_CANT_CHANGE" },
		{ 0x00000080, L"ENCRYPTED_TEXT_PWD_ALLOWED" }, { 0x00000100, L"TEMP_DUPLICATE_ACCOUNT" },
		{ 0x00000200, L"NORMAL_ACCOUNT" }, { 0x00000800, L"INTERDOMAIN_TRUST_ACCOUNT" },
		{ 0x00001000, L"WORKSTATION_TRUST_ACCOUNT" }, { 0x00002000, L"SERVER_TRUST_ACCOUNT" },
		{ 0x00010000, L"DONT_EXPIRE_PASSWORD" }, { 0x00020000, L"MNS_LOGON_ACCOUNT" },
		{ 0x00040000, L"SMARTCARD_REQUIRED" }, { 0x00080000, L"TRUSTED_FOR_DELEGATION" },
		{ 0x00100000, L"NOT_DELEGATED" }, { 0x00200000, L"USE_DES_KEY_ONLY" },
		{ 0x00400000, L"DONT_REQ_PREAUTH" }, { 0x00800000, L"PASSWORD_EXPIRED" },
		{ 0x01000000, L"TRUSTED_TO_AUTH_FOR_DELEGATION" }, { 0x04000000, L"PARTIAL_SECRETS_ACCOUNT" },
	};
	Json flags = Json::arr();
	uint32_t rest = value;
	for (const auto& f : FLAGS)
		if (value & f.bit) { flags.push(Json::str(f.name)); rest &= ~f.bit; }
	if (rest) flags.push(Json::str(L"0x" + to_hex(rest, 8)));
	return flags;
}

bool directoryDatabaseLocation(std::wstring& database, std::wstring& logFolder) {
	if (!conf.CurrentControlSet) return false;
	if (getRegSzValue(conf.CurrentControlSet, NTDS_PARAMETERS, L"DSA Database file", &database) != ERROR_SUCCESS || database.empty())
		return false;
	if (getRegSzValue(conf.CurrentControlSet, NTDS_PARAMETERS, L"Database log files path", &logFolder) != ERROR_SUCCESS)
		logFolder.clear();
	return true;
}

HRESULT ActiveDirectory::getData() {
	log(0, L"ℹ️Active Directory :");
	std::wstring source, logFolder;
	if (!directoryDatabaseLocation(source, logFolder)) {
		log(2, L"❇️no Services\\NTDS\\Parameters: not a domain controller");
		return ERROR_SUCCESS;
	}
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(source));
	if (found == index.end() || found->second.workingFile.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const HRESULT opened = OpenRecoveredEseDatabase(database_, found->second.workingFile, found->second.sourcePath,
	                                                logFolder.empty() ? std::wstring() : std::wstring(extractedPath(logFolder)));
	if (opened != ERROR_SUCCESS) return opened;
	if (database_.dirtyShutdown())
		log(1, L"⚠️ntds.dit read as copied live (dirty shutdown): the latest changes are in its logs, in the exhibit store, not in active_directory_*.json");
	const EseTable* table = database_.table(L"datatable");
	if (!table) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	readNames(*table);
	opened_ = true;
	log(2, L"❇️" + std::to_wstring(tree_.size()) + L" row(s), " + std::to_wstring(attributeNames_.size()) + L" attribute(s) in the schema");
	return ERROR_SUCCESS;
}

/*! First pass over the rows: the tree, the schema's names, the controllers. */
void ActiveDirectory::readNames(const EseTable& table) {
	const std::set<uint32_t> needed = { ATTRIBUTE_ID, GOVERNS_ID, LDAP_DISPLAY_NAME, LINK_ID, OBJECT_NAME, INVOCATION_ID };
	const EseTable reduced = reducedTo(table, [&](const EseColumn& c) {
		uint32_t attribute = 0;
		return (attributeOfColumn(c.name, attribute) && needed.count(attribute))
		    || c.name == L"DNT_col" || c.name == L"PDNT_col" || c.name == L"RDNtyp_col";
	});
	auto attributeColumn = [&](uint32_t attribute) {
		for (const EseColumn& c : reduced.columns) {
			uint32_t id = 0;
			if (attributeOfColumn(c.name, id) && id == attribute) return &c;
		}
		return static_cast<const EseColumn*>(nullptr);
	};
	const EseColumn* dnt = columnNamed(reduced, L"DNT_col"), * parent = columnNamed(reduced, L"PDNT_col"), * naming = columnNamed(reduced, L"RDNtyp_col");
	const EseColumn* attributeId = attributeColumn(ATTRIBUTE_ID), * governsId = attributeColumn(GOVERNS_ID), * display = attributeColumn(LDAP_DISPLAY_NAME);
	const EseColumn* linkId = attributeColumn(LINK_ID), * name = attributeColumn(OBJECT_NAME), * invocation = attributeColumn(INVOCATION_ID);
	database_.forEachRecord(reduced, [&](EseRecord& r) {
		const uint32_t number = (uint32_t)numberIn(r, dnt);
		TreeNode node;
		node.parent = (uint32_t)numberIn(r, parent);
		node.namingAttribute = (uint32_t)numberIn(r, naming);
		if (const EseCell* c = cellOf(r, name)) node.name = textOf(c->values.front());
		tree_[number] = std::move(node);
		if (const EseCell* c = cellOf(r, invocation))
			if (c->values.front().size() == GUID_SIZE) invocationIds_[guid_to_wstring(c->values.front().data())] = number;
		const EseCell* label = cellOf(r, display);
		if (!label) return;
		const std::wstring text = textOf(label->values.front());
		if (cellOf(r, attributeId)) attributeNames_[(uint32_t)numberIn(r, attributeId)] = text;
		if (cellOf(r, governsId)) classNames_[(uint32_t)numberIn(r, governsId)] = text;
		// A forward link's identifier is even, its back link's the next: both share link_base.
		if (cellOf(r, linkId) && numberIn(r, linkId) % 2 == 0) linkNames_[(uint32_t)numberIn(r, linkId) / 2] = text;
	});
}

std::wstring ActiveDirectory::distinguishedName(uint32_t dnt) const {
	std::wstring path;
	//! Deepest tree followed: a forged parent's loop stops there.
	const unsigned DEPTH_MAX = 256;
	uint32_t at = dnt;
	for (unsigned depth = 0; depth < DEPTH_MAX; ++depth) {
		const auto node = tree_.find(at);
		// The root of the tree, of parent 0, names no level.
		if (node == tree_.end() || node->second.parent == 0) break;
		const auto type = attributeNames_.find(node->second.namingAttribute);
		if (!path.empty()) path.push_back(L',');
		path += distinguishedNameLevel(type == attributeNames_.end() ? L"CN" : type->second, node->second.name);
		at = node->second.parent;
	}
	return path;
}

Json directoryNumberToJson(DirectoryValueKind kind, const std::vector<uint8_t>& value) {
	// A value too short for its kind is no value: a zero here would read as one the directory holds.
	switch (kind) {
	case K::Int32: return value.size() >= 4 ? Json::num((long long)(int32_t)readLittleEndian<uint32_t>(value.data())) : Json::str(L"");
	case K::Int64: return value.size() >= 8 ? Json::num((long long)readLittleEndian<uint64_t>(value.data())) : Json::str(L"");
	case K::Flag: return value.size() >= 4 ? Json::boolean(readLittleEndian<uint32_t>(value.data()) != 0) : Json::str(L"");
	default: return Json::str(L"");
	}
}

/*! One value of an attribute, by its kind.
 *  @param kind how it reads
 *  @param value the value
 *  @return the JSON value; a text empty, not emitted, if it cannot be read as that */
Json ActiveDirectory::valueToJson(DirectoryValueKind kind, const std::vector<uint8_t>& value) const {
	switch (kind) {
	case K::Int32: case K::Int64: case K::Flag: return directoryNumberToJson(kind, value);
	case K::Sid: return Json::str(directorySidToText(value));
	case K::Guid: return Json::str(value.size() == GUID_SIZE ? guid_to_wstring(value.data()) : L"");
	case K::ObjectName: return Json::str(value.size() >= 4 ? distinguishedName(readLittleEndian<uint32_t>(value.data())) : L"");
	case K::ClassName: {
		const auto found = classNames_.find(value.size() >= 4 ? readLittleEndian<uint32_t>(value.data()) : 0);
		return Json::str(found == classNames_.end() ? L"" : found->second);
	}
	default: return Json::str(textOf(value));
	}
}

namespace {

/*! An attribute whose value is a descriptor: a number in sd_table (SdId, 8
 *  bytes), the one form measured; otherwise the descriptor itself. */
void addDescriptor(Json& object, const std::wstring& field, const std::vector<uint8_t>& value) {
	if (value.size() == 8) object.add(field + L"SdId", Json::num((unsigned long long)readLittleEndian<uint64_t>(value.data())));
	else object.add(field, securityDescriptorToJson(value.data(), value.size()));
}

//! An attribute's change, as its date, version and origin.
void addChange(Json& row, const DirectoryChange& change, const std::wstring& server) {
	row.add(L"Version", Json::num((unsigned long long)change.version));
	addSeconds(row, L"Created", change.createdSeconds);
	addSeconds(row, L"Changed", change.changedSeconds);
	row.add(L"OriginatingInvocationId", Json::str(change.invocationId));
	if (!server.empty()) row.add(L"OriginatingServer", Json::str(server));
	row.add(L"OriginatingUsn", Json::num((unsigned long long)change.originatingUsn));
	if (change.localUsn) row.add(L"LocalUsn", Json::num((unsigned long long)change.localUsn));
}

} // namespace

std::wstring ActiveDirectory::serverOf(const std::wstring& invocationId) const {
	const auto found = invocationIds_.find(invocationId);
	return found == invocationIds_.end() ? L"" : distinguishedName(found->second);
}

/*! Second pass over the rows: each object, and its attributes' changes. A
 *  phantom (OBJ_col false) only names what a link points to: not an object. */
HRESULT ActiveDirectory::writeObjects(const EseTable& table) {
	std::map<std::wstring, uint32_t> identifiers;
	for (const auto& [id, name] : attributeNames_) identifiers[name] = id;
	std::map<uint32_t, const Attribute*> wanted;
	for (const Attribute& a : ATTRIBUTES) {
		const auto found = identifiers.find(a.name);
		if (found != identifiers.end()) wanted[found->second] = &a;
	}
	const EseTable reduced = reducedTo(table, [&](const EseColumn& c) {
		uint32_t attribute = 0;
		return (attributeOfColumn(c.name, attribute) && (wanted.count(attribute) || attribute == REPL_PROPERTY_METADATA))
		    || c.name == L"DNT_col" || c.name == L"OBJ_col";
	});
	const EseColumn* dnt = columnNamed(reduced, L"DNT_col"), * isObject = columnNamed(reduced, L"OBJ_col");
	std::vector<std::pair<const EseColumn*, const Attribute*>> columns;
	const EseColumn* metadata = nullptr;
	const EseColumn* objectGuid = nullptr;
	for (const EseColumn& c : reduced.columns) {
		uint32_t attribute = 0;
		if (!attributeOfColumn(c.name, attribute)) continue;
		if (attribute == REPL_PROPERTY_METADATA) { metadata = &c; continue; }
		columns.emplace_back(&c, wanted.at(attribute));
		if (wcscmp(wanted.at(attribute)->name, L"objectGUID") == 0) objectGuid = &c;
	}
	JsonArrayWriter objects("active_directory_objects.json"), replication("active_directory_replication.json");
	database_.forEachRecord(reduced, [&](EseRecord& r) {
		if (!numberIn(r, isObject)) return;
		const std::wstring name = distinguishedName((uint32_t)numberIn(r, dnt));
		// The root of the tree and the engine's own rows, of parent 0: no object of the directory.
		if (name.empty()) return;
		Json object = Json::obj();
		object.add(L"DistinguishedName", Json::str(name));
		for (const auto& [column, attribute] : columns) {
			const EseCell* cell = cellOf(r, column);
			if (!cell) continue;
			const std::wstring field = fieldOf(attribute->name);
			if (cell->compressionScheme >= 0 || cell->longValueMissing) {
				object.add(field, eseCellToJson(*column, *cell));
				continue;
			}
			const std::vector<uint8_t>& first = cell->values.front();
			if (attribute->kind == K::Seconds && first.size() >= 8) addSeconds(object, field, readLittleEndian<uint64_t>(first.data()));
			else if (attribute->kind == K::FileTime && first.size() >= 8) addDate(object, field, readLittleEndian<uint64_t>(first.data()));
			else if (attribute->kind == K::Descriptor) addDescriptor(object, field, first);
			else if (cell->values.size() == 1) object.add(field, valueToJson(attribute->kind, first));
			else {
				Json list = Json::arr();
				for (const std::vector<uint8_t>& v : cell->values) list.push(valueToJson(attribute->kind, v));
				object.add(field, list);
			}
			if (wcscmp(attribute->name, L"userAccountControl") == 0 && first.size() >= 4)
				object.add(L"UserAccountControlFlags", userAccountControlFlags(readLittleEndian<uint32_t>(first.data())));
		}
		objects.add(object);
		const EseCell* changes = cellOf(r, metadata);
		if (!changes) return;
		for (const DirectoryChange& change : parseReplicationMetadata(changes->values.front().data(), changes->values.front().size())) {
			Json row = Json::obj();
			row.add(L"DistinguishedName", Json::str(name));
			if (const EseCell* guid = cellOf(r, objectGuid))
				if (guid->values.front().size() == GUID_SIZE) row.add(L"ObjectGUID", Json::str(guid_to_wstring(guid->values.front().data())));
			addNameOf(row, L"Attribute", attributeNames_, change.attribute);
			row.add(L"AttributeId", Json::num((unsigned long long)change.attribute));
			addChange(row, change, serverOf(change.invocationId));
			replication.add(row);
		}
	});
	const HRESULT objectsClosed = objects.close(), replicationClosed = replication.close();
	return objectsClosed != ERROR_SUCCESS ? objectsClosed : replicationClosed;
}

/*! Every value of every linked attribute, a removed one kept with its date. */
HRESULT ActiveDirectory::writeLinks() {
	JsonArrayWriter links("active_directory_links.json");
	const EseTable* table = database_.table(L"link_table");
	if (!table) return links.close();
	const EseColumn* source = columnNamed(*table, L"link_DNT"), * target = columnNamed(*table, L"backlink_DNT"),
	               * base = columnNamed(*table, L"link_base"), * deleted = columnNamed(*table, L"link_deltime"),
	               * usn = columnNamed(*table, L"link_usnchanged"), * metadata = columnNamed(*table, L"link_metadata"),
	               * data = columnNamed(*table, L"link_data");
	database_.forEachRecord(*table, [&](EseRecord& r) {
		Json row = Json::obj();
		const uint32_t linkBase = (uint32_t)numberIn(r, base);
		addNameOf(row, L"Attribute", linkNames_, linkBase);
		row.add(L"LinkBase", Json::num((unsigned long long)linkBase));
		row.add(L"Object", Json::str(distinguishedName((uint32_t)numberIn(r, source))));
		row.add(L"Target", Json::str(distinguishedName((uint32_t)numberIn(r, target))));
		addSeconds(row, L"Removed", numberIn(r, deleted));
		if (const EseCell* c = cellOf(r, data)) row.add(L"Data", eseCellToJson(*data, *c));
		DirectoryChange change;
		const EseCell* m = cellOf(r, metadata);
		if (m && parseLinkMetadata(m->values.front().data(), m->values.front().size(), change)) {
			change.localUsn = numberIn(r, usn);
			addChange(row, change, serverOf(change.invocationId));
		}
		links.add(row);
	});
	return links.close();
}

/*! Each descriptor once: objects carry its number (…SdId). */
HRESULT ActiveDirectory::writeSecurityDescriptors() {
	JsonArrayWriter descriptors("active_directory_security_descriptors.json");
	const EseTable* table = database_.table(L"sd_table");
	if (!table) return descriptors.close();
	const EseColumn* id = columnNamed(*table, L"sd_id"), * count = columnNamed(*table, L"sd_refcount"), * value = columnNamed(*table, L"sd_value");
	database_.forEachRecord(*table, [&](EseRecord& r) {
		const EseCell* cell = cellOf(r, value);
		if (!cell) return;
		Json row = Json::obj();
		row.add(L"SdId", Json::num((unsigned long long)numberIn(r, id)));
		row.add(L"ReferenceCount", Json::num((unsigned long long)numberIn(r, count)));
		if (cell->compressionScheme >= 0 || cell->longValueMissing) row.add(L"Descriptor", eseCellToJson(*value, *cell));
		else row.merge(securityDescriptorToJson(cell->values.front().data(), cell->values.front().size()));
		descriptors.add(row);
	});
	return descriptors.close();
}

HRESULT ActiveDirectory::toJson() {
	if (!opened_) {
		// Not a controller: the files exist, empty, as those of an absent role.
		JsonArrayWriter objects("active_directory_objects.json"), links("active_directory_links.json"),
		                replication("active_directory_replication.json"), descriptors("active_directory_security_descriptors.json");
		const HRESULT closed[] = { objects.close(), links.close(), replication.close(), descriptors.close() };
		for (HRESULT hr : closed) if (hr != ERROR_SUCCESS) return hr;
		return ERROR_SUCCESS;
	}
	HRESULT hr = writeObjects(*database_.table(L"datatable"));
	if (hr == ERROR_SUCCESS) hr = writeLinks();
	if (hr == ERROR_SUCCESS) hr = writeSecurityDescriptors();
	return hr;
}

void ActiveDirectory::clear() {
	tree_.clear();
	attributeNames_.clear();
	classNames_.clear();
	linkNames_.clear();
	invocationIds_.clear();
}
