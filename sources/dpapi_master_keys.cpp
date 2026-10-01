/*! \file
 *  \brief DPAPI master keys (see dpapi_master_keys.h).
 */
#include "dpapi_master_keys.h"
#include "consigne.h"
#include <cstring>
#include <filesystem>
#include <fstream>

const wchar_t DPAPI_PROFILE_FOLDER[] = L"\\AppData\\Roaming\\Microsoft\\Protect";
const wchar_t DPAPI_SYSTEM_FOLDER[] = L"\\Windows\\System32\\Microsoft\\Protect";

namespace {

// Layout of a master key file's header (as the DPAPI implementations document it).
const size_t MK_VERSION = 0x00;          //!< uint32
const size_t MK_GUID = 0x0C;             //!< 36 UTF-16 characters, no terminator
const size_t MK_GUID_CHARACTERS = 36;
const size_t MK_POLICY = 0x5C;           //!< uint32
const size_t MK_MASTER_KEY_LENGTH = 0x60;  //!< uint64, then backup, CREDHIST, domain key
const size_t MK_HEADER_SIZE = 0x80;
const size_t PREFERRED_SIZE = 24;        //!< GUID (16), then the expiry FILETIME (8)

/*! Whether a file name is a key's: a GUID of 36 characters, 8-4-4-4-12.
 *  @param name the file name
 *  @return true for a key file */
bool isKeyFileName(const std::wstring& name) {
	if (name.size() != MK_GUID_CHARACTERS) return false;
	for (size_t i = 0; i < name.size(); ++i) {
		const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
		if (dash ? name[i] != L'-' : !iswxdigit(name[i])) return false;
	}
	return true;
}

//! @return the content of a file of the working copy, empty if unreadable
std::vector<uint8_t> readFile(const std::filesystem::path& file) {
	std::ifstream in(file, std::ios::binary);
	return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

/*! Reads one Protect\\<SID> folder of the working copy: its key files, and
 *  which of them `Preferred` names.
 *  @param folder the folder, in the working copy
 *  @param scope "User" or "System"
 *  @param sid the owner
 *  @param keys receives the key files */
void readSidFolder(const std::filesystem::path& folder, const std::wstring& scope, const std::wstring& sid,
                   std::vector<DpapiMasterKey>& keys) {
	std::wstring preferredGuid;
	FILETIME preferredExpires = { 0 };
	const std::vector<uint8_t> preferred = readFile(folder / L"Preferred");
	if (!preferred.empty() && !parseDpapiPreferred(preferred.data(), preferred.size(), preferredGuid, preferredExpires))
		log(2, L"🔥DPAPI: Preferred of " + sid + L" is not 24 bytes long");
	const size_t first = keys.size();
	std::error_code ec;
	for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(folder, ec)) {
		const std::wstring name = e.path().filename().wstring();
		if (!e.is_regular_file(ec) || !isKeyFileName(name)) continue;
		DpapiMasterKey key;
		key.scope = scope;
		key.sid = sid;
		key.path = originalPath(e.path().wstring());
		ExhibitSourceTimes(e.path().wstring(), key.sourceCreatedUtc, key.sourceModifiedUtc, key.sourceAccessedUtc);
		const std::vector<uint8_t> bytes = readFile(e.path());
		DpapiMasterKeyHeader header;
		if (!parseDpapiMasterKeyHeader(bytes.data(), bytes.size(), header))
			log(2, L"🔥DPAPI: unreadable header in " + key.path);
		else if (toLower(header.guid) != toLower(name))
			log(2, L"🔥DPAPI: " + key.path + L" names another key in its header (" + header.guid + L")");
		else key.header = header;
		if (!preferredGuid.empty() && toLower(name) == preferredGuid) {
			key.preferred = true;
			key.preferredExpiresUtc = preferredExpires;
		}
		keys.push_back(std::move(key));
	}
	bool found = preferredGuid.empty();
	for (size_t i = first; i < keys.size(); ++i) found = found || keys[i].preferred;
	if (!found) log(2, L"🔥DPAPI: Preferred of " + sid + L" names a key that is not there (" + preferredGuid + L")");
}

/*! Reads every SID folder under one Protect folder of the working copy.
 *  @param protect the Protect folder, in the working copy
 *  @param scope "User" or "System"
 *  @param keys receives the key files */
void readProtectFolder(const std::filesystem::path& protect, const std::wstring& scope, std::vector<DpapiMasterKey>& keys) {
	std::error_code ec;
	for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(protect, ec)) {
		const std::wstring sid = e.path().filename().wstring();
		if (!e.is_directory(ec) || sid.compare(0, 4, L"S-1-") != 0) continue;
		readSidFolder(e.path(), scope, sid, keys);
		// The system account keeps its own user keys apart, in User\.
		if (scope == L"System") readSidFolder(e.path() / L"User", scope, sid, keys);
	}
}

} // namespace

bool parseDpapiMasterKeyHeader(const uint8_t* data, size_t size, DpapiMasterKeyHeader& header) {
	if (size < MK_HEADER_SIZE) return false;
	header.version = readLittleEndian<uint32_t>(data + MK_VERSION);
	header.guid.clear();
	for (size_t i = 0; i < MK_GUID_CHARACTERS; ++i)
		header.guid += (wchar_t)readLittleEndian<uint16_t>(data + MK_GUID + 2 * i);
	header.policy = readLittleEndian<uint32_t>(data + MK_POLICY);
	header.masterKeyLength = readLittleEndian<uint64_t>(data + MK_MASTER_KEY_LENGTH);
	header.backupKeyLength = readLittleEndian<uint64_t>(data + MK_MASTER_KEY_LENGTH + 8);
	header.credHistLength = readLittleEndian<uint64_t>(data + MK_MASTER_KEY_LENGTH + 16);
	header.domainKeyLength = readLittleEndian<uint64_t>(data + MK_MASTER_KEY_LENGTH + 24);
	// The four blocks follow the header: together they cannot exceed the file.
	const uint64_t room = size - MK_HEADER_SIZE;
	uint64_t total = 0;
	for (uint64_t length : { header.masterKeyLength, header.backupKeyLength, header.credHistLength, header.domainKeyLength }) {
		if (length > room - total) return false;
		total += length;
	}
	return true;
}

bool parseDpapiPreferred(const uint8_t* data, size_t size, std::wstring& guid, FILETIME& expiresUtc) {
	if (size != PREFERRED_SIZE) return false;
	GUID g;
	std::memcpy(&g, data, sizeof g);
	guid = toLower(guid_to_wstring(g).substr(1, MK_GUID_CHARACTERS));   // without the braces, as the files are named
	expiresUtc.dwLowDateTime = readLittleEndian<uint32_t>(data + 16);
	expiresUtc.dwHighDateTime = readLittleEndian<uint32_t>(data + 20);
	return true;
}

Json DpapiMasterKey::toJson() const {
	Json o = Json::obj();
	o.add(L"Scope", Json::str(scope));
	addUser(o, sid);
	o.add(L"Path", Json::str(path));
	addDate(o, L"SourceCreated", sourceCreatedUtc);
	addDate(o, L"SourceModified", sourceModifiedUtc);
	addDate(o, L"SourceAccessed", sourceAccessedUtc);
	if (header) {
		o.add(L"Guid", Json::str(toLower(header->guid)));
		o.add(L"Version", Json::num((unsigned long long)header->version));
		o.add(L"Policy", Json::str(L"0x" + to_hex(header->policy, 8)));
		o.add(L"MasterKeyLength", Json::num((unsigned long long)header->masterKeyLength));
		o.add(L"BackupKeyLength", Json::num((unsigned long long)header->backupKeyLength));
		o.add(L"CredHistLength", Json::num((unsigned long long)header->credHistLength));
		o.add(L"DomainKeyLength", Json::num((unsigned long long)header->domainKeyLength));
	}
	if (preferred) {
		o.add(L"Preferred", Json::boolean(true));
		addDate(o, L"PreferredExpires", preferredExpiresUtc);
	}
	return o;
}

HRESULT DpapiMasterKeys::getData() {
	log(0, L"ℹ️DPAPI master keys :");
	readProtectFolder(extractedPath(conf.systemDrive + DPAPI_SYSTEM_FOLDER), L"System", keys_);
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
		readProtectFolder(extractedPath(std::get<1>(profileEntry)) + DPAPI_PROFILE_FOLDER, L"User", keys_);
	return ERROR_SUCCESS;
}

HRESULT DpapiMasterKeys::toJson() {
	Json list = Json::arr();
	for (const DpapiMasterKey& k : keys_) list.push(k.toJson());
	return writeJsonFile("dpapi_master_keys.json", list);
}

void DpapiMasterKeys::clear() {
	keys_.clear();
}
