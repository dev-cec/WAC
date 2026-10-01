/*! \file
 *  \brief Implementation of the local groups reading (see local_groups.h).
 */
#include "local_groups.h"

#include <cstring>
#include "users.h"     // openSam
#include "tools.h"     // sidToText, getNameFromSid, log, getRegBinaryValue

namespace {

// The C value: a header of 13 little-endian DWORDs, then the data at 0x34. The
// pairs below are the (offset, length) of each part, the offset being relative
// to the data. Confirmed on the test machine against Get-LocalGroupMember.
const size_t C_DATA = 0x34;
const size_t C_NAME_OFFSET = 4, C_NAME_LENGTH = 5;
const size_t C_DESC_OFFSET = 7, C_DESC_LENGTH = 8;
const size_t C_MEMBERS_OFFSET = 10, C_MEMBERS_LENGTH = 11, C_MEMBERS_COUNT = 12;

//! The DWORD at index `i` of the C header; 0 if out of range.
DWORD header(const std::vector<BYTE>& c, size_t i) {
	if (c.size() < (i + 1) * sizeof(DWORD)) return 0;
	DWORD v = 0;
	memcpy(&v, c.data() + i * sizeof(DWORD), sizeof(DWORD));
	return v;
}

//! A UTF-16 string of the C value, from its (offset, length) header fields.
std::wstring cString(const std::vector<BYTE>& c, size_t offsetField, size_t lengthField) {
	const size_t offset = header(c, offsetField), length = header(c, lengthField);
	const size_t start = C_DATA + offset;
	if (length == 0 || start + length > c.size()) return L"";
	return std::wstring((PCWSTR)(c.data() + start), length / sizeof(wchar_t));
}

/*! The member SIDs: a packed sequence, each SID being revision (1), subauthority
 *  count (1), authority (6), then count 32-bit subauthorities. Reads exactly the
 *  announced number, never past the member block.
 *  @param c the C value
 *  @param out receives the SIDs, as text */
void readMembers(const std::vector<BYTE>& c, std::vector<std::wstring>& out) {
	const size_t offset = header(c, C_MEMBERS_OFFSET), length = header(c, C_MEMBERS_LENGTH);
	const DWORD count = header(c, C_MEMBERS_COUNT);
	const size_t start = C_DATA + offset;
	if (length == 0 || start + length > c.size()) return;
	size_t at = start;
	const size_t end = start + length;
	for (DWORD i = 0; i < count; ++i) {
		if (at + 8 > end) break;                      // header of a SID: 8 bytes
		const size_t subCount = c[at + 1];
		const size_t sidSize = 8 + 4 * subCount;
		if (at + sidSize > end) break;
		const std::wstring sid = sidToText(c.data() + at, sidSize);
		if (!sid.empty()) out.push_back(sid);
		at += sidSize;
	}
}

/*! Reads every alias of one domain key into the groups.
 *  @param hSam the open SAM hive
 *  @param domain "Builtin" or "Account"
 *  @param scope the scope to label the groups with
 *  @param sidPrefix the group SID without its RID ("S-1-5-32" or the machine SID)
 *  @param base the SAM key prefix (openSam)
 *  @param out receives the groups */
void readAliases(ORHKEY hSam, const std::wstring& domain, const std::wstring& scope,
                 const std::wstring& sidPrefix, const std::wstring& base,
                 std::vector<LocalGroup>& out) {
	const std::wstring path = base + L"Domains\\" + domain + L"\\Aliases";
	ORHKEY aliases = NULL;
	if (OROpenKey(hSam, path.c_str(), &aliases) != ERROR_SUCCESS) return;
	DWORD count = 0;
	if (ORQueryInfoKey(aliases, NULL, NULL, &count, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
		ORCloseKey(aliases);
		return;
	}
	WCHAR name[MAX_KEY_NAME] = L"";
	for (DWORD i = 0; i < count; ++i) {
		DWORD size = MAX_KEY_NAME;
		if (OREnumKey(aliases, i, name, &size, NULL, NULL, NULL) != ERROR_SUCCESS) continue;
		// "Members" and "Names" are indexes under Aliases, not groups.
		const std::wstring keyName = name;
		if (toLower(keyName) == L"members" || toLower(keyName) == L"names") continue;
		ORHKEY alias = NULL;
		if (OROpenKey(aliases, keyName.c_str(), &alias) != ERROR_SUCCESS) continue;
		std::vector<BYTE> c;
		if (getRegBinaryValue(alias, nullptr, L"C", c) == ERROR_SUCCESS && c.size() >= C_DATA) {
			LocalGroup g;
			g.scope = scope;
			g.rid = (DWORD)wcstoul(keyName.c_str(), nullptr, 16);
			if (!sidPrefix.empty()) g.sid = sidPrefix + L"-" + std::to_wstring(g.rid);
			g.name = cString(c, C_NAME_OFFSET, C_NAME_LENGTH);
			g.description = cString(c, C_DESC_OFFSET, C_DESC_LENGTH);
			ORQueryInfoKey(alias, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &g.keyLastWriteUtc);
			readMembers(c, g.members);
			out.push_back(std::move(g));
		}
		ORCloseKey(alias);
	}
	ORCloseKey(aliases);
}

} // namespace

Json LocalGroup::toJson() const {
	Json o = Json::obj();
	o.add(L"Scope", Json::str(scope));
	o.add(L"Rid", Json::num(rid));
	if (!sid.empty()) o.add(L"Sid", Json::str(sid));
	if (!name.empty()) o.add(L"Name", Json::str(name));
	if (!description.empty()) o.add(L"Description", Json::str(description));
	if (!members.empty()) {
		Json arr = Json::arr();
		for (const std::wstring& sid : members) {
			Json m = Json::obj();
			m.add(L"Sid", Json::str(sid));
			const std::wstring account = getNameFromSid(sid);
			if (!account.empty()) m.add(L"SIDName", Json::str(account));
			arr.push(m);
		}
		o.add(L"Members", arr);
	}
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT LocalGroups::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Local groups :");
	log(0, L"*******************************************************************************************************************");
	ORHKEY hSam = NULL;
	std::wstring base;
	const HRESULT hresult = openSam(&hSam, &base);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥SAM hive unavailable: local groups not collected", hresult);
		return hresult;
	}
	const std::wstring machineSid = readMachineSid(hSam, base);
	readAliases(hSam, L"Builtin", L"Builtin", L"S-1-5-32", base, groups_);
	readAliases(hSam, L"Account", L"Local", machineSid, base, groups_);
	ORCloseHive(hSam);
	log(2, L"❇️" + std::to_wstring(groups_.size()) + L" local groups read in the SAM");
	return groups_.empty() ? ERROR_EMPTY : ERROR_SUCCESS;
}

HRESULT LocalGroups::toJson() {
	Json arr = Json::arr();
	for (const LocalGroup& g : groups_) arr.push(g.toJson());
	return writeJsonFile("local_groups.json", arr);
}

void LocalGroups::clear() { groups_.clear(); }
