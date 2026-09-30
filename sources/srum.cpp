/*! \file
 *  \brief System Resource Usage Monitor (see srum.h).
 */
#include "srum.h"
#include "consigne.h"
#include <cstring>
#include <cwctype>

namespace {

//! SRUDB.dat, relative to the system volume, in lower case as the manifest index is.
const wchar_t DATABASE[] = L"\\windows\\system32\\sru\\srudb.dat";
const wchar_t IDENTITIES[] = L"SruDbIdMapTable";
const uint32_t ID_TYPE = 1, ID_INDEX = 2, ID_BLOB = 256;   //!< SruDbIdMapTable's columns
const unsigned ID_TYPE_SID = 3;

//! The first value of a cell as a little-endian integer (at most 4 bytes).
int32_t integerOf(const EseCell& cell) {
	uint32_t n = 0;
	const std::vector<uint8_t>& v = cell.values.front();
	for (size_t i = 0; i < v.size() && i < 4; ++i) n |= (uint32_t)v[i] << (8 * i);
	return (int32_t)n;
}

} // namespace

std::wstring srumProviderName(const std::wstring& table) {
	// As SrumECmd and the published descriptions of SRUM name them.
	static const std::pair<const wchar_t*, const wchar_t*> NAMES[] = {
		{ L"{973F5D5C-1D90-4944-BE8E-24B94231A174}", L"NetworkUsage" },
		{ L"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", L"ApplicationResourceUsage" },
		{ L"{DD6636C4-8929-4683-974E-22C046A43763}", L"NetworkConnectivity" },
		{ L"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}", L"EnergyUsage" },
		{ L"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT", L"EnergyUsageLongTerm" },
		{ L"{5C8CF1C7-7257-4F13-B223-970EF5939312}", L"ApplicationTimeline" },
		{ L"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}", L"PushNotifications" },
	};
	for (const auto& [guid, name] : NAMES)
		if (_wcsicmp(table.c_str(), guid) == 0) return name;
	return L"";
}

std::wstring srumKey(const std::wstring& column) {
	std::wstring key;
	for (wchar_t c : column) if (std::iswalnum(c) && c < 128) key.push_back(c);
	return key;
}

std::wstring srumIdentity(unsigned type, const std::vector<uint8_t>& blob) {
	if (type == ID_TYPE_SID) return sidToText(blob.data(), blob.size());
	return readWideZ(blob.data(), blob.size() & ~(size_t)1, 0);
}

HRESULT Srum::getData() {
	log(0, L"ℹ️SRUM :");
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(conf.systemDrive.substr(0, 2)) + DATABASE);
	if (found == index.end() || found->second.file.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const HRESULT opened = database_.open(found->second.file);
	if (opened != ERROR_SUCCESS) return opened;
	if (database_.dirtyShutdown())
		log(1, L"⚠️SRUDB.dat copied live (dirty shutdown): the last hour is in SRU*.log, in the exhibit store, not in srum.json");
	if (const EseTable* ids = database_.table(IDENTITIES)) {
		for (const EseRecord& r : database_.records(*ids)) {
			const EseCell* type = nullptr, * id = nullptr, * blob = nullptr;
			for (const EseCell& c : r) {
				if (c.values.empty()) continue;
				if (c.columnId == ID_TYPE) type = &c;
				else if (c.columnId == ID_INDEX) id = &c;
				else if (c.columnId == ID_BLOB) blob = &c;
			}
			if (!type || !id || !blob) continue;
			const unsigned t = (unsigned)integerOf(*type);
			identities_[integerOf(*id)] = { t, srumIdentity(t, blob->values.front()) };
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Srum::toJson() {
	JsonArrayWriter out("srum.json");
	for (const EseTable& table : database_.tables()) {
		// The catalog and its shadow are ESE's, not SRUM's.
		if (table.name.compare(0, 4, L"MSys") == 0) continue;
		const std::wstring provider = srumProviderName(table.name);
		for (const EseRecord& r : database_.records(table)) {
			Json row = Json::obj();
			row.add(L"Table", Json::str(table.name));
			row.add(L"Provider", Json::str(provider));
			for (const EseCell& cell : r)
				for (const EseColumn& c : table.columns) {
					if (c.id != cell.columnId) continue;
					row.add(srumKey(c.name), eseCellToJson(c, cell));
					// The identities behind AppId and UserId.
					const auto identity = (c.name == L"AppId" || c.name == L"UserId") && !cell.values.empty()
					                      ? identities_.find(integerOf(cell)) : identities_.end();
					if (identity == identities_.end()) continue;
					if (c.name == L"AppId") row.add(L"App", Json::str(identity->second.second));
					else if (identity->second.first == ID_TYPE_SID) {
						row.add(L"UserSID", Json::str(identity->second.second));
						row.add(L"UserName", Json::str(getNameFromSid(identity->second.second)));
					}
				}
			// SruDbIdMapTable's own rows: the identity its IdBlob holds, in text.
			if (table.name == IDENTITIES)
				for (const EseCell& cell : r)
					if (cell.columnId == ID_INDEX && !cell.values.empty()) {
						const auto identity = identities_.find(integerOf(cell));
						if (identity != identities_.end()) row.add(L"Identity", Json::str(identity->second.second));
					}
			out.add(row);
		}
	}
	return out.close();
}

void Srum::clear() {
	identities_.clear();
}
