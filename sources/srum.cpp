/*! \file
 *  \brief System Resource Usage Monitor (see srum.h).
 */
#include "srum.h"
#include "ese_recovery.h"
#include "consigne.h"
#include <cstring>
#include <cwctype>

namespace {

//! SRUDB.dat, relative to the system volume, in lower case as the manifest index is.
const wchar_t DATABASE[] = L"\\windows\\system32\\sru\\srudb.dat";
const wchar_t IDENTITIES[] = L"SruDbIdMapTable";
const uint32_t ID_TYPE = 1, ID_INDEX = 2, ID_BLOB = 256;   //!< SruDbIdMapTable's columns
const unsigned ID_TYPE_SID = 3;

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
	if (found == index.end() || found->second.workingFile.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	// The last hour is in SRU*.log, collected with the database: replayed into the copy first (B-046).
	const HRESULT opened = OpenRecoveredEseDatabase(database_, found->second.workingFile, found->second.sourcePath);
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
			const unsigned t = (unsigned)eseCellInteger(*type).value_or(0);
			identities_[(int32_t)eseCellInteger(*id).value_or(0)] = { t, srumIdentity(t, blob->values.front()) };
		}
	}
	return ERROR_SUCCESS;
}

namespace {

/*! Columns SRUM stores as a 64-bit integer that is a FILETIME: ESE does not
 *  type them as dates. Checked against the row's own TimeStamp: an EndTime of
 *  134346735000047273 is 2026-09-23 21:45:00.0047 UTC, the row being of
 *  21:45:00 (B-015, as SrumECmd reads them). */
bool isFiletimeColumn(const std::wstring& name) {
	return name == L"EndTime" || name == L"StartTime" || name == L"ConnectStartTime" || name == L"EventTimestamp";
}

/*! One cell of a row: as ESE types it, but a FILETIME column as its date, UTC
 *  and local, and the Tag text, declared one byte per character, as the UTF-16
 *  it holds. */
void addSrumValue(Json& row, const EseColumn& c, const EseCell& cell) {
	const std::wstring key = srumKey(c.name);
	if (cell.values.size() == 1 && cell.values.front().size() == 8 && isFiletimeColumn(c.name)) {
		uint64_t ticks;
		memcpy(&ticks, cell.values.front().data(), 8);
		const FILETIME utc = filetimeFromTicks(ticks);
		if (ticks) {
			row.add(key + L"Utc", Json::str(timeToIso8601Utc(utc)));
			row.add(key, Json::str(utcTimeToIso8601Local(utc)));
		}
		return;
	}
	if (c.name == L"Tag" && cell.values.size() == 1 && (c.type == 10 || c.type == 12)) {
		const std::vector<uint8_t>& v = cell.values.front();
		row.add(key, Json::str(readWideZ(v.data(), v.size() & ~(size_t)1, 0)));
		return;
	}
	row.add(key, eseCellToJson(c, cell));
}

} // namespace

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
					addSrumValue(row, c, cell);
					// The identities behind AppId and UserId.
					const auto identity = (c.name == L"AppId" || c.name == L"UserId") && !cell.values.empty()
					                      ? identities_.find((int32_t)eseCellInteger(cell).value_or(0)) : identities_.end();
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
						const auto identity = identities_.find((int32_t)eseCellInteger(cell).value_or(0));
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
