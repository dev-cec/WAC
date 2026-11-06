/*! \file
 *  \brief User Access Logging (see user_access_log.h).
 */
#include "user_access_log.h"
#include "consigne.h"
#include "conversions.h"
#include "ese_recovery.h"
#include "ip_address.h"
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <map>
#include <utility>

namespace {

//! The folder, relative to the system volume, in lower case as the manifest index is.
const wchar_t FOLDER[] = L"\\windows\\system32\\logfiles\\sum\\";
const wchar_t ROLES_DATABASE[] = L"systemidentity.mdb";
const wchar_t ROLES_TABLE[] = L"ROLE_IDS";
const unsigned YEAR_DAYS_MAX = 366;
const size_t IPV4_SIZE = 4, IPV6_SIZE = 16, FILETIME_SIZE = 8, GUID_SIZE = 16;

//! A role's name and product, by its GUID in lower case.
using RoleNames = std::map<std::wstring, std::pair<std::wstring, std::wstring>>;

//! @return true for a column declared DateTime that holds a FILETIME: all those of these databases
bool isDateColumn(const EseColumn& column) { return column.type == 8; }

//! @return the N of a column named DayN, or 0
unsigned dayOfColumn(const std::wstring& name) {
	if (name.size() < 4 || name.size() > 6 || name.compare(0, 3, L"Day") != 0) return 0;
	unsigned day = 0;
	for (size_t i = 3; i < name.size(); ++i) {
		if (name[i] < L'0' || name[i] > L'9') return 0;
		day = day * 10 + (name[i] - L'0');
	}
	return day <= YEAR_DAYS_MAX ? day : 0;
}

//! @return the cell of a column by its name, or null
const EseCell* cellNamed(const EseRecord& record, const EseTable& table, const wchar_t* name) {
	for (const EseColumn& c : table.columns)
		if (c.name == name)
			for (const EseCell& cell : record)
				if (cell.columnId == c.id && !cell.values.empty()) return &cell;
	return nullptr;
}

//! @return the column of a cell, or null
const EseColumn* columnOf(const EseTable& table, const EseCell& cell) {
	for (const EseColumn& c : table.columns)
		if (c.id == cell.columnId) return &c;
	return nullptr;
}

//! @return the year of a FILETIME cell, or 0
unsigned yearOf(const EseCell* cell) {
	if (!cell || cell->values.front().size() != FILETIME_SIZE) return 0;
	uint64_t ticks = 0;
	memcpy(&ticks, cell->values.front().data(), FILETIME_SIZE);
	const FILETIME time = filetimeFromTicks(ticks);
	SYSTEMTIME utc;
	return ticks && FileTimeToSystemTime(&time, &utc) ? utc.wYear : 0;
}

/*! Writes one column of a row, as the header says.
 *  @param row the element
 *  @param column,cell the column and its value
 *  @param roles the roles' names */
void addValue(Json& row, const EseColumn& column, const EseCell& cell, const RoleNames& roles) {
	const std::vector<uint8_t>& value = cell.values.front();
	if (isDateColumn(column) && cell.values.size() == 1 && value.size() == FILETIME_SIZE) {
		uint64_t ticks = 0;
		memcpy(&ticks, value.data(), FILETIME_SIZE);
		if (!ticks) return;
		const FILETIME utc = filetimeFromTicks(ticks);
		row.add(column.name + L"Utc", Json::str(timeToIso8601Utc(utc)));
		row.add(column.name, Json::str(utcTimeToIso8601Local(utc)));
		return;
	}
	// Text in the table DNS: only the binary form needs reading.
	if (column.name == L"Address" && column.type != 10 && column.type != 12 && cell.values.size() == 1) {
		row.add(column.name, Json::str(userAccessAddressText(value)));
		return;
	}
	if (column.name == L"TenantId" && std::all_of(value.begin(), value.end(), [](uint8_t b) { return b == 0; })) return;
	row.add(column.name, eseCellToJson(column, cell));
	if (column.name != L"RoleGuid" || value.size() != GUID_SIZE) return;
	const auto role = roles.find(toLower(guid_to_wstring(value.data())));
	if (role == roles.end()) return;
	row.add(L"RoleName", Json::str(role->second.first));
	row.add(L"ProductName", Json::str(role->second.second));
}

//! @return a cell's UTF-16 text, the form of these databases' names; empty without a cell
std::wstring textOf(const EseCell* cell) {
	if (!cell) return L"";
	const std::vector<uint8_t>& value = cell->values.front();
	return readWideZ(value.data(), value.size() & ~(size_t)1, 0);
}

//! Reads the roles' names out of SystemIdentity.mdb.
void readRoles(EseDatabase& database, RoleNames& roles) {
	const EseTable* table = database.table(ROLES_TABLE);
	if (!table) return;
	for (const EseRecord& r : database.records(*table)) {
		const EseCell* guid = cellNamed(r, *table, L"RoleGuid"), * role = cellNamed(r, *table, L"RoleName"), * product = cellNamed(r, *table, L"ProductName");
		if (!guid || guid->values.front().size() != GUID_SIZE) continue;
		roles[toLower(guid_to_wstring(guid->values.front().data()))] = { textOf(role), textOf(product) };
	}
}

/*! Adds every row of a database.
 *  @param database the database
 *  @param file its name, written on each row
 *  @param roles the roles' names
 *  @param rows receives the rows */
void readRows(EseDatabase& database, const std::wstring& file, const RoleNames& roles, Json& rows) {
	for (const EseTable& table : database.tables()) {
		// The catalog and its shadow are ESE's.
		if (table.name.compare(0, 4, L"MSys") == 0) continue;
		for (const EseRecord& r : database.records(table)) {
			Json row = Json::obj(), days = Json::arr();
			row.add(L"Database", Json::str(file));
			row.add(L"Table", Json::str(table.name));
			const unsigned year = yearOf(cellNamed(r, table, L"InsertDate"));
			for (const EseCell& cell : r) {
				const EseColumn* column = columnOf(table, cell);
				if (!column || cell.values.empty()) continue;
				const unsigned day = dayOfColumn(column->name);
				if (!day) { addValue(row, *column, cell, roles); continue; }
				Json entry = Json::obj();
				entry.add(L"DayOfYear", Json::num((unsigned long long)day));
				entry.add(L"Date", Json::str(userAccessDayDate(year, day)));
				entry.add(L"Accesses", eseCellToJson(*column, cell));
				days.push(std::move(entry));
			}
			row.add(L"Days", std::move(days));
			rows.push(std::move(row));
		}
	}
}

} // namespace

bool userAccessDatabaseCandidate(const std::wstring& file) {
	// The engine's own files beside the databases: transaction logs, reserve logs, checkpoint, flush map.
	static const wchar_t* const ENGINE_EXTENSIONS[] = { L".log", L".jrs", L".chk", L".jfm" };
	for (const wchar_t* extension : ENGINE_EXTENSIONS) {
		const size_t size = wcslen(extension);
		if (file.size() > size && file.compare(file.size() - size, size, extension) == 0) return false;
	}
	return !file.empty() && file.find(L'\\') == std::wstring::npos;
}

std::wstring userAccessAddressText(const std::vector<uint8_t>& address) {
	if (address.size() == IPV4_SIZE) return Ipv4Text(address.data());
	if (address.size() == IPV6_SIZE) return Ipv6Text(address.data());
	static const wchar_t DIGITS[] = L"0123456789ABCDEF";
	std::wstring text;
	for (uint8_t b : address) {
		text.push_back(DIGITS[b >> 4]);
		text.push_back(DIGITS[b & 15]);
	}
	return text;
}

std::wstring userAccessDayDate(unsigned year, unsigned day) {
	static const unsigned MONTH_DAYS[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	if (year < 1601 || year > 9999 || day == 0) return L"";
	const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
	unsigned left = day;
	for (unsigned month = 0; month < 12; ++month) {
		const unsigned days = MONTH_DAYS[month] + (month == 1 && leap ? 1 : 0);
		if (left <= days) {
			wchar_t text[16];
			swprintf(text, sizeof(text) / sizeof(text[0]), L"%04u-%02u-%02u", year, month + 1, left);
			return text;
		}
		left -= days;
	}
	return L"";
}

HRESULT UserAccessLog::getData() {
	const std::wstring prefix = toLower(conf.systemDrive.substr(0, 2)) + FOLDER;
	std::vector<std::pair<std::wstring, const StoredExhibit*>> files;
	for (const auto& [path, exhibit] : ExhibitStoreIndex()) {
		if (path.compare(0, prefix.size(), prefix) != 0 || exhibit.workingFile.empty()) continue;
		const std::wstring file = path.substr(prefix.size());
		if (userAccessDatabaseCandidate(file)) files.emplace_back(file, &exhibit);
	}
	// The roles first: their names go on the rows of the other databases, read in any order.
	std::stable_partition(files.begin(), files.end(), [](const auto& f) { return f.first == ROLES_DATABASE; });
	RoleNames roles;
	for (const auto& [file, exhibit] : files) {
		EseDatabase database;
		const HRESULT opened = OpenRecoveredEseDatabase(database, exhibit->workingFile, exhibit->sourcePath);
		if (opened != ERROR_SUCCESS) {
			log(1, L"⚠️" + file + L" not read: " + std::to_wstring((unsigned long)opened));
			continue;
		}
		if (file == ROLES_DATABASE) readRoles(database, roles);
		readRows(database, std::filesystem::path(exhibit->sourcePath).filename().wstring(), roles, rows_);
	}
	return ERROR_SUCCESS;
}

HRESULT UserAccessLog::toJson() { return writeJsonFile("user_access_log.json", rows_); }
void UserAccessLog::clear() { rows_ = Json::arr(); }
