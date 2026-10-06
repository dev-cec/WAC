/*! \file
 *  \brief Windows Timeline (ActivitiesCache.db): see activities_cache.h.
 */
#include "activities_cache.h"
#include "consigne.h"
#include "conversions.h"
#include "sqlite_reader.h"
#include <algorithm>
#include <cstring>
#include <filesystem>

const wchar_t CONNECTED_DEVICES_FOLDER[] = L"\\AppData\\Local\\ConnectedDevicesPlatform";

namespace {

const wchar_t DATABASE_NAME[] = L"ActivitiesCache.db";

/*! A blob as JSON: the JSON it holds (the Payloads), else its text when it
 *  is UTF-8 text, else its bytes in hexadecimal.
 *  @param bytes the blob
 *  @return its JSON form */
Json blobToJson(const std::vector<uint8_t>& bytes) {
	const std::wstring text = decodeText(std::string(bytes.begin(), bytes.end()), CP_UTF8);
	Json parsed = Json::null();
	std::wstring error;
	if (Json::parse(text, parsed, error)) return parsed;
	const bool isText = !text.empty() && std::none_of(text.begin(), text.end(), [](wchar_t c) {
		return c == 0xFFFD || (c < 0x20 && c != L'\t' && c != L'\r' && c != L'\n');
	});
	return Json::str(isText ? text : toHexadecimal(bytes.data(), bytes.size()));
}

/*! Adds one column of a row, converted by its declared type (see the
 *  header): nothing for NULL, a zero date or a zero GUID.
 *  @param o the record's columns
 *  @param row the row
 *  @param column the column's index */
void addColumn(Json& o, const SqliteRow& row, int column) {
	if (row.isNull(column)) return;
	const std::wstring name = row.name(column);
	const std::string type = row.declaredType(column);
	if (type == "DATETIME") {
		const int64_t seconds = row.integer(column);
		if (seconds > 0) addDate(o, name, unixToFiletime((unsigned long long)seconds));
	} else if (type == "GUID") {
		const std::vector<uint8_t> bytes = row.blob(column);
		if (bytes.size() != sizeof(GUID)) {
			o.add(name, blobToJson(bytes));
			return;
		}
		if (std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0; })) return;
		GUID guid;
		memcpy(&guid, bytes.data(), sizeof guid);   // Guid.ToByteArray: the struct's own layout
		o.add(name, Json::str(guid_to_wstring(guid)));
	} else if (type.find("INT") != std::string::npos) {
		o.add(name, Json::num((long long)row.integer(column)));
	} else if (type == "BLOB") {
		o.add(name, blobToJson(row.blob(column)));
	} else {
		o.add(name, Json::str(row.text(column)));
	}
}

} // namespace

Json TimelineActivity::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	o.add(L"Path", Json::str(path));
	o.add(L"Table", Json::str(table));
	o.merge(columns);   // the columns at the record's level, already filtered by add
	return o;
}

HRESULT readActivitiesCache(const std::wstring& file, const TimelineActivity& base,
                            std::vector<TimelineActivity>& activities) {
	SqliteDatabase db;
	const HRESULT hr = db.open(file);
	if (hr != ERROR_SUCCESS) return hr;
	for (const char* table : { "Activity", "ActivityOperation" }) {
		if (!db.hasTable(table)) continue;
		const std::string sql = std::string("SELECT * FROM ") + table;   // a constant of this file, never a value of the database
		const HRESULT hrQuery = db.query(sql.c_str(), [&](const SqliteRow& row) {
			TimelineActivity a = base;
			a.table = decodeText(table, CP_UTF8);
			for (int c = 0; c < row.columnCount(); ++c) addColumn(a.columns, row, c);
			activities.push_back(std::move(a));
		});
		if (hrQuery != ERROR_SUCCESS) log(2, L"🔥Timeline table unreadable: " + base.path + L" " + decodeText(table, CP_UTF8));
	}
	return ERROR_SUCCESS;
}

HRESULT ActivitiesCaches::getData() {
	log(0, L"ℹ️Timeline (ActivitiesCache.db) :");
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::filesystem::path folder = extractedPath(std::get<1>(profileEntry) + CONNECTED_DEVICES_FOLDER);
		std::error_code ec;
		if (!std::filesystem::is_directory(folder, ec)) continue;
		// One folder per account of the profile (L.<user>, or the account's identifier).
		for (const std::filesystem::directory_entry& account : std::filesystem::directory_iterator(folder, ec)) {
			const std::filesystem::path file = account.path() / DATABASE_NAME;
			if (!account.is_directory(ec) || !std::filesystem::is_regular_file(file, ec)) continue;
			TimelineActivity base;
			base.sid = std::get<0>(profileEntry);
			base.path = originalPath(file.wstring());
			const size_t before = activities_.size();
			if (readActivitiesCache(file.wstring(), base, activities_) != ERROR_SUCCESS) {
				log(2, L"🔥Timeline database unreadable: " + base.path);
				continue;
			}
			log(2, L"❇️" + base.path + L" : " + std::to_wstring(activities_.size() - before) + L" activity(ies)");
		}
	}
	return ERROR_SUCCESS;
}

HRESULT ActivitiesCaches::toJson() {
	Json list = Json::arr();
	for (const TimelineActivity& a : activities_) list.push(a.toJson());
	return writeJsonFile("activities_cache.json", list);
}

void ActivitiesCaches::clear() {
	activities_.clear();
}
