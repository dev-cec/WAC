/*! \file
 *  \brief Reading of an SQLite database collected from the examined machine (see sqlite_reader.h).
 */
#include "sqlite_reader.h"
#include "consigne.h"
#include "tools.h"
#include <atomic>
#include <cstring>
#include <filesystem>
#include "sqlite3.h"

namespace {

//! Numbers the private copies: two databases open at once never share a folder.
std::atomic<unsigned> g_copies{ 0 };

} // namespace

bool SqliteRow::isNull(int column) const {
	return sqlite3_column_type(statement_, column) == SQLITE_NULL;
}

int64_t SqliteRow::integer(int column) const {
	return sqlite3_column_int64(statement_, column);
}

std::wstring SqliteRow::text(int column) const {
	const unsigned char* bytes = sqlite3_column_text(statement_, column);
	const int size = sqlite3_column_bytes(statement_, column);   // after the text: its length in UTF-8
	if (!bytes || size <= 0) return L"";
	return decodeText(std::string(reinterpret_cast<const char*>(bytes), (size_t)size), CP_UTF8);
}

std::vector<uint8_t> SqliteRow::blob(int column) const {
	const uint8_t* bytes = static_cast<const uint8_t*>(sqlite3_column_blob(statement_, column));
	const int size = sqlite3_column_bytes(statement_, column);
	if (!bytes || size <= 0) return {};
	return std::vector<uint8_t>(bytes, bytes + size);
}

SqliteType SqliteRow::type(int column) const {
	switch (sqlite3_column_type(statement_, column)) {
	case SQLITE_INTEGER: return SqliteType::Integer;
	case SQLITE_FLOAT:   return SqliteType::Real;
	case SQLITE_TEXT:    return SqliteType::Text;
	case SQLITE_BLOB:    return SqliteType::Blob;
	default:             return SqliteType::Null;
	}
}

double SqliteRow::real(int column) const {
	return sqlite3_column_double(statement_, column);
}

int SqliteRow::columnCount() const {
	return sqlite3_column_count(statement_);
}

std::wstring SqliteRow::name(int column) const {
	const char* text = sqlite3_column_name(statement_, column);
	return text ? decodeText(text, CP_UTF8) : L"";
}

std::string SqliteRow::declaredType(int column) const {
	const char* text = sqlite3_column_decltype(statement_, column);
	std::string type = text ? text : "";
	for (char& c : type) c = (char)toupper((unsigned char)c);
	return type;
}

SqliteDatabase::~SqliteDatabase() {
	close();
}

void SqliteDatabase::close() {
	if (db_) {
		const int closed = sqlite3_close(db_);
		if (closed != SQLITE_OK) log(2, L"🔥SQLite close: " + std::to_wstring(closed));
		db_ = nullptr;
	}
	if (!copyFolder_.empty()) {
		std::error_code ec;
		std::filesystem::remove_all(copyFolder_, ec);
		if (ec) log(2, L"🔥SQLite private copy not deleted: " + copyFolder_);
		copyFolder_.clear();
	}
}

HRESULT SqliteDatabase::open(const std::wstring& file) {
	close();
	const std::filesystem::path source(file);
	copyFolder_ = (std::filesystem::path(workingFolder()) / L"sqlite-copies"
	               / std::to_wstring(++g_copies)).wstring();
	/* The folders are numbered from 1 at each run: one left by an interrupted
	   run is emptied first — its copy was kept (no overwrite), and its -wal
	   replayed into another database copied beside it. */
	if (!removeFolderTree(copyFolder_)) return HRESULT_FROM_WIN32(ERROR_CANNOT_MAKE);
	std::error_code ec;
	std::filesystem::create_directories(copyFolder_, ec);
	if (ec) return HRESULT_FROM_WIN32(ERROR_CANNOT_MAKE);
	const std::filesystem::path copy = std::filesystem::path(copyFolder_) / source.filename();
	// The source is a working copy, whose path can pass MAX_PATH (B-049).
	if (!copyFileLong(file, copy.wstring(), false)) {
		log(2, L"🔥SQLite: copy of " + file + L" failed");
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}
	// The logs go along, under the names SQLite looks for beside the copy.
	for (const wchar_t* suffix : { L"-wal", L"-journal" }) {
		const std::filesystem::path journal = source.wstring() + suffix;
		if (pathExists(journal.wstring()) && !copyFileLong(journal.wstring(), copy.wstring() + suffix, false))
			log(2, L"🔥SQLite: copy of " + journal.wstring() + L" failed, its latest changes are not read");
	}
	const int opened = sqlite3_open_v2(encodeText(copy.wstring()).c_str(), &db_, SQLITE_OPEN_READWRITE, nullptr);
	if (opened != SQLITE_OK) {
		log(2, L"🔥SQLite open " + file + L": " + decodeText(sqlite3_errstr(opened), CP_UTF8));
		close();
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	/* Windows Search declares collations of its own ("UNICODE_en-US_LINGUISTIC_
	   IGNORECASE"), which SQLite does not know: a statement touching such a
	   column would not even prepare. Each one is declared on demand as a
	   comparison of the bytes. The order it gives may differ from Windows':
	   it only matters to a lookup through an index of that collation, and the
	   readers here scan whole tables, never search them by such a key. */
	const int declared = sqlite3_collation_needed(db_, nullptr, [](void*, sqlite3* db, int encoding, const char* name) {
		const int created = sqlite3_create_collation(db, name, encoding, nullptr,
		                                             [](void*, int sizeA, const void* a, int sizeB, const void* b) {
			const int common = memcmp(a, b, (size_t)(sizeA < sizeB ? sizeA : sizeB));
			return common ? common : sizeA - sizeB;
		});
		if (created != SQLITE_OK) log(2, L"🔥SQLite collation not declared: " + decodeText(name, CP_UTF8));
	});
	if (declared != SQLITE_OK) log(2, L"🔥SQLite: unknown collations will not be declared in " + file);
	// A file that is no database only fails at its first read: check now.
	if (query("SELECT count(*) FROM sqlite_master", [](const SqliteRow&) {}) != ERROR_SUCCESS) {
		close();
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	return ERROR_SUCCESS;
}

bool SqliteDatabase::hasTable(const char* table) {
	bool found = false;
	sqlite3_stmt* statement = nullptr;
	if (!db_ || sqlite3_prepare_v2(db_, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", -1,
	                               &statement, nullptr) != SQLITE_OK) return false;
	// The name is BOUND, never put into the query.
	if (sqlite3_bind_text(statement, 1, table, -1, SQLITE_STATIC) == SQLITE_OK)
		found = sqlite3_step(statement) == SQLITE_ROW;
	sqlite3_finalize(statement);
	return found;
}

HRESULT SqliteDatabase::query(const char* sql, const std::function<void(const SqliteRow&)>& row) {
	if (!db_) return HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE);
	sqlite3_stmt* statement = nullptr;
	if (sqlite3_prepare_v2(db_, sql, -1, &statement, nullptr) != SQLITE_OK) {
		log(2, L"🔥SQLite query not prepared (" + decodeText(sqlite3_errmsg(db_), CP_UTF8) + L"): "
		     + decodeText(sql, CP_UTF8));
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	int stepped;
	while ((stepped = sqlite3_step(statement)) == SQLITE_ROW) row(SqliteRow(statement));
	sqlite3_finalize(statement);
	if (stepped != SQLITE_DONE) {
		log(2, L"🔥SQLite reading stopped: " + decodeText(sqlite3_errmsg(db_), CP_UTF8));
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	return ERROR_SUCCESS;
}
