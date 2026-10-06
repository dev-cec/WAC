/*! \file
 *  \brief Reading of an SQLite database collected from the examined machine (browsers, timeline).
 *
 *  NEVER THE EXHIBIT ITSELF. A database is opened on a PRIVATE COPY, made in
 *  the working directory with its `-wal` or `-journal` when they were
 *  collected beside it. SQLite then does what the application would have
 *  done at its next start: it replays the write-ahead log — the last visits
 *  of a browser that was running are often only there — or rolls back the
 *  transaction a hot journal left unfinished. That needs write access, which
 *  the copy gives and the sealed exhibit must never give; the copy is
 *  deleted when the database is closed. The same principle as the hives,
 *  whose logs are replayed on the working copy (raw_collect.h).
 *
 *  Every value comes back through SqliteRow, read by column and type: a text
 *  column decoded from UTF-8, an integer, a BLOB with its size. A database
 *  whose schema is not the one expected (a column missing in an older
 *  version) is detected by the query's preparation failing: logged, and the
 *  caller's artefact keeps what it could read.
 */
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <windows.h>

struct sqlite3;
struct sqlite3_stmt;

/*! One row of a query's result. */
class SqliteRow {
public:
	//! @param statement the statement positioned on the row
	explicit SqliteRow(sqlite3_stmt* statement) : statement_(statement) {}
	//! @return true if the column holds NULL
	bool isNull(int column) const;
	//! @return the column as a 64-bit integer (0 for NULL)
	int64_t integer(int column) const;
	//! @return the column as text, decoded from UTF-8 ("" for NULL)
	std::wstring text(int column) const;
	//! @return the column's bytes (empty for NULL)
	std::vector<uint8_t> blob(int column) const;
	//! @return the number of columns of the result
	int columnCount() const;
	//! @return the column's name, as the query or the table names it
	std::wstring name(int column) const;
	/*! @return the type the table's schema declares for the column ("GUID",
	 *          "DATETIME"…), upper case; "" for an expression. SQLite stores
	 *          any value in any column: the declared type is what says how the
	 *          application meant it — a Unix time, a GUID's bytes. */
	std::string declaredType(int column) const;
private:
	sqlite3_stmt* statement_;   //!< owned by SqliteDatabase::query
};

/*! An SQLite database, opened on a private copy (see the file's header). */
class SqliteDatabase {
public:
	SqliteDatabase() = default;
	SqliteDatabase(const SqliteDatabase&) = delete;             //!< one owner of the connection and of the copy
	SqliteDatabase& operator=(const SqliteDatabase&) = delete;  //!< one owner of the connection and of the copy
	//! Closes the connection and deletes the private copy.
	~SqliteDatabase();

	/*! Copies the database, with its -wal and -journal if present, into a
	 *  private folder of the working directory, and opens the copy.
	 *  @param file the database in the working copy of the collection
	 *  @return ERROR_SUCCESS, or the failure of the copy or of the opening
	 *          (a file that is no SQLite database included) */
	HRESULT open(const std::wstring& file);

	/*! @param table a table's name
	 *  @return true if the database has that table */
	bool hasTable(const char* table);

	/*! Runs a query, one call per row.
	 *  @param sql the query, constant: no value of the database is ever put in it
	 *  @param row called with each row
	 *  @return ERROR_SUCCESS, or ERROR_INVALID_DATA if the query cannot be
	 *          prepared (schema of another version) or its reading fails */
	HRESULT query(const char* sql, const std::function<void(const SqliteRow&)>& row);

private:
	sqlite3* db_ = nullptr;         //!< the connection, on the copy
	std::wstring copyFolder_;       //!< the private folder, deleted at the end
	//! Closes and deletes the copy.
	void close();
};
