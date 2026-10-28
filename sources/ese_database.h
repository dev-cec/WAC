/*! \file
 *  \brief Reader of ESE databases (Extensible Storage Engine, "JET Blue"):
 *         SRUDB.dat, qmgr.db, and the other databases Windows keeps this way.
 *
 *  WHY OUR OWN. ESENT's API opens a database for writing and may rewrite its
 *  pages, and its reading would depend on the DLL of the analysis
 *  workstation. The format is read here, page by page, from the working copy;
 *  esent.dll only replays the transaction logs into that copy beforehand
 *  (ese_recovery.h), never reads it.
 *
 *  THE FORMAT, as described by J. Metz (libesedb) and Fox-IT (dissect.esedb),
 *  checked on the test VM against dissect.esedb on the same files:
 *   - page 0 is the header (page size at 236, state at 52); logical page n is
 *     at (n + 1) × page size;
 *   - a page: a header of 40 bytes, 80 above 8 KiB; at its end, one tag of
 *     4 bytes per entry (size, offset); an entry is a key (with a prefix
 *     shared through the page's first tag) then data — a child page number
 *     in a branch, a record in a leaf;
 *   - the catalog, MSysObjects, rooted at page 4, gives each table its root
 *     page, its columns (identifier, type, code page) and its long values'
 *     root;
 *   - a record: fixed columns (identifiers 1–127) with a null bitmap,
 *     variable ones (128–255) through an offset table, tagged ones (256 and
 *     above) through a table of identifier/offset pairs; a tagged value too
 *     large is "separated" into the long-value tree, keyed by its identifier
 *     then its offset, big-endian.
 *
 *  COMPRESSED VALUES: 7-bit text (ASCII or UTF-16), met in the Windows.edb
 *  of Windows 8.1, is unpacked; XPRESS, met in neither SRUDB.dat, qmgr.db
 *  nor that Windows.edb, is said so, with its scheme, rather than guessed.
 *  Records whose tagged columns are in the pre-Vista format give their fixed
 *  and variable columns only.
 *
 *  A DATABASE COPIED LIVE is in "dirty shutdown" state: what the service
 *  changed since its last checkpoint may be only in its transaction logs,
 *  which are collected alongside and replayed into the working copy before
 *  it is read (ese_recovery.h); a replay not applied is said in the log.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#include "tools.h"

//! A column of a table, as the catalog describes it.
struct EseColumn {
	uint32_t id = 0;
	std::wstring name;
	uint32_t type = 0;          //!< JET_coltyp: 4 Long, 8 DateTime, 11 LongBinary, 16 GUID…
	uint32_t size = 0;          //!< fixed columns: their size
	uint32_t codePage = 0;      //!< text columns: 1200 UTF-16, 1252, 20127
	uint32_t offset = 0;        //!< fixed columns: their offset after the record header
};

//! A table: its tree, its long values' tree, its columns in identifier order.
struct EseTable {
	std::wstring name;
	uint32_t root = 0, longValueRoot = 0;
	std::vector<EseColumn> columns;
};

/*! The value of one column in one record: one value, or several for a
 *  multi-valued tagged column. */
struct EseCell {
	uint32_t columnId = 0;
	std::vector<std::vector<uint8_t>> values;
	std::vector<bool> separated;  //!< per value: the long-value key, until resolved
	int compressionScheme = -1;   //!< >= 0: compressed in a scheme not decoded (3 XPRESS…); 7-bit text is unpacked
	bool longValueMissing = false; //!< separated into the long-value tree, not found there
};

//! The columns a record holds, in identifier order; a column empty or null is absent.
using EseRecord = std::vector<EseCell>;

/*! The value of a cell in JSON: a number, a boolean, a date (DateTime, an OLE
 *  date), a GUID, text, or hexadecimal for binary; an array when multi-valued;
 *  an object saying so when compressed or missing.
 *  @param column the cell's column
 *  @param cell the cell */
Json eseCellToJson(const EseColumn& column, const EseCell& cell);

/*! The integer a cell holds: its first value, 1 to 8 bytes little-endian,
 *  unsigned as stored. Every reader of an identifier or a date goes through
 *  it: parsed from its JSON text, a compressed cell or an unexpected type
 *  threw, and the whole conversion stopped.
 *  @return none if the cell holds no such value (empty, compressed, wider) */
std::optional<uint64_t> eseCellInteger(const EseCell& cell);

/*! Unpacks a value compressed on 7 bits (schemes 1 and 2): after a header
 *  byte — the scheme in its high 5 bits, in its low 3 the data bits of the
 *  last byte less one —, units of 7 bits packed from the lowest bit: bytes
 *  under scheme 1 (of any text, UTF-16 included), UTF-16 characters whose
 *  high byte is zero under scheme 2. Measured on the Windows.edb of Windows
 *  8.1, every value confronted with dissect.esedb.
 *  @param value the value with its header byte; receives the text's bytes
 *  @return false, and the value untouched, for another scheme (XPRESS…) */
bool decompressSevenBit(std::vector<uint8_t>& value);

/*! Decodes one record.
 *  @param data the record
 *  @param columns the table's columns
 *  @param smallPages true for pages of 8 KiB and less (the tag fields' layout)
 *  @param newFormat the page's "new record format" flag: tagged columns readable
 *  @return the cells; a separated value holds its long-value key, to resolve */
EseRecord parseEseRecord(const std::vector<uint8_t>& data, const std::vector<EseColumn>& columns,
                         bool smallPages, bool newFormat);

/*! An ESE database, read from its copy. */
class EseDatabase {
public:
	/*! Opens the database and reads its catalog.
	 *  @param path the file
	 *  @return ERROR_SUCCESS, or why it cannot be read */
	HRESULT open(const std::wstring& path);
	//! @return true if the database was not shut down cleanly (copied live)
	bool dirtyShutdown() const { return state_ != CLEAN_SHUTDOWN; }
	//! @return the user tables and the system ones, in the catalog's order
	const std::vector<EseTable>& tables() const { return tables_; }
	//! @return the table of that name, or nullptr
	const EseTable* table(const std::wstring& name) const;
	/*! Every record of a table, long values resolved.
	 *  @param table a table of this database
	 *  @return the records, in key order */
	std::vector<EseRecord> records(const EseTable& table);

private:
	//! A leaf entry: its key and its data.
	struct Entry { std::vector<uint8_t> key, data; bool newFormat = false; };
	bool readPage(uint32_t logical, std::vector<uint8_t>& page);
	void leaves(uint32_t root, std::vector<Entry>& out);
	void walk(uint32_t page, unsigned depth, std::vector<bool>& visited, std::vector<Entry>& out, uint32_t& lastLeaf);
	std::map<std::string, std::vector<uint8_t>> longValueTree(const EseTable& table);

	static const uint32_t CLEAN_SHUTDOWN = 3;
	std::ifstream file_;
	uint64_t fileSize_ = 0;
	uint32_t pageSize_ = 0, state_ = 0, pageCount_ = 0;
	std::vector<EseTable> tables_;
};
