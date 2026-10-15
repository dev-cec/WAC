/*! \file
 *  \brief Windows Search index (Windows 11): see search_index.h.
 */
#include "search_index.h"
#include "conversions.h"
#include "ese_database.h"
#include "ese_recovery.h"
#include "sqlite_reader.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <map>

const wchar_t SEARCH_INDEX_FOLDER[] = L"\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows";

namespace {

// VARIANT types of the property store (wtypes.h), as its metadata declares them.
const int VT_BOOLEAN = 11;     //!< VT_BOOL, which wtypes.h names without the suffix
const int VT_SIGNED_64 = 20;   //!< VT_I8
const int VT_UNSIGNED_64 = 21; //!< VT_UI8
const int VT_UTF16 = 31;       //!< VT_LPWSTR
const int VT_TIME = 64;        //!< VT_FILETIME
const int VT_GUID = 72;        //!< VT_CLSID
const int VT_VECTOR_FLAG = 0x1000;

// The first byte of Windows 7's text once decoded: its form (decodeSearchText).
const uint8_t SEARCH_TEXT_RUNS = 0;   //!< runs of characters sharing their high byte
const uint8_t SEARCH_TEXT_BYTES = 1;  //!< one byte per character, the high one zero

//! Deepest scope chain followed when rebuilding a URL: a loop stops there.
const int SCOPE_DEPTH_MAX = 256;

/*! UTF-16 text in a blob: the strings it holds, separated by their NULs.
 *  @param bytes the blob
 *  @param strings receives the strings, empty ones left out
 *  @return false if the blob is not UTF-16 text (odd size, control characters) */
bool utf16Strings(const std::vector<uint8_t>& bytes, std::vector<std::wstring>& strings) {
	if (bytes.empty() || bytes.size() % 2) return false;
	std::wstring current;
	for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
		const wchar_t c = (wchar_t)readLittleEndian<uint16_t>(bytes.data() + i);
		if (c == 0) {
			if (!current.empty()) strings.push_back(current);
			current.clear();
		} else if (c < 0x20 && c != L'\t' && c != L'\r' && c != L'\n') {
			return false;
		} else current += c;
	}
	if (!current.empty()) strings.push_back(current);
	return !strings.empty();
}

// JET column types (esent.h) of the ESE index whose bytes are converted here.
const uint32_t JET_BINARY = 9, JET_LONG_BINARY = 11;

/*! The canonical name of a property-store column of Windows.edb: the column
 *  is the property's number, "-", then its name with "_" for ".".
 *  @param column "4385-System_ItemPathDisplay"
 *  @return "System.ItemPathDisplay" */
std::wstring edbPropertyName(const std::wstring& column) {
	const size_t dash = column.find(L'-');
	std::wstring name = dash == std::wstring::npos ? column : column.substr(dash + 1);
	std::replace(name.begin(), name.end(), L'_', L'.');
	return name;
}

/*! A value of the ESE index: its bytes by the property's VARIANT type when
 *  the column is binary, as ESE types it otherwise (text, number, boolean). */
void addEseValue(Json& o, const std::wstring& key, const EseColumn& column, const EseCell& cell, int variantType) {
	if ((column.type == JET_BINARY || column.type == JET_LONG_BINARY) && cell.compressionScheme < 0
	    && !cell.longValueMissing && cell.values.size() == 1) {
		addSearchBlob(o, key, variantType, cell.values.front());
		return;
	}
	o.add(key, eseCellToJson(column, cell));
}

/*! A value of Windows 7's property store (SystemIndex_0A): its numbers and
 *  dates are 8 big-endian bytes, its text in a long binary column encoded
 *  (decodeSearchText). Anything else as on Windows 8. */
void addWindows7Value(Json& o, const std::wstring& key, const EseColumn& column, const EseCell& cell, int variantType) {
	if (cell.compressionScheme < 0 && !cell.longValueMissing && cell.values.size() == 1) {
		const std::vector<uint8_t>& bytes = cell.values.front();
		if (column.type == JET_BINARY && bytes.size() == 8
		    && (variantType == VT_TIME || variantType == VT_UNSIGNED_64 || variantType == VT_SIGNED_64)) {
			addSearchBlob(o, key, variantType, std::vector<uint8_t>(bytes.rbegin(), bytes.rend()));
			return;
		}
		std::wstring text;
		if (column.type == JET_LONG_BINARY && variantType == VT_UTF16 && decodeSearchText(bytes, text)) {
			if (!text.empty()) o.add(key, Json::str(text));
			return;
		}
	}
	addEseValue(o, key, column, cell, variantType);
}

//! The column of that identifier, or nullptr.
const EseColumn* columnOf(const EseTable& table, uint32_t id) {
	for (const EseColumn& c : table.columns) if (c.id == id) return &c;
	return nullptr;
}

/*! The JSON key of a property: its name without "System.", PascalCase.
 *  @param name the property's canonical name (System.Search.GatherTime)
 *  @return the key (SearchGatherTime) */
std::wstring propertyKey(const std::wstring& name) {
	const std::wstring prefix = L"System.";
	return registryNameToJsonKey(name.compare(0, prefix.size(), prefix) == 0 ? name.substr(prefix.size()) : name);
}

} // namespace

bool decodeSearchText(const std::vector<uint8_t>& encoded, std::wstring& text) {
	text.clear();
	if (encoded.empty()) return false;
	// The obfuscation: each byte XOR a byte of (0x05000113 XOR the size), in
	// turn, XOR its own position's low byte.
	const uint32_t mask = 0x05000113u ^ (uint32_t)encoded.size();
	std::vector<uint8_t> d(encoded.size());
	for (size_t i = 0; i < encoded.size(); ++i)
		d[i] = (uint8_t)(encoded[i] ^ (uint8_t)(mask >> (8 * (i & 3))) ^ (uint8_t)i);
	if (d[0] == SEARCH_TEXT_BYTES) {
		for (size_t i = 1; i < d.size(); ++i) text += (wchar_t)d[i];
		return true;
	}
	if (d[0] != SEARCH_TEXT_RUNS) return false;
	// Runs: a count, the high byte they share, then the low byte of each.
	for (size_t at = 1; at < d.size();) {
		if (!fits(d.size(), at, 2)) return false;
		const size_t count = d[at];
		const wchar_t high = (wchar_t)(d[at + 1] << 8);
		at += 2;
		if (!fits(d.size(), at, count)) return false;
		for (size_t i = 0; i < count; ++i) text += (wchar_t)(high | d[at + i]);
		at += count;
	}
	return true;
}

void addSearchBlob(Json& o, const std::wstring& key, int variantType, const std::vector<uint8_t>& bytes) {
	if (variantType == VT_TIME && bytes.size() == 8) {
		const uint64_t value = readLittleEndian<uint64_t>(bytes.data());
		FILETIME ft = { (DWORD)value, (DWORD)(value >> 32) };
		addDate(o, key, ft);
		return;
	}
	if ((variantType == VT_UNSIGNED_64 || variantType == VT_SIGNED_64) && bytes.size() == 8) {
		const uint64_t value = readLittleEndian<uint64_t>(bytes.data());
		o.add(key, variantType == VT_SIGNED_64 ? Json::num((long long)value) : Json::num((unsigned long long)value));
		return;
	}
	if (variantType == VT_GUID && bytes.size() == sizeof(GUID)) {
		GUID guid;
		memcpy(&guid, bytes.data(), sizeof guid);
		o.add(key, Json::str(guid_to_wstring(guid)));
		return;
	}
	std::vector<std::wstring> strings;
	if (utf16Strings(bytes, strings)) {
		if ((variantType & VT_VECTOR_FLAG) || strings.size() > 1) {
			Json list = Json::arr();
			for (const std::wstring& s : strings) list.push(Json::str(s));
			o.add(key, std::move(list));
		} else o.add(key, Json::str(strings.front()));
		return;
	}
	o.add(key, Json::str(toHexadecimal(bytes.data(), bytes.size())));
}

Json SearchIndexItem::toJson() const {
	Json o = Json::obj();
	o.add(L"Path", Json::str(path));
	o.add(L"Table", Json::str(table));
	o.merge(fields);   // the item's fields at the record's level, already filtered by add
	return o;
}

HRESULT readSearchPropertyStore(const std::wstring& file, const std::wstring& path, std::vector<SearchIndexItem>& items) {
	SqliteDatabase db;
	const HRESULT hr = db.open(file);
	if (hr != ERROR_SUCCESS) return hr;
	struct Property { std::wstring key; int variantType; };
	std::map<int64_t, Property> properties;
	if (db.query("SELECT Id, Name, VariantType FROM SystemIndex_1_PropertyStore_Metadata", [&](const SqliteRow& row) {
		properties[row.integer(0)] = { propertyKey(row.text(1)), (int)row.integer(2) };
	}) != ERROR_SUCCESS) {
		log(2, L"🔥Search index: property names unreadable in " + path);
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	// The table's key is (WorkId, ColumnId): a scan gives each item's rows together.
	int64_t currentWorkId = -1;
	const HRESULT hrQuery = db.query("SELECT WorkId, ColumnId, Value FROM SystemIndex_1_PropertyStore", [&](const SqliteRow& row) {
		const int64_t workId = row.integer(0);
		if (workId != currentWorkId) {
			currentWorkId = workId;
			SearchIndexItem item;
			item.path = path;
			item.table = L"PropertyStore";
			item.fields.add(L"WorkId", Json::num((long long)workId));
			items.push_back(std::move(item));
		}
		Json& fields = items.back().fields;
		const auto known = properties.find(row.integer(1));
		const std::wstring key = known != properties.end() ? known->second.key : L"Column" + std::to_wstring(row.integer(1));
		const int variantType = known != properties.end() ? known->second.variantType : 0;
		switch (row.type(2)) {
		case SqliteType::Integer:
			fields.add(key, variantType == VT_BOOLEAN ? Json::boolean(row.integer(2) != 0) : Json::num((long long)row.integer(2)));
			break;
		case SqliteType::Real: fields.add(key, Json::real(row.real(2))); break;
		case SqliteType::Text: fields.add(key, Json::str(row.text(2))); break;
		case SqliteType::Blob: addSearchBlob(fields, key, variantType, row.blob(2)); break;
		case SqliteType::Null: break;
		}
	});
	if (hrQuery != ERROR_SUCCESS) log(2, L"🔥Search index: property store unreadable in " + path);
	return ERROR_SUCCESS;
}

HRESULT readSearchGather(const std::wstring& file, const std::wstring& path, std::vector<SearchIndexItem>& items) {
	SqliteDatabase db;
	const HRESULT hr = db.open(file);
	if (hr != ERROR_SUCCESS) return hr;
	// The scope tree: each scope's parent and its part of the URL ("Users/").
	std::map<int64_t, std::pair<int64_t, std::wstring>> scopes;
	if (db.query("SELECT Scope, Parent, Name FROM SystemIndex_GthrPth", [&](const SqliteRow& row) {
		scopes[row.integer(0)] = { row.integer(1), row.text(2) };
	}) != ERROR_SUCCESS) log(2, L"🔥Search index: scope tree unreadable in " + path);
	auto url = [&](int64_t scope) {
		std::wstring text;
		for (int depth = 0; depth < SCOPE_DEPTH_MAX; ++depth) {
			const auto s = scopes.find(scope);
			if (s == scopes.end()) break;
			text = s->second.second + text;
			if (s->second.first == scope) break;
			scope = s->second.first;
		}
		return text;
	};
	const HRESULT hrQuery = db.query("SELECT * FROM SystemIndex_Gthr", [&](const SqliteRow& row) {
		SearchIndexItem item;
		item.path = path;
		item.table = L"Gather";
		std::wstring scopeUrl, name;
		for (int c = 0; c < row.columnCount(); ++c) {
			const std::wstring column = row.name(c);
			if (column == L"ScopeID") scopeUrl = url(row.integer(c));
			if (column == L"FileName") name = row.text(c);
		}
		item.fields.add(L"Url", Json::str(scopeUrl + name));
		for (int c = 0; c < row.columnCount(); ++c) {
			const std::wstring column = registryNameToJsonKey(row.name(c));
			switch (row.type(c)) {
			case SqliteType::Integer: item.fields.add(column, Json::num((long long)row.integer(c))); break;
			case SqliteType::Real:    item.fields.add(column, Json::real(row.real(c))); break;
			case SqliteType::Text:    item.fields.add(column, Json::str(row.text(c))); break;
			case SqliteType::Blob:
				// LastModified: the FILETIME the crawler saw; any other blob as its bytes.
				addSearchBlob(item.fields, column, column == L"LastModified" ? VT_TIME : 0, row.blob(c));
				break;
			case SqliteType::Null: break;
			}
		}
		items.push_back(std::move(item));
	});
	if (hrQuery != ERROR_SUCCESS) log(2, L"🔥Search index: crawler's table unreadable in " + path);
	return ERROR_SUCCESS;
}

HRESULT readSearchEdb(const std::wstring& file, const std::wstring& path, std::vector<SearchIndexItem>& items) {
	// What the indexer wrote since its last checkpoint is in edb*.log, collected with it.
	const EseReplay replayed = ReplayEseLogsOnce(file, path);
	if (replayed.attempted && !replayed.applied) log(1, L"⚠️Search index logs not replayed: " + replayed.detail);
	EseDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	// Windows 7 names its property store otherwise (see search_index.h).
	const EseTable* store = db.table(L"SystemIndex_PropertyStore");
	const bool windows7 = store == nullptr;
	if (windows7) store = db.table(L"SystemIndex_0A");
	if (store) {
		std::vector<std::pair<std::wstring, int>> properties;   // by column: JSON key, VARIANT type
		for (const EseColumn& c : store->columns) {
			const std::wstring name = edbPropertyName(c.name);
			// Windows 7's DocID is Windows 8's WorkID: the item, DocumentID in the crawler's table.
			const bool identifier = c.name == L"WorkID" || c.name == L"DocID";
			properties.emplace_back(identifier ? L"WorkId" : propertyKey(name), searchPropertyVariantType(name));
		}
		for (const EseRecord& r : db.records(*store)) {
			SearchIndexItem item;
			item.path = path;
			item.table = L"PropertyStore";
			for (const EseCell& cell : r) {
				const EseColumn* column = columnOf(*store, cell.columnId);
				if (!column || cell.values.empty()) continue;
				const auto& property = properties[column - store->columns.data()];
				if (windows7) addWindows7Value(item.fields, property.first, *column, cell, property.second);
				else addEseValue(item.fields, property.first, *column, cell, property.second);
			}
			items.push_back(std::move(item));
		}
	}
	else log(2, L"🔥Search index: no property store in " + path);
	readEseGather(db, path, items);
	return ERROR_SUCCESS;
}

void readEseGather(EseDatabase& db, const std::wstring& path, std::vector<SearchIndexItem>& items) {
	const EseTable* gather = db.table(L"SystemIndex_Gthr");
	const EseTable* tree = db.table(L"SystemIndex_GthrPth");
	if (!gather) {
		log(2, L"🔥Search index: no crawler's table in " + path);
		return;
	}
	// The scope tree: each scope's parent and its part of the URL.
	std::map<int64_t, std::pair<int64_t, std::wstring>> scopes;
	if (tree)
		for (const EseRecord& r : db.records(*tree)) {
			int64_t scope = -1, parent = -1;
			std::wstring name;
			for (const EseCell& cell : r) {
				const EseColumn* column = columnOf(*tree, cell.columnId);
				if (!column || cell.values.empty()) continue;
				const Json value = eseCellToJson(*column, cell);
				if (column->name == L"Scope") scope = std::stoll(value.text());
				else if (column->name == L"Parent") parent = std::stoll(value.text());
				else if (column->name == L"Name") name = value.text();
			}
			if (scope >= 0) scopes[scope] = { parent, name };
		}
	auto url = [&](int64_t scope) {
		std::wstring text;
		for (int depth = 0; depth < SCOPE_DEPTH_MAX; ++depth) {
			const auto s = scopes.find(scope);
			if (s == scopes.end()) break;
			text = s->second.second + text;
			if (s->second.first == scope) break;
			scope = s->second.first;
		}
		return text;
	};
	for (const EseRecord& r : db.records(*gather)) {
		SearchIndexItem item;
		item.path = path;
		item.table = L"Gather";
		std::wstring scopeUrl, name;
		for (const EseCell& cell : r) {
			const EseColumn* column = columnOf(*gather, cell.columnId);
			if (!column || cell.values.empty()) continue;
			if (column->name == L"ScopeID") scopeUrl = url(std::stoll(eseCellToJson(*column, cell).text()));
			if (column->name == L"FileName") name = eseCellToJson(*column, cell).text();
		}
		item.fields.add(L"Url", Json::str(scopeUrl + name));
		for (const EseCell& cell : r) {
			const EseColumn* column = columnOf(*gather, cell.columnId);
			if (!column || cell.values.empty()) continue;
			const std::wstring key = registryNameToJsonKey(column->name);
			if (column->name == L"LastModified" && cell.values.size() == 1 && cell.values.front().size() == 8) {
				/* The FILETIME the crawler saw, written BIG-endian in the ESE
				   index (Windows 8.1, measured: read the other way, the date
				   falls in the year 6961), little-endian in Windows 11's
				   SQLite one. */
				std::vector<uint8_t> littleEndian(cell.values.front().rbegin(), cell.values.front().rend());
				addSearchBlob(item.fields, key, VT_TIME, littleEndian);
			}
			else addEseValue(item.fields, key, *column, cell, 0);
		}
		items.push_back(std::move(item));
	}
}

HRESULT SearchIndex::getData() {
	log(0, L"ℹ️Windows Search index :");
	const std::wstring folder = extractedPath(SEARCH_INDEX_FOLDER);
	struct Database { const wchar_t* name; HRESULT (*read)(const std::wstring&, const std::wstring&, std::vector<SearchIndexItem>&); };
	for (const Database& d : { Database{ L"Windows.db", readSearchPropertyStore }, Database{ L"Windows-gather.db", readSearchGather },
	                           Database{ L"Windows.edb", readSearchEdb } }) {
		const std::wstring file = folder + L"\\" + d.name;
		std::error_code ec;
		if (!std::filesystem::is_regular_file(file, ec)) continue;
		const std::wstring path = originalPath(file);
		const size_t before = items_.size();
		if (d.read(file, path, items_) != ERROR_SUCCESS) {
			log(2, L"🔥Search index database unreadable: " + path);
			continue;
		}
		log(2, L"❇️" + path + L" : " + std::to_wstring(items_.size() - before) + L" item(s)");
	}
	return ERROR_SUCCESS;
}

HRESULT SearchIndex::toJson() {
	Json list = Json::arr();
	for (const SearchIndexItem& item : items_) list.push(item.toJson());
	return writeJsonFile("search_index.json", list);
}

void SearchIndex::clear() {
	items_.clear();
}
