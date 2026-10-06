/*! \file
 *  \brief Windows Search index (Windows 11): see search_index.h.
 */
#include "search_index.h"
#include "conversions.h"
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

/*! The JSON key of a property: its name without "System.", PascalCase.
 *  @param name the property's canonical name (System.Search.GatherTime)
 *  @return the key (SearchGatherTime) */
std::wstring propertyKey(const std::wstring& name) {
	const std::wstring prefix = L"System.";
	return registryNameToJsonKey(name.compare(0, prefix.size(), prefix) == 0 ? name.substr(prefix.size()) : name);
}

} // namespace

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

HRESULT SearchIndex::getData() {
	log(0, L"ℹ️Windows Search index :");
	const std::wstring folder = extractedPath(SEARCH_INDEX_FOLDER);
	struct Database { const wchar_t* name; HRESULT (*read)(const std::wstring&, const std::wstring&, std::vector<SearchIndexItem>&); };
	for (const Database& d : { Database{ L"Windows.db", readSearchPropertyStore }, Database{ L"Windows-gather.db", readSearchGather } }) {
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
