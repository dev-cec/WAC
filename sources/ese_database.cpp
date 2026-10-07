/*! \file
 *  \brief Reader of ESE databases (see ese_database.h).
 */
#include "conversions.h"
#include "ese_database.h"
#include "sha.h"
#include <algorithm>
#include <cstring>
#include <filesystem>

namespace {

const size_t HEADER_SMALL = 40, HEADER_LARGE = 80;   //!< page header: 40 bytes, 80 above 8 KiB
const uint32_t PAGE_LEAF = 0x02, PAGE_NEW_RECORD_FORMAT = 0x800;
const uint16_t TAG_COMPRESSED_KEY = 0x04;             //!< the key starts with a prefix of the page's
const uint32_t CATALOG_ROOT = 4;                       //!< MSysObjects' root page
const unsigned DEPTH_MAX = 64;
const size_t VALUE_MAX = 256 * 1024 * 1024;           //!< a long value beyond this is not assembled
// Tagged value header flags.
const uint8_t TAGGED_COMPRESSED = 0x02, TAGGED_SEPARATED = 0x04, TAGGED_MULTI = 0x08, TAGGED_TWO = 0x10, TAGGED_NULL = 0x20;

//! Size of a fixed column of a type (JET_coltyp), when the catalog gives none.
uint32_t typeSize(uint32_t type) {
	switch (type) {
	case 1: case 2: return 1;                 // Bit, UnsignedByte
	case 3: case 17: return 2;                // Short, UnsignedShort
	case 4: case 6: case 14: return 4;        // Long, IEEESingle, UnsignedLong
	case 5: case 7: case 8: case 15: return 8; // Currency, IEEEDouble, DateTime, LongLong
	case 16: return 16;                       // GUID
	default: return 0;
	}
}

//! The catalog's own columns: its layout is fixed.
std::vector<EseColumn> catalogColumns() {
	const std::pair<uint32_t, uint32_t> fixed[] = { { 1, 4 }, { 2, 3 }, { 3, 4 }, { 4, 4 }, { 5, 4 }, { 6, 4 }, { 7, 4 },
	                                                { 8, 1 }, { 9, 3 }, { 10, 4 }, { 11, 17 }, { 12, 4 } };
	std::vector<EseColumn> columns;
	uint32_t offset = 0;
	for (const auto& [id, type] : fixed) {
		EseColumn c;
		c.id = id; c.type = type; c.size = typeSize(type); c.offset = offset;
		offset += c.size;
		columns.push_back(c);
	}
	EseColumn name;
	name.id = 128; name.type = 10; name.codePage = 1252;
	columns.push_back(name);
	return columns;
}

//! The first value of a cell, or nullptr.
const std::vector<uint8_t>* firstValue(const EseRecord& record, uint32_t id) {
	for (const EseCell& c : record)
		if (c.columnId == id && !c.values.empty()) return &c.values.front();
	return nullptr;
}

//! A little-endian integer of 1, 2 or 4 bytes.
uint32_t smallInteger(const std::vector<uint8_t>* v) {
	if (!v) return 0;
	uint32_t n = 0;
	for (size_t i = 0; i < v->size() && i < 4; ++i) n |= (uint32_t)(*v)[i] << (8 * i);
	return n;
}

/*! Splits a multi-valued tagged value: two values (the first's size in a
 *  byte), or an offset table whose high bit marks a separated value. */
bool splitValues(const uint8_t* p, size_t size, uint8_t flags, EseCell& cell) {
	if (flags & TAGGED_TWO) {
		if (size < 1 || p[0] > size - 1) return false;
		cell.values.emplace_back(p + 1, p + 1 + p[0]);
		cell.values.emplace_back(p + 1 + p[0], p + size);
		cell.separated = { false, false };
		return true;
	}
	if (size < 2) return false;
	const size_t first = readLittleEndian<uint16_t>(p) & 0x7FFF, count = first / 2;
	if (count == 0 || first > size) return false;
	for (size_t i = 0; i < count; ++i) {
		const uint16_t raw = readLittleEndian<uint16_t>(p + 2 * i);
		const size_t begin = raw & 0x7FFF, end = i + 1 < count ? (readLittleEndian<uint16_t>(p + 2 * (i + 1)) & 0x7FFF) : size;
		if (begin > end || end > size) return false;
		cell.values.emplace_back(p + begin, p + end);
		cell.separated.push_back((raw & 0x8000) != 0);
	}
	return true;
}

//! Tagged columns: identifier/offset pairs, then their values.
void parseTagged(const uint8_t* d, size_t size, size_t start, const std::vector<EseColumn>& columns,
                 bool smallPages, EseRecord& out) {
	if (!fits(size, start, 4)) return;
	const uint16_t mask = smallPages ? 0x1FFF : 0x7FFF;
	const size_t count = (readLittleEndian<uint16_t>(d + start + 2) & mask) / 4;
	if (count == 0 || !fits(size, start, count * 4)) return;
	for (size_t i = 0; i < count; ++i) {
		const uint16_t id = readLittleEndian<uint16_t>(d + start + 4 * i), field = readLittleEndian<uint16_t>(d + start + 4 * i + 2);
		const size_t begin = start + (field & mask);
		const size_t end = i + 1 < count ? start + (readLittleEndian<uint16_t>(d + start + 4 * (i + 1) + 2) & mask) : size;
		if (begin > end || end > size) return;
		const bool extended = !smallPages || (field & 0x4000);
		const uint8_t flags = extended && begin < end ? d[begin] : 0;
		if (smallPages ? (field & 0x2000) : (flags & TAGGED_NULL)) continue;
		const size_t valueBegin = begin + (extended ? 1 : 0);
		if (valueBegin > end || !std::any_of(columns.begin(), columns.end(), [&](const EseColumn& c) { return c.id == id; })) continue;
		EseCell cell;
		cell.columnId = id;
		if (flags & (TAGGED_MULTI | TAGGED_TWO)) {
			if (!splitValues(d + valueBegin, end - valueBegin, flags, cell)) continue;
		}
		else {
			cell.values.emplace_back(d + valueBegin, d + end);
			cell.separated.push_back((flags & TAGGED_SEPARATED) != 0);
		}
		if ((flags & TAGGED_COMPRESSED) && !cell.values.front().empty() && !cell.separated.front())
			cell.compressionScheme = cell.values.front()[0] >> 3;
		out.push_back(std::move(cell));
	}
}

//! An OLE date (days since 30/12/1899, as a double) in ISO 8601, UTC.
std::wstring oleDateText(double date) {
	SYSTEMTIME st;
	FILETIME ft;
	if (!oleDateToSystemTime(date, st) || !SystemTimeToFileTime(&st, &ft)) return L"";
	return timeToIso8601Utc(ft);
}

//! A real, in text with every digit needed to give it back.
std::wstring realText(double value, int digits) {
	wchar_t text[40];
	swprintf(text, 40, L"%.*g", digits, value);
	return text;
}

//! One value of a column in JSON.
Json valueToJson(const EseColumn& column, const std::vector<uint8_t>& v) {
	const uint8_t* p = v.data();
	const size_t n = v.size();
	switch (column.type) {
	case 1: if (n >= 1) return Json::boolean(p[0] != 0); break;
	case 2: if (n >= 1) return Json::num((unsigned)p[0]); break;
	case 3: if (n >= 2) return Json::num((int)(int16_t)readLittleEndian<uint16_t>(p)); break;
	case 17: if (n >= 2) return Json::num((unsigned)readLittleEndian<uint16_t>(p)); break;
	case 4: if (n >= 4) return Json::num((int32_t)readLittleEndian<uint32_t>(p)); break;
	case 14: if (n >= 4) return Json::num(readLittleEndian<uint32_t>(p)); break;
	case 5: case 15: if (n >= 8) return Json::num((long long)readLittleEndian<uint64_t>(p)); break;
	case 6: if (n >= 4) { float f; memcpy(&f, p, 4); return Json::str(realText(f, 9)); } break;
	case 7: if (n >= 8) { double d; memcpy(&d, p, 8); return Json::str(realText(d, 17)); } break;
	case 8: if (n >= 8) { double d; memcpy(&d, p, 8); const std::wstring t = oleDateText(d); if (!t.empty()) return Json::str(t); } break;
	case 16: if (n >= 16) return Json::str(guid_to_wstring(p)); break;
	case 10: case 12:
		if (column.codePage == 1200) return Json::str(readWideZ(p, n & ~(size_t)1, 0));
	{
		// As declared, inner NULs included — a column declared one byte per
		// character may hold UTF-16 (SRUM's Tag) —, the terminating ones out.
		size_t end = n;
		while (end > 0 && p[end - 1] == 0) --end;
		return Json::str(decodeText(std::string(p, p + end), column.codePage ? column.codePage : 1252));
	}
	default: break;
	}
	return Json::str(toHexadecimal(p, n));
}

} // namespace

Json eseCellToJson(const EseColumn& column, const EseCell& cell) {
	if (cell.compressionScheme >= 0 || cell.longValueMissing) {
		Json o = Json::obj();
		if (cell.compressionScheme >= 0) o.add(L"CompressionScheme", Json::num(cell.compressionScheme));
		if (cell.longValueMissing) o.add(L"LongValueMissing", Json::boolean(true));
		o.add(L"Undecoded", Json::boolean(true));
		return o;
	}
	if (cell.values.size() == 1) return valueToJson(column, cell.values.front());
	Json list = Json::arr();
	for (const std::vector<uint8_t>& v : cell.values) list.push(valueToJson(column, v));
	return list;
}

EseRecord parseEseRecord(const std::vector<uint8_t>& data, const std::vector<EseColumn>& columns,
                         bool smallPages, bool newFormat) {
	EseRecord out;
	const uint8_t* d = data.data();
	const size_t size = data.size();
	if (size < 4) return out;
	const unsigned lastFixed = d[0], lastVariable = d[1];
	const size_t endOfFixed = readLittleEndian<uint16_t>(d + 2), bitmapBytes = (lastFixed + 7) / 8;
	if (endOfFixed > size || endOfFixed < 4 + bitmapBytes) return out;
	const size_t bitmap = endOfFixed - bitmapBytes;
	const size_t variables = lastVariable >= 128 ? lastVariable - 127 : 0;
	const size_t variableData = endOfFixed + 2 * variables;
	if (variableData > size) return out;
	for (const EseColumn& c : columns) {
		EseCell cell;
		cell.columnId = c.id;
		if (c.id <= 127) {
			if (c.id > lastFixed || (d[bitmap + (c.id - 1) / 8] & (1 << ((c.id - 1) % 8)))) continue;
			if (!fits(bitmap, 4 + c.offset, c.size) || c.size == 0) continue;
			cell.values.emplace_back(d + 4 + c.offset, d + 4 + c.offset + c.size);
		}
		else if (c.id <= 255) {
			if (c.id > lastVariable) continue;
			const size_t index = c.id - 128;
			const uint16_t end = readLittleEndian<uint16_t>(d + endOfFixed + 2 * index);
			if (end & 0x8000) continue;
			const size_t begin = index == 0 ? 0 : (readLittleEndian<uint16_t>(d + endOfFixed + 2 * (index - 1)) & 0x7FFF);
			if (begin > end || !fits(size, variableData + begin, end - begin) || begin == end) continue;
			cell.values.emplace_back(d + variableData + begin, d + variableData + end);
		}
		else continue;                                          // tagged: below, all at once
		cell.separated.push_back(false);
		out.push_back(std::move(cell));
	}
	const size_t tagged = variableData + (variables ? (readLittleEndian<uint16_t>(d + endOfFixed + 2 * (variables - 1)) & 0x7FFF) : 0);
	if (newFormat && tagged < size) parseTagged(d, size, tagged, columns, smallPages, out);
	return out;
}

// ------------------------------------------------------------ database

HRESULT EseDatabase::open(const std::wstring& path) {
	std::error_code ec;
	fileSize_ = std::filesystem::file_size(path, ec);
	if (ec) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	file_.open(std::filesystem::path(path), std::ios::binary);
	uint8_t header[240] = {};
	file_.read(reinterpret_cast<char*>(header), sizeof header);
	if (file_.gcount() != (std::streamsize)sizeof header || readLittleEndian<uint32_t>(header + 4) != 0x89ABCDEF)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	state_ = readLittleEndian<uint32_t>(header + 52);
	pageSize_ = readLittleEndian<uint32_t>(header + 236);
	if (pageSize_ != 4096 && pageSize_ != 8192 && pageSize_ != 16384 && pageSize_ != 32768)
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	pageCount_ = (uint32_t)std::min<uint64_t>(fileSize_ / pageSize_, UINT32_MAX);
	// The catalog: a table, then its columns, its indexes and its long-value tree.
	EseTable catalog;
	catalog.root = CATALOG_ROOT;
	catalog.columns = catalogColumns();
	for (const EseRecord& r : records(catalog)) {
		const uint32_t type = smallInteger(firstValue(r, 2)), idOrPage = smallInteger(firstValue(r, 4));
		const std::vector<uint8_t>* name = firstValue(r, 128);
		const std::wstring text = name ? decodeText(std::string(name->begin(), name->end()), 1252) : L"";
		if (type == 1) tables_.push_back({ text, idOrPage, 0, {} });
		else if (tables_.empty()) continue;
		else if (type == 2) {
			EseColumn c;
			c.id = smallInteger(firstValue(r, 3));
			c.name = text;
			c.type = idOrPage;
			c.size = smallInteger(firstValue(r, 5));
			if (c.size == 0) c.size = typeSize(c.type);
			c.codePage = smallInteger(firstValue(r, 7));
			tables_.back().columns.push_back(c);
		}
		else if (type == 4) tables_.back().longValueRoot = idOrPage;
	}
	// Fixed columns: one after the other, in identifier order.
	for (EseTable& t : tables_) {
		std::sort(t.columns.begin(), t.columns.end(), [](const EseColumn& a, const EseColumn& b) { return a.id < b.id; });
		uint32_t offset = 0;
		for (EseColumn& c : t.columns)
			if (c.id <= 127) { c.offset = offset; offset += c.size; }
	}
	return tables_.empty() ? HRESULT_FROM_WIN32(ERROR_INVALID_DATA) : ERROR_SUCCESS;
}

const EseTable* EseDatabase::table(const std::wstring& name) const {
	for (const EseTable& t : tables_) if (t.name == name) return &t;
	return nullptr;
}

bool EseDatabase::readPage(uint32_t logical, std::vector<uint8_t>& page) {
	const uint64_t at = ((uint64_t)logical + 1) * pageSize_;
	if (logical == 0 || at > fileSize_ || fileSize_ - at < pageSize_) return false;
	page.resize(pageSize_);
	file_.clear();
	file_.seekg((std::streamoff)at);
	file_.read(reinterpret_cast<char*>(page.data()), pageSize_);
	return file_.gcount() == (std::streamsize)pageSize_;
}

/*! Walks a tree from a page: a leaf gives its entries, a branch its children
 *  (the page number in each entry's data), each page once. */
void EseDatabase::walk(uint32_t number, unsigned depth, std::vector<bool>& visited, std::vector<Entry>& out, uint32_t& lastLeaf) {
	if (depth > DEPTH_MAX || number >= visited.size() || visited[number]) return;
	visited[number] = true;
	std::vector<uint8_t> page;
	if (!readPage(number, page)) return;
	const bool small = pageSize_ <= 8192;
	const size_t header = small ? HEADER_SMALL : HEADER_LARGE;
	const uint32_t flags = readLittleEndian<uint32_t>(page.data() + 36);
	const size_t dataSize = std::min<size_t>(readLittleEndian<uint16_t>(page.data() + 32), pageSize_ - header);
	const unsigned tags = readLittleEndian<uint16_t>(page.data() + 34) & 0x0FFF, reserved = std::max(1u, (unsigned)(readLittleEndian<uint16_t>(page.data() + 34) >> 12));
	if (tags == 0 || (size_t)tags * 4 > pageSize_ - header) return;
	const uint16_t mask = small ? 0x1FFF : 0x7FFF;
	auto tag = [&](unsigned i, size_t& offset, size_t& size) {
		const uint8_t* t = page.data() + pageSize_ - 4 * (i + 1);
		size = readLittleEndian<uint16_t>(t) & mask;
		offset = readLittleEndian<uint16_t>(t + 2) & mask;
		return fits(dataSize, offset, size);
	};
	size_t prefixOffset = 0, prefixSize = 0;
	if (!tag(0, prefixOffset, prefixSize)) prefixSize = 0;
	const uint8_t* data = page.data() + header;
	const bool leaf = (flags & PAGE_LEAF) != 0;
	// Tag 0 holds the page's shared key prefix; the entries follow, up to the reserved tags.
	for (unsigned i = 1; i + reserved <= tags; ++i) {
		size_t offset = 0, size = 0;
		if (!tag(i, offset, size) || size < 2) continue;
		const uint8_t* e = data + offset;
		const uint16_t first = readLittleEndian<uint16_t>(e);
		const uint16_t tagFlags = small ? (readLittleEndian<uint16_t>(page.data() + pageSize_ - 4 * (i + 1) + 2) >> 13) : (first >> 13);
		size_t o = 0, shared = 0;
		if (tagFlags & TAG_COMPRESSED_KEY) { shared = std::min<size_t>(first & 0x1FFF, prefixSize); o = 2; }
		if (!fits(size, o, 2)) continue;
		const size_t suffix = readLittleEndian<uint16_t>(e + o) & 0x1FFF;
		o += 2;
		if (!fits(size, o, suffix)) continue;
		Entry entry;
		entry.key.assign(data + prefixOffset, data + prefixOffset + shared);
		entry.key.insert(entry.key.end(), e + o, e + o + suffix);
		o += suffix;
		entry.data.assign(e + o, e + size);
		if (leaf) {
			entry.newFormat = (flags & PAGE_NEW_RECORD_FORMAT) != 0;
			out.push_back(std::move(entry));
		}
		else if (entry.data.size() >= 4) walk(readLittleEndian<uint32_t>(entry.data.data()), depth + 1, visited, out, lastLeaf);
	}
	if (leaf) lastLeaf = number;
}

void EseDatabase::leaves(uint32_t root, std::vector<Entry>& out) {
	std::vector<bool> visited(pageCount_, false);
	uint32_t lastLeaf = 0;
	walk(root, 0, visited, out, lastLeaf);
	// A database copied live may have leaves a branch does not reach yet: the
	// last leaf's successors, as ESE chains them.
	std::vector<uint8_t> page;
	while (lastLeaf && readPage(lastLeaf, page)) {
		const uint32_t next = readLittleEndian<uint32_t>(page.data() + 20);
		if (next == 0 || next >= visited.size() || visited[next]) break;
		const uint32_t before = lastLeaf;
		walk(next, 0, visited, out, lastLeaf);
		if (lastLeaf == before) break;
	}
}

//! The long-value tree of a table, by key: identifier alone for a header, identifier then offset for a chunk.
std::map<std::string, std::vector<uint8_t>> EseDatabase::longValueTree(const EseTable& table) {
	std::map<std::string, std::vector<uint8_t>> out;
	if (!table.longValueRoot) return out;
	std::vector<Entry> entries;
	leaves(table.longValueRoot, entries);
	for (Entry& e : entries) out[std::string(e.key.begin(), e.key.end())] = std::move(e.data);
	return out;
}

namespace {

//! A 32-bit big-endian number: a chunk's offset in its key.
uint32_t be32(const std::string& key, size_t at) {
	const uint8_t* k = reinterpret_cast<const uint8_t*>(key.data()) + at;
	return ((uint32_t)k[0] << 24) | ((uint32_t)k[1] << 16) | ((uint32_t)k[2] << 8) | k[3];
}

/*! Assembles one long value. Its identifier is 4 or 8 bytes — as long as the
 *  record's reference —, little-endian in the record, big-endian in the
 *  tree: the header entry, keyed by the identifier, gives the total size;
 *  the chunks follow, keyed by identifier then offset. A chunk shorter than
 *  its span is compressed: not decoded, its scheme said.
 *  @return true if assembled; otherwise `scheme` >= 0 when compressed */
bool assembleLongValue(const std::map<std::string, std::vector<uint8_t>>& tree, const std::vector<uint8_t>& reference,
                       std::vector<uint8_t>& value, int& scheme) {
	scheme = -1;
	if (reference.size() != 4 && reference.size() != 8) return false;
	const std::string id(reference.rbegin(), reference.rend());
	const auto header = tree.find(id);
	if (header == tree.end() || header->second.size() < 8) return false;
	const uint32_t total = readLittleEndian<uint32_t>(header->second.data() + 4);
	if (total > VALUE_MAX) return false;
	auto isChunk = [&](std::map<std::string, std::vector<uint8_t>>::const_iterator it) {
		return it != tree.end() && it->first.size() == id.size() + 4 && it->first.compare(0, id.size(), id) == 0;
	};
	value.clear();
	for (auto it = std::next(header); isChunk(it); ++it) {
		const uint32_t offset = be32(it->first, id.size());
		const auto next = std::next(it);
		const uint32_t end = isChunk(next) ? be32(next->first, id.size()) : total;
		if (offset != value.size() || end < offset) return false;
		if (it->second.size() != end - offset) {
			scheme = it->second.empty() ? 0 : it->second[0] >> 3;
			return false;
		}
		value.insert(value.end(), it->second.begin(), it->second.end());
	}
	return value.size() == total;
}

} // namespace

std::vector<EseRecord> EseDatabase::records(const EseTable& table) {
	std::vector<Entry> entries;
	leaves(table.root, entries);
	std::map<std::string, std::vector<uint8_t>> tree;
	bool treeRead = false;
	std::vector<EseRecord> out;
	for (const Entry& e : entries) {
		EseRecord record = parseEseRecord(e.data, table.columns, pageSize_ <= 8192, e.newFormat);
		for (EseCell& cell : record)
			for (size_t i = 0; i < cell.values.size(); ++i) {
				if (!cell.separated[i]) continue;
				if (!treeRead) { tree = longValueTree(table); treeRead = true; }
				std::vector<uint8_t> value;
				int scheme = -1;
				if (assembleLongValue(tree, cell.values[i], value, scheme)) { cell.values[i] = std::move(value); cell.separated[i] = false; }
				else if (scheme >= 0) cell.compressionScheme = scheme;
				else cell.longValueMissing = true;
			}
		if (!record.empty()) out.push_back(std::move(record));
	}
	return out;
}
