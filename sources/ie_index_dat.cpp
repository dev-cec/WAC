/*! \file
 *  \brief Internet Explorer 5 to 9's cache files (see ie_index_dat.h).
 */
#include "ie_index_dat.h"
#include "conversions.h"
#include "tools.h"
#include <algorithm>
#include <cstring>
#include <set>

namespace {

const char SIGNATURE[] = "Client UrlCache MMF Ver ";   //!< then "5.2" and a NUL, 28 bytes in all
const size_t DIRECTORY_COUNT = 72, DIRECTORIES = 76, DIRECTORY_ENTRY = 12, DIRECTORY_NAME = 8;
const size_t FIRST_HASH = 32;
const size_t BLOCK = 128, BLOCKS_START = 0x4000;
const size_t HASH_HEADER = 16, HASH_ENTRY = 8;
const uint32_t HASH_UNINITIALISED = 0x0BADF00D, HASH_UNINITIALISED_IE8 = 0xDEADBEEF;
const unsigned MAX_HASH_TABLES = 4096;     //!< a longer chain is a loop, or a forged file
// URL record, version 5.2.
const size_t URL_SECONDARY = 8, URL_PRIMARY = 16, URL_EXPIRY = 24, URL_SIZE = 32, URL_LOCATION = 52,
             URL_DIRECTORY = 56, URL_FILENAME = 60, URL_FLAGS = 64, URL_DATA = 68, URL_DATA_SIZE = 72,
             URL_CHECKED = 80, URL_HITS = 84, URL_MINIMUM = 96;
const size_t REDR_LOCATION = 16;
const size_t LEAK_SIZE = 32, LEAK_DIRECTORY = 56, LEAK_FILENAME = 60, LEAK_MINIMUM = 64;
const uint8_t NO_DIRECTORY_FIRST = 0xFE;   //!< 0xFE and 0xFF: no cached file (history, cookies…)

//! @return the kind of the record at `at`, "" if there is none
std::wstring kindAt(const uint8_t* data, size_t size, size_t at) {
	if (at + 8 > size) return L"";
	if (std::memcmp(data + at, "URL ", 4) == 0) return L"URL";
	if (std::memcmp(data + at, "REDR", 4) == 0) return L"REDR";
	if (std::memcmp(data + at, "LEAK", 4) == 0) return L"LEAK";
	return L"";
}

/*! A NUL-terminated string of a record, at an offset the record declares.
 *  @param record the record's first byte
 *  @param length the record's size, bounded by the file
 *  @param offset the string's offset in the record; 0 for none
 *  @return the string, decoded from the examined machine's ANSI code page */
std::wstring recordString(const uint8_t* record, size_t length, uint32_t offset) {
	if (offset == 0 || offset >= length) return L"";
	size_t end = offset;
	while (end < length && record[end] != 0) ++end;
	return decodeText(std::string(reinterpret_cast<const char*>(record + offset), end - offset));
}

/*! Decodes the record at `at`.
 *  @param data,size the file
 *  @param at the record's offset, its signature checked
 *  @param record receives the fields
 *  @return false if the record does not fit in the file */
bool readRecord(const uint8_t* data, size_t size, size_t at, IeIndexRecord& record) {
	record.kind = kindAt(data, size, at);
	record.offset = (uint32_t)at;
	const uint32_t blocks = readLittleEndian<uint32_t>(data + at + 4);
	// The record's declared size, bounded by the file: what lies beyond is not its.
	size_t length = blocks && blocks <= (size - at) / BLOCK ? blocks * BLOCK : size - at;
	/* …and by the next record: a record deleted then partly overwritten by a
	   newer one (recovered from the blocks) ends where that one begins — its
	   declared tail is the other's bytes, valid-looking and not its. */
	for (size_t next = at + BLOCK; next < at + length; next += BLOCK)
		if (!kindAt(data, size, next).empty()) { length = next - at; break; }
	const uint8_t* r = data + at;
	if (record.kind == L"URL") {
		if (length < URL_MINIMUM) return false;
		record.secondaryTime = readLittleEndian<uint64_t>(r + URL_SECONDARY);
		record.primaryTime = readLittleEndian<uint64_t>(r + URL_PRIMARY);
		record.expiry = readLittleEndian<uint32_t>(r + URL_EXPIRY);
		record.fileSize = readLittleEndian<uint64_t>(r + URL_SIZE);
		record.location = recordString(r, length, readLittleEndian<uint32_t>(r + URL_LOCATION));
		if (r[URL_DIRECTORY] < NO_DIRECTORY_FIRST) record.cacheDirectory = r[URL_DIRECTORY];
		record.filename = recordString(r, length, readLittleEndian<uint32_t>(r + URL_FILENAME));
		record.flags = readLittleEndian<uint32_t>(r + URL_FLAGS);
		const uint32_t dataOffset = readLittleEndian<uint32_t>(r + URL_DATA);
		const uint32_t dataSize = readLittleEndian<uint32_t>(r + URL_DATA_SIZE);
		// What remains of the data in the record: all of it, or the part a newer record left.
		if (dataOffset && dataOffset < length)
			record.data.assign(r + dataOffset, r + dataOffset + std::min<size_t>(dataSize, length - dataOffset));
		record.lastChecked = readLittleEndian<uint32_t>(r + URL_CHECKED);
		record.hits = readLittleEndian<uint32_t>(r + URL_HITS);
	}
	else if (record.kind == L"REDR") {
		record.location = recordString(r, length, (uint32_t)REDR_LOCATION);
	}
	else if (record.kind == L"LEAK") {
		if (length < LEAK_MINIMUM) return false;
		record.fileSize = readLittleEndian<uint32_t>(r + LEAK_SIZE);
		if (r[LEAK_DIRECTORY] < NO_DIRECTORY_FIRST) record.cacheDirectory = r[LEAK_DIRECTORY];
		record.filename = recordString(r, length, readLittleEndian<uint32_t>(r + LEAK_FILENAME));
	}
	else return false;
	return true;
}

} // namespace

bool parseIeIndexDat(const uint8_t* data, size_t size, IeIndexFile& file) {
	const size_t prefix = sizeof(SIGNATURE) - 1;
	if (size < BLOCKS_START || std::memcmp(data, SIGNATURE, prefix) != 0
	    || std::memcmp(data + prefix, "5.2", 4) != 0) return false;   // 4: the version and its NUL
	file.version = L"5.2";
	const uint32_t directories = readLittleEndian<uint32_t>(data + DIRECTORY_COUNT);
	for (uint32_t i = 0; i < directories && DIRECTORIES + (i + 1) * DIRECTORY_ENTRY <= BLOCKS_START; ++i) {
		const uint8_t* name = data + DIRECTORIES + i * DIRECTORY_ENTRY + 4;
		file.cacheDirectories.push_back(decodeText(std::string(reinterpret_cast<const char*>(name), DIRECTORY_NAME)));
	}

	// The hash tables, in their chain: the records they name are the entries.
	std::set<size_t> named, tables;
	std::vector<size_t> order;
	size_t table = readLittleEndian<uint32_t>(data + FIRST_HASH);
	while (table && table >= BLOCKS_START && table + HASH_HEADER <= size && tables.size() < MAX_HASH_TABLES
	       && tables.insert(table).second && std::memcmp(data + table, "HASH", 4) == 0) {
		const uint32_t blocks = readLittleEndian<uint32_t>(data + table + 4);
		const size_t end = blocks <= (size - table) / BLOCK ? table + blocks * BLOCK : size;
		for (size_t e = table + HASH_HEADER; e + HASH_ENTRY <= end; e += HASH_ENTRY) {
			const uint32_t hash = readLittleEndian<uint32_t>(data + e);
			const uint32_t at = readLittleEndian<uint32_t>(data + e + 4);
			if (hash == at || hash == HASH_UNINITIALISED || hash == HASH_UNINITIALISED_IE8 || at < BLOCKS_START
			    || at % BLOCK || kindAt(data, size, at).empty()) continue;
			if (named.insert(at).second) order.push_back(at);
		}
		table = readLittleEndian<uint32_t>(data + table + 8);
	}
	for (size_t at : order) {
		IeIndexRecord record;
		if (readRecord(data, size, at, record)) file.records.push_back(std::move(record));
	}
	// The blocks: every LEAK is an entry; a URL or REDR no table names is recovered.
	std::vector<IeIndexRecord> recovered;
	for (size_t at = BLOCKS_START; at + 8 <= size;) {
		const std::wstring kind = kindAt(data, size, at);
		const uint32_t blocks = kind.empty() ? 0 : readLittleEndian<uint32_t>(data + at + 4);
		if (!kind.empty() && !named.count(at)) {
			IeIndexRecord record;
			if (readRecord(data, size, at, record)) {
				record.recovered = kind != L"LEAK";
				(record.recovered ? recovered : file.records).push_back(std::move(record));
			}
		}
		at += blocks && blocks <= (size - at) / BLOCK ? blocks * BLOCK : BLOCK;
	}
	for (IeIndexRecord& r : recovered) file.records.push_back(std::move(r));
	return true;
}
