/*! \file
 *  \brief Windows Search index: what the indexer recorded of each file, read
 *         in Windows.db and Windows-gather.db (Windows 11), or in Windows.edb
 *         (Windows 10 and earlier).
 *
 *  WHAT THE ARTEFACT PROVES. The indexer keeps, for each item it crawled —
 *  file, folder, shortcut, mail —, its path, its dates (created, modified,
 *  accessed, gathered), its size, owner, type and, for documents, a summary
 *  of its text (`AutoSummary`). The record outlives the file until the next
 *  crawl notices it gone: a deleted document can still show here with its
 *  path and dates, sometimes its first lines.
 *
 *  TWO DATABASES. `Windows.db` holds the property store: one row per item
 *  (WorkId) and property, the property's name and type given by
 *  `SystemIndex_1_PropertyStore_Metadata`. `Windows-gather.db` holds what the
 *  crawler saw of each document (DocumentID, the same number as WorkId): its
 *  URL, rebuilt from the scope tree `SystemIndex_GthrPth`, and its last
 *  modification at crawl time — it lists documents the property store no
 *  longer has. Both are read whole, one record per item of each (`Table`).
 *
 *  VALUES. Each property is converted by its VARIANT type, as the metadata
 *  declares it, and by how SQLite stored it: a FILETIME (8 bytes) as a date
 *  in UTC and in local time, a 64-bit integer from its 8 little-endian
 *  bytes, a CLSID as a GUID, a VT_BOOL as true or false, a string vector or a
 *  UTF-16 blob as text, any other blob in hexadecimal. A property's name
 *  (System.ItemPathDisplay) becomes a key without its "System." prefix
 *  (ItemPathDisplay). A zero date is not emitted.
 *
 *  WINDOWS.EDB. Windows 10 and earlier keep the same index in an ESE
 *  database: the same tables, SystemIndex_PropertyStore with one column per
 *  property ("4385-System_ItemPathDisplay": its number, then its name with
 *  "_" for ".") and SystemIndex_Gthr with SystemIndex_GthrPth. Its text is
 *  compressed on 7 bits (unpacked by the ESE reader); it does not say the
 *  VARIANT type of a binary column, which the table of search_property_types
 *  gives — a FILETIME and a size are both 8 bytes. The crawler's
 *  LastModified is big-endian there. Measured on Windows 8.1; a value of
 *  Windows 10 compressed otherwise (XPRESS) is said, not decoded.
 *
 *  WINDOWS 7 names its property store SystemIndex_0A, its columns by the
 *  property's name alone ("System_ItemPathDisplay"), its item DocID (given
 *  as WorkId, the same number). Its numbers and dates are 8 big-endian bytes
 *  — the size of a 57-byte file reads 57, a ThumbnailCacheId the one Windows
 *  gives, only that way. A text property in a long binary column (the
 *  AutoSummary) is obfuscated and packed (decodeSearchText). Measured on the
 *  test VM; Vista's index was not.
 *
 *  NOT CONVERTED. The inverted index (SystemIndex_1_DATA_*, the words of the
 *  files): the summary and the properties are what an analysis reads.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

//! Folder of the Windows Search index, relative to the system volume.
extern const wchar_t SEARCH_INDEX_FOLDER[];

/*! One item of the index: a row group of the property store, or one row of
 *  the crawler's table. */
struct SearchIndexItem {
	std::wstring path;          //!< the database on the examined machine
	std::wstring table;         //!< "PropertyStore" or "Gather"
	Json fields = Json::obj();  //!< its identifier and properties (see the file's header)
	//! @return the item as a JSON object
	Json toJson() const;
};

/*! Decodes a text value of Windows 7's index, as libyal describes the
 *  format and as measured on the test VM: each byte XOR a byte of
 *  (0x05000113 XOR the value's size), in turn, XOR its position's low byte;
 *  then a first byte for the form — 1: one byte per character; 0: runs of a
 *  count, the high byte the run shares, the low byte of each character.
 *  Every run is bounded by the value's size.
 *  @param encoded the value as the column holds it
 *  @param text receives the text
 *  @return false for another form, or a run past the value's end */
bool decodeSearchText(const std::vector<uint8_t>& encoded, std::wstring& text);

/*! Converts one property-store value by its VARIANT type.
 *  @param o the item's fields
 *  @param key the property's key (already without "System.")
 *  @param variantType the VARIANT type the metadata declares (VT_FILETIME 64…)
 *  @param bytes the value when SQLite stored it as a blob */
void addSearchBlob(Json& o, const std::wstring& key, int variantType, const std::vector<uint8_t>& bytes);

/*! Reads the property store of Windows.db.
 *  @param file the database in the working copy of the collection
 *  @param path the database on the examined machine
 *  @param items receives one item per WorkId
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readSearchPropertyStore(const std::wstring& file, const std::wstring& path, std::vector<SearchIndexItem>& items);

/*! Reads the crawler's table of Windows-gather.db.
 *  @param file the database in the working copy of the collection
 *  @param path the database on the examined machine
 *  @param items receives one item per document
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readSearchGather(const std::wstring& file, const std::wstring& path, std::vector<SearchIndexItem>& items);

/*! Reads the ESE index of Windows 10 and earlier, Windows.edb: its property
 *  store and its crawler's table, one item per WorkID and per document as
 *  from the SQLite databases of Windows 11. Its transaction logs are
 *  replayed into the copy first.
 *  @param file the database in the working copy of the collection
 *  @param path the database on the examined machine
 *  @param items receives the items
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readSearchEdb(const std::wstring& file, const std::wstring& path, std::vector<SearchIndexItem>& items);

/*! Reads the crawler's table of an open ESE index, its URLs rebuilt from the
 *  scope tree.
 *  @param db the database
 *  @param path the database on the examined machine
 *  @param items receives one item per document */
void readEseGather(class EseDatabase& db, const std::wstring& path, std::vector<SearchIndexItem>& items);

/*! The VARIANT type a property has in the index (search_property_types.cpp).
 *  @param name its canonical name (System.ItemPathDisplay)
 *  @return its type, 0 for a property the table does not hold */
int searchPropertyVariantType(const std::wstring& name);

/*! The Windows Search index (search_index.json). */
class SearchIndex {
public:
	/*! Reads the databases extracted from the system volume.
	 *  @return ERROR_SUCCESS, even without any database: none is an answer */
	HRESULT getData();
	/*! Writes search_index.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the items read.
	void clear();
private:
	std::vector<SearchIndexItem> items_;   //!< the property store's, then the crawler's
};
