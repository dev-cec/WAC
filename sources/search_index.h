/*! \file
 *  \brief Windows Search index (Windows 11): what the indexer recorded of each
 *         file, read in Windows.db and Windows-gather.db.
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
 *  NOT READ HERE. Windows 10 and earlier keep the same index in an ESE
 *  database, Windows.edb, its columns compressed: it is collected with the
 *  folder but not converted (backlog B-010, to be checked on a real Windows
 *  10). The inverted index (SystemIndex_1_DATA_*, the words of the files) is
 *  not converted: the summary and the properties are what an analysis reads.
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
