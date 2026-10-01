/*! \file
 *  \brief Helpers shared by the registry artefacts read in the copied hives
 *  (registry_lot2, registry_lot3): a key's last write, its subkeys, a value as
 *  text, a list written to its JSON file, the user an entry belongs to.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "offline_registry.h"
#include "tools.h"

//! Name/Value pairs, in the order read.
using NameValues = std::vector<std::pair<std::wstring, std::wstring>>;

/*! @param key an open key
 *  @return its last write time, or a null FILETIME */
FILETIME lastWrite(ORHKEY key);

/*! @param root an open key
 *  @param path a key under it
 *  @return the names of the subkeys of `path`, empty if it cannot be opened */
std::vector<std::wstring> subkeys(ORHKEY root, const std::wstring& path);

/*! @param type,data a registry value
 *  @return a string as written, a DWORD as its number, "" for any other type */
std::wstring valueText(DWORD type, const std::vector<BYTE>& data);

/*! @param values Name/Value pairs
 *  @return them as a JSON array of {Name, Value} */
Json pairs(const NameValues& values);

/*! Adds the user an entry belongs to: `SID`, and `SIDName` as resolved
 *  offline in the examined machine's hives.
 *  @param o the entry's object
 *  @param sid the user's SID */
void addUser(Json& o, const std::wstring& sid);

/*! Writes an array of elements that have toJson().
 *  @param file the JSON file, in the output directory
 *  @param elements the elements
 *  @return the result of the write */
template <class Element>
HRESULT writeList(const char* file, const std::vector<Element>& elements) {
	Json list = Json::arr();
	for (const Element& e : elements) list.push(e.toJson());
	return writeJsonFile(file, list);
}
