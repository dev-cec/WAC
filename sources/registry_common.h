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

/*! One subkey, as its parent lists it. */
struct Subkey {
	std::wstring name;
	FILETIME lastWriteUtc = { 0 };   //!< its last write
};

/*! THE enumeration of a key's subkeys, every walk of WAC through it.
 *  Their number is asked first: a subkey that cannot be read (a damaged
 *  cell) is logged and skipped, not taken for the list's end — a loop that
 *  stopped at the first error dropped every later sibling (Uninstall
 *  programs, LSA secrets…) without a word; and a name longer than a fixed
 *  buffer is read whole (ERROR_MORE_DATA): one that did not fit left the
 *  previous name in the buffer, a service read twice and the long-named
 *  one hidden.
 *  @param key an open key
 *  @return its subkeys, in the hive's order; empty if it has none or its
 *          count cannot be read */
std::vector<Subkey> subkeysOf(ORHKEY key);

/*! @param root an open key
 *  @param path a key under it
 *  @return the names of the subkeys of `path` (subkeysOf), empty if it cannot be opened */
std::vector<std::wstring> subkeys(ORHKEY root, const std::wstring& path);

/*! @param type,data a registry value
 *  @return a string as written, a DWORD as its number, "" for any other type */
std::wstring valueText(DWORD type, const std::vector<BYTE>& data);

/*! The number of a value named `url<N>` — TypedPaths, TypedURLs, their
 *  TypedURLsTime —, url1 being the most recent.
 *  @param name the value's name
 *  @return N, or 0 if the name is not url followed by digits only */
unsigned urlValueNumber(const std::wstring& name);

/*! Every value of an open key, typed as the hive stores it, under its
 *  PascalCase name.
 *  @param key the key
 *  @param out receives the values */
void readAllValues(ORHKEY key, std::vector<std::pair<std::wstring, Json>>& out);

/*! @param values Name/Value pairs
 *  @return them as a JSON array of {Name, Value} */
Json pairs(const NameValues& values);

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
