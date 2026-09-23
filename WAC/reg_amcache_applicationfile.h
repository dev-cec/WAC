/*! \file
 *  \brief Amcache, inventoried binaries: an executable, its publisher, its link date.
 *
 *  WHAT IT SHOWS. The other half of the Amcache inventory: the individual
 *  EXECUTABLES the machine has seen, with their full path, the publisher they
 *  declare, their version, and the link date stamped in the PE header at
 *  compile time. An entry proves the binary was PRESENT and inventoried; it
 *  does not prove it ran. Its worth is the identification: the entry survives
 *  the file's deletion, and the declared publisher contradicts a binary
 *  disguised as a system component.
 *
 *  WHERE IT IS READ. In `Windows\AppCompat\Programs\Amcache.hve`, under
 *  `Root\InventoryApplicationFile`.
 *
 *  With `--binary`, the file is hashed and collected if it is still there,
 *  which settles what the inventory alone cannot: whether that path today holds
 *  the binary it names.
 */
#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include "tools.h"
#include "usb.h"
#include "quickdigest5.h"
#include "binaires.h"


/*! One executable inventoried by Amcache. */
struct AmcacheApplicationFile {
public:
	std::wstring name = L"";       //!< file name of the executable
	std::wstring publisher = L"";  //!< company it declares in its resources
	std::wstring longPath = L"";   //!< full path where it was inventoried
	BinaryFingerprint fingerprint;    //!< fingerprints of that file, if `--binary` was given
	std::wstring version = L"";    //!< version it declares
	std::wstring linkDate = L"";    //!< PE link date, suspect's local time
	std::wstring linkDateUtc = L"";	//!< the same instant in UTC
	bool IsOsComponent = false;    //!< whether Windows counts it as one of its own components

	/*! Builds the entry from its Amcache key.
	 *  @param hKey_amcache the file's key, already open. */
	AmcacheApplicationFile(ORHKEY hKey_amcache);

	/*! Converts the entry to JSON.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the entry.
	void clear();
};

/*! All the executables the Amcache hive inventories. */
struct AmcacheApplicationFiles {
public:
	std::vector<AmcacheApplicationFile> amcacheapplicationfiles; //!< the entries, in the order they were read


	/*! Opens Amcache.hve and walks the subkeys of `Root\InventoryApplicationFile`.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `amcache_application_files.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();
};