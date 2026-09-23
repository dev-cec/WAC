/*! \file
 *  \brief Amcache, installed applications: what was installed, by whom, when.
 *
 *  WHAT IT SHOWS. Amcache keeps an inventory of the programs known to the
 *  machine. This half lists the APPLICATIONS — the installed products, with
 *  their publisher, their version and their installation date — where
 *  InventoryApplicationFile lists the individual binaries. It documents the
 *  software present on the machine, including what has since been uninstalled,
 *  since the entry survives the removal.
 *
 *  WHERE IT IS READ. Not in a hive of the system, but in
 *  `Windows\AppCompat\Programs\Amcache.hve`, a hive of its own, under
 *  `Root\InventoryApplication`. It is extracted like the others and read
 *  offline.
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



/*! One application inventoried by Amcache. */
struct AmcacheApplication {
public:
	std::wstring Name = L"";         //!< name of the product
	std::wstring Publisher = L"";    //!< company that publishes it
	std::wstring RootDirPath = L"";  //!< directory it was installed in
	std::wstring Version = L"";      //!< version of the product
	std::wstring InstallDate = L"";    //!< installation date, suspect's local time
	std::wstring InstallDateUtc = L"";	//!< the same instant in UTC

	/*! Builds the application from its Amcache key.
	 *  @param hKey_amcache the application's key, already open. */
	AmcacheApplication(ORHKEY hKey_amcache);

	/*! Converts the application to JSON.
	 *  @return its JSON object. */
	Json toJson();
	//! Releases the memory held by the application.
	void clear();
};

/*! All the applications the Amcache hive inventories. */
struct AmcacheApplications {
public:
	std::vector<AmcacheApplication> amcacheapplications; //!< the applications, in the order they were read
	

	/*! Opens Amcache.hve and walks the subkeys of `Root\InventoryApplication`.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `amcache_applications.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the applications.
	void clear();
};