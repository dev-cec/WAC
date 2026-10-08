/*! \file
 *  \brief Amcache: the inventory Windows keeps of the applications, binaries,
 *  drivers, devices and shortcuts the machine has known.
 *
 *  WHAT IT SHOWS. `Windows\AppCompat\Programs\Amcache.hve` is a hive of its own,
 *  whose `Root\Inventory*` keys each hold one table: InventoryApplication (the
 *  installed products), InventoryApplicationFile (the executables, with their
 *  SHA-1, size and PE link date), InventoryDriverBinary, InventoryDevicePnp,
 *  InventoryApplicationShortcut… An entry proves the object was PRESENT and
 *  inventoried, not that it ran; it survives the object's deletion, and the
 *  SHA-1 identifies a binary long gone.
 *
 *  WHY EVERY VALUE. Only four to six values of two tables were read: no SHA-1,
 *  no size, no driver, no device (B-015, against AmcacheParser, which gives
 *  them). Each table is now read whole — every value of every entry, typed as
 *  the hive stores it, with the key's last write time — so that a value a
 *  later Windows adds is not lost either. Values are converted only where the
 *  conversion was checked:
 *    - `FileId` of an executable and `DriverId` of a driver ("0000" + 40
 *      hexadecimal digits) give `AmcacheSha1`; for a file larger than 30 MiB, Amcache
 *      hashed only its first 31,457,280 bytes, which `AmcacheSha1CoversBytes` says;
 *    - `LinkDate`, InventoryApplication's `InstallDate` and a driver's
 *      `DriverLastWriteTime`, text dates, are UTC (measured against the PE
 *      header, the folder's creation and the driver file's own date);
 *    - `DriverTimeStamp`, the driver's PE TimeDateStamp, is a Unix time;
 *    - `LowerCaseLongPath` is published as `LongPath`, its name since the start.
 *  The other text dates are given as written: a device's `InstallDate` holds
 *  only the day, a driver package's `Date` too; their time zone is not known.
 *
 *  OUTPUT. InventoryApplication in `amcache_applications.json`,
 *  InventoryApplicationFile in `amcache_application_files.json` (their names
 *  since the start), every other table in `amcache_inventory.json`, each entry
 *  with its `Table`.
 */
#pragma once
#include <windows.h>
#include <string>
#include <utility>
#include <vector>
#include "offline_registry.h"
#include "tools.h"
#include "binaires.h"

/*! One entry of an Amcache table: one key, every value of it. */
struct AmcacheEntry {
	std::wstring table = L"";       //!< the table: name of the Root\\Inventory* key
	std::wstring keyName = L"";     //!< name of the entry's key (identifier of the object)
	FILETIME keyLastWriteUtc = { 0, 0 }; //!< last write of that key: when Windows last updated the entry
	std::vector<std::pair<std::wstring, Json>> values; //!< every value, by name, converted (see the file's header)
	BinaryFingerprint fingerprint;  //!< fingerprints of the file an InventoryApplicationFile entry names, with `--binary`

	/*! Reads one entry.
	 *  @param key its key, already open
	 *  @param table name of its table
	 *  @param name name of its key */
	AmcacheEntry(ORHKEY key, const std::wstring& table, const std::wstring& name);

	/*! Converts the entry to JSON.
	 *  @param withTable whether to name the table (entries of amcache_inventory.json)
	 *  @return its JSON object */
	Json toJson(bool withTable) const;
};

/*! Every table of the Amcache hive. */
struct Amcache {
	std::vector<AmcacheEntry> entries; //!< every entry, table after table

	/*! Opens Amcache.hve and reads every table under `Root`.
	 *  @return S_OK, or why the hive or its root could not be read */
	HRESULT getData();

	/*! Writes amcache_applications.json, amcache_application_files.json and
	 *  amcache_inventory.json into the output directory.
	 *  @return the first failed write, or S_OK */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();
};
