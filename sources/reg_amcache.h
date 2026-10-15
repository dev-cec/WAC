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
 *
 *  WINDOWS 7: RecentFileCache.bcf. Before Amcache.hve (and next to it once
 *  KB2952664 brought it to Windows 7), Windows lists in
 *  `Windows\AppCompat\Programs\RecentFileCache.bcf` the executables run
 *  since the last pass of its ProgramDataUpdater task: their paths only, no
 *  date. A header of 20 bytes, its first 8 a signature (FE FF EE FF 11 22 00
 *  00), the others not known; then each path as a count of characters on 32
 *  bits, the characters in UTF-16 and a null. Measured on the Windows 7 VM.
 *  Each path goes to `amcache_application_files.json` with `Table`
 *  "RecentFileCache".
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
	std::vector<Json> unnamed;      //!< values of a Windows 8 table whose meaning is not confirmed: name, type, value
	std::wstring volume = L"";      //!< File (Windows 8): the volume's GUID, the key above the entry
	bool mftReferenceKnown = false; //!< File (Windows 8): the key's name gave the file's $MFT reference
	unsigned long long mftEntry = 0, mftSequence = 0; //!< that reference
	BinaryFingerprint fingerprint;  //!< fingerprints of the file an InventoryApplicationFile entry names, with `--binary`

	/*! Reads one entry.
	 *  @param key its key, already open
	 *  @param table name of its table
	 *  @param name name of its key
	 *  @param volume File of Windows 8: the volume's GUID */
	AmcacheEntry(ORHKEY key, const std::wstring& table, const std::wstring& name, const std::wstring& volume = L"");

	/*! Converts the entry to JSON.
	 *  @param withTable whether to name the table (entries of amcache_inventory.json)
	 *  @return its JSON object */
	Json toJson(bool withTable) const;
};

/*! Decodes RecentFileCache.bcf (see the file's header). Every count is
 *  bounded by the file's size: a cut or forged entry ends the reading, the
 *  paths before it kept.
 *  @param bytes the file
 *  @param paths receives the paths, in the file's order
 *  @return false if the signature is not there */
bool decodeRecentFileCache(const std::vector<uint8_t>& bytes, std::vector<std::wstring>& paths);

/*! Every table of the Amcache hive, and the paths of RecentFileCache.bcf. */
struct Amcache {
	std::vector<AmcacheEntry> entries; //!< every entry, table after table
	std::vector<std::wstring> recentFiles; //!< the paths RecentFileCache.bcf lists
	std::wstring recentFileCache;      //!< that file on the examined machine, when read

	/*! Reads RecentFileCache.bcf, then opens Amcache.hve and reads every
	 *  table under `Root`.
	 *  @return S_OK, or why the hive or its root could not be read when
	 *          RecentFileCache.bcf was not read either */
	HRESULT getData();

	/*! Writes amcache_applications.json, amcache_application_files.json and
	 *  amcache_inventory.json into the output directory.
	 *  @return the first failed write, or S_OK */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();

private:
	/*! Reads RecentFileCache.bcf of the copy, if there is one.
	 *  @return true if it was read */
	bool readRecentFileCache();

	/*! Opens Amcache.hve and reads every table under `Root`.
	 *  @return S_OK, or why the hive or its root could not be read */
	HRESULT readHive();

	/*! Reads the files of one volume of the Windows 8 File table.
	 *  @param volumeKey the volume's key, open
	 *  @param volume its name, the volume's GUID */
	void readVolumeFiles(ORHKEY volumeKey, const std::wstring& volume);
};
