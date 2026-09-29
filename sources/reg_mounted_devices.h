/*! \file
 *  \brief MountedDevices: which device was mounted behind which drive letter.
 *
 *  WHAT IT SHOWS. Windows records, for each drive letter and each mount point,
 *  the identifier of the volume mounted there. That is what ties a letter found
 *  in a path — in a shortcut, a Prefetch trace, a shellbag — to a physical
 *  device: without it, "E:\report.docx" names no medium. For a removable
 *  device the identifier carries the USB serial number, which links the letter
 *  to the very stick, and hence to the USBSTOR entries.
 *
 *  WHERE IT IS READ. In SYSTEM, the `MountedDevices` key. Its values are named
 *  `\DosDevices\X:` for letters and `\??\Volume{GUID}` for volumes. The data
 *  takes one of three forms, told apart by their content:
 *    - 12 bytes: an MBR partition, as the disk signature (4 bytes) and the
 *      partition's offset on the disk in bytes (8 bytes);
 *    - "DMIO:ID:" followed by a GUID (24 bytes): a GPT partition, by its
 *      partition GUID;
 *    - a device path in UTF-16, "\??\..." ("_??_..." on older systems): a
 *      removable device or a CD-ROM, with its USB serial number if any.
 *
 *  WHAT WAS WRONG. Only the old "_??_" prefix was recognised: every current
 *  device path was decoded as ANSI text and stopped at its first zero byte,
 *  giving "\" — six mounts out of seven on the test machine. An MBR value
 *  would have been decoded as text too. Each form now has its own fields, and
 *  an unknown one is kept in hexadecimal rather than guessed.
 *
 *  The key holds no per-value timestamp: it says which device HAD the letter
 *  when the collection ran, not since when.
 */
#pragma once

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include "offline_registry.h"
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <ctype.h>
#include "tools.h"
#include "json.h"
#include "usb.h"



/*! One mount: a drive letter or volume, and the device behind it. */
struct MountedDevice {
public:
	std::wstring drive = L"";          //!< the mount: drive letter, or volume GUID
	std::wstring type = L"";           //!< "GPT partition", "MBR partition", "Device path" or "Unknown"
	std::wstring partitionGuid = L"";  //!< GPT: partition GUID, "{...}"
	std::wstring diskSignature = L"";  //!< MBR: disk signature, "0x1A2B3C4D"
	unsigned long long partitionOffset = 0; //!< MBR: offset of the partition on the disk, in bytes
	bool hasPartitionOffset = false;   //!< true for an MBR value (an offset of 0 is not emitted otherwise)
	std::wstring device = L"";         //!< device path (removable device, CD-ROM)
	std::wstring data = L"";           //!< unknown form: the bytes in hexadecimal

	/*! Builds the mount from a registry value.
	 *  @param hKey the MountedDevices key, already open.
	 *  @param szSubValue name of the value, that is the mount itself. */
	MountedDevice(ORHKEY hKey, PCWSTR szSubValue);

	/*! Converts the mount to JSON.
	 *  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the mount.
	void clear();
};

/*! All the mounts recorded by the examined machine. */
struct MountedDevices {
public:
	std::vector<MountedDevice> mounteddevices; //!< the mounts, in the order they were read

	/*! Reads every value of the MountedDevices key.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `mounted_device.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the mounts.
	void clear();
};
