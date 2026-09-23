/*! \file
 *  \brief USBSTOR: the USB mass-storage devices connected to the machine.
 *
 *  WHAT IT SHOWS. Windows keeps an entry per USB storage device it has ever
 *  seen, with the device's own identifiers and its serial number. That answers
 *  the recurring question of an exfiltration case — which stick was plugged in,
 *  and when — and, through MountedDevices, which drive letter it held, hence
 *  which paths in the other artefacts refer to it.
 *
 *  WHERE IT IS READ. In SYSTEM, `CurrentControlSet\Enum\USBSTOR`. The
 *  insertion dates come from the device properties, under
 *  `Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: value `0064` is the
 *  first installation, `0066` the last connection.
 *
 *  The serial number is the device's, as it declares it: a device may declare
 *  one it shares with a whole production batch, and some declare none.
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
#include "tools.h"
#include "usb.h"



/*! One USB mass-storage device known to the machine. */
struct Usbstor {
public:
	std::vector<std::wstring> HardwareId; //!< hardware identifiers the device declares
	std::wstring FriendlyName = L"";      //!< name of the device, as it declares it
	std::wstring CompatibleIds = L"";     //!< identifiers of the compatible device classes
	std::wstring ClassGuid = L"";         //!< GUID of the device class
	std::wstring SerialNumber = L"";      //!< serial number the device declares
	std::wstring LastInsertion = L"";     //!< last connection, in the suspect's local time
	std::wstring LastInsertionUtc = L"";  //!< the same instant in UTC
	std::wstring FirstInsertion = L"";    //!< first installation, in the suspect's local time
	std::wstring FirstInsertionUtc = L"";	//!< the same instant in UTC

	/*! Builds the device from its registry key.
	 *  @param hKey_usb the device's key under `Enum\USBSTOR`, already open. */
	Usbstor(ORHKEY hKey_usb);

	/*! Converts the device to JSON.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the device.
	void clear();
};

/*! All the USB mass-storage devices the machine has recorded. */
struct Usbstors {
public:
	std::vector<Usbstor> usbs;  //!< the devices, in the order they were read


	/*! Walks the subkeys of `Enum\USBSTOR` and reads each device.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `Usbstor.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the devices.
	void clear();
};
