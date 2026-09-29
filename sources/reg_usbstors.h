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
 *  WHO THE DEVICE IS. The key names carry the identification, not values:
 *  `Enum\USBSTOR\<device>\<instance>`, where <device> reads
 *  "Disk&Ven_<vendor>&Prod_<product>&Rev_<revision>" and <instance> is the
 *  serial number followed by "&<n>". WAC used to look for a "SerialNumber"
 *  VALUE, which does not exist there: no collected device carried its serial
 *  number, vendor or product — the very data that ties a stick to a person.
 *
 *  The serial number is the device's, as it declares it: a device may declare
 *  one it shares with a whole production batch, and some declare none — Windows
 *  then makes up an instance identifier whose SECOND character is "&", which is
 *  not a serial number and is not published as one.
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
#include "tools.h"
#include "usb.h"



/*! One USB mass-storage device known to the machine. */
struct Usbstor {
public:
	std::vector<std::wstring> HardwareId; //!< hardware identifiers the device declares
	std::wstring FriendlyName = L"";      //!< name of the device, as it declares it
	std::vector<std::wstring> CompatibleIds; //!< identifiers of the compatible device classes
	std::wstring ClassGuid = L"";         //!< GUID of the device class
	std::wstring deviceId = L"";          //!< the device key: "Disk&Ven_...&Prod_...&Rev_..."
	std::wstring instanceId = L"";        //!< the instance key: the serial number and "&<n>"
	std::wstring type = L"";              //!< device type, from deviceId ("Disk", "CdRom")
	std::wstring vendor = L"";            //!< vendor, from deviceId
	std::wstring product = L"";           //!< product, from deviceId
	std::wstring revision = L"";          //!< revision, from deviceId
	std::wstring serialNumber = L"";      //!< serial number, from instanceId (empty if Windows made one up)
	FILETIME lastInsertionUtc = { 0, 0 };   //!< last connection (DEVPKEY_Device_LastArrivalDate), UTC
	FILETIME firstInsertionUtc = { 0, 0 };  //!< first installation (DEVPKEY_Device_InstallDate), UTC

	/*! Builds the device from its registry key.
	 *  @param hKey_usb the instance key under `Enum\USBSTOR\<device>`, already open.
	 *  @param device name of the device key ("Disk&Ven_...&Prod_...&Rev_...").
	 *  @param instance name of the instance key (serial number and "&<n>"). */
	Usbstor(ORHKEY hKey_usb, const std::wstring& device, const std::wstring& instance);

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
