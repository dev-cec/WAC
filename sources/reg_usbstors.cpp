/*! \file
 *  \brief Reading of the Enum\\USBSTOR key (see reg_usbstors.h).
 */
#include "reg_usbstors.h"

Usbstor::Usbstor(ORHKEY hKey_usb, const std::wstring& device, const std::wstring& instance)
	: deviceId(device), instanceId(instance) {
	HRESULT hresult = 0;

	log(3, L"🔈getRegSzValue FriendlyName");
	hresult = getRegSzValue(hKey_usb, nullptr, L"FriendlyName", &FriendlyName);
	log(2, L"❇️USB Friendlyname : " + FriendlyName);
	log(3, L"🔈getRegMultiSzValue HardwareId");
	hresult = getRegMultiSzValue(hKey_usb, NULL, L"HardwareId", &HardwareId);
	// A REG_MULTI_SZ: read as a single string, only its first identifier came out.
	log(3, L"🔈getRegMultiSzValue CompatibleIds");
	hresult = getRegMultiSzValue(hKey_usb, NULL, L"CompatibleIds", &CompatibleIds);
	log(3, L"🔈getRegSzValue ClassGuid");
	hresult = getRegSzValue(hKey_usb, nullptr, L"ClassGuid", &ClassGuid);

	// "Disk&Ven_QEMU&Prod_QEMU_HARDDISK&Rev_2.5+": the type, then named fields.
	size_t start = 0;
	for (size_t end = 0; start <= deviceId.size(); start = end + 1) {
		end = deviceId.find(L'&', start);
		if (end == std::wstring::npos) end = deviceId.size();
		const std::wstring field = deviceId.substr(start, end - start);
		if (start == 0) type = field;
		else if (field.rfind(L"Ven_", 0) == 0)  vendor = field.substr(4);
		else if (field.rfind(L"Prod_", 0) == 0) product = field.substr(5);
		else if (field.rfind(L"Rev_", 0) == 0)  revision = field.substr(4);
	}
	// "<serial>&<n>". A second character "&" marks an identifier made up by Windows.
	const size_t last = instanceId.rfind(L'&');
	if (instanceId.size() > 1 && instanceId[1] != L'&' && last != std::wstring::npos && last > 0)
		serialNumber = instanceId.substr(0, last);
	else if (instanceId.size() > 1 && instanceId[1] != L'&' && last == std::wstring::npos)
		serialNumber = instanceId;

	/* The two dates are device properties of type DEVPROP_TYPE_FILETIME, in
	   UTC: 0066 = DEVPKEY_Device_LastArrivalDate, 0064 = DEVPKEY_Device_InstallDate.
	   They used to be read as LOCAL times, shifting both keys by the time-zone
	   offset; confronted on the test VM with Get-PnpDeviceProperty, which gives
	   the same instants in UTC. Read through the subkey path: no key handle to
	   open, and none left open. */
	const std::wstring properties = L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\";
	log(3, L"🔈getRegFiletimeValue 0066");
	hresult = getRegFiletimeValue(hKey_usb, (properties + L"0066").c_str(), L"", &lastInsertionUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegFiletimeValue 0066", hresult);
		lastInsertionUtc = FILETIME{ 0, 0 };
	}
	log(3, L"🔈getRegFiletimeValue 0064");
	hresult = getRegFiletimeValue(hKey_usb, (properties + L"0064").c_str(), L"", &firstInsertionUtc);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegFiletimeValue 0064", hresult);
		firstInsertionUtc = FILETIME{ 0, 0 };
	}
}

Json Usbstor::toJson() {
	log(3, L"🔈usbstor toJson");
	Json ids = Json::arr();                         // a real JSON array
	for (const std::wstring& h : HardwareId) ids.push(Json::str(h));
	Json o = Json::obj();
	o.add(L"HardwareId",       ids);
	o.add(L"FriendlyName",     Json::str(FriendlyName));
	Json compatible = Json::arr();
	for (const std::wstring& c : CompatibleIds) compatible.push(Json::str(c));
	o.add(L"CompatibleIds",    std::move(compatible));
	o.add(L"ClassGuid",        Json::str(ClassGuid));
	o.add(L"DeviceId",         Json::str(deviceId));
	o.add(L"InstanceId",       Json::str(instanceId));
	o.add(L"Type",             Json::str(type));
	o.add(L"Vendor",           Json::str(vendor));
	o.add(L"Product",          Json::str(product));
	o.add(L"Revision",         Json::str(revision));
	o.add(L"SerialNumber",     Json::str(serialNumber));
	o.add(L"LastInsertion",    Json::str(utcTimeToIso8601Local(lastInsertionUtc)));
	o.add(L"LastInsertionUtc", Json::str(timeToIso8601Utc(lastInsertionUtc)));
	o.add(L"FirstInsertion",   Json::str(utcTimeToIso8601Local(firstInsertionUtc)));
	o.add(L"FirstInsertionUtc",Json::str(timeToIso8601Utc(firstInsertionUtc)));
	return o;
}

void Usbstor::clear() {
	log(3, L"🔈usbstor clear");
}

HRESULT Usbstors::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Usbstor :");
	log(0, L"*******************************************************************************************************************");

	ORHKEY usbstor = NULL;
	log(3, L"🔈OROpenKey CurrentControlSet\\Enum\\USBSTOR");
	HRESULT hresult = OROpenKey(conf.CurrentControlSet, L"Enum\\USBSTOR", &usbstor);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenKey CurrentControlSet\\Enum\\USBSTOR", hresult);
		return hresult;
	}
	/* Two levels: the device ("Disk&Ven_...&Prod_...&Rev_..."), then its
	   instances (serial number). Their NAMES identify the device: they are
	   passed to Usbstor. Every key opened here is closed here. */
	// A key name holds up to MAX_KEY_NAME characters, plus the terminating zero.
	wchar_t device[MAX_KEY_NAME + 1] = L"", instance[MAX_KEY_NAME + 1] = L"";
	DWORD devices = 0;
	if (ORQueryInfoKey(usbstor, NULL, NULL, &devices, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		log(2, L"🔥ORQueryInfoKey Enum\\USBSTOR: progress shown without a total");
	for (DWORD i = 0; ; ++i) {
		DWORD length = MAX_KEY_NAME + 1;
		hresult = OREnumKey(usbstor, i, device, &length, NULL, NULL, NULL);
		if (hresult == ERROR_NO_MORE_ITEMS) break;
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OREnumKey Enum\\USBSTOR " + std::to_wstring(i), hresult);
			continue;
		}
		printProgressStep(L"Usbstor", (unsigned)i + 1, (unsigned)devices);
		ORHKEY deviceKey = NULL;
		log(3, L"🔈OROpenKey Enum\\USBSTOR\\" + std::wstring(device));
		if ((hresult = OROpenKey(usbstor, device, &deviceKey)) != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey Enum\\USBSTOR\\" + std::wstring(device), hresult);
			continue;
		}
		for (DWORD j = 0; ; ++j) {
			length = MAX_KEY_NAME + 1;
			hresult = OREnumKey(deviceKey, j, instance, &length, NULL, NULL, NULL);
			if (hresult == ERROR_NO_MORE_ITEMS) break;
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OREnumKey Enum\\USBSTOR\\" + std::wstring(device) + L" " + std::to_wstring(j), hresult);
				continue;
			}
			ORHKEY instanceKey = NULL;
			log(3, L"🔈OROpenKey Enum\\USBSTOR\\" + std::wstring(device) + L"\\" + instance);
			if ((hresult = OROpenKey(deviceKey, instance, &instanceKey)) != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey Enum\\USBSTOR\\" + std::wstring(device) + L"\\" + instance, hresult);
				continue;
			}
			log(1, L"➕USB ");
			usbs.push_back(Usbstor(instanceKey, device, instance));
			ORCloseKey(instanceKey);
		}
		ORCloseKey(deviceKey);
	}
	ORCloseKey(usbstor);
	return ERROR_SUCCESS;
}

HRESULT Usbstors::toJson() {
	log(3, L"🔈usbstors toJson");
	std::vector<Usbstor>::iterator usb;
	Json arr = Json::arr();
	for (Usbstor& e : usbs) arr.push(e.toJson());
	return writeJsonFile("Usbstor.json", arr);
}

void Usbstors::clear() {
	log(3, L"🔈usbstors clear");
	usbs.clear();   // destroys the elements -> really releases them
}
