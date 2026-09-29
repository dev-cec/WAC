/*! \file
 *  \brief Reading of the MountedDevices key (see reg_mounted_devices.h).
 */
#include "reg_mounted_devices.h"
#include <cstring>

MountedDevice::MountedDevice(ORHKEY hKey, PCWSTR szSubValue) {
	drive = szSubValue;
	log(1, L"➕Drive " + drive);
	DWORD size = 0;
	log(3, L"🔈ORGetValue size");
	HRESULT hr = ORGetValue(hKey, nullptr, szSubValue, nullptr, nullptr, &size);
	std::vector<BYTE> bytes(size);
	if (hr == ERROR_SUCCESS && size) {
		log(3, L"🔈ORGetValue data");
		hr = ORGetValue(hKey, nullptr, szSubValue, nullptr, bytes.data(), &size);
		bytes.resize(size);
	}
	if (hr != ERROR_SUCCESS) {
		log(2, L"🔥ORGetValue MountedDevices " + drive, hr);
		return;
	}
	// The form is told by the content; every read below is bounded by bytes.size().
	static const char GPT_PREFIX[] = "DMIO:ID:";
	if (bytes.size() == 24 && std::memcmp(bytes.data(), GPT_PREFIX, 8) == 0) {
		GUID guid;
		std::memcpy(&guid, bytes.data() + 8, sizeof(guid));
		type = L"GPT partition";
		partitionGuid = guid_to_wstring(guid);
	}
	else if (bytes.size() == 12) {
		uint32_t signature = 0;
		uint64_t offset = 0;
		std::memcpy(&signature, bytes.data(), 4);
		std::memcpy(&offset, bytes.data() + 4, 8);
		type = L"MBR partition";
		diskSignature = L"0x" + to_hex(signature, 8);
		partitionOffset = offset;
		hasPartitionOffset = true;
	}
	else if (bytes.size() >= 8 && bytes.size() % 2 == 0
	         && (std::memcmp(bytes.data(), L"\\??\\", 8) == 0 || std::memcmp(bytes.data(), L"_??_", 8) == 0)) {
		// UTF-16, read by copy (the buffer carries no alignment guarantee), without trailing zeros.
		std::wstring path(bytes.size() / 2, L'\0');
		std::memcpy(&path[0], bytes.data(), bytes.size());
		while (!path.empty() && path.back() == L'\0') path.pop_back();
		type = L"Device path";
		device = path;
	}
	else {
		type = L"Unknown";
		data = dump_wstring(bytes.data(), 0, (int)bytes.size());
		log(2, L"🔥MountedDevices " + drive + L": unknown form, kept in hexadecimal");
	}
}

Json MountedDevice::toJson() const {
	log(3, L"🔈MountedDevice toJson");
	Json o = Json::obj();
	o.add(L"Drive",         Json::str(drive));
	o.add(L"Type",          Json::str(type));
	o.add(L"PartitionGuid", Json::str(partitionGuid));
	o.add(L"DiskSignature", Json::str(diskSignature));
	if (hasPartitionOffset) o.add(L"PartitionOffset", Json::num(partitionOffset));
	o.add(L"Device",        Json::str(device));
	o.add(L"Data",          Json::str(data));
	return o;
}

void MountedDevice::clear() {
	log(3, L"🔈MountedDevice clear");
}

HRESULT MountedDevices::getData() {

	//variables
	HRESULT hresult;
	ORHKEY hKey;
	DWORD nSubkeys;
	DWORD nValues;
	FILETIME lastWriteTimeUtc = { 0 };

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Mounted devices :");
	log(0, L"*******************************************************************************************************************");

	log(3, L"🔈OROpenKey System\\MountedDevices");
	hresult = OROpenKey(conf.System, L"MountedDevices", &hKey);
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
		log(2, L"🔥OROpenKey System\\MountedDevices", hresult);
		return hresult;
	};

	log(3, L"🔈ORQueryInfoKey System\\MountedDevices");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, &lastWriteTimeUtc);
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
		log(2, L"🔥ORQueryInfoKey System\\MountedDevices", hresult);
		return hresult;
	};

	for (int i = 0; i < (int)nValues; i++) {
		printProgressStep(L"MountedDevice", (unsigned)i + 1, nValues);
		DWORD bufferSize = MAX_VALUE_NAME;
		DWORD cData = MAX_DATA;
		WCHAR  szSubValue[MAX_VALUE_NAME];
		log(3, L"🔈OREnumValue System\\MountedDevices Value " + std::to_wstring(i));
		hresult = OREnumValue(hKey, i, szSubValue, &bufferSize, NULL, NULL, &cData);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OREnumValue System\\MountedDevices Value " + std::to_wstring(i), hresult);
			continue;
		}
		//save
		log(1, L"➕MountedDevice");
		mounteddevices.push_back(MountedDevice(hKey, szSubValue));

	}
	return ERROR_SUCCESS;
}

HRESULT MountedDevices::toJson() {
	log(3, L"🔈MountedDevices toJson");
	Json arr = Json::arr();
	for (const MountedDevice& d : mounteddevices) arr.push(d.toJson());
	return writeJsonFile("mounted_device.json", arr);
}

void MountedDevices::clear() {
	log(3, L"🔈MountedDevices clear");
	mounteddevices.clear();   // destroys the elements -> really releases them
}
