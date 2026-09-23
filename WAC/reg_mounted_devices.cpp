/*! \file
 *  \brief Reading of the MountedDevices key (see reg_mounted_devices.h).
 */
#include "reg_mounted_devices.h"

MountedDevice::MountedDevice(ORHKEY hKey, PCWSTR szSubValue) {
	LPBYTE buffer = NULL;
	DWORD size = 0;
	log(3, L"🔈getRegBinaryValue device");
	HRESULT hr = getRegBinaryValue(hKey, NULL, szSubValue, &buffer, &size);
	if (hr == ERROR_SUCCESS) {
		if (std::wstring((wchar_t*)buffer,(wchar_t*)buffer+4).compare(L"_??_")==0) {//WSTRING
			device = std::wstring((wchar_t*)buffer, (wchar_t*)buffer + size / sizeof(wchar_t)).data();
			log(2, L"❇️MountedDevice device : " + device);
		}
		else { //STRING
			if (std::string(buffer, buffer + 8).compare("DMIO:ID:") == 0) {
				log(3, L"🔈guid_to_wstring device");
				device = (L"\\VOLUME" + guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8))).data();
			}else{
				device = string_to_wstring(std::string((char*)buffer, (char*)buffer + size)).data();
			}
		}
	}
	else {
		log(2, L"🔥getRegSzValue", hr);
	}
	delete[] buffer;

	drive = std::wstring(szSubValue).data();
	log(1, L"➕Drive " + drive);
}

Json MountedDevice::toJson() const {
	log(3, L"🔈MountedDevice toJson");
	Json o = Json::obj();
	o.add(L"Drive",  Json::str(drive));    // raw values: escaped here
	o.add(L"Device", Json::str(device));
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
