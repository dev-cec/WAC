/*! \file
 *  \brief Reading of the Enum\\USBSTOR key (see reg_usbstors.h).
 */
#include "reg_usbstors.h"

Usbstor::Usbstor(ORHKEY hKey_usb) {
	HRESULT hresult = 0;
	ORHKEY hkey_time = NULL;

	log(3, L"🔈getRegSzValue FriendlyName");
	hresult = getRegSzValue(hKey_usb, nullptr, L"FriendlyName", &FriendlyName);
	log(2, L"❇️USB Friendlyname : " + FriendlyName);
	log(3, L"🔈getRegMultiSzValue HardwareId");
	hresult = getRegMultiSzValue(hKey_usb, NULL, L"HardwareId", &HardwareId);
	log(3, L"🔈getRegSzValue CompatibleIds");
	hresult = getRegSzValue(hKey_usb, nullptr, L"CompatibleIds", &CompatibleIds);
	log(3, L"🔈replaceAll CompatibleIds");
	log(3, L"🔈getRegSzValue ClassGuid");
	hresult = getRegSzValue(hKey_usb, nullptr, L"ClassGuid", &ClassGuid);
	log(3, L"🔈getRegSzValue SerialNumber");
	hresult = getRegSzValue(hKey_usb, nullptr, L"SerialNumber", &SerialNumber);
	FILETIME tempFiletime = { 0 };
	log(3, L"🔈OROpenKey hkey_time 0066");
	hresult = OROpenKey(hKey_usb, L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066", &hkey_time);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenKey hkey_time 0066", hresult);
	}
	else {
		log(3, L"🔈getRegFiletimeValue tempFiletime 0066");
		hresult = getRegFiletimeValue(hkey_time, nullptr, L"", &tempFiletime);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegFiletimeValue tempFiletime 0066", hresult);
		}
		else {
			log(3, L"🔈timeToIso8601 tempFiletime");
			LastInsertion = timeToIso8601Local(tempFiletime);
			log(3, L"🔈timeToIso8601 LastInsertionUtc");
			LastInsertionUtc = localTimeToIso8601Utc(tempFiletime);
		}
	}
	log(3, L"🔈OROpenKey hkey_time 0064");
	hresult = OROpenKey(hKey_usb, L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064", &hkey_time);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenKey hkey_time 0064", hresult);
	}
	else {
		tempFiletime = { 0 };
		log(3, L"🔈getRegFiletimeValue tempFiletime 0064");
		hresult = getRegFiletimeValue(hkey_time, nullptr, L"", &tempFiletime);

		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥getRegFiletimeValue tempFiletime 0064", hresult);
		}
		else {
			log(3, L"🔈timeToIso8601 FirstInsertion");
			FirstInsertion = timeToIso8601Local(tempFiletime);
			log(3, L"🔈timeToIso8601 FirstInsertionUtc");
			FirstInsertionUtc = localTimeToIso8601Utc(tempFiletime);
		}
	}
}

Json Usbstor::toJson() {
	log(3, L"🔈usbstor toJson");
	Json ids = Json::arr();                         // a real JSON array
	for (const std::wstring& h : HardwareId) ids.push(Json::str(h));
	Json o = Json::obj();
	o.add(L"HardwareId",       ids);
	o.add(L"FriendlyName",     Json::str(FriendlyName));
	o.add(L"CompatibleIds",    Json::str(CompatibleIds));
	o.add(L"ClassGuid",        Json::str(ClassGuid));
	o.add(L"SerialNumber",     Json::str(SerialNumber));
	o.add(L"LastInsertion",    Json::str(LastInsertion));
	o.add(L"LastInsertionUtc", Json::str(LastInsertionUtc));
	o.add(L"FirstInsertion",   Json::str(FirstInsertion));
	o.add(L"FirstInsertionUtc",Json::str(FirstInsertionUtc));
	return o;
}

void Usbstor::clear() {
	log(3, L"🔈usbstor clear");
}

HRESULT Usbstors::getData() {

	//variables
	HRESULT hresult = 0;
	ORHKEY hkey = NULL, hKey_manufacturer = NULL, hKey_usb = NULL;
	DWORD nSubkeys_usbstor = 0;
	DWORD nSubkeys_manufacturer = 0;
	DWORD nValues = 0;
	wchar_t szSubKey_usbstor[MAX_VALUE_NAME] = L"";
	wchar_t szSubKey_manufacturer[MAX_VALUE_NAME] = L"";
	DWORD bufferSize = MAX_VALUE_NAME;

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Usbstor :");
	log(0, L"*******************************************************************************************************************");

	log(3, L"🔈OROpenKey CurrentControlSet\\Enum\\USBSTOR");
	hresult = OROpenKey(conf.CurrentControlSet, L"Enum\\USBSTOR\\", &hkey);
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
		log(2, L"🔥OROpenKey CurrentControlSet\\Enum\\USBSTOR", hresult);
		return hresult;
	}
	log(3, L"🔈ORQueryInfoKey CurrentControlSet\\Enum\\USBSTOR");
	hresult = ORQueryInfoKey(hkey, NULL, NULL, &nSubkeys_usbstor, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
		log(2, L"🔥ORQueryInfoKey CurrentControlSet\\Enum\\USBSTOR", hresult);
		return hresult;
	};

	for (int i = 0; i < (int)nSubkeys_usbstor; i++) {
		printProgressStep(L"Usbstor", (unsigned)i + 1, nSubkeys_usbstor);
		bufferSize = MAX_KEY_NAME;
		log(3, L"🔈OREnumKey CurrentControlSet\\Enum\\USBSTOR Value " + std::to_wstring(i));
		hresult = OREnumKey(hkey, i, szSubKey_usbstor, &bufferSize, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥OREnumKey CurrentControlSet\\Enum\\USBSTOR Value " + std::to_wstring(i), hresult);
			continue;
		}
		log(3, L"🔈OROpenKey CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor));
		hresult = OROpenKey(hkey, szSubKey_usbstor, &hKey_manufacturer); // open the manufacturer's key
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey hKey_fabricant", hresult);
			continue;
		}
		log(3, L"🔈ORQueryInfoKey CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor));
		hresult = ORQueryInfoKey(hKey_manufacturer, NULL, NULL, &nSubkeys_manufacturer, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
		if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
			log(2, L"🔥ORQueryInfoKey CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor), hresult);
			continue;
		}

		for (int j = 0; j < (int)nSubkeys_manufacturer; j++) {
			bufferSize = MAX_KEY_NAME;
			log(3, L"🔈OREnumKey CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L" Value " + std::to_wstring(j));
			hresult = OREnumKey(hKey_manufacturer, j, szSubKey_manufacturer, &bufferSize, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) {
				log(2, L"🔥OREnumKey CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L" Value " + std::to_wstring(j), hresult);
				continue;
			}

			log(3, L"🔈OROpenKey CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L" \\" + szSubKey_manufacturer);
			hresult = OROpenKey(hKey_manufacturer, szSubKey_manufacturer, &hKey_usb);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey CurrentControlSet\\Enum\\USBSTOR\\" + std::wstring(szSubKey_usbstor) + L" \\" + szSubKey_manufacturer, hresult);
				continue;
			}
			log(1, L"➕USB ");
			
			//save
			usbs.push_back(Usbstor(hKey_usb));
		}
	}
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
