#include "reg_bams.h"

Bam::Bam(LPBYTE data, std::wstring valueName, std::wstring psid) {
	name = valueName;
	log(2, L"❇️Bam Name : " + name);
	FILETIME temp = *reinterpret_cast<FILETIME*>(data);
	log(3, L"🔈timeToIso8601 datetime");
	executionTime = timeToIso8601Local(temp);
	log(3, L"🔈timeToIso8601 datetimeUtc");
	executionTimeUtc = localTimeToIso8601Utc(temp);
	sid = psid;
	log(3, L"🔈getNameFromSid sidName");
	sidName = getNameFromSid(sid);
}

Json Bam::toJson() const {
	log(3, L"🔈Bam toJson");
	Json o = Json::obj();
	o.add(L"SID",              Json::str(sid));
	o.add(L"SIDName",          Json::str(sidName));
	o.add(L"Name",             Json::str(name));      // raw path
	o.add(L"executionTime",    Json::str(executionTime));
	o.add(L"executionTimeUtc", Json::str(executionTimeUtc));
	return o;
}

void Bam::clear() {
	log(3, L"🔈Bam clear");
}

HRESULT Bams::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Bams : ");
	log(0, L"*******************************************************************************************************************");

	//variables
	HRESULT hresult = NULL;
	ORHKEY hKey = NULL;
	DWORD nSubkeys = 0;
	DWORD nValues = 0;
	DWORD dType = 0;
	DWORD bufferSize = 0;
	WCHAR valueName[MAX_VALUE_NAME]=L"";
	std::wstring bam_keys[2] = { L"bam",L"bam\\state" };
	for (std::wstring key : bam_keys) {
		for (std::tuple<std::wstring, std::wstring> profileEntry : conf.profiles) {
			std::wstring temp = L"Services\\" + key + L"\\UserSettings\\" + std::get<0>(profileEntry);
			CONST wchar_t* regkey = temp.c_str();
			log(3, L"🔈OROpenKey CurrentControlSet\\" + std::wstring(regkey));
			hresult = OROpenKey(conf.CurrentControlSet, regkey, &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2,  L"🔥OROpenKey CurrentControlSet\\" + std::wstring(regkey), hresult);
				continue;
			};

			log(3, L"🔈ORQueryInfoKey CurrentControlSet\\" + std::wstring(regkey));
			hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubkeys, NULL, NULL, &nValues, NULL, NULL, NULL, NULL);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥ORQueryInfoKey CurrentControlSet\\" + std::wstring(regkey), hresult);
				continue;
			};

			for (int i = 0; i < (int)nValues; i++) {
				printProgressStep(L"Bam", (unsigned)i + 1, nValues);
				bufferSize = MAX_KEY_NAME;
				DWORD cData = 0;
				LPBYTE data = NULL;

				do {
					if (data != NULL)
						delete[] data;
					data = new BYTE[cData];
					log(3, L"🔈OREnumValue CurrentControlSet\\" + std::wstring(regkey));
					hresult = OREnumValue(hKey, i, valueName, &bufferSize, &dType, (LPBYTE)data, &cData);
				} while (hresult == ERROR_MORE_DATA);
				if (dType != REG_BINARY) {
					log(2, L"🔥OREnumValue "+ std::wstring(valueName) + L" not a REG_BINARY value");
				}
				else {
					if (hresult != ERROR_SUCCESS) {
						log(2, L"🔥OREnumValue OREnumValue CurrentControlSet\\" + std::wstring(regkey), hresult);
					}
					else {
						log(1, L"➕Bam");
						Bam bam(data, std::wstring(valueName), std::wstring(std::get<0>(profileEntry)));
						//save
						bams.push_back(bam);
					}
				}
				delete[] data;
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Bams::toJson() {
	log(3, L"🔈Bams toJson");
	Json arr = Json::arr();
	for (const Bam& b : bams) arr.push(b.toJson());
	return writeJsonFile("bams.json", arr);
}

void Bams::clear() {
	log(3, L"🔈Bams clear");
	bams.clear();   // detruit les elements -> libere reellement
}
