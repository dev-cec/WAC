/*! \file
 *  \brief Reading of the Background Activity Monitor keys (see reg_bams.h).
 */
#include "reg_bams.h"
#include <cstring>

Bam::Bam(const std::vector<BYTE>& data, std::wstring valueName, std::wstring psid) {
	name = valueName;
	log(2, L"❇️Bam Name : " + name);
	/* The execution time is a FILETIME in UTC. It used to be read as a LOCAL
	   time, shifting both keys by the time-zone offset — measured on the test
	   VM: taskkill.exe, run by the harness at 19:28:21 UTC, was published at
	   17:28:21 UTC. Read by copy: the buffer carries no alignment guarantee. */
	if (data.size() >= sizeof(executionTimeUtc))
		std::memcpy(&executionTimeUtc, data.data(), sizeof(executionTimeUtc));
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
	o.add(L"executionTime",    Json::str(utcTimeToIso8601Local(executionTimeUtc)));
	o.add(L"executionTimeUtc", Json::str(timeToIso8601Utc(executionTimeUtc)));
	return o;
}

void Bam::clear() {
	log(3, L"🔈Bam clear");
}

HRESULT Bams::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Bams : ");
	log(0, L"*******************************************************************************************************************");

	const std::wstring bamKeys[2] = { L"bam", L"bam\\state" };
	for (const std::wstring& key : bamKeys) {
		for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
			const std::wstring subkey = L"Services\\" + key + L"\\UserSettings\\" + std::get<0>(profileEntry);
			ORHKEY hKey = NULL;
			log(3, L"🔈OROpenKey CurrentControlSet\\" + subkey);
			HRESULT hresult = OROpenKey(conf.CurrentControlSet, subkey.c_str(), &hKey);
			if (hresult != ERROR_SUCCESS) {
				log(2, L"🔥OROpenKey CurrentControlSet\\" + subkey, hresult);
				continue;
			}
			std::wstring valueName;
			DWORD type = 0;
			std::vector<BYTE> data;
			for (DWORD i = 0; ; ++i) {
				log(3, L"🔈enumRegistryValue CurrentControlSet\\" + subkey + L" " + std::to_wstring(i));
				hresult = enumRegistryValue(hKey, i, valueName, type, data);
				if (hresult == ERROR_NO_MORE_ITEMS) break;
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥enumRegistryValue CurrentControlSet\\" + subkey, hresult);
					break;
				}
				// The key also holds "Version" and "SequenceNumber" (REG_DWORD): not entries.
				if (type != REG_BINARY || data.size() < sizeof(FILETIME)) {
					log(3, L"🔈Bam " + valueName + L": not an execution entry");
					continue;
				}
				log(1, L"➕Bam");
				bams.push_back(Bam(data, valueName, std::get<0>(profileEntry)));
			}
			ORCloseKey(hKey);
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
	bams.clear();   // destroys the elements -> really releases them
}
