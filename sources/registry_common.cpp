/*! \file
 *  \brief Helpers shared by the registry artefacts (see registry_common.h).
 */
#include "registry_common.h"

FILETIME lastWrite(ORHKEY key) {
	FILETIME f = { 0, 0 };
	ORQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &f);
	return f;
}

std::vector<Subkey> subkeysOf(ORHKEY key) {
	std::vector<Subkey> found;
	DWORD count = 0;
	const DWORD queried = ORQueryInfoKey(key, NULL, NULL, &count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (queried != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey: subkeys not counted", queried);
		return found;
	}
	std::vector<wchar_t> name(256);
	for (DWORD i = 0; i < count; ++i) {
		Subkey s;
		DWORD length = (DWORD)name.size();
		DWORD read = OREnumKey(key, i, name.data(), &length, NULL, NULL, &s.lastWriteUtc);
		if (read == ERROR_MORE_DATA) {             // length now holds what the name needs
			name.resize((size_t)length + 1);
			length = (DWORD)name.size();
			read = OREnumKey(key, i, name.data(), &length, NULL, NULL, &s.lastWriteUtc);
		}
		if (read != ERROR_SUCCESS) {
			log(2, L"🔥OREnumKey: subkey " + std::to_wstring(i) + L" of " + std::to_wstring(count) + L" unreadable, skipped", read);
			continue;
		}
		s.name.assign(name.data(), length);
		found.push_back(std::move(s));
	}
	return found;
}

std::vector<std::wstring> subkeys(ORHKEY root, const std::wstring& path) {
	std::vector<std::wstring> names;
	ORHKEY key = NULL;
	if (OROpenKey(root, path.c_str(), &key) != ERROR_SUCCESS) return names;
	for (Subkey& s : subkeysOf(key)) names.push_back(std::move(s.name));
	ORCloseKey(key);
	return names;
}

std::wstring valueText(DWORD type, const std::vector<BYTE>& data) {
	if (type == REG_SZ || type == REG_EXPAND_SZ) return readWideZ(data.data(), data.size(), 0);
	if (type == REG_DWORD && data.size() >= sizeof(DWORD)) {
		DWORD v = 0;
		memcpy(&v, data.data(), sizeof(DWORD));
		return std::to_wstring(v);
	}
	return L"";
}

unsigned urlValueNumber(const std::wstring& name) {
	if (name.size() < 4 || name.size() > 12 || _wcsnicmp(name.c_str(), L"url", 3) != 0
	    || name.find_first_not_of(L"0123456789", 3) != std::wstring::npos) return 0;
	return (unsigned)std::stoul(name.substr(3));   // at most 9 digits: no overflow
}

Json pairs(const NameValues& values) {
	Json list = Json::arr();
	for (const auto& [name, value] : values) {
		Json p = Json::obj();
		p.add(L"Name", Json::str(name));
		p.add(L"Value", Json::str(value));
		list.push(std::move(p));
	}
	return list;
}

void readAllValues(ORHKEY key, std::vector<std::pair<std::wstring, Json>>& out) {
	for (DWORD i = 0;; ++i) {
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
		out.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
	}
}
