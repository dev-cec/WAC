/*! \file
 *  \brief What remote and archive tools keep in each user's hive (see application_registry.h).
 */
#include "application_registry.h"
#include "application_traces.h"
#include "registry_common.h"

namespace {

const unsigned KEY_DEPTH_MAX = 8;   //!< these tools' keys are shallow: guard against a forged hive

/*! Reads a key and its subkeys into the list.
 *  @param key the open key
 *  @param path its path in the hive
 *  @param lastWrite its last write
 *  @param product,sid who it belongs to
 *  @param depth levels left
 *  @param out receives one object per key holding values */
void walkKey(ORHKEY key, const std::wstring& path, const FILETIME& lastWrite, const wchar_t* product, const std::wstring& sid, unsigned depth, Json& out) {
	Json values = Json::arr();
	bool hasValue = false, hasPassword = false;
	for (DWORD i = 0;; ++i) {
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
		hasValue = true;
		if (isPasswordValue(name)) { hasPassword = true; continue; }
		Json v = Json::obj();
		v.add(L"Name", Json::str(name));
		v.add(L"Value", Json::str(valueText(type, data)));
		values.push(std::move(v));
	}
	if (hasValue) {
		Json o = Json::obj();
		addUser(o, sid);   // its SID and the name the shared table gives it, as every per-user artefact
		o.add(L"Product", Json::str(product));
		o.add(L"Key", Json::str(path));
		addDate(o, L"KeyLastWrite", lastWrite);
		if (hasPassword) o.add(L"HasPassword", Json::boolean(true));
		o.add(L"Values", std::move(values));
		out.push(std::move(o));
	}
	if (depth == 0) return;
	for (const Subkey& sub : subkeysOf(key)) {
		ORHKEY child = NULL;
		if (OROpenKey(key, sub.name.c_str(), &child) != ERROR_SUCCESS) continue;
		walkKey(child, path + L"\\" + sub.name, sub.lastWriteUtc, product, sid, depth - 1, out);
		ORCloseKey(child);
	}
}

} // namespace

const std::vector<RegistryProduct>& registryProducts() {
	static const std::vector<RegistryProduct> products = {
		{ "putty", L"PuTTY", { L"Software\\SimonTatham\\PuTTY\\Sessions", L"Software\\SimonTatham\\PuTTY\\SshHostKeys" } },
		{ "seven_zip", L"7-Zip", { L"Software\\7-Zip\\FM", L"Software\\7-Zip\\Compression" } },
		{ "winrar", L"WinRAR", { L"Software\\WinRAR\\ArcHistory", L"Software\\WinRAR\\DialogEditHistory" } },
		{ "winscp", L"WinSCP", { L"Software\\Martin Prikryl\\WinSCP 2\\Sessions", L"Software\\Martin Prikryl\\WinSCP 2\\SshHostKeys", L"Software\\Martin Prikryl\\WinSCP 2\\History" } },
	};
	return products;
}

HRESULT ApplicationRegistry::getData() {
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		for (const RegistryProduct& product : registryProducts()) {
			if (!traceProductWanted(conf.traceProducts, "application_registry", product.key)) continue;
			for (const wchar_t* path : product.paths) {
				ORHKEY key = NULL;
				if (OROpenKey(root, path, &key) != ERROR_SUCCESS) continue;
				walkKey(key, path, lastWrite(key), product.name, sid, KEY_DEPTH_MAX, keys_);
				ORCloseKey(key);
			}
		}
	});
	return ERROR_SUCCESS;
}

HRESULT ApplicationRegistry::toJson() { return writeJsonFile("application_registry.json", keys_); }
void ApplicationRegistry::clear() { keys_ = Json::arr(); }
