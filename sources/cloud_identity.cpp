/*! \file
 *  \brief The Entra ID registrations (see cloud_identity.h).
 */
#include "cloud_identity.h"

const wchar_t* const CLOUD_TOKEN_FOLDERS[2] = {
	L"\\AppData\\Local\\Microsoft\\TokenBroker",
	L"\\AppData\\Local\\Packages\\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy" };

namespace {

/*! Reads the registrations under a key: one per subkey of each of its two lists.
 *  @param root the hive's root (or the control set)
 *  @param base the key holding JoinInfo and TenantInfo
 *  @param label what the source says ("CloudDomainJoin", "WorkplaceJoin")
 *  @param sid the user, empty for the machine
 *  @param out receives the registrations */
void readRegistrations(ORHKEY root, const std::wstring& base, const wchar_t* label, const std::wstring& sid,
                       std::vector<CloudRegistration>& out) {
	if (!root) return;
	for (const wchar_t* list : { L"JoinInfo", L"TenantInfo" }) {
		const std::wstring path = base + L"\\" + list;
		for (const std::wstring& name : subkeys(root, path)) {
			ORHKEY key = NULL;
			if (OROpenKey(root, (path + L"\\" + name).c_str(), &key) != ERROR_SUCCESS) continue;
			CloudRegistration r;
			r.source = std::wstring(label) + L"\\" + list;
			r.sid = sid;
			r.keyName = name;
			r.keyLastWriteUtc = lastWrite(key);
			readAllValues(key, r.values);
			ORCloseKey(key);
			out.push_back(std::move(r));
		}
	}
}

} // namespace

Json CloudRegistration::toJson() const {
	Json o = Json::obj();
	o.add(L"Source", Json::str(source));
	if (!sid.empty()) addUser(o, sid);
	o.add(L"KeyName", Json::str(keyName));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	for (const auto& [name, value] : values) o.add(name, value);
	return o;
}

HRESULT CloudIdentity::getData() {
	readRegistrations(conf.CurrentControlSet, L"Control\\CloudDomainJoin", L"CloudDomainJoin", L"", registrations_);
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		readRegistrations(root, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\WorkplaceJoin", L"WorkplaceJoin", sid, registrations_);
	});
	return ERROR_SUCCESS;
}

HRESULT CloudIdentity::toJson() { return writeList("cloud_identity.json", registrations_); }
void CloudIdentity::clear() { registrations_.clear(); }
