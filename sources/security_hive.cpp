/*! \file
 *  \brief The SECURITY hive (see security_hive.h).
 */
#include "security_hive.h"
#include "sha.h"

namespace {

//! A NL$n value begins with the length of the cached user's name: 0, an empty slot.
const size_t NL_USER_NAME_LENGTH = 0;

//! The last write time of a key of the hive, or zero.
FILETIME lastWrite(ORHKEY root, const wchar_t* path) {
	FILETIME f = { 0, 0 };
	ORHKEY key = NULL;
	if (OROpenKey(root, path, &key) != ERROR_SUCCESS) return f;
	ORQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &f);
	ORCloseKey(key);
	return f;
}

} // namespace

Json LsaSecret::toJson() const {
	Json o = Json::obj();
	o.add(L"Name", Json::str(name));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	addDate(o, L"CurrentValueSet", currentSetUtc);
	addDate(o, L"PreviousValueSet", previousSetUtc);
	return o;
}

HRESULT SecurityHive::getData() {
	log(0, L"ℹ️SECURITY hive :");
	ORHKEY root = NULL;
	const std::wstring file = conf.mountpoint + L"\\Windows\\system32\\config\\SECURITY";
	const HRESULT opened = OROpenHive(file.c_str(), &root);
	if (opened != ERROR_SUCCESS) return opened;

	// LSA secrets: the subkeys of Policy\Secrets, their names and the dates of their values.
	ORHKEY secrets = NULL;
	if (OROpenKey(root, L"Policy\\Secrets", &secrets) == ERROR_SUCCESS) {
		wchar_t name[256];
		for (DWORD i = 0;; ++i) {
			DWORD length = (DWORD)(sizeof(name) / sizeof(name[0]));
			LsaSecret secret;
			if (OREnumKey(secrets, i, name, &length, NULL, NULL, &secret.keyLastWriteUtc) != ERROR_SUCCESS) break;
			secret.name.assign(name, length);
			const std::wstring path = L"Policy\\Secrets\\" + secret.name;
			// The (default) value of CupdTime and OupdTime: a FILETIME.
			getRegFiletimeValue(root, (path + L"\\CupdTime").c_str(), L"", &secret.currentSetUtc);
			getRegFiletimeValue(root, (path + L"\\OupdTime").c_str(), L"", &secret.previousSetUtc);
			secrets_.push_back(std::move(secret));
		}
		ORCloseKey(secrets);
	}

	// Cached domain logons: the NL$n values of Cache, counted, never decrypted.
	ORHKEY cache = NULL;
	if (OROpenKey(root, L"Cache", &cache) == ERROR_SUCCESS) {
		cacheRead_ = true;
		ORQueryInfoKey(cache, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &cacheLastWriteUtc_);
		for (DWORD i = 0;; ++i) {
			std::wstring valueName;
			DWORD type = 0;
			std::vector<BYTE> data;
			if (enumRegistryValue(cache, i, valueName, type, data) != ERROR_SUCCESS) break;
			if (valueName.size() < 4 || valueName.compare(0, 3, L"NL$") != 0
			    || valueName.find_first_not_of(L"0123456789", 3) != std::wstring::npos) continue;
			++cacheSlots_;
			if (data.size() >= NL_USER_NAME_LENGTH + 2
			    && (data[NL_USER_NAME_LENGTH] | data[NL_USER_NAME_LENGTH + 1]) != 0) ++cacheUsed_;
		}
		ORCloseKey(cache);
	}

	// Audit policy: the (default) value of Policy\PolAdtEv, as its bytes.
	getRegBinaryValue(root, L"Policy\\PolAdtEv", L"", auditPolicy_);
	auditPolicyLastWriteUtc_ = lastWrite(root, L"Policy\\PolAdtEv");

	ORCloseHive(root);
	return ERROR_SUCCESS;
}

HRESULT SecurityHive::toJson() {
	Json o = Json::obj();
	Json list = Json::arr();
	for (const LsaSecret& s : secrets_) list.push(s.toJson());
	o.add(L"LsaSecretCount", Json::num((unsigned long long)secrets_.size()));
	o.add(L"LsaSecrets", std::move(list));
	if (cacheRead_) {
		Json cache = Json::obj();
		cache.add(L"Slots", Json::num(cacheSlots_));
		cache.add(L"Used", Json::num(cacheUsed_));
		addDate(cache, L"KeyLastWrite", cacheLastWriteUtc_);
		o.add(L"CachedLogons", std::move(cache));
	}
	if (!auditPolicy_.empty()) {
		Json audit = Json::obj();
		audit.add(L"PolAdtEv", Json::str(toHexadecimal(auditPolicy_.data(), auditPolicy_.size())));
		audit.add(L"Decoded", Json::boolean(false));
		addDate(audit, L"KeyLastWrite", auditPolicyLastWriteUtc_);
		o.add(L"AuditPolicy", std::move(audit));
	}
	return writeJsonFile("security.json", o);
}

void SecurityHive::clear() {
	secrets_.clear();
	auditPolicy_.clear();
}
