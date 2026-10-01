/*! \file
 *  \brief The SECURITY hive (see security_hive.h).
 */
#include "security_hive.h"
#include "sha.h"
#include <cstring>
#include <cstdint>

namespace {

//! A NL$n value begins with the length of the cached user's name: 0, an empty slot.
const size_t NL_USER_NAME_LENGTH = 0;

/* Privilege LUIDs are well-known and fixed across Windows versions (the low
 * part; the high part is zero). The name of each is written here so the output
 * reads without a Windows lookup — which would query LSA on the running
 * machine. Indexed by the LUID value, from SeCreateTokenPrivilege (2). */
const wchar_t* const PRIVILEGE_NAMES[] = {
	nullptr, nullptr,                       // 0, 1: unused
	L"SeCreateTokenPrivilege",              // 2
	L"SeAssignPrimaryTokenPrivilege",       // 3
	L"SeLockMemoryPrivilege",               // 4
	L"SeIncreaseQuotaPrivilege",            // 5
	L"SeMachineAccountPrivilege",           // 6
	L"SeTcbPrivilege",                      // 7
	L"SeSecurityPrivilege",                 // 8
	L"SeTakeOwnershipPrivilege",            // 9
	L"SeLoadDriverPrivilege",               // 10
	L"SeSystemProfilePrivilege",            // 11
	L"SeSystemtimePrivilege",               // 12
	L"SeProfileSingleProcessPrivilege",     // 13
	L"SeIncreaseBasePriorityPrivilege",     // 14
	L"SeCreatePagefilePrivilege",           // 15
	L"SeCreatePermanentPrivilege",          // 16
	L"SeBackupPrivilege",                   // 17
	L"SeRestorePrivilege",                  // 18
	L"SeShutdownPrivilege",                 // 19
	L"SeDebugPrivilege",                    // 20
	L"SeAuditPrivilege",                    // 21
	L"SeSystemEnvironmentPrivilege",        // 22
	L"SeChangeNotifyPrivilege",             // 23
	L"SeRemoteShutdownPrivilege",           // 24
	L"SeUndockPrivilege",                   // 25
	L"SeSyncAgentPrivilege",                // 26
	L"SeEnableDelegationPrivilege",         // 27
	L"SeManageVolumePrivilege",             // 28
	L"SeImpersonatePrivilege",              // 29
	L"SeCreateGlobalPrivilege",             // 30
	L"SeTrustedCredManAccessPrivilege",     // 31
	L"SeRelabelPrivilege",                  // 32
	L"SeIncreaseWorkingSetPrivilege",       // 33
	L"SeTimeZonePrivilege",                 // 34
	L"SeCreateSymbolicLinkPrivilege",       // 35
	L"SeDelegateSessionUserImpersonatePrivilege", // 36
};

//! The ActSysAc bitmask: the logon rights (and their denials) of an account.
const struct { DWORD bit; const wchar_t* name; } LOGON_RIGHTS[] = {
	{ 0x00000001, L"SeInteractiveLogonRight" },
	{ 0x00000002, L"SeNetworkLogonRight" },
	{ 0x00000004, L"SeBatchLogonRight" },
	{ 0x00000010, L"SeServiceLogonRight" },
	{ 0x00000040, L"SeDenyInteractiveLogonRight" },
	{ 0x00000080, L"SeDenyNetworkLogonRight" },
	{ 0x00000100, L"SeDenyBatchLogonRight" },
	{ 0x00000200, L"SeDenyServiceLogonRight" },
	{ 0x00000400, L"SeRemoteInteractiveLogonRight" },
	{ 0x00000800, L"SeDenyRemoteInteractiveLogonRight" },
};

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

	// Account rights: each subkey of Policy\Accounts is a SID; its Privilgs and
	// ActSysAc subkeys carry, in their default value, the privilege LUIDs and the
	// logon-right bitmask held by that account.
	ORHKEY accounts = NULL;
	if (OROpenKey(root, L"Policy\\Accounts", &accounts) == ERROR_SUCCESS) {
		wchar_t sidName[256];
		for (DWORD i = 0;; ++i) {
			DWORD length = (DWORD)(sizeof(sidName) / sizeof(sidName[0]));
			AccountRight right;
			if (OREnumKey(accounts, i, sidName, &length, NULL, NULL, &right.keyLastWriteUtc) != ERROR_SUCCESS) break;
			right.sid.assign(sidName, length);
			const std::wstring path = L"Policy\\Accounts\\" + right.sid;

			// Privilgs: PrivilegeCount (DWORD), Control (DWORD), then
			// count entries of 12 bytes (LUID low, LUID high, attributes).
			std::vector<BYTE> privilges;
			if (getRegBinaryValue(root, (path + L"\\Privilgs").c_str(), L"", privilges) == ERROR_SUCCESS
			    && privilges.size() >= 8) {
				DWORD count = 0;
				memcpy(&count, privilges.data(), sizeof(DWORD));
				for (DWORD n = 0; n < count && 8 + (size_t)(n + 1) * 12 <= privilges.size(); ++n) {
					DWORD low = 0, high = 0;
					memcpy(&low,  privilges.data() + 8 + (size_t)n * 12,     sizeof(DWORD));
					memcpy(&high, privilges.data() + 8 + (size_t)n * 12 + 4, sizeof(DWORD));
					if (high == 0 && low < sizeof(PRIVILEGE_NAMES) / sizeof(PRIVILEGE_NAMES[0])
					    && PRIVILEGE_NAMES[low] != nullptr)
						right.privileges.push_back(PRIVILEGE_NAMES[low]);
					else
						// An unknown LUID is not dropped: it is a right all the same.
						right.privileges.push_back(L"Privilege-" + std::to_wstring(high ? (((uint64_t)high << 32) | low) : low));
				}
			}

			// ActSysAc: a DWORD bitmask of logon rights.
			std::vector<BYTE> actSysAc;
			if (getRegBinaryValue(root, (path + L"\\ActSysAc").c_str(), L"", actSysAc) == ERROR_SUCCESS
			    && actSysAc.size() >= sizeof(DWORD)) {
				DWORD mask = 0;
				memcpy(&mask, actSysAc.data(), sizeof(DWORD));
				for (const auto& r : LOGON_RIGHTS)
					if (mask & r.bit) right.logonRights.push_back(r.name);
			}

			if (!right.privileges.empty() || !right.logonRights.empty())
				accountRights_.push_back(std::move(right));
		}
		ORCloseKey(accounts);
	}

	ORCloseHive(root);
	return ERROR_SUCCESS;
}

Json AccountRight::toJson() const {
	Json o = Json::obj();
	o.add(L"Sid", Json::str(sid));
	const std::wstring name = getNameFromSid(sid);
	if (!name.empty()) o.add(L"SIDName", Json::str(name));
	if (!privileges.empty()) {
		Json arr = Json::arr();
		for (const std::wstring& p : privileges) arr.push(Json::str(p));
		o.add(L"Privileges", std::move(arr));
	}
	if (!logonRights.empty()) {
		Json arr = Json::arr();
		for (const std::wstring& r : logonRights) arr.push(Json::str(r));
		o.add(L"LogonRights", std::move(arr));
	}
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
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
	if (!accountRights_.empty()) {
		Json list = Json::arr();
		for (const AccountRight& r : accountRights_) list.push(r.toJson());
		o.add(L"AccountRights", std::move(list));
	}
	return writeJsonFile("security.json", o);
}

void SecurityHive::clear() {
	secrets_.clear();
	auditPolicy_.clear();
	accountRights_.clear();
}
