/*! \file
 *  \brief Offline names of the SIDs (see account_names.h).
 */
#include "account_names.h"
#include "tools.h"
#include "users.h"
#include "sha.h"
#include <cstring>
#include <filesystem>
#include <map>
#include <vector>

namespace {

//! SID in upper case -> name. Filled once by loadAccountNames.
std::map<std::wstring, std::wstring> g_names;

/*! The well-known SIDs of Windows, under the canonical (English) names of
 *  Microsoft's documentation ("Well-known SIDs"). LookupAccountSidW returns
 *  them translated into the language of the machine that asks, hence one SID
 *  named differently from one analysis workstation to another; a fixed name
 *  keeps the output reproducible. The built-in groups (S-1-5-32-…) are found
 *  in the SAM, in the language of the examined machine, which takes precedence. */
const struct { const wchar_t* sid; const wchar_t* name; } WELL_KNOWN[] = {
	{ L"S-1-1-0", L"Everyone" }, { L"S-1-2-0", L"LOCAL" }, { L"S-1-2-1", L"CONSOLE LOGON" },
	{ L"S-1-3-0", L"CREATOR OWNER" }, { L"S-1-3-1", L"CREATOR GROUP" }, { L"S-1-3-4", L"OWNER RIGHTS" },
	{ L"S-1-5-1", L"DIALUP" }, { L"S-1-5-2", L"NETWORK" }, { L"S-1-5-3", L"BATCH" },
	{ L"S-1-5-4", L"INTERACTIVE" }, { L"S-1-5-6", L"SERVICE" }, { L"S-1-5-7", L"ANONYMOUS LOGON" },
	{ L"S-1-5-8", L"PROXY" }, { L"S-1-5-9", L"ENTERPRISE DOMAIN CONTROLLERS" }, { L"S-1-5-10", L"SELF" },
	{ L"S-1-5-11", L"Authenticated Users" }, { L"S-1-5-12", L"RESTRICTED" },
	{ L"S-1-5-13", L"TERMINAL SERVER USER" }, { L"S-1-5-14", L"REMOTE INTERACTIVE LOGON" },
	{ L"S-1-5-15", L"This Organization" }, { L"S-1-5-17", L"IUSR" },
	{ L"S-1-5-18", L"SYSTEM" }, { L"S-1-5-19", L"LOCAL SERVICE" }, { L"S-1-5-20", L"NETWORK SERVICE" },
	{ L"S-1-5-32-544", L"Administrators" }, { L"S-1-5-32-545", L"Users" }, { L"S-1-5-32-546", L"Guests" },
	{ L"S-1-5-32-547", L"Power Users" }, { L"S-1-5-32-551", L"Backup Operators" },
	{ L"S-1-5-32-555", L"Remote Desktop Users" }, { L"S-1-5-32-562", L"Distributed COM Users" },
	{ L"S-1-5-32-568", L"IIS_IUSRS" }, { L"S-1-5-32-573", L"Event Log Readers" },
	{ L"S-1-5-32-580", L"Remote Management Users" },
	{ L"S-1-5-64-10", L"NTLM Authentication" }, { L"S-1-5-64-14", L"SChannel Authentication" },
	{ L"S-1-5-64-21", L"Digest Authentication" }, { L"S-1-5-80-0", L"ALL SERVICES" },
	{ L"S-1-5-113", L"Local account" }, { L"S-1-5-114", L"Local account and member of Administrators group" },
	{ L"S-1-16-4096", L"Low Mandatory Level" }, { L"S-1-16-8192", L"Medium Mandatory Level" },
	{ L"S-1-16-12288", L"High Mandatory Level" }, { L"S-1-16-16384", L"System Mandatory Level" },
};

//! Upper case, ASCII only: the key of the table (a SID is ASCII).
std::wstring upper(std::wstring s) {
	for (wchar_t& c : s) if (c >= L'a' && c <= L'z') c = (wchar_t)(c - L'a' + L'A');
	return s;
}

/*! Adds the names of one index of the SAM ("…\Names"): each subkey is a name,
 *  and the TYPE of its default value is the RID.
 *  @param hSam the open SAM hive
 *  @param path path of the Names key
 *  @param domainSid SID of the domain the RIDs belong to
 *  @return the number of names added */
unsigned addSamIndex(ORHKEY hSam, const std::wstring& path, const std::wstring& domainSid) {
	ORHKEY names = NULL;
	if (OROpenKey(hSam, path.c_str(), &names) != ERROR_SUCCESS) return 0;
	unsigned added = 0;
	wchar_t name[MAX_KEY_NAME + 1] = L"";
	for (DWORD i = 0; ; ++i) {
		DWORD length = MAX_KEY_NAME + 1;
		const HRESULT hresult = OREnumKey(names, i, name, &length, NULL, NULL, NULL);
		if (hresult == ERROR_NO_MORE_ITEMS) break;
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OREnumKey " + path + L" " + std::to_wstring(i), hresult);
			continue;
		}
		DWORD rid = 0, size = 0;
		if (ORGetValue(names, name, nullptr, &rid, nullptr, &size) == ERROR_SUCCESS
		    && g_names.emplace(upper(domainSid + L"-" + std::to_wstring(rid)), name).second)
			++added;
	}
	ORCloseKey(names);
	return added;
}

//! Local users, groups and aliases, and built-in groups, from the SAM.
HRESULT addSamNames() {
	ORHKEY hSam = NULL;
	std::wstring base;
	const HRESULT hresult = openSam(&hSam, &base);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥SAM unreadable: local accounts not named", hresult);
		return hresult;
	}
	const std::wstring machine = readMachineSid(hSam, base);
	unsigned count = 0;
	if (!machine.empty())
		for (PCWSTR index : { L"Users", L"Groups", L"Aliases" })
			count += addSamIndex(hSam, base + L"Domains\\Account\\" + index + L"\\Names", machine);
	count += addSamIndex(hSam, base + L"Domains\\Builtin\\Aliases\\Names", L"S-1-5-32");
	ORCloseHive(hSam);
	log(2, L"❇️Account names from the SAM: " + std::to_wstring(count));
	return ERROR_SUCCESS;
}

//! Service SIDs, from the service names of the SYSTEM hive.
void addServiceNames() {
	if (!conf.CurrentControlSet) return;
	ORHKEY services = NULL;
	if (OROpenKey(conf.CurrentControlSet, L"Services", &services) != ERROR_SUCCESS) {
		log(2, L"🔥OROpenKey Services: service SIDs not named");
		return;
	}
	unsigned count = 0;
	wchar_t name[MAX_KEY_NAME + 1] = L"";
	for (DWORD i = 0; ; ++i) {
		DWORD length = MAX_KEY_NAME + 1;
		const HRESULT hresult = OREnumKey(services, i, name, &length, NULL, NULL, NULL);
		if (hresult == ERROR_NO_MORE_ITEMS) break;
		if (hresult != ERROR_SUCCESS) continue;
		if (g_names.emplace(upper(serviceSid(name)), std::wstring(L"NT SERVICE\\") + name).second) ++count;
	}
	ORCloseKey(services);
	log(2, L"❇️Service SIDs named: " + std::to_wstring(count));
}

//! Domain (and other) accounts that have a profile: the profile folder names them.
void addProfileNames() {
	for (const std::tuple<std::wstring, std::wstring>& p : conf.profiles) {
		const std::wstring folder = std::filesystem::path(std::get<1>(p)).filename().wstring();
		if (!folder.empty()) g_names.emplace(upper(std::get<0>(p)), folder);
	}
}

/*! SIDs named by a pattern: the window manager and font driver sessions,
 *  one SID per session number. */
std::wstring patternName(const std::wstring& sid) {
	static const struct { const wchar_t* prefix; const wchar_t* name; } PATTERNS[] = {
		{ L"S-1-5-90-0-", L"DWM-" },    // Window Manager\DWM-<session>
		{ L"S-1-5-96-0-", L"UMFD-" },   // Font Driver Host\UMFD-<session>
	};
	for (const auto& p : PATTERNS) {
		const size_t n = wcslen(p.prefix);
		if (sid.size() > n && sid.compare(0, n, p.prefix) == 0
		    && sid.find_first_not_of(L"0123456789", n) == std::wstring::npos)
			return p.name + sid.substr(n);
	}
	return L"";
}

} // namespace

std::wstring serviceSid(const std::wstring& service) {
	const std::wstring name = upper(service);
	std::vector<uint8_t> bytes(name.size() * 2);
	for (size_t k = 0; k < name.size(); ++k) {           // UTF-16LE, whatever the platform
		bytes[2 * k] = (uint8_t)(name[k] & 0xFF);
		bytes[2 * k + 1] = (uint8_t)(name[k] >> 8);
	}
	uint8_t digest[20];
	sha1Bytes(bytes.data(), bytes.size(), digest);
	std::wstring sid = L"S-1-5-80";
	for (int k = 0; k < 5; ++k) {
		uint32_t word = 0;
		std::memcpy(&word, digest + 4 * k, 4);
		sid += L"-" + std::to_wstring(word);
	}
	return sid;
}

HRESULT loadAccountNames() {
	g_names.clear();
	// In order of precedence: emplace keeps the first name given to a SID.
	const HRESULT hresult = addSamNames();
	for (const auto& w : WELL_KNOWN) g_names.emplace(upper(w.sid), w.name);
	addServiceNames();
	addProfileNames();
	log(2, L"❇️SIDs named offline: " + std::to_wstring(g_names.size()));
	return hresult;
}

std::wstring getNameFromSid(std::wstring _sid) {
	if (_sid.empty()) return L"";
	const auto found = g_names.find(upper(_sid));
	if (found != g_names.end()) return found->second;
	return patternName(upper(_sid));
}
