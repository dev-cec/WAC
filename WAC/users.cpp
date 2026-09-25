/*! \file
 *  \brief Offline reading of the local accounts in the SAM hive (see users.h).
 */
#include "users.h"

namespace {

/* Offsets in the `F` value of a SAM account (a fixed-size structure, 0x50
 * bytes). Aligned on RegRipper (samparse.pl) and creddump, which agree.
 * Named rather than written in plain in the code: a bare offset cannot be
 * read back.
 */
const size_t F_MIN_SIZE          = 0x44;
const size_t F_LAST_LOGON  = 0x08;   // FILETIME
const size_t F_PASSWORD_SET   = 0x18;   // FILETIME
const size_t F_EXPIRATION          = 0x20;   // FILETIME
const size_t F_LAST_FAILURE       = 0x28;   // FILETIME
const size_t F_RID                 = 0x30;   // DWORD
const size_t F_FLAGS            = 0x38;   // WORD (ACB)
const size_t F_FAILURES              = 0x40;   // WORD
const size_t F_LOGONS          = 0x42;   // WORD

/* Offsets in the `V` value. The value starts with a table of 12-byte entries
 * (offset, length, unknown); the offsets are relative to 0xCC, that is the end
 * of that table. */
const size_t V_BASE          = 0xCC;
const size_t V_NAME           = 0x0C;
const size_t V_FULL_NAME   = 0x18;
const size_t V_COMMENT   = 0x24;

//! Reads a FILETIME at an offset, never going past the buffer.
FILETIME readFiletime(const BYTE* data, DWORD size, size_t offset) {
	FILETIME ft = { 0, 0 };
	if (offset + sizeof(FILETIME) > size) return ft;
	memcpy(&ft, data + offset, sizeof(FILETIME));
	return ft;
}

/*! Reads a string of the `V` value from its entry in the offset table.
*
* The strings are NOT zero-terminated: the entry's length is the only bound. A
* corrupted length would point out of the buffer, hence the systematic check.
*
* @param data the `V` value
* @param size its size
* @param entry the offset of the entry in the table (V_NAME, V_FULL_NAME, …)
* @return the string, or "" if the entry is empty or inconsistent
*/
std::wstring readStringV(const BYTE* data, DWORD size, size_t entry) {
	if (entry + 8 > size) return L"";
	DWORD relativeOffset = 0, length = 0;
	memcpy(&relativeOffset, data + entry,     sizeof(DWORD));
	memcpy(&length,      data + entry + 4, sizeof(DWORD));
	if (length == 0 || length > size) return L"";
	const size_t start = V_BASE + relativeOffset;
	if (start + length > size) {
		log(2, L"🔥SAM V value inconsistent: entry outside the buffer");
		return L"";
	}
	return std::wstring((PCWSTR)(data + start), length / sizeof(wchar_t));
}

/*! Breaks the account flags (ACB) down into readable labels.
*
* `Disabled` alone is not enough to describe an account: "password never
* expires", "account locked out" or "password not required" are facts the
* analyst must see without having to decode an integer.
*/
std::wstring describeFlags(DWORD acb) {
	/* MIND THIS: these bits are the SAM's ACB, NOT the UF_* of lmaccess.h. The
	   two spaces look alike but are shifted — ACB_DISABLED is 0x0001 whereas
	   UF_ACCOUNTDISABLE is 0x0002. Replacing these values by the UF_* constants
	   "to make it clean" would invert the reading of every account. They are
	   therefore written in plain, with their ACB name. */
	struct { DWORD bit; PCWSTR name; } TABLE[] = {
		{ 0x0001, L"ACCOUNT_DISABLED" },
		{ 0x0002, L"HOME_DIRECTORY_REQUIRED" },
		{ 0x0004, L"PASSWORD_NOT_REQUIRED" },
		{ 0x0008, L"TEMPORARY_DUPLICATE_ACCOUNT" },
		{ 0x0010, L"NORMAL_ACCOUNT" },
		{ 0x0020, L"MNS_LOGON_ACCOUNT" },
		{ 0x0040, L"INTERDOMAIN_TRUST_ACCOUNT" },
		{ 0x0080, L"WORKSTATION_TRUST_ACCOUNT" },
		{ 0x0100, L"SERVER_TRUST_ACCOUNT" },
		{ 0x0200, L"PASSWORD_DOES_NOT_EXPIRE" },
		{ 0x0400, L"ACCOUNT_AUTO_LOCKED" },
	};
	std::wstring s;
	for (const auto& e : TABLE) {
		if ((acb & e.bit) == 0) continue;
		if (!s.empty()) s += L"|";
		s += e.name;
	}
	return s;
}

//! Profile path attached to a SID, "" if the account never logged on.
std::wstring profileOfSid(const std::wstring& sid) {
	if (sid.empty()) return L"";
	for (const std::tuple<std::wstring, std::wstring>& p : conf.profiles)
		if (toLower(std::get<0>(p)) == toLower(sid)) return std::get<1>(p);
	return L"";
}

} // namespace

/*! Rebuilds the machine's SID from `SAM\Domains\Account`, value `V`.
*
* The three subauthorities of the local domain SID occupy the last 12 bytes of
* the value. Without them, only the RID would be known — and a RID cannot be
* interpreted on its own, nor correlated with any other artefact.
*
* @param hSam the open SAM hive
* @param base key prefix ("SAM\\" or "", see `samRoot`)
* @return "S-1-5-21-a-b-c", or "" on failure
*/
std::wstring readMachineSid(ORHKEY hSam, const std::wstring& base) {
	LPBYTE data = NULL;
	DWORD size = 0;
	log(3, L"🔈getRegBinaryValue " + base + L"Domains\\Account V");
	if (getRegBinaryValue(hSam, (base + L"Domains\\Account").c_str(), L"V",
	                      &data, &size) != ERROR_SUCCESS) {
		log(2, L"🔥Machine SID unreadable: the SIDs will be limited to the RID");
		// getRegBinaryValue allocates the buffer BEFORE reading: it must be released
		// even when the reading fails, otherwise the error path leaks.
		delete[] data;
		return L"";
	}
	std::wstring sid;
	if (size >= 12) {
		const BYTE* end = data + size - 12;
		DWORD a = 0, b = 0, c = 0;
		memcpy(&a, end,     sizeof(DWORD));
		memcpy(&b, end + 4, sizeof(DWORD));
		memcpy(&c, end + 8, sizeof(DWORD));
		sid = L"S-1-5-21-" + std::to_wstring(a) + L"-" + std::to_wstring(b)
		    + L"-" + std::to_wstring(c);
		log(2, L"❇️Machine SID: " + sid);
	}
	else
		log(2, L"🔥V value of SAM\\Domains\\Account too short");
	delete[] data;
	return sid;
}


HRESULT openSam(ORHKEY* hSam, std::wstring* base) {
	if (!hSam || !base) return ERROR_INVALID_PARAMETER;
	*hSam = NULL;
	const std::wstring samHive = conf.mountpoint + L"\\Windows\\system32\\config\\SAM";
	log(3, L"🔈OROpenHive SAM");
	HRESULT hresult = OROpenHive(samHive.c_str(), hSam);
	if (hresult != ERROR_SUCCESS) return hresult;
	/* The SAM hive carries a root key named "SAM": the full path is therefore
	   `SAM\Domains\Account`. Both forms are tried, because the root exposed
	   depends on the way the hive was written — an ERROR_FILE_NOT_FOUND here
	   would otherwise read as "hive absent" while it is present and readable. */
	for (PCWSTR prefix : { L"SAM\\", L"" }) {
		ORHKEY account = NULL;
		if (OROpenKey(*hSam, (std::wstring(prefix) + L"Domains\\Account").c_str(), &account) == ERROR_SUCCESS) {
			ORCloseKey(account);
			*base = prefix;
			return ERROR_SUCCESS;
		}
	}
	ORCloseHive(*hSam);
	*hSam = NULL;
	return ERROR_FILE_NOT_FOUND;
}


Json User::toJson() const {
	log(3, L"🔈user toJson");
	Json o = Json::obj();
	o.add(L"Name",     Json::str(name));
	if (!fullName.empty()) o.add(L"FullName", Json::str(fullName));
	if (!comment.empty())  o.add(L"Comment",  Json::str(comment));
	o.add(L"SID",      Json::str(SID));
	o.add(L"RID",      Json::num(rid));
	o.add(L"Disabled", Json::boolean((flags & 0x0001) != 0));
	if (!flagLabels.empty()) o.add(L"AccountFlags", Json::str(flagLabels));
	/* An absent profile means the account never logged on to this machine: a fact
	   in its own right, not a failed reading. */
	if (!profile.empty()) o.add(L"Profile", Json::str(profile));

	o.add(L"LogonCount",       Json::num(logonCount));
	o.add(L"BadPasswordCount", Json::num(badPasswordCount));

	// Every timestamp is emitted in both references, as everywhere else in WAC;
	// empty if the SAM does not carry the date.
	struct { PCWSTR name; PCWSTR nameUtc; const FILETIME* ft; } DATES[] = {
		{ L"LastLogon",        L"LastLogonUtc",        &lastLogonUtc },
		{ L"PasswordLastSet",  L"PasswordLastSetUtc",  &passwordLastSetUtc },
		{ L"AccountExpires",   L"AccountExpiresUtc",   &accountExpiresUtc },
		{ L"LastBadPassword",  L"LastBadPasswordUtc",  &lastBadPasswordUtc },
		{ L"AccountModified",  L"AccountModifiedUtc",  &keyLastWriteUtc },
	};
	for (const auto& d : DATES) {
		const std::wstring local = utcTimeToIso8601Local(*d.ft);
		if (local.empty()) continue;
		o.add(d.name,    Json::str(local));
		o.add(d.nameUtc, Json::str(timeToIso8601Utc(*d.ft)));
	}
	return o;
}

void User::clear() {
	log(3, L"🔈user clear");
}

HRESULT Users::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Users :");
	log(0, L"*******************************************************************************************************************");

	ORHKEY hSam = NULL;
	std::wstring base;
	HRESULT hresult = openSam(&hSam, &base);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥SAM hive unavailable: local accounts not collected", hresult);
		return hresult;
	}
	ORHKEY hUsers = NULL;
	log(3, L"🔈OROpenKey " + base + L"Domains\\Account\\Users");
	if (OROpenKey(hSam, (base + L"Domains\\Account\\Users").c_str(), &hUsers) != ERROR_SUCCESS) hUsers = NULL;
	if (!hUsers) {
		log(2, L"🔥OROpenKey Domains\\Account\\Users not found in the SAM hive");
		ORCloseHive(hSam);
		return ERROR_FILE_NOT_FOUND;
	}
	log(2, L"❇️Racine SAM : \"" + base + L"Domains\\Account\\Users\"");

	const std::wstring sidMachine = readMachineSid(hSam, base);

	DWORD nSubKeys = 0;
	log(3, L"🔈ORQueryInfoKey SAM\\Domains\\Account\\Users");
	hresult = ORQueryInfoKey(hUsers, NULL, NULL, &nSubKeys, NULL, NULL, NULL,
	                         NULL, NULL, NULL, NULL);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey SAM\\Domains\\Account\\Users", hresult);
		ORCloseKey(hUsers);
		ORCloseHive(hSam);
		return hresult;
	}

	WCHAR keyName[MAX_KEY_NAME] = L"";
	for (DWORD i = 0; i < nSubKeys; ++i) {
		printProgressStep(L"User", i + 1, nSubKeys);
		DWORD size = MAX_KEY_NAME;
		log(3, L"🔈OREnumKey Users " + std::to_wstring(i));
		if (OREnumKey(hUsers, i, keyName, &size, NULL, NULL, NULL) != ERROR_SUCCESS)
			continue;
		/* The `Names` subkey is not an account but a name -> RID index: it is
		   ignored, the RIDs being already carried by the `F` value. */
		if (toLower(keyName) == L"names") continue;

		ORHKEY hAccount = NULL;
		log(3, L"🔈OROpenKey Users\\" + std::wstring(keyName));
		if (OROpenKey(hUsers, keyName, &hAccount) != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey Users\\" + std::wstring(keyName));
			continue;
		}

		User u;
		log(3, L"🔈ORQueryInfoKey Users\\" + std::wstring(keyName));
		ORQueryInfoKey(hAccount, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		               &u.keyLastWriteUtc);

		// --- value F: timestamps, RID, flags, counters ---
		LPBYTE f = NULL;
		DWORD sizeF = 0;
		if (getRegBinaryValue(hAccount, nullptr, L"F", &f, &sizeF) == ERROR_SUCCESS
		    && sizeF >= F_MIN_SIZE) {
			u.lastLogonUtc       = readFiletime(f, sizeF, F_LAST_LOGON);
			u.passwordLastSetUtc = readFiletime(f, sizeF, F_PASSWORD_SET);
			u.accountExpiresUtc  = readFiletime(f, sizeF, F_EXPIRATION);
			u.lastBadPasswordUtc = readFiletime(f, sizeF, F_LAST_FAILURE);
			memcpy(&u.rid, f + F_RID, sizeof(DWORD));
			WORD w = 0;
			memcpy(&w, f + F_FLAGS,   sizeof(WORD)); u.flags = w;
			memcpy(&w, f + F_FAILURES,     sizeof(WORD)); u.badPasswordCount = w;
			memcpy(&w, f + F_LOGONS, sizeof(WORD)); u.logonCount = w;
			u.flagLabels = describeFlags(u.flags);
		}
		else
			log(2, L"🔥F value missing or too short for " + std::wstring(keyName));
		delete[] f;

		/* If `F` did not give the RID, the key's name carries it in hexadecimal: a
		   fallback that avoids losing the account for a single unreadable
		   field. */
		if (u.rid == 0) u.rid = (DWORD)wcstoul(keyName, nullptr, 16);

		// --- value V: name, full name, comment ---
		LPBYTE v = NULL;
		DWORD sizeV = 0;
		if (getRegBinaryValue(hAccount, nullptr, L"V", &v, &sizeV) == ERROR_SUCCESS) {
			u.name     = readStringV(v, sizeV, V_NAME);
			u.fullName = readStringV(v, sizeV, V_FULL_NAME);
			u.comment  = readStringV(v, sizeV, V_COMMENT);
		}
		else
			log(2, L"🔥V value missing for " + std::wstring(keyName));
		delete[] v;
		ORCloseKey(hAccount);

		if (u.name.empty()) {
			// Without a name, the entry is not usable: reported, not emitted.
			log(2, L"🔥Account without a usable name, RID " + std::to_wstring(u.rid));
			continue;
		}
		if (!sidMachine.empty()) u.SID = sidMachine + L"-" + std::to_wstring(u.rid);
		u.profile = profileOfSid(u.SID);

		log(1, L"➕User");
		log(2, L"❇️User name : " + u.name + L" (RID " + std::to_wstring(u.rid) + L")");
		users.push_back(std::move(u));
	}

	ORCloseKey(hUsers);
	ORCloseHive(hSam);
	log(2, L"❇️" + std::to_wstring(users.size()) + L" local accounts read in the SAM");
	return users.empty() ? ERROR_EMPTY : ERROR_SUCCESS;
}

HRESULT Users::toJson() {
	log(3, L"🔈users toJson");
	Json arr = Json::arr();
	for (const User& u : users) arr.push(u.toJson());
	return writeJsonFile("users.json", arr);
}

void Users::clear() {
	log(3, L"🔈users clear");
	users.clear();   // destroys the elements -> really releases them
}
