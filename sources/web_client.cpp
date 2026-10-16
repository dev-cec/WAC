/*! \file
 *  \brief The web, client side (see web_client.h).
 */
#include "web_client.h"
#include "ese_recovery.h"
#include "sqlite_reader.h"
#include "registry_common.h"
#include "ese_database.h"
#include "ie_index_dat.h"
#include "browser_sessions.h"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <map>

const ChromiumRoot CHROMIUM_ROOTS[] = {
	{ L"\\AppData\\Local\\Microsoft\\Edge\\User Data",                L"Edge" },
	{ L"\\AppData\\Local\\Google\\Chrome\\User Data",                 L"Chrome" },
	{ L"\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data",   L"Brave" },
	{ L"\\AppData\\Local\\Vivaldi\\User Data",                        L"Vivaldi" },
	{ L"\\AppData\\Local\\Chromium\\User Data",                       L"Chromium" },
	{ L"\\AppData\\Roaming\\Opera Software\\Opera Stable",            L"Opera" },   // the root is a profile too
};
const size_t CHROMIUM_ROOT_COUNT = sizeof(CHROMIUM_ROOTS) / sizeof(CHROMIUM_ROOTS[0]);
const std::vector<std::wstring> CHROMIUM_PROFILE_FILES = {
	L"History", L"Login Data", L"Web Data", L"Shortcuts", L"Top Sites", L"Bookmarks",
	L"Preferences", L"Secure Preferences", L"Cookies", L"Network\\Cookies",
	L"Favicons", L"Network Action Predictor", L"Sessions\\*" };
const std::vector<std::wstring> CHROMIUM_ROOT_FILES = { L"Local State" };
const wchar_t WEBCACHE_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Windows\\WebCache";
const wchar_t INETCACHE_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE";
const std::vector<std::wstring> INETCACHE_EXTENSIONS = {
	L".hta", L".htm", L".html", L".js", L".jse", L".vbs", L".vbe", L".wsf", L".wsh", L".ps1", L".psm1", L".bat", L".cmd",
	L".exe", L".dll", L".scr", L".cpl", L".msi", L".jar", L".zip", L".rar", L".7z", L".cab", L".iso", L".img", L".lnk",
	L".doc", L".docm", L".xls", L".xlsm", L".ppt", L".pptm", L".rtf", L".pdf" };
const std::vector<IeIndexFolder> IE_INDEX_FOLDERS = {
	{ L"\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5", true },
	{ L"\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Low\\Content.IE5", true },
	{ L"\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5", false },
	{ L"\\AppData\\Local\\Microsoft\\Windows\\History\\Low\\History.IE5", false },
	{ L"\\AppData\\Roaming\\Microsoft\\Windows\\Cookies", false },   // its Low subfolder within
	{ L"\\AppData\\Roaming\\Microsoft\\Windows\\IEDownloadHistory", false } };
const wchar_t FIREFOX_PROFILES[] = L"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles";
const uintmax_t IE_INDEX_MAX = 1024ull * 1024 * 1024;   //!< an index.dat grows to hundreds of MiB at most
const uintmax_t LOGINS_MAX = 64ull * 1024 * 1024;       //!< logins.json: a few KiB per saved password
const uintmax_t SESSION_FILE_MAX = 256ull * 1024 * 1024; //!< a session file: a few MiB with many tabs and their page states
const std::vector<std::wstring> FIREFOX_PROFILE_FILES = {
	L"places.sqlite", L"formhistory.sqlite", L"cookies.sqlite", L"permissions.sqlite", L"logins.json",
	L"key4.db", L"extensions.json", L"prefs.js", L"sessionstore.jsonlz4", L"favicons.sqlite",
	L"protections.sqlite", L"sessionstore-backups\\*", L"bookmarkbackups\\*" };
const wchar_t IE_LOCAL_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Internet Explorer";
const std::vector<std::wstring> WININET_LOCAL_FOLDERS = {
	L"\\AppData\\Local\\Microsoft\\Windows\\INetCookies", L"\\AppData\\Local\\Microsoft\\Windows\\IEDownloadHistory" };

namespace {

// ui::PageTransition (Chromium, ui/base/page_transition_types.h).
const int64_t TRANSITION_CORE_MASK = 0xFF;
const wchar_t* const TRANSITION_CORES[] = { L"link", L"typed", L"auto_bookmark", L"auto_subframe", L"manual_subframe",
	L"generated", L"auto_toplevel", L"form_submit", L"reload", L"keyword", L"keyword_generated" };
const struct { int64_t bit; const wchar_t* name; } TRANSITION_QUALIFIERS[] = {
	{ 0x00800000, L"blocked" }, { 0x01000000, L"forward_back" }, { 0x02000000, L"from_address_bar" },
	{ 0x04000000, L"home_page" }, { 0x08000000, L"from_api" }, { 0x10000000, L"chain_start" },
	{ 0x20000000, L"chain_end" }, { 0x40000000, L"client_redirect" }, { 0x80000000LL, L"server_redirect" } };
/* history::DownloadState, as the History database stores it. The danger type
   and the interrupt reason are given as numbers: the database's numbering is
   its own, not the enumerations of Chromium's code, and a wrong name would be
   valid JSON and false. */
const wchar_t* const DOWNLOAD_STATES[] = { L"in_progress", L"complete", L"cancelled", L"bug_140687", L"interrupted" };

// Firefox's visit types (nsINavHistoryService::TRANSITION_*), 1 to 9.
const wchar_t* const FIREFOX_VISIT_TYPES[] = { L"link", L"typed", L"bookmark", L"embed", L"redirect_permanent",
	L"redirect_temporary", L"download", L"framed_link", L"reload" };
const uint64_t MICROSECONDS_1601_TO_1970 = SECONDS_1601_TO_1970 * 1000000ULL;

//! The common fields of a record: browser, profile, SID, source.
WebClientRecord startRecord(const WebClientRecord& base, const wchar_t* type) {
	WebClientRecord r;
	r.type = type;
	r.browser = base.browser;
	r.browserProfile = base.browserProfile;
	r.sid = base.sid;
	r.source = base.source;
	return r;
}

void readUrls(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	db.query("SELECT id, url, title, visit_count, typed_count, last_visit_time, hidden FROM urls ORDER BY id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Url");
		r.fields.add(L"Id", Json::num((long long)row.integer(0)));
		r.fields.add(L"Url", Json::str(row.text(1)));
		r.fields.add(L"Title", Json::str(row.text(2)));
		r.fields.add(L"VisitCount", Json::num((long long)row.integer(3)));
		r.fields.add(L"TypedCount", Json::num((long long)row.integer(4)));
		addDate(r.fields, L"LastVisit", chromiumTime(row.integer(5)));
		if (row.integer(6)) r.fields.add(L"Hidden", Json::boolean(true));
		records.push_back(std::move(r));
	});
}

void readVisits(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	db.query("SELECT v.id, u.url, u.title, v.visit_time, v.transition, v.from_visit, fu.url, v.visit_duration "
	         "FROM visits v JOIN urls u ON u.id = v.url "
	         "LEFT JOIN visits fv ON fv.id = v.from_visit LEFT JOIN urls fu ON fu.id = fv.url "
	         "ORDER BY v.visit_time, v.id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Visit");
		r.fields.add(L"Id", Json::num((long long)row.integer(0)));
		r.fields.add(L"Url", Json::str(row.text(1)));
		r.fields.add(L"Title", Json::str(row.text(2)));
		addDate(r.fields, L"Visit", chromiumTime(row.integer(3)));
		r.fields.add(L"Transition", Json::str(transitionCore(row.integer(4))));
		r.fields.add(L"TransitionQualifiers", Json::str(transitionQualifiers(row.integer(4))));
		if (row.integer(5)) {
			r.fields.add(L"FromVisitId", Json::num((long long)row.integer(5)));
			r.fields.add(L"FromUrl", Json::str(row.text(6)));
		}
		if (row.integer(7) > 0) r.fields.add(L"DurationMicroseconds", Json::num((long long)row.integer(7)));
		records.push_back(std::move(r));
	});
}

void readDownloads(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	// The chain of each download: the URL first asked, then every redirection.
	std::map<int64_t, std::vector<std::wstring>> chains;
	db.query("SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index", [&](const SqliteRow& row) {
		chains[row.integer(0)].push_back(row.text(1));
	});
	db.query("SELECT id, guid, current_path, target_path, start_time, end_time, received_bytes, total_bytes, state, "
	         "danger_type, interrupt_reason, opened, last_access_time, referrer, site_url, tab_url, tab_referrer_url, "
	         "mime_type, original_mime_type, hash FROM downloads ORDER BY start_time, id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Download");
		r.fields.add(L"Id", Json::num((long long)row.integer(0)));
		r.fields.add(L"Guid", Json::str(row.text(1)));
		r.fields.add(L"TargetPath", Json::str(row.text(3)));
		if (row.text(2) != row.text(3)) r.fields.add(L"CurrentPath", Json::str(row.text(2)));
		const auto chain = chains.find(row.integer(0));
		if (chain != chains.end()) {
			r.fields.add(L"Url", Json::str(chain->second.back()));   // what was finally downloaded
			Json list = Json::arr();
			for (const std::wstring& u : chain->second) list.push(Json::str(u));
			r.fields.add(L"UrlChain", std::move(list));
		}
		addDate(r.fields, L"Start", chromiumTime(row.integer(4)));
		addDate(r.fields, L"End", chromiumTime(row.integer(5)));
		r.fields.add(L"ReceivedBytes", Json::num((long long)row.integer(6)));
		r.fields.add(L"TotalBytes", Json::num((long long)row.integer(7)));
		const int64_t state = row.integer(8);
		r.fields.add(L"State", state >= 0 && state < (int64_t)(sizeof(DOWNLOAD_STATES) / sizeof(DOWNLOAD_STATES[0]))
		                       ? Json::str(DOWNLOAD_STATES[state]) : Json::num((long long)state));
		r.fields.add(L"DangerType", Json::num((long long)row.integer(9)));
		if (row.integer(10)) r.fields.add(L"InterruptReason", Json::num((long long)row.integer(10)));
		r.fields.add(L"Opened", Json::boolean(row.integer(11) != 0));
		addDate(r.fields, L"LastAccess", chromiumTime(row.integer(12)));
		r.fields.add(L"Referrer", Json::str(row.text(13)));
		r.fields.add(L"SiteUrl", Json::str(row.text(14)));
		r.fields.add(L"TabUrl", Json::str(row.text(15)));
		r.fields.add(L"TabReferrerUrl", Json::str(row.text(16)));
		r.fields.add(L"MimeType", Json::str(row.text(17)));
		if (row.text(18) != row.text(17)) r.fields.add(L"OriginalMimeType", Json::str(row.text(18)));
		const std::vector<uint8_t> hash = row.blob(19);   // SHA-256 of the file, when Chromium computed it
		if (hash.size() == 32) r.fields.add(L"SHA256", Json::str(toHexadecimal(hash.data(), hash.size())));
		records.push_back(std::move(r));
	});
}

void readSearchTerms(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	db.query("SELECT k.term, k.normalized_term, u.url, u.last_visit_time FROM keyword_search_terms k "
	         "LEFT JOIN urls u ON u.id = k.url_id ORDER BY u.last_visit_time",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"SearchTerm");
		r.fields.add(L"Term", Json::str(row.text(0)));
		if (row.text(1) != row.text(0)) r.fields.add(L"NormalizedTerm", Json::str(row.text(1)));
		r.fields.add(L"Url", Json::str(row.text(2)));
		addDate(r.fields, L"LastVisit", chromiumTime(row.integer(3)));
		records.push_back(std::move(r));
	});
}

void readFirefoxUrls(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	db.query("SELECT id, url, title, visit_count, typed, last_visit_date, hidden FROM moz_places ORDER BY id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Url");
		r.fields.add(L"Id", Json::num((long long)row.integer(0)));
		r.fields.add(L"Url", Json::str(row.text(1)));
		r.fields.add(L"Title", Json::str(row.text(2)));
		r.fields.add(L"VisitCount", Json::num((long long)row.integer(3)));
		if (row.integer(4)) r.fields.add(L"Typed", Json::boolean(true));
		addDate(r.fields, L"LastVisit", firefoxTime(row.integer(5)));
		if (row.integer(6)) r.fields.add(L"Hidden", Json::boolean(true));
		records.push_back(std::move(r));
	});
}

void readFirefoxVisits(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	db.query("SELECT v.id, p.url, p.title, v.visit_date, v.visit_type, v.from_visit, fp.url "
	         "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id "
	         "LEFT JOIN moz_historyvisits fv ON fv.id = v.from_visit LEFT JOIN moz_places fp ON fp.id = fv.place_id "
	         "ORDER BY v.visit_date, v.id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Visit");
		r.fields.add(L"Id", Json::num((long long)row.integer(0)));
		r.fields.add(L"Url", Json::str(row.text(1)));
		r.fields.add(L"Title", Json::str(row.text(2)));
		addDate(r.fields, L"Visit", firefoxTime(row.integer(3)));
		r.fields.add(L"Transition", Json::str(firefoxVisitType(row.integer(4))));
		if (row.integer(5)) {
			r.fields.add(L"FromVisitId", Json::num((long long)row.integer(5)));
			r.fields.add(L"FromUrl", Json::str(row.text(6)));
		}
		records.push_back(std::move(r));
	});
}

/*! Firefox's downloads: two annotations of the place the file came from —
 *  its destination (a file URI) and a JSON of metadata (state, end in
 *  milliseconds, size). */
void readFirefoxDownloads(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	db.query("SELECT p.url, d.content, d.dateAdded, m.content FROM moz_annos d "
	         "JOIN moz_anno_attributes dn ON dn.id = d.anno_attribute_id AND dn.name = 'downloads/destinationFileURI' "
	         "JOIN moz_places p ON p.id = d.place_id "
	         "LEFT JOIN moz_annos m ON m.place_id = d.place_id AND m.anno_attribute_id = "
	         "(SELECT id FROM moz_anno_attributes WHERE name = 'downloads/metaData') "
	         "ORDER BY d.dateAdded",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Download");
		r.fields.add(L"Url", Json::str(row.text(0)));
		r.fields.add(L"TargetPath", Json::str(fileUriToPath(row.text(1))));
		addDate(r.fields, L"Start", firefoxTime(row.integer(2)));
		Json meta = Json::obj();
		std::wstring error;
		if (!row.isNull(3) && Json::parse(row.text(3), meta, error)) {
			// State as Firefox stores it (DownloadHistory), a number: see Chromium's DangerType.
			auto number = [](const Json* v) { return (long long)std::wcstoll(v->text().c_str(), nullptr, 10); };
			if (const Json* state = meta.find(L"state")) r.fields.add(L"State", Json::num(number(state)));
			if (const Json* end = meta.find(L"endTime"))
				addDate(r.fields, L"End", firefoxTime(number(end) * 1000));   // milliseconds there
			if (const Json* size = meta.find(L"fileSize")) r.fields.add(L"ReceivedBytes", Json::num(number(size)));
			if (const Json* deleted = meta.find(L"deleted"); deleted && deleted->text() == L"true")
				r.fields.add(L"Deleted", Json::boolean(true));
		}
		else if (!row.isNull(3)) log(2, L"🔥Firefox download metadata not JSON: " + error);
		records.push_back(std::move(r));
	});
}

void readFirefoxInputs(SqliteDatabase& db, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	// What was typed in the address bar, and the place it led to.
	db.query("SELECT i.input, p.url FROM moz_inputhistory i JOIN moz_places p ON p.id = i.place_id ORDER BY i.input",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"TypedInput");
		r.fields.add(L"Input", Json::str(row.text(0)));
		r.fields.add(L"Url", Json::str(row.text(1)));
		records.push_back(std::move(r));
	});
}

/*! TypedURLs and TypedURLsTime of one profile's NTUSER.DAT.
 *  @param root the hive's root
 *  @param sid the profile
 *  @param records receives one TypedUrl per url<N> value */
void readTypedUrls(ORHKEY root, const std::wstring& sid, std::vector<WebClientRecord>& records) {
	const wchar_t KEY[] = L"Software\\Microsoft\\Internet Explorer\\TypedURLs";
	ORHKEY key = NULL;
	if (OROpenKey(root, KEY, &key) != ERROR_SUCCESS) return;
	const FILETIME written = lastWrite(key);
	// The instants, by the same value names, in the sibling key.
	std::map<unsigned, FILETIME> typed;
	ORHKEY times = NULL;
	if (OROpenKey(root, L"Software\\Microsoft\\Internet Explorer\\TypedURLsTime", &times) == ERROR_SUCCESS) {
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		for (DWORD i = 0; enumRegistryValue(times, i, name, type, data) == ERROR_SUCCESS; ++i)
			if (urlValueNumber(name) && type == REG_BINARY && data.size() == sizeof(FILETIME))
				typed[urlValueNumber(name)] = FILETIME{ readLittleEndian<uint32_t>(data.data()),
				                                        readLittleEndian<uint32_t>(data.data() + 4) };
		ORCloseKey(times);
	}
	std::wstring name;
	DWORD type = 0;
	std::vector<BYTE> data;
	for (DWORD i = 0; enumRegistryValue(key, i, name, type, data) == ERROR_SUCCESS; ++i) {
		const unsigned number = urlValueNumber(name);
		if (!number) continue;
		WebClientRecord r;
		r.type = L"TypedUrl";
		r.sid = sid;
		r.source = L"NTUSER.DAT\\" + std::wstring(KEY);
		r.fields.add(L"Url", Json::str(valueText(type, data)));
		r.fields.add(L"MruPosition", Json::num((long long)number - 1));   // 0: the most recent
		const auto at = typed.find(number);
		if (at != typed.end()) addDate(r.fields, L"Typed", at->second);
		addDate(r.fields, L"KeyLastWrite", written);
		records.push_back(std::move(r));
	}
	ORCloseKey(key);
}

/*! A cell of a record, by its column's name.
 *  @param record the record
 *  @param table its table
 *  @param name the column
 *  @param column receives the column's description
 *  @return the cell, or nullptr if the record has no value there */
const EseCell* cellOf(const EseRecord& record, const EseTable& table, const wchar_t* name, const EseColumn** column) {
	for (const EseColumn& c : table.columns) {
		if (c.name != name) continue;
		*column = &c;
		for (const EseCell& cell : record) if (cell.columnId == c.id) return &cell;
		return nullptr;
	}
	return nullptr;
}

//! @return a text or number column as text, "" if absent or not decoded
std::wstring cellText(const EseRecord& record, const EseTable& table, const wchar_t* name) {
	const EseColumn* column = nullptr;
	const EseCell* cell = cellOf(record, table, name, &column);
	return cell ? eseCellToJson(*column, *cell).text() : L"";
}

//! @return an integer column (Long, LongLong, UnsignedLong…), 0 if absent
int64_t cellInteger(const EseRecord& record, const EseTable& table, const wchar_t* name) {
	const EseColumn* column = nullptr;
	const EseCell* cell = cellOf(record, table, name, &column);
	if (!cell || cell->values.empty() || cell->compressionScheme >= 0) return 0;
	const std::vector<uint8_t>& v = cell->values.front();
	if (v.size() >= 8) return (int64_t)readLittleEndian<uint64_t>(v.data());
	if (v.size() >= 4) return (int64_t)readLittleEndian<uint32_t>(v.data());
	return 0;
}

//! @return a FILETIME column, null if absent or zero
FILETIME cellTime(const EseRecord& record, const EseTable& table, const wchar_t* name) {
	const uint64_t ticks = (uint64_t)cellInteger(record, table, name);
	return filetimeFromTicks(ticks);
}

} // namespace

HRESULT readChromiumLogins(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	// password_value is never selected: it stays encrypted in the exhibit.
	db.query("SELECT origin_url, action_url, signon_realm, username_value, date_created, date_last_used, "
	         "date_password_modified, times_used, blacklisted_by_user FROM logins ORDER BY date_created",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"SavedLogin");
		r.fields.add(L"Origin", Json::str(row.text(0)));
		if (row.text(1) != row.text(0)) r.fields.add(L"Action", Json::str(row.text(1)));
		r.fields.add(L"Realm", Json::str(row.text(2)));
		r.fields.add(L"UserName", Json::str(row.text(3)));
		addDate(r.fields, L"Created", chromiumTime(row.integer(4)));
		addDate(r.fields, L"LastUsed", chromiumTime(row.integer(5)));
		addDate(r.fields, L"PasswordModified", chromiumTime(row.integer(6)));
		r.fields.add(L"TimesUsed", Json::num((long long)row.integer(7)));
		if (row.integer(8)) r.fields.add(L"NeverSave", Json::boolean(true));   // the user refused to save it here
		records.push_back(std::move(r));
	});
	return ERROR_SUCCESS;
}

HRESULT readChromiumCookies(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	// value and encrypted_value are never selected.
	db.query("SELECT host_key, name, path, creation_utc, expires_utc, last_access_utc, is_secure, is_httponly, is_persistent "
	         "FROM cookies ORDER BY creation_utc",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Cookie");
		r.fields.add(L"Host", Json::str(row.text(0)));
		r.fields.add(L"Name", Json::str(row.text(1)));
		r.fields.add(L"Path", Json::str(row.text(2)));
		addDate(r.fields, L"Created", chromiumTime(row.integer(3)));
		addDate(r.fields, L"Expires", chromiumTime(row.integer(4)));
		addDate(r.fields, L"LastAccess", chromiumTime(row.integer(5)));
		r.fields.add(L"Secure", Json::boolean(row.integer(6) != 0));
		r.fields.add(L"HttpOnly", Json::boolean(row.integer(7) != 0));
		if (!row.integer(8)) r.fields.add(L"Session", Json::boolean(true));
		records.push_back(std::move(r));
	});
	return ERROR_SUCCESS;
}

HRESULT readFirefoxLogins(const std::wstring& text, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	Json root = Json::obj();
	std::wstring error;
	if (!Json::parse(text, root, error) || !root.find(L"logins")) {
		log(2, L"🔥logins.json not read: " + error);
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	auto fieldText = [](const Json& o, const wchar_t* key) { const Json* v = o.find(key); return v ? v->text() : std::wstring(); };
	auto milliseconds = [&](const Json& o, const wchar_t* key) {
		return firefoxTime((int64_t)std::wcstoll(fieldText(o, key).c_str(), nullptr, 10) * 1000); };
	for (const auto& member : root.find(L"logins")->members()) {
		const Json& login = member.second;
		WebClientRecord r = startRecord(base, L"SavedLogin");
		r.fields.add(L"Origin", Json::str(fieldText(login, L"hostname")));
		r.fields.add(L"Action", Json::str(fieldText(login, L"formSubmitURL")));
		r.fields.add(L"Realm", Json::str(fieldText(login, L"httpRealm")));
		addDate(r.fields, L"Created", milliseconds(login, L"timeCreated"));
		addDate(r.fields, L"LastUsed", milliseconds(login, L"timeLastUsed"));
		addDate(r.fields, L"PasswordModified", milliseconds(login, L"timePasswordChanged"));
		r.fields.add(L"TimesUsed", Json::num((long long)std::wcstoll(fieldText(login, L"timesUsed").c_str(), nullptr, 10)));
		records.push_back(std::move(r));
	}
	return ERROR_SUCCESS;
}

HRESULT readFirefoxCookies(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	db.query("SELECT host, name, path, creationTime, expiry, lastAccessed, isSecure, isHttpOnly FROM moz_cookies ORDER BY creationTime",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Cookie");
		r.fields.add(L"Host", Json::str(row.text(0)));
		r.fields.add(L"Name", Json::str(row.text(1)));
		r.fields.add(L"Path", Json::str(row.text(2)));
		addDate(r.fields, L"Created", firefoxTime(row.integer(3)));
		addDate(r.fields, L"Expires", firefoxTime(row.integer(4) * 1000000));   // seconds there
		addDate(r.fields, L"LastAccess", firefoxTime(row.integer(5)));
		r.fields.add(L"Secure", Json::boolean(row.integer(6) != 0));
		r.fields.add(L"HttpOnly", Json::boolean(row.integer(7) != 0));
		records.push_back(std::move(r));
	});
	return ERROR_SUCCESS;
}

std::wstring webCacheFile(const std::wstring& directory, const std::wstring& secureDirectories, int64_t index,
                          const std::wstring& filename) {
	const size_t NAME = 8;   // each subfolder's name: 8 characters, no separator
	if (directory.empty() || filename.empty() || index < 1 || (uint64_t)index * NAME > secureDirectories.size()) return L"";
	return directory + secureDirectories.substr((size_t)(index - 1) * NAME, NAME) + L"\\" + filename;
}

namespace {

//! A FAT date-time as written, a clock time without a time zone; "" for none or an impossible one.
std::wstring fatAsWritten(uint32_t value) {
	if (!value) return L"";
	const FILETIME clock = FatDateTime(value).toFileTime();
	std::wstring text = timeToIso8601Utc(clock);
	if (!text.empty() && text.back() == L'Z') text.pop_back();   // no zone: not an instant
	return text;
}

/*! The container of an index.dat, from its folder: Content, History,
 *  MSHist01<from><to>, Cookies, iedownload.
 *  @param path the file's path
 *  @param weekly receives true for a weekly history (its range spans more than a day)
 *  @return the container's name */
std::wstring ieContainer(const std::wstring& path, bool& weekly) {
	weekly = false;
	const std::wstring lower = toLower(path);
	const size_t hist = lower.find(L"\\mshist01");
	if (hist != std::wstring::npos) {
		const std::wstring name = path.substr(hist + 1, 24);   // MSHist01 + two dates
		if (name.size() == 24) {
			SYSTEMTIME a = {}, b = {};
			a.wYear = (WORD)_wtoi(name.substr(8, 4).c_str()); a.wMonth = (WORD)_wtoi(name.substr(12, 2).c_str()); a.wDay = (WORD)_wtoi(name.substr(14, 2).c_str());
			b.wYear = (WORD)_wtoi(name.substr(16, 4).c_str()); b.wMonth = (WORD)_wtoi(name.substr(20, 2).c_str()); b.wDay = (WORD)_wtoi(name.substr(22, 2).c_str());
			FILETIME fa = {}, fb = {};
			if (SystemTimeToFileTime(&a, &fa) && SystemTimeToFileTime(&b, &fb)) {
				const uint64_t ta = ticksFromFiletime(fa), tb = ticksFromFiletime(fb);
				weekly = tb > ta && tb - ta > 864000000000ULL;   // more than one day
			}
		}
		return name;
	}
	if (lower.find(L"\\content.ie5\\") != std::wstring::npos) return L"Content";
	if (lower.find(L"\\history.ie5\\") != std::wstring::npos) return L"History";
	if (lower.find(L"\\iedownloadhistory\\") != std::wstring::npos) return L"iedownload";
	if (lower.find(L"\\cookies\\") != std::wstring::npos) return L"Cookies";
	return L"";
}

} // namespace

HRESULT readIeIndexDat(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	std::vector<uint8_t> bytes;
	if (!readWholeFile(std::filesystem::path(file), IE_INDEX_MAX, bytes)) return HRESULT_FROM_WIN32(ERROR_READ_FAULT);
	IeIndexFile index;
	if (!parseIeIndexDat(bytes.data(), bytes.size(), index)) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	bool weekly = false;
	const std::wstring container = ieContainer(base.source, weekly);
	const std::wstring folder = base.source.substr(0, base.source.find_last_of(L'\\') + 1);
	for (const IeIndexRecord& e : index.records) {
		WebClientRecord r = startRecord(base, L"CacheEntry");
		r.fields.add(L"Container", Json::str(container));
		if (e.kind != L"URL") r.fields.add(L"RecordKind", Json::str(e.kind));   // REDR, LEAK
		if (e.recovered) r.fields.add(L"Recovered", Json::boolean(true));
		r.fields.add(L"Url", Json::str(e.location));
		std::wstring user, page;
		if (splitWebCacheUrl(e.location, user, page)) {
			r.fields.add(L"User", Json::str(user));
			r.fields.add(L"Page", Json::str(page));
		}
		if (e.kind == L"URL") {
			r.fields.add(L"AccessCount", Json::num((long long)e.hits));
			/* The two times by container (libmsiecf): the cache and the cookies,
			   last access then the server's modification; a history, the last
			   visit — in a weekly one the primary is the index's creation, the
			   visit is the secondary, in LOCAL time; the downloads, the start. */
			if (weekly) {
				addDate(r.fields, L"IndexCreated", filetimeFromTicks(e.primaryTime));
				addDate(r.fields, L"Accessed", suspectLocalToUtc(filetimeFromTicks(e.secondaryTime)));
			}
			else if (container == L"iedownload") addDate(r.fields, L"Created", filetimeFromTicks(e.primaryTime));
			else {
				addDate(r.fields, L"Accessed", filetimeFromTicks(e.primaryTime));
				if (container == L"Content" || container == L"Cookies") addDate(r.fields, L"Modified", filetimeFromTicks(e.secondaryTime));
			}
			r.fields.add(L"ExpiresAsWritten", Json::str(fatAsWritten(e.expiry)));
			r.fields.add(L"LastCheckedAsWritten", Json::str(fatAsWritten(e.lastChecked)));
			r.fields.add(L"Flags", Json::str(L"0x" + to_hex(e.flags, 8)));
			// A cache entry's data: the server's response headers, text.
			if (e.data.size() > 5 && std::memcmp(e.data.data(), "HTTP/", 5) == 0) {
				size_t end = e.data.size();
				while (end > 0 && e.data[end - 1] == 0) --end;
				r.fields.add(L"ResponseHeaders", Json::str(decodeText(std::string(e.data.begin(), e.data.begin() + end))));
			}
		}
		r.fields.add(L"Filename", Json::str(e.filename));
		if (e.cacheDirectory >= 0 && (size_t)e.cacheDirectory < index.cacheDirectories.size() && !e.filename.empty())
			r.fields.add(L"CachedFile", Json::str(folder + index.cacheDirectories[e.cacheDirectory] + L"\\" + e.filename));
		if (e.fileSize) r.fields.add(L"FileSize", Json::num((unsigned long long)e.fileSize));
		records.push_back(std::move(r));
	}
	return ERROR_SUCCESS;
}

namespace {

//! Where a layout of the iedownload record puts the server's address and the strings.
struct IeDownloadLayout {
	uint32_t version;  //!< the record's first DWORD
	size_t address;    //!< address family, then the IPv4 address
	size_t strings;    //!< the four UTF-16 strings
};

/* The layouts measured: Internet Explorer 11 of Windows 8.1 (version 0x89)
   writes the address and the strings 8 bytes before that of Windows 11
   (0x8C); the size is at 0x50 in both. Another version is not guessed. */
const IeDownloadLayout IE_DOWNLOAD_LAYOUTS[] = { { 0x8C, 0xA0, 0x158 }, { 0x89, 0x98, 0x150 } };

} // namespace

bool decodeIeDownload(const std::vector<uint8_t>& blob, Json& fields) {
	const size_t SIZE = 0x50;
	if (blob.size() < 4) return false;
	const uint32_t version = readLittleEndian<uint32_t>(blob.data());
	const IeDownloadLayout* layout = nullptr;
	for (const IeDownloadLayout& l : IE_DOWNLOAD_LAYOUTS) if (l.version == version) layout = &l;
	if (!layout) return false;
	const size_t ADDRESS = layout->address, STRINGS = layout->strings;
	if (blob.size() <= STRINGS) return false;
	// The four strings, each ending with its NUL, within the blob.
	std::vector<std::wstring> strings;
	for (size_t at = STRINGS; strings.size() < 4 && at + 2 <= blob.size();) {
		std::wstring text;
		size_t end = at;
		while (end + 2 <= blob.size() && readLittleEndian<uint16_t>(blob.data() + end) != 0) {
			text += (wchar_t)readLittleEndian<uint16_t>(blob.data() + end);
			end += 2;
		}
		if (end + 2 > blob.size()) break;   // no terminator: not that layout
		strings.push_back(text);
		at = end + 2;
	}
	if (strings.size() < 4 || strings[2].find(L"://") == std::wstring::npos) return false;
	fields.add(L"Url", Json::str(strings[2]));
	fields.add(L"MimeType", Json::str(strings[0]));
	fields.add(L"CachePath", Json::str(strings[1]));
	// A full path once saved, the name it would take otherwise.
	const bool path = strings[3].size() > 2 && strings[3][1] == L':' && strings[3][2] == L'\\';
	fields.add(path ? L"TargetPath" : L"SuggestedName", Json::str(strings[3]));
	fields.add(L"FileSize", Json::num((unsigned long long)readLittleEndian<uint64_t>(blob.data() + SIZE)));
	/* A sockaddr_in: the family on 16 bits (AF_INET), the port, then the
	   address in network order. The family read on 32 bits took the port
	   with it, and a server on another port than 0 lost its address
	   (Windows 8, measured: port 8765). */
	if (readLittleEndian<uint16_t>(blob.data() + ADDRESS) == 2) {
		const uint8_t* ip = blob.data() + ADDRESS + 4;
		fields.add(L"ServerAddress", Json::str(std::to_wstring(ip[0]) + L"." + std::to_wstring(ip[1]) + L"."
		                                       + std::to_wstring(ip[2]) + L"." + std::to_wstring(ip[3])));
	}
	return true;
}

bool splitWebCacheUrl(const std::wstring& url, std::wstring& user, std::wstring& page) {
	size_t start = std::wstring::npos;
	if (url.compare(0, 9, L"Visited: ") == 0) start = 9;
	else if (url.size() > 2 && url[0] == L':') {
		const size_t close = url.find(L": ", 1);
		if (close != std::wstring::npos && url.find_first_not_of(L"0123456789", 1) == close) start = close + 2;
	}
	if (start == std::wstring::npos) return false;
	const size_t at = url.find(L'@', start);
	if (at == std::wstring::npos) return false;
	user = url.substr(start, at - start);
	page = url.substr(at + 1);
	return true;
}

HRESULT readWebCache(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	EseDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	const EseTable* containers = db.table(L"Containers");
	if (!containers) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	for (const EseRecord& c : db.records(*containers)) {
		const int64_t id = cellInteger(c, *containers, L"ContainerId");
		const std::wstring name = cellText(c, *containers, L"Name");
		const std::wstring directory = cellText(c, *containers, L"Directory");
		const std::wstring secureDirectories = cellText(c, *containers, L"SecureDirectories");
		const EseTable* table = db.table(L"Container_" + std::to_wstring(id));
		if (!table) continue;   // the cookies' containers keep their entries in CookieEntryEx_<n>
		// The daily and weekly history write their modification time in local time.
		const bool localModified = name.compare(0, 6, L"MSHist") == 0;
		for (const EseRecord& e : db.records(*table)) {
			WebClientRecord r = startRecord(base, L"CacheEntry");
			r.fields.add(L"Container", Json::str(name));
			r.fields.add(L"ContainerId", Json::num((long long)id));
			r.fields.add(L"EntryId", Json::num((long long)cellInteger(e, *table, L"EntryId")));
			const std::wstring url = cellText(e, *table, L"Url");
			r.fields.add(L"Url", Json::str(url));
			std::wstring user, page;
			if (splitWebCacheUrl(url, user, page)) {
				r.fields.add(L"User", Json::str(user));
				r.fields.add(L"Page", Json::str(page));
			}
			r.fields.add(L"AccessCount", Json::num((long long)cellInteger(e, *table, L"AccessCount")));
			const FILETIME modified = cellTime(e, *table, L"ModifiedTime");
			addDate(r.fields, L"Modified", localModified ? suspectLocalToUtc(modified) : modified);
			addDate(r.fields, L"Accessed", cellTime(e, *table, L"AccessedTime"));
			addDate(r.fields, L"Created", cellTime(e, *table, L"CreationTime"));
			addDate(r.fields, L"Expiry", cellTime(e, *table, L"ExpiryTime"));
			addDate(r.fields, L"Sync", cellTime(e, *table, L"SyncTime"));
			const std::wstring filename = cellText(e, *table, L"Filename");
			r.fields.add(L"Filename", Json::str(filename));
			r.fields.add(L"CachedFile", Json::str(webCacheFile(directory, secureDirectories,
			                                                   cellInteger(e, *table, L"SecureDirectory"), filename)));
			if (const int64_t size = cellInteger(e, *table, L"FileSize")) r.fields.add(L"FileSize", Json::num((long long)size));
			r.fields.add(L"RedirectUrl", Json::str(cellText(e, *table, L"RedirectUrl")));
			// A download of Internet Explorer: its URL, file and path are in a blob of its own.
			if (name == L"iedownload") {
				const EseColumn* column = nullptr;
				const EseCell* blob = cellOf(e, *table, L"ResponseHeaders", &column);
				Json download = Json::obj();
				if (blob && !blob->values.empty() && blob->compressionScheme < 0 && decodeIeDownload(blob->values.front(), download))
					r.fields.add(L"Download", std::move(download));
				else log(2, L"🔥iedownload entry without the known layout: " + url);
			}
			records.push_back(std::move(r));
		}
	}
	if (db.dirtyShutdown()) log(2, L"❇️WebCache copied live (dirty): the last entries may be in its logs only — " + base.source);
	return ERROR_SUCCESS;
}

FILETIME firefoxTime(int64_t microseconds) {
	if (microseconds <= 0) return FILETIME{ 0, 0 };
	return chromiumTime((int64_t)((uint64_t)microseconds + MICROSECONDS_1601_TO_1970));
}

std::wstring firefoxVisitType(int64_t type) {
	return type >= 1 && type <= (int64_t)(sizeof(FIREFOX_VISIT_TYPES) / sizeof(FIREFOX_VISIT_TYPES[0]))
	       ? FIREFOX_VISIT_TYPES[type - 1] : std::to_wstring(type);
}

std::wstring fileUriToPath(const std::wstring& uri) {
	const std::wstring PREFIX = L"file:///";
	if (toLower(uri.substr(0, PREFIX.size())) != PREFIX) return uri;
	std::wstring path = decodeText(decodeURIComponent(encodeText(uri.substr(PREFIX.size()))), CP_UTF8);
	for (wchar_t& c : path) if (c == L'/') c = L'\\';
	return path;
}

HRESULT readFirefoxPlaces(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	readFirefoxUrls(db, base, records);
	readFirefoxVisits(db, base, records);
	readFirefoxDownloads(db, base, records);
	readFirefoxInputs(db, base, records);
	return ERROR_SUCCESS;
}

HRESULT readFirefoxFormHistory(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	db.query("SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory ORDER BY firstUsed, id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"FormEntry");
		r.fields.add(L"FieldName", Json::str(row.text(0)));
		r.fields.add(L"Value", Json::str(row.text(1)));
		r.fields.add(L"TimesUsed", Json::num((long long)row.integer(2)));
		addDate(r.fields, L"FirstUsed", firefoxTime(row.integer(3)));
		addDate(r.fields, L"LastUsed", firefoxTime(row.integer(4)));
		records.push_back(std::move(r));
	});
	return ERROR_SUCCESS;
}

bool isChromiumProfile(const std::vector<std::wstring>& names) {
	for (const std::wstring& n : names)
		if (toLower(n) == L"history" || toLower(n) == L"preferences") return true;
	return false;
}

FILETIME chromiumTime(int64_t microseconds) {
	// A FILETIME counts 100 ns from the same origin: ten per microsecond.
	if (microseconds <= 0 || microseconds > INT64_MAX / 10) return FILETIME{ 0, 0 };
	const uint64_t ticks = (uint64_t)microseconds * 10;
	return filetimeFromTicks(ticks);
}

std::wstring transitionCore(int64_t transition) {
	const int64_t core = transition & TRANSITION_CORE_MASK;
	return core < (int64_t)(sizeof(TRANSITION_CORES) / sizeof(TRANSITION_CORES[0]))
	       ? TRANSITION_CORES[core] : std::to_wstring(core);
}

std::wstring transitionQualifiers(int64_t transition) {
	std::wstring text;
	int64_t rest = transition & ~TRANSITION_CORE_MASK & 0xFFFFFFFFLL;
	for (const auto& q : TRANSITION_QUALIFIERS)
		if (rest & q.bit) {
			text += (text.empty() ? L"" : L", ") + std::wstring(q.name);
			rest &= ~q.bit;
		}
	if (rest) text += (text.empty() ? L"0x" : L", 0x") + to_hex(rest, 8);   // a bit Chromium does not define here
	return text;
}

Json WebClientRecord::toJson() const {
	Json o = Json::obj();
	o.add(L"Type", Json::str(type));
	o.add(L"Browser", Json::str(browser));
	o.add(L"BrowserProfile", Json::str(browserProfile));
	addUser(o, sid);
	o.add(L"Source", Json::str(source));
	o.merge(fields);
	return o;
}

HRESULT readChromiumHistory(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	// Each table on its own: a version without one still gives the others.
	readUrls(db, base, records);
	readVisits(db, base, records);
	readDownloads(db, base, records);
	readSearchTerms(db, base, records);
	return ERROR_SUCCESS;
}

HRESULT readChromiumSessions(const std::wstring& folder, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	std::error_code ec;
	if (!std::filesystem::is_directory(folder, ec)) return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
	std::vector<std::filesystem::path> files;
	for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(folder, ec))
		if (e.is_regular_file(ec)) files.push_back(e.path());
	std::sort(files.begin(), files.end());   // Session_<time> and Tabs_<time>: in the order they were written
	for (const std::filesystem::path& file : files) {
		const std::wstring name = file.filename().wstring();
		const bool tabs = name.compare(0, 5, L"Tabs_") == 0;
		if (!tabs && name.compare(0, 8, L"Session_") != 0) continue;
		std::vector<uint8_t> bytes;
		SnssContents contents;
		WebClientRecord fileBase = base;
		fileBase.source = originalPath(file.wstring());
		if (!readWholeFile(file, SESSION_FILE_MAX, bytes)
		    || !decodeSnss(bytes.data(), bytes.size(), tabs ? SnssKind::TabRestore : SnssKind::Session, contents)) {
			log(2, L"🔥Session file not read: " + fileBase.source);
			continue;
		}
		for (const SnssNavigation& n : contents.navigations) {
			WebClientRecord r = startRecord(fileBase, L"SessionEntry");
			r.fields.add(L"State", Json::str(tabs ? L"Closed" : L"Open"));
			r.fields.add(L"Tab", Json::num((long long)n.tab));
			r.fields.add(L"NavigationIndex", Json::num((long long)n.index));
			r.fields.add(L"Url", Json::str(decodeText(n.url, CP_UTF8)));
			r.fields.add(L"Title", Json::str(n.title));
			addDate(r.fields, L"Navigated", chromiumTime(n.time));
			if (n.time) {
				r.fields.add(L"Transition", Json::str(transitionCore(n.transition)));
				r.fields.add(L"TransitionQualifiers", Json::str(transitionQualifiers(n.transition)));
			}
			if (n.httpStatus) r.fields.add(L"HttpStatus", Json::num((long long)n.httpStatus));
			r.fields.add(L"Referrer", Json::str(decodeText(n.referrer, CP_UTF8)));
			if (n.originalUrl != n.url) r.fields.add(L"OriginalUrl", Json::str(decodeText(n.originalUrl, CP_UTF8)));
			const auto closed = contents.closedTimes.find(n.tab);
			if (closed != contents.closedTimes.end()) {
				addDate(r.fields, L"Closed", chromiumTime(closed->second));
				r.fields.add(L"Shown", Json::boolean(contents.selectedIndex[n.tab] == n.index));
			}
			records.push_back(std::move(r));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT readChromiumFavicons(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	// One row per page and icon; the bitmaps' times, the latest of the icon's sizes. The image is not read.
	db.query("SELECT icon_mapping.page_url, favicons.url, MAX(favicon_bitmaps.last_updated), MAX(favicon_bitmaps.last_requested) "
	         "FROM icon_mapping JOIN favicons ON favicons.id = icon_mapping.icon_id "
	         "LEFT JOIN favicon_bitmaps ON favicon_bitmaps.icon_id = favicons.id "
	         "GROUP BY icon_mapping.id ORDER BY icon_mapping.id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Favicon");
		r.fields.add(L"PageUrl", Json::str(row.text(0)));
		r.fields.add(L"IconUrl", Json::str(row.text(1)));
		addDate(r.fields, L"IconUpdated", chromiumTime(row.integer(2)));
		addDate(r.fields, L"IconRequested", chromiumTime(row.integer(3)));
		records.push_back(std::move(r));
	});
	return ERROR_SUCCESS;
}

HRESULT readChromiumPredictor(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	db.query("SELECT user_text, url, number_of_hits, number_of_misses FROM network_action_predictor ORDER BY user_text, url",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"AddressBarPrediction");
		r.fields.add(L"TypedText", Json::str(row.text(0)));
		r.fields.add(L"Url", Json::str(row.text(1)));
		r.fields.add(L"Hits", Json::num((long long)row.integer(2)));
		r.fields.add(L"Misses", Json::num((long long)row.integer(3)));
		records.push_back(std::move(r));
	});
	return ERROR_SUCCESS;
}

namespace {

//! A whole number of a Firefox session's JSON; 0 if absent.
long long jsonInteger(const Json& o, const wchar_t* key) {
	const Json* v = o.find(key);
	return v ? std::wcstoll(v->text().c_str(), nullptr, 10) : 0;
}

/*! The entries of one tab of a Firefox session, as SessionEntry records.
 *  @param tab the tab's object (entries, index from 1, lastAccessed in milliseconds)
 *  @param state Open, ClosedTab or ClosedWindow
 *  @param closedMs when the tab or its window was closed, milliseconds since 1970; 0 if open */
void firefoxTab(const Json& tab, const WebClientRecord& base, const std::wstring& state, size_t window, size_t number,
                long long closedMs, std::vector<WebClientRecord>& records) {
	const Json* entries = tab.find(L"entries");
	if (!entries) return;
	const long long shown = jsonInteger(tab, L"index") - 1;
	long long index = 0;
	for (const auto& member : entries->members()) {
		const Json& entry = member.second;
		WebClientRecord r = startRecord(base, L"SessionEntry");
		r.fields.add(L"State", Json::str(state));
		r.fields.add(L"Window", Json::num((unsigned long long)window));
		r.fields.add(L"Tab", Json::num((unsigned long long)number));
		r.fields.add(L"NavigationIndex", Json::num(index));
		const Json* url = entry.find(L"url");
		const Json* title = entry.find(L"title");
		if (url) r.fields.add(L"Url", Json::str(url->text()));
		if (title) r.fields.add(L"Title", Json::str(title->text()));
		r.fields.add(L"Shown", Json::boolean(index == shown));
		addDate(r.fields, L"TabLastAccessed", firefoxTime(jsonInteger(tab, L"lastAccessed") * 1000));
		addDate(r.fields, L"Closed", firefoxTime(closedMs * 1000));
		records.push_back(std::move(r));
		++index;
	}
}

/*! The tabs of one Firefox window, open and closed. */
void firefoxWindow(const Json& w, const WebClientRecord& base, bool closedWindow, size_t number,
                   std::vector<WebClientRecord>& records) {
	const long long windowClosed = closedWindow ? jsonInteger(w, L"closedAt") : 0;
	if (const Json* tabs = w.find(L"tabs")) {
		size_t tab = 0;
		for (const auto& member : tabs->members())
			firefoxTab(member.second, base, closedWindow ? L"ClosedWindow" : L"Open", number, tab++, windowClosed, records);
	}
	if (const Json* closedTabs = w.find(L"_closedTabs")) {
		size_t tab = 0;
		for (const auto& member : closedTabs->members())
			if (const Json* state = member.second.find(L"state"))
				firefoxTab(*state, base, L"ClosedTab", number, tab++, jsonInteger(member.second, L"closedAt"), records);
	}
}

} // namespace

HRESULT readFirefoxSession(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	std::vector<uint8_t> bytes, json;
	if (!readWholeFile(std::filesystem::path(file), SESSION_FILE_MAX, bytes)) return HRESULT_FROM_WIN32(ERROR_READ_FAULT);
	if (!decompressMozLz4(bytes.data(), bytes.size(), (size_t)SESSION_FILE_MAX, json)) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	Json root = Json::obj();
	std::wstring error;
	if (!Json::parse(decodeText(std::string(json.begin(), json.end()), CP_UTF8), root, error)) {
		log(2, L"🔥Firefox session not read: " + error);
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	size_t window = 0;
	if (const Json* windows = root.find(L"windows"))
		for (const auto& member : windows->members()) firefoxWindow(member.second, base, false, window++, records);
	if (const Json* closed = root.find(L"_closedWindows"))
		for (const auto& member : closed->members()) firefoxWindow(member.second, base, true, window++, records);
	return ERROR_SUCCESS;
}

HRESULT readFirefoxFavicons(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records) {
	SqliteDatabase db;
	const HRESULT opened = db.open(file);
	if (opened != ERROR_SUCCESS) return opened;
	// One row per page and icon; when the link expires (milliseconds since 1970). The image is not read.
	db.query("SELECT moz_pages_w_icons.page_url, moz_icons.icon_url, moz_icons_to_pages.expire_ms "
	         "FROM moz_icons_to_pages JOIN moz_pages_w_icons ON moz_pages_w_icons.id = moz_icons_to_pages.page_id "
	         "JOIN moz_icons ON moz_icons.id = moz_icons_to_pages.icon_id ORDER BY moz_pages_w_icons.id, moz_icons.id",
	         [&](const SqliteRow& row) {
		WebClientRecord r = startRecord(base, L"Favicon");
		r.fields.add(L"PageUrl", Json::str(row.text(0)));
		r.fields.add(L"IconUrl", Json::str(row.text(1)));
		addDate(r.fields, L"Expires", firefoxTime(row.integer(2) * 1000));
		records.push_back(std::move(r));
	});
	return ERROR_SUCCESS;
}

HRESULT WebClient::getData() {
	log(0, L"ℹ️Web client (browsers) :");
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
		for (size_t i = 0; i < CHROMIUM_ROOT_COUNT; ++i) {
			const std::filesystem::path root = extractedPath(std::get<1>(profileEntry) + CHROMIUM_ROOTS[i].relative);
			std::error_code ec;
			if (!std::filesystem::is_directory(root, ec)) continue;
			std::vector<std::filesystem::path> folders = { root };
			for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(root, ec))
				if (e.is_directory(ec)) folders.push_back(e.path());
			for (const std::filesystem::path& folder : folders) {
				const std::filesystem::path history = folder / L"History";
				if (!std::filesystem::is_regular_file(history, ec)) continue;
				WebClientRecord base;
				base.browser = CHROMIUM_ROOTS[i].browser;
				base.browserProfile = folder == root ? L"" : folder.filename().wstring();
				base.sid = std::get<0>(profileEntry);
				base.source = originalPath(history.wstring());
				if (readChromiumHistory(history.wstring(), base, records_) != ERROR_SUCCESS)
					log(2, L"🔥History not read: " + base.source);
				const std::filesystem::path logins = folder / L"Login Data";
				if (std::filesystem::is_regular_file(logins, ec)) {
					base.source = originalPath(logins.wstring());
					if (readChromiumLogins(logins.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥Login Data not read: " + base.source);
				}
				// Network\Cookies since Chromium 96, Cookies before.
				for (const std::filesystem::path& cookies : { folder / L"Network" / L"Cookies", folder / L"Cookies" }) {
					if (!std::filesystem::is_regular_file(cookies, ec)) continue;
					base.source = originalPath(cookies.wstring());
					if (readChromiumCookies(cookies.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥Cookies not read: " + base.source);
					break;
				}
				const std::filesystem::path favicons = folder / L"Favicons", predictor = folder / L"Network Action Predictor";
				if (std::filesystem::is_regular_file(favicons, ec)) {
					base.source = originalPath(favicons.wstring());
					if (readChromiumFavicons(favicons.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥Favicons not read: " + base.source);
				}
				if (std::filesystem::is_regular_file(predictor, ec)) {
					base.source = originalPath(predictor.wstring());
					if (readChromiumPredictor(predictor.wstring(), base, records_) != ERROR_SUCCESS)
						log(2, L"🔥Network Action Predictor not read: " + base.source);
				}
				const HRESULT sessions = readChromiumSessions((folder / L"Sessions").wstring(), base, records_);
				if (FAILED(sessions) && sessions != HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND))   // no Sessions folder: no session kept
					log(2, L"🔥Sessions not read: " + base.source);
			}
		}
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) { readTypedUrls(root, sid, records_); });
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
		for (const IeIndexFolder& f : IE_INDEX_FOLDERS) {
			const std::filesystem::path root = extractedPath(std::get<1>(profileEntry) + f.relative);
			std::error_code ec;
			std::filesystem::recursive_directory_iterator it(root, ec), end;
			for (; !ec && it != end; it.increment(ec)) {
				if (it.depth() > 1) { it.disable_recursion_pending(); continue; }   // MSHist01…\index.dat: one level
				if (!it->is_regular_file(ec) || toLower(it->path().filename().wstring()) != L"index.dat") continue;
				WebClientRecord base;
				base.browser = L"Internet Explorer";
				base.sid = std::get<0>(profileEntry);
				base.source = originalPath(it->path().wstring());
				if (readIeIndexDat(it->path().wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥index.dat not read: " + base.source);
			}
		}
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::filesystem::path cache = extractedPath(std::get<1>(profileEntry) + WEBCACHE_FOLDER + L"\\WebCacheV01.dat");
		std::error_code ec;
		if (!std::filesystem::is_regular_file(cache, ec)) continue;
		WebClientRecord base;
		base.browser = L"WebCache";
		base.sid = std::get<0>(profileEntry);
		base.source = originalPath(cache.wstring());
		/* Its latest entries may still be in its transaction logs, collected
		   with it: replayed into the copy first (B-046). */
		const EseReplay replayed = ReplayEseLogsOnce(cache.wstring(), base.source);
		if (replayed.attempted && !replayed.applied)
			log(1, L"⚠️WebCache logs not replayed: its latest entries may be missing — " + base.source);
		if (readWebCache(cache.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥WebCache not read: " + base.source);
	}
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::filesystem::path root = extractedPath(std::get<1>(profileEntry) + FIREFOX_PROFILES);
		std::error_code ec;
		for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(root, ec)) {
			if (!e.is_directory(ec)) continue;
			WebClientRecord base;
			base.browser = L"Firefox";
			base.browserProfile = e.path().filename().wstring();
			base.sid = std::get<0>(profileEntry);
			const std::filesystem::path places = e.path() / L"places.sqlite", forms = e.path() / L"formhistory.sqlite";
			if (std::filesystem::is_regular_file(places, ec)) {
				base.source = originalPath(places.wstring());
				if (readFirefoxPlaces(places.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥places.sqlite not read: " + base.source);
			}
			if (std::filesystem::is_regular_file(forms, ec)) {
				base.source = originalPath(forms.wstring());
				if (readFirefoxFormHistory(forms.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥formhistory.sqlite not read: " + base.source);
			}
			const std::filesystem::path cookies = e.path() / L"cookies.sqlite", logins = e.path() / L"logins.json";
			if (std::filesystem::is_regular_file(cookies, ec)) {
				base.source = originalPath(cookies.wstring());
				if (readFirefoxCookies(cookies.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥cookies.sqlite not read: " + base.source);
			}
			if (std::filesystem::is_regular_file(logins, ec)) {
				base.source = originalPath(logins.wstring());
				std::string bytes;
				if (readWholeFile(logins, LOGINS_MAX, bytes)) readFirefoxLogins(decodeText(bytes, CP_UTF8), base, records_);
				else log(2, L"🔥logins.json unreadable or larger than 64 MiB: " + base.source);
			}
			const std::filesystem::path favicons = e.path() / L"favicons.sqlite";
			if (std::filesystem::is_regular_file(favicons, ec)) {
				base.source = originalPath(favicons.wstring());
				if (readFirefoxFavicons(favicons.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥favicons.sqlite not read: " + base.source);
			}
			// The session, and its backups: the previous session, the one before an upgrade.
			std::vector<std::filesystem::path> sessions = { e.path() / L"sessionstore.jsonlz4" };
			for (const std::filesystem::directory_entry& b : std::filesystem::directory_iterator(e.path() / L"sessionstore-backups", ec))
				if (b.is_regular_file(ec)) sessions.push_back(b.path());
			for (const std::filesystem::path& session : sessions) {
				if (!std::filesystem::is_regular_file(session, ec)) continue;
				base.source = originalPath(session.wstring());
				if (readFirefoxSession(session.wstring(), base, records_) != ERROR_SUCCESS) log(2, L"🔥Firefox session not read: " + base.source);
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT WebClient::toJson() {
	Json list = Json::arr();
	for (const WebClientRecord& r : records_) list.push(r.toJson());
	return writeJsonFile("web_client.json", list);
}

void WebClient::clear() {
	records_.clear();
}
