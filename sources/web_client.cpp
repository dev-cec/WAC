/*! \file
 *  \brief The web, client side (see web_client.h).
 */
#include "web_client.h"
#include "sqlite_reader.h"
#include "registry_common.h"
#include <filesystem>
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
	L"Preferences", L"Secure Preferences", L"Cookies", L"Network\\Cookies" };
const std::vector<std::wstring> CHROMIUM_ROOT_FILES = { L"Local State" };
const wchar_t FIREFOX_PROFILES[] = L"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles";
const std::vector<std::wstring> FIREFOX_PROFILE_FILES = {
	L"places.sqlite", L"formhistory.sqlite", L"cookies.sqlite", L"permissions.sqlite", L"logins.json",
	L"key4.db", L"extensions.json", L"prefs.js", L"sessionstore.jsonlz4" };

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
const uint64_t MICROSECONDS_1601_TO_1970 = 11644473600ULL * 1000000ULL;

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

} // namespace

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
	return FILETIME{ (DWORD)(ticks & 0xFFFFFFFFULL), (DWORD)(ticks >> 32) };
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

HRESULT WebClient::getData() {
	log(0, L"ℹ️Web client (browsers) :");
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles)
		for (size_t i = 0; i < CHROMIUM_ROOT_COUNT; ++i) {
			const std::filesystem::path root = extractedPath(std::get<1>(profileEntry)) + CHROMIUM_ROOTS[i].relative;
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
			}
		}
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) { readTypedUrls(root, sid, records_); });
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::filesystem::path root = extractedPath(std::get<1>(profileEntry)) + FIREFOX_PROFILES;
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
