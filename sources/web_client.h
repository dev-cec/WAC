/*! \file
 *  \brief The web, client side: what each user did in the Chromium browsers (Edge, Chrome, Brave, Vivaldi, Opera) and Firefox.
 *
 *  WHAT THE ARTEFACT PROVES. The `History` database of each browser profile
 *  holds the pages visited — each visit with its instant, how it was reached
 *  (typed, a link, a bookmark, a redirect: `Transition`) and from which
 *  visit —, the terms searched in the address bar, and the files downloaded:
 *  where from (the whole chain of redirections, the referrer, the tab), where
 *  to, how many bytes, whether the download was flagged dangerous, whether it
 *  was opened. A downloaded tool, the page that served it and the user's
 *  search before it are read here.
 *
 *  WHAT IS COLLECTED, RAW. For every Chromium profile of every user: History,
 *  and beside it the databases this artefact does not convert yet but the
 *  analysis may — Login Data (saved logins, their passwords encrypted by the
 *  key of `Local State`, itself protected by DPAPI: see
 *  dpapi_master_keys.h), Web Data (autofill), Cookies, Shortcuts, Top Sites,
 *  Bookmarks, Preferences —, each with its -journal or -wal. Never the
 *  caches. The databases are read on a private copy (sqlite_reader.h).
 *
 *  TIMES. Chromium counts microseconds since 1601-01-01 UTC — FILETIME's
 *  origin, a tenth of its resolution: converted exactly, without a time zone.
 *
 *  FIREFOX. `places.sqlite` holds the same story under other names — places,
 *  visits with a visit type, downloads as annotations of the place they came
 *  from — and `formhistory.sqlite` what was typed in forms and the search bar.
 *  Its times are microseconds since 1970 (milliseconds for a download's end).
 *  Collected raw beside them: cookies, logins.json and key4.db (saved
 *  logins, encrypted), extensions, preferences, the session.
 *
 *  SAVED LOGINS AND COOKIES, NEVER THEIR SECRETS. Chromium's `Login Data`
 *  and Firefox's `logins.json` say on which sites the user saved a login,
 *  under which account name (Chromium keeps it in clear, Firefox encrypted),
 *  since when and how often used; the cookies, which sites set one and when
 *  it was last sent. Passwords and cookie values are encrypted and are NOT
 *  decoded: the databases are in the exhibit store for an analysis that holds
 *  the user's DPAPI key (dpapi_master_keys.h).
 *
 *  TYPED URLS. What was typed in Internet Explorer's address bar — and in
 *  File Explorer's, which writes there too: `TypedURLs` of each NTUSER.DAT,
 *  url1 the most recent, and `TypedURLsTime` the instant of each (Windows 8
 *  and later).
 *
 *  WEBCACHE. Internet Explorer, Edge Legacy and the applications built on
 *  WinINet keep their history, their cache and their downloads in one ESE
 *  database per user, `WebCacheV01.dat`. Its `Containers` table names each
 *  `Container_<n>`: History, the daily and weekly `MSHist…`, Content (the
 *  cache: the page or file each entry stored), iedownload,
 *  BackgroundTransferApi. Each entry gives its URL and its times as FILETIME
 *  — in UTC, EXCEPT the modification time of the `MSHist` containers,
 *  written in the machine's local time: 7,200 s apart from the same entry of
 *  `History` in summer on the test VM. It is converted with the offset in
 *  force at its date (suspectLocalToUtc), never read as UTC. The database is
 *  copied live, in "dirty" state: what WinINet wrote since its last
 *  checkpoint is only in its logs, collected beside it (esentutl /r).
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! A Chromium browser's user data folder, relative to a profile. */
struct ChromiumRoot {
	const wchar_t* relative;   //!< e.g. \\AppData\\Local\\Microsoft\\Edge\\User Data
	const wchar_t* browser;    //!< its name in the JSON
};

//! The Chromium browsers looked for in every profile.
extern const ChromiumRoot CHROMIUM_ROOTS[];
//! Number of entries of CHROMIUM_ROOTS.
extern const size_t CHROMIUM_ROOT_COUNT;
/*! The files collected in a browser profile folder, relative to it; each with
 *  its -journal and -wal when present. */
extern const std::vector<std::wstring> CHROMIUM_PROFILE_FILES;
/*! The files collected at the root of a browser's user data (Local State:
 *  the key that encrypts the saved passwords and cookies, under DPAPI). */
extern const std::vector<std::wstring> CHROMIUM_ROOT_FILES;

//! The WebCache folder of Internet Explorer and Edge Legacy, relative to a Windows profile.
extern const wchar_t WEBCACHE_FOLDER[];
//! Firefox's profiles folder, relative to a Windows profile; each subfolder is a Firefox profile.
extern const wchar_t FIREFOX_PROFILES[];
//! The files collected in a Firefox profile, each with its -wal and -journal when present.
extern const std::vector<std::wstring> FIREFOX_PROFILE_FILES;

/*! A Firefox time — microseconds since 1970-01-01 UTC — as a FILETIME.
 *  @param microseconds the value; 0 or negative for none
 *  @return the FILETIME, null for none */
FILETIME firefoxTime(int64_t microseconds);

/*! The name of a Firefox visit type (nsINavHistoryService): link, typed,
 *  bookmark, embed, redirect_permanent, redirect_temporary, download,
 *  framed_link, reload.
 *  @param type the column's value
 *  @return the name, or the number for a type Firefox does not define */
std::wstring firefoxVisitType(int64_t type);

/*! The local path of a `file:///` URI, as Firefox records a download's destination.
 *  @param uri the URI, percent-encoded UTF-8
 *  @return the path with backslashes, or the URI unchanged if it is no file URI */
std::wstring fileUriToPath(const std::wstring& uri);

/*! Whether a folder of a browser's user data is a browser profile: it holds
 *  a History or a Preferences file.
 *  @param names the names of the folder's files
 *  @return true for a profile (Default, Profile 1, Guest Profile, Opera's root…) */
bool isChromiumProfile(const std::vector<std::wstring>& names);

/*! A Chromium time — microseconds since 1601-01-01 UTC — as a FILETIME.
 *  @param microseconds the value; 0 or negative for none
 *  @return the FILETIME, null for none (then not emitted) */
FILETIME chromiumTime(int64_t microseconds);

/*! The core type of a visit's transition, Chromium's ui::PageTransition
 *  (the low byte): link, typed, auto_bookmark, auto_subframe, manual_subframe,
 *  generated, auto_toplevel, form_submit, reload, keyword, keyword_generated.
 *  @param transition the column's value
 *  @return the name, or the number for a core type Chromium does not define */
std::wstring transitionCore(int64_t transition);

/*! The qualifiers of a transition (the high bits): forward_back, from_address_bar,
 *  home_page, from_api, chain_start, chain_end, client_redirect,
 *  server_redirect. An unknown bit is given in hexadecimal.
 *  @param transition the column's value
 *  @return the qualifiers, comma-separated, empty for none */
std::wstring transitionQualifiers(int64_t transition);

/*! One record of web_client.json: a URL, a visit, a download or a search term. */
struct WebClientRecord {
	std::wstring type;              //!< Url, Visit, Download, SearchTerm, TypedInput, FormEntry, SavedLogin, Cookie, TypedUrl (NTUSER.DAT), CacheEntry (WebCache)
	std::wstring browser;           //!< Edge, Chrome…
	std::wstring browserProfile;    //!< the profile folder: Default, Profile 1…
	std::wstring sid;               //!< the Windows profile it belongs to
	std::wstring source;            //!< the database, on the examined machine
	Json fields = Json::obj();      //!< the record's own fields
	//! @return the record as a JSON object
	Json toJson() const;
};

/*! Reads one Chromium History database.
 *  @param file the database, in the working copy
 *  @param base browser, profile, SID and source copied into each record
 *  @param records receives the URLs, visits, downloads and search terms
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readChromiumHistory(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! Reads one Firefox places.sqlite: places, visits, downloads, typed inputs.
 *  @param file the database, in the working copy
 *  @param base browser, profile, SID and source copied into each record
 *  @param records receives the records
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readFirefoxPlaces(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! Reads one Firefox formhistory.sqlite: each value typed in a form field or the search bar.
 *  @param file the database, in the working copy
 *  @param base browser, profile, SID and source copied into each record
 *  @param records receives the records
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readFirefoxFormHistory(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! Reads Chromium's `Login Data`: each saved login, never its password.
 *  @param file the database, in the working copy
 *  @param base browser, profile, SID and source copied into each record
 *  @param records receives one SavedLogin per login
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readChromiumLogins(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! Reads Chromium's cookies database: each cookie's site, name and dates, never its value.
 *  @param file the database, in the working copy
 *  @param base browser, profile, SID and source copied into each record
 *  @param records receives one Cookie per cookie
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readChromiumCookies(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! Reads Firefox's `logins.json`: each saved login's site and dates (its
 *  account name and password are encrypted: neither is given).
 *  @param text the file's content
 *  @param base browser, profile, SID and source copied into each record
 *  @param records receives one SavedLogin per login
 *  @return ERROR_SUCCESS, or ERROR_INVALID_DATA if the file is not that JSON */
HRESULT readFirefoxLogins(const std::wstring& text, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! Reads Firefox's `cookies.sqlite`: each cookie's site, name and dates, never its value.
 *  @param file the database, in the working copy
 *  @param base browser, profile, SID and source copied into each record
 *  @param records receives one Cookie per cookie
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readFirefoxCookies(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! Splits a WebCache history URL — "Visited: user@page" (History) or
 *  ":2026090720260914: user@page" (MSHist) — into its user and its page.
 *  @param url the entry's URL
 *  @param user receives the account name, empty if the URL has no such prefix
 *  @param page receives the page, empty likewise
 *  @return true if the URL had a history prefix */
bool splitWebCacheUrl(const std::wstring& url, std::wstring& user, std::wstring& page);

/*! Reads one WebCacheV01.dat: every entry of every container.
 *  @param file the database, in the working copy
 *  @param base SID and source copied into each record
 *  @param records receives one CacheEntry per entry
 *  @return ERROR_SUCCESS, or why the database cannot be read */
HRESULT readWebCache(const std::wstring& file, const WebClientRecord& base, std::vector<WebClientRecord>& records);

/*! The web, client side (web_client.json). */
class WebClient {
public:
	/*! Reads the History of every Chromium profile, the places and form
	 *  history of every Firefox profile, the TypedURLs and the WebCache, of
	 *  every user.
	 *  @return ERROR_SUCCESS, even without any browser */
	HRESULT getData();
	/*! Writes web_client.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases what was read.
	void clear();
private:
	std::vector<WebClientRecord> records_;   //!< every browser's, in order
};
