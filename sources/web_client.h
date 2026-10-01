/*! \file
 *  \brief The web, client side: what each user did in the Chromium browsers (Edge, Chrome, Brave, Vivaldi, Opera).
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
 *  Firefox, the WebCache of Internet Explorer and Edge Legacy, and TypedURLs
 *  follow (backlog B-016).
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
	std::wstring type;              //!< Url, Visit, Download, SearchTerm
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

/*! The web, client side (web_client.json). */
class WebClient {
public:
	/*! Reads the History of every Chromium profile of every user.
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
