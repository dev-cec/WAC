/*! \file
 *  \brief The browsers' sessions: Chromium's SNSS files (Session_*, Tabs_*)
 *         and Firefox's mozLz4 (.jsonlz4) files, decoded.
 *
 *  WHAT THEY PROVE. A browser keeps, beside its history, what was OPEN: the
 *  windows and tabs of the current and the last session, each tab's pages
 *  back and forward, and the tabs and windows the user closed. A page read
 *  in a private window leaves no visit, and a history the user cleared none
 *  either; the session file may still hold the tab, its title and when it
 *  was shown. KAPE collected these files and WAC did not (backlog B-048).
 *
 *  CHROMIUM, SNSS. `Sessions\Session_<time>` and `Sessions\Tabs_<time>`: a
 *  header ("SNSS", a version) then commands, each a 16-bit size, an 8-bit
 *  identifier and its payload. The payload that matters is the navigation,
 *  a base::Pickle (a 32-bit payload size, then 32-bit-aligned fields) written
 *  by SerializedNavigationEntry::WriteToPickle: tab, index, URL, title
 *  (UTF-16), page state, transition, type mask, referrer, referrer policy,
 *  original URL, user agent override, time (microseconds since 1601, UTC),
 *  search terms, HTTP status. Its command identifier is 6 in a Session file
 *  (SessionService) and 1 in a Tabs file (TabRestoreService), where command 4
 *  gives, for a closed tab, the navigation shown and the instant it was
 *  closed. A file is a log: a later command for the same tab and index
 *  replaces the earlier one.
 *
 *  FIREFOX, mozLz4. "mozLz40\0", the decompressed size on 32 bits, then one
 *  LZ4 block (the block format, without the frame): sessionstore.jsonlz4,
 *  the backups of sessionstore-backups and of bookmarkbackups are JSON
 *  compressed so.
 *
 *  Every read is bounded by the buffer, never by a length the file states:
 *  the files come from the examined machine. Portable C++, without
 *  windows.h, for the native test (browser_sessions_test).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

/*! The kind of an SNSS file, which decides its commands' identifiers. */
enum class SnssKind {
	Session,      //!< Session_<time>: the windows and tabs open
	TabRestore    //!< Tabs_<time>: the tabs and windows closed
};

/*! One navigation of a Chromium session: a page of a tab's history. */
struct SnssNavigation {
	int32_t tab = 0;                  //!< the tab (Session) or the closed entry (TabRestore)
	int32_t index = 0;                //!< its place in the tab's history, from 0
	std::string url;                  //!< the page, UTF-8
	std::wstring title;               //!< its title
	int32_t transition = 0;           //!< ui::PageTransition, as History's visits carry it
	std::string referrer;             //!< the referring page, UTF-8; empty for none
	std::string originalUrl;          //!< the URL first requested, before redirections; empty if absent
	int64_t time = 0;                 //!< when it was shown, microseconds since 1601 UTC; 0 if absent
	int32_t httpStatus = 0;           //!< the HTTP status; 0 if absent
};

/*! What an SNSS file holds. */
struct SnssContents {
	int32_t version = 0;                          //!< the file's version
	std::vector<SnssNavigation> navigations;      //!< the last state of each (tab, index), in file order
	std::map<int32_t, int64_t> closedTimes;       //!< TabRestore: closed entry -> instant (microseconds since 1601)
	std::map<int32_t, int32_t> selectedIndex;     //!< TabRestore: closed entry -> the navigation shown
};

/*! Decodes a Chromium SNSS file.
 *  @param data the file's bytes
 *  @param size their number
 *  @param kind Session or TabRestore, from the file's name
 *  @param contents receives the navigations
 *  @return false if the bytes are not an SNSS file (a damaged command ends
 *          the reading: what was read before it is kept) */
bool decodeSnss(const uint8_t* data, size_t size, SnssKind kind, SnssContents& contents);

/*! Decompresses one LZ4 block (the block format, without a frame).
 *  @param data the block
 *  @param size its size
 *  @param expected the decompressed size, which the block must give exactly
 *  @param output receives the bytes
 *  @return false for a block that is damaged, reaches before the start of
 *          its output, or does not give exactly `expected` bytes */
bool decompressLz4Block(const uint8_t* data, size_t size, size_t expected, std::vector<uint8_t>& output);

/*! Decompresses a Firefox mozLz4 file (.jsonlz4, .baklz4).
 *  @param data the file's bytes
 *  @param size their number
 *  @param maximum the largest decompressed size accepted
 *  @param output receives the decompressed bytes (UTF-8 JSON)
 *  @return false if the magic is absent, the stated size passes `maximum`,
 *          or the block is damaged */
bool decompressMozLz4(const uint8_t* data, size_t size, size_t maximum, std::vector<uint8_t>& output);
