/*! \file
 *  \brief Logs in the W3C extended format: the Windows Firewall's
 *  (pfirewall.log, firewall_log.h) and IIS's (web_server.h).
 *
 *  THE FORMAT. Text lines; directives first, each starting with "#":
 *  "#Version:", "#Software:", "#Date:", "#Fields:" — the names of the fields
 *  of the lines that follow, in their order — and, for the firewall only,
 *  "#Time Format:". Then one line per record, the fields separated by
 *  spaces, "-" for a field without value. A log may repeat its directives
 *  further down (IIS writes them again each time it restarts): a new
 *  "#Fields:" applies to the lines after it.
 *
 *  THE TIME ZONE OF THE DATES depends on the writer: the firewall writes
 *  local time and says so ("#Time Format: Local"); IIS writes UTC and says
 *  nothing (W3C's own rule). Each caller gives its default; a header that
 *  names another format leaves the date as stored, never converted with a
 *  guessed zone.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! The time zone of a log's dates. */
enum class W3cTime {
	Local,   //!< the examined machine's local time: converted with its time zone
	Utc,     //!< UTC, as written
	Unknown  //!< a format the reader does not know: the date is given as stored
};

/*! One field of "#Fields:" and its JSON key. */
struct W3cFieldKey {
	const wchar_t* field;  //!< the name in "#Fields:", as written ("src-ip", "cs(User-Agent)")
	const wchar_t* key;    //!< its JSON key
};

/*! One line of a log: one record. */
struct W3cLogEntry {
	std::wstring file;              //!< the log on the examined machine
	unsigned long long line = 0;    //!< its line, from 1
	FILETIME time = { 0 };          //!< date and time as written, in `zone`; 0 if unreadable or not converted
	W3cTime zone = W3cTime::Local;  //!< the zone of `time`
	std::wstring timeAsStored;      //!< "2026-10-24 15:01:02", given when it is not converted
	std::vector<std::pair<std::wstring, std::wstring>> fields; //!< the other fields, by their JSON key, "-" left out
	Json toJson() const;            //!< @return the entry as a JSON object
};

/*! Reads the lines of a log.
 *  @param text the log, decoded
 *  @param file its path on the examined machine, recorded in each entry
 *  @param keys the JSON key of each known field; another keeps its name, in PascalCase
 *  @param zone the zone of the dates when no "#Time Format:" names one
 *  @return the entries, in the log's order; a line before any "#Fields:" is skipped */
std::vector<W3cLogEntry> parseW3cLog(const std::wstring& text, const std::wstring& file,
                                     const std::vector<W3cFieldKey>& keys, W3cTime zone);
