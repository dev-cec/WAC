/*! \file
 *  \brief The hosts file: `\\Windows\\System32\\drivers\\etc\\hosts`.
 *
 *  WHAT THE ARTEFACT PROVES. Every name listed there is resolved to its
 *  address before any DNS query. An intruder uses it to divert a site (a bank,
 *  an update server) or to cut a security product off from its console:
 *  `127.0.0.1 update.vendor.com`. An untouched Windows lists no name; each
 *  entry is therefore worth a look, and the file's modification date says
 *  when the last one was added.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One line of the file that maps names to an address. */
struct HostsEntry {
	unsigned long long line = 0;     //!< line of the file, from 1
	std::wstring address;            //!< the address, as written
	std::vector<std::wstring> names; //!< the names it is given
	//! @return the entry as a JSON object
	Json toJson() const;
};

/*! Reads the entries of a hosts file; comments (`#` to the end of the line)
 *  and blank lines are not entries.
 *  @param text the file, decoded
 *  @return the entries, in the file's order */
std::vector<HostsEntry> parseHostsFile(const std::wstring& text);

/*! The hosts file (hosts.json). */
class HostsFile {
public:
	/*! Reads the extracted file.
	 *  @return ERROR_SUCCESS, or ERROR_FILE_NOT_FOUND if it was not extracted */
	HRESULT getData();
	/*! Writes hosts.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases what was read.
	void clear();
private:
	std::wstring path_;                    //!< the file on the examined machine
	FILETIME createdUtc_ = { 0 };          //!< its creation, UTC
	FILETIME modifiedUtc_ = { 0 };         //!< its last write, UTC: the last entry added, at the latest
	FILETIME accessedUtc_ = { 0 };         //!< its last access, UTC
	std::vector<HostsEntry> entries_;      //!< its entries
};
