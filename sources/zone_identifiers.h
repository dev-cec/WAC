/*! \file
 *  \brief Zone.Identifier streams ("Mark of the Web"): where downloaded files came from.
 *
 *  WHAT THE ARTEFACT PROVES. A browser, a mail client or an archiver writes a
 *  `Zone.Identifier` stream on each file it brings from outside: the zone
 *  (3, Internet) and often the page it came from (`ReferrerUrl`) and the file's
 *  own address (`HostUrl`). It ties a suspicious binary or document to the URL
 *  it was fetched from, and it outlives the browser's history being cleared.
 *
 *  WHERE IT IS READ. The stream is a few dozen bytes, hence resident: its
 *  content is inside the file's $MFT record. It is read in the copy of the
 *  $MFT already collected — no further read of the examined machine. A stream
 *  too large to be resident (rare) is listed with its size, without content.
 *
 *  THE FORMAT. Text, INI-like:
 *      [ZoneTransfer]
 *      ZoneId=3
 *      ReferrerUrl=https://…
 *      HostUrl=https://…/file.exe
 *  Every Key=Value is kept, in order, as a Name/Value pair.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "mft.h"

/*! The Zone.Identifier stream of one file. */
struct ZoneIdentifier {
	std::wstring path;                  //!< the file carrying the stream
	bool pathComplete = true;           //!< false if a parent directory could not be named
	bool deleted = false;               //!< the file's record is free: a deleted file
	FILETIME createdUtc = { 0 };        //!< the file's creation ($STANDARD_INFORMATION), UTC: its download, as a rule
	bool resident = false;              //!< the stream's content was in the record
	uint64_t size = 0;                  //!< the stream's size
	std::vector<std::pair<std::wstring, std::wstring>> values;   //!< every Key=Value, in order
	//! @return the stream as a JSON object
	Json toJson() const;
};

/*! Reads the content of a Zone.Identifier stream.
 *  @param content its bytes (UTF-8, or UTF-16LE with its byte-order mark)
 *  @param zone receives its Key=Value pairs; section headers are not values
 *  @return false if the content holds no Key=Value at all */
bool parseZoneIdentifier(const std::string& content, ZoneIdentifier& zone);

/*! The name of a URL zone (URLZONE of urlmon), or empty for an unknown one.
 *  @param zoneId the ZoneId, as written
 *  @return "Local machine", "Local intranet", "Trusted sites", "Internet" or
 *          "Restricted sites" */
std::wstring zoneName(const std::wstring& zoneId);

/*! The Zone.Identifier streams of the system volume (zone_identifiers.json). */
class ZoneIdentifiers {
public:
	/*! Collects every Zone.Identifier stream of the $MFT, present or deleted.
	 *  @param mft the $MFT, loaded
	 *  @return ERROR_SUCCESS, or why the $MFT could not be read */
	HRESULT getData(const Mft& mft);
	/*! Writes zone_identifiers.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the streams read.
	void clear();
private:
	std::vector<ZoneIdentifier> zones_;   //!< one per stream
};
