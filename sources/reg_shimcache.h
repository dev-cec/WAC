/*! \file
 *  \brief ShimCache (AppCompatCache): binaries the system examined for compatibility.
 *
 *  WHAT IT SHOWS. Before running a program, the compatibility layer records its
 *  path and the file's last modification date. The entry proves the binary was
 *  PRESENT and looked at — not that it ran: an executable merely listed in a
 *  folder the shell displayed can end up here. Its worth is elsewhere: entries
 *  survive the binary's deletion, and the cache is ordered from the most recent
 *  to the oldest, which gives a relative sequence no timestamp provides.
 *
 *  WHERE IT IS READ. In SYSTEM,
 *  `CurrentControlSet\Control\Session Manager\AppCompatCache`, a single
 *  binary value whose format changes with the Windows version. The cache is
 *  written to the registry at SHUTDOWN: on a machine seized while running, the
 *  key holds the state of the previous session.
 *
 *  With `--binary`, the target file is hashed and collected if it is still
 *  there, which settles what the entry alone cannot: whether that path today
 *  holds the binary it names.
 */
#pragma once

#include <iostream>
#include <windows.h>
#include <stdio.h>
#include "offline_registry.h"
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cstring>
#include "tools.h"
#include "quickdigest5.h"
#include "binaires.h"
#include "usb.h"

/*! One ShimCache entry: a binary the compatibility layer examined. */
struct Shimcache {
public:
	std::wstring path = L"";     //!< path of the binary the entry names (tab-separated fields for a packaged application)
	/*! Rank in the cache, 0 for the most recent entry: the order is the
	 *  information, and survives a consumer that sorts the array. */
	size_t position = 0;
	BinaryFingerprint fingerprint;  //!< fingerprints of that file, if `--binary` was given
	std::wstring lastModification = L"";    //!< the file's last modification, suspect's local time
	std::wstring lastModificationUtc = L"";	//!< the same instant in UTC
	/* No execution flag. One used to be read at the end of the entry and
	   emitted as "Executes"; confronted with Prefetch on the test VM, it said
	   nothing: 12 % "true" among binaries Prefetch proves were run, 23 % among
	   the others. A field that does not mean what its name says is worse than
	   no field — the Windows 10/11 cache proves presence, not execution.
	   Measured again on 2026-09-30 (B-015), against AppCompatCacheParser which
	   gives it: "Yes" is nearly reliable (12 of 13 confirmed by Prefetch), "No"
	   not at all (105 of the 117 binaries Prefetch proves were run). A "No"
	   would lead the analysis to conclude that a program never ran: the flag
	   is not collected. */

	/*! Converts the entry to JSON.
	 *  @return its JSON object. */
	Json toJson();
	//! Releases the memory held by the entry.
	void clear();

};

/*! The whole cache, in the order it is stored: most recent entry first. */
struct Shimcaches {
public:
	std::vector<Shimcache> shimcaches;  //!< the entries, in cache order
	bool unsupportedFormat = false;     //!< the value is in a format WAC has no decoder for (pieceFormat): no entry was read
	unsigned formatSignature = 0;       //!< what the value states of its format: its header, or the tag of its first entry under Windows 8 and 8.1

	/*! Reads the AppCompatCache value and parses it according to its format.
	 *  @return S_OK, or the failure of the read. */
	HRESULT getData();

	/*! Parses an AppCompatCache value according to its format.
	 *  @param value the value's bytes
	 *  @return S_OK, or why it cannot be read */
	HRESULT parse(const std::vector<BYTE>& value);

	/*! Writes `shimcache.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();

private:
	/*! Adds one entry, in cache order: its path, its fingerprints with
	 *  `--binary`, its last modification. */
	void addEntry(const std::wstring& path, const FILETIME& lastModifiedUtc);

	/*! Reads the value of Windows 7 and Server 2008 R2 (magic 0xBADC0FEE).
	 *  @return S_OK, or ERROR_INVALID_DATA if neither layout fits it */
	HRESULT parseWindows7(const BYTE* data, size_t size);
};
