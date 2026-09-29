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
	std::wstring path = L"";     //!< path of the binary the entry names
	BinaryFingerprint fingerprint;  //!< fingerprints of that file, if `--binary` was given
	std::wstring lastModification = L"";    //!< the file's last modification, suspect's local time
	std::wstring lastModificationUtc = L"";	//!< the same instant in UTC
	/* No execution flag. One used to be read at the end of the entry and
	   emitted as "Executes"; confronted with Prefetch on the test VM, it said
	   nothing: 12 % "true" among binaries Prefetch proves were run, 23 % among
	   the others. A field that does not mean what its name says is worse than
	   no field — the Windows 10/11 cache proves presence, not execution. */

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

	/*! Reads the AppCompatCache value and parses it according to its format.
	 *  @return S_OK, or the failure of the read. */
	HRESULT getData();

	/*! Writes `shimcache.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();
};
