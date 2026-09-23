/*! \file
 *  \brief Background Activity Monitor (BAM): last execution of a binary, per user.
 *
 *  WHAT IT SHOWS. The BAM service throttles the background activity of
 *  applications, and to do so records, FOR EACH USER, the path of every
 *  executable run and the time it last ran. That makes it one of the most
 *  direct execution proofs on a Windows system: a full path, a user, and a
 *  date — where Prefetch gives no user and Shimcache does not prove execution.
 *
 *  WHERE IT IS READ. In SYSTEM, `CurrentControlSet\Services\bam\UserSettings\<SID>`
 *  and `…\bam\state\UserSettings\<SID>` (the second path since Windows 10
 *  1809; both are read, since either may be the one populated). Each value is
 *  named after the executable's path, in NT form (`\Device\HarddiskVolume3\…`),
 *  and holds the execution time as a FILETIME.
 *
 *  Its span is short — the entries are pruned — so an absent path means nothing,
 *  while a present one dates a run precisely.
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
#include "tools.h"
#include "usb.h"
#include "users.h"

/*! One BAM entry: a binary, the user who ran it, and when it last ran. */
struct Bam {
public:
	std::wstring sid = L"";      //!< SID of the user who ran the binary
	std::wstring sidName = L"";  //!< name of that user
	std::wstring name = L"";     //!< path of the executable, as the value names it
	std::wstring executionTime = L"";    //!< last execution, in the suspect's local time
	std::wstring executionTimeUtc = L""; //!< the same instant in UTC

	/*! Builds the entry from a registry value.
	 *  @param data the value's bytes, which start with the execution FILETIME.
	 *  @param valueName name of the value, that is the executable's path.
	 *  @param psid SID of the user whose UserSettings subkey holds the value. */
	Bam(LPBYTE data, std::wstring valueName, std::wstring psid);

	/*! Converts the entry to JSON.
	 *  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the entry.
	void clear();
};

/*! All the BAM entries collected, for every user of the machine. */
struct Bams {
public:
	std::vector<Bam> bams;  //!< the entries, in the order they were read
	
	/*! Walks the UserSettings subkeys of both BAM paths, for each user.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `bams.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the entries.
	void clear();
};