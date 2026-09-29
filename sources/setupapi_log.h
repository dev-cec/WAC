/*! \file
 *  \brief Device installation log: `\\Windows\\INF\\setupapi.dev.log`.
 *
 *  WHAT THE ARTEFACT PROVES. Windows writes a section to this log every time
 *  it installs a device — the first time a USB key, a phone or a disk is
 *  plugged in — with the device's identifier (vendor, product, serial number)
 *  and the instant. It complements USBSTOR: the registry keeps the device,
 *  the log dates its FIRST connection, and keeps it when the key was
 *  cleaned. Windows rotates it into `setupapi.dev.<date>.log`: both are read.
 *
 *  A SECTION:
 *      >>>  [Device Install (Hardware initiated) - USB\VID_0781&PID_5567\4C53…]
 *      >>>  Section start 2023/05/12 10:11:12.345
 *      …
 *      <<<  Section end 2023/05/12 10:11:13.456
 *      <<<  [Exit status: SUCCESS]
 *
 *  THE DATES are in the LOCAL time of the examined machine, with no offset
 *  written: they are converted with its time zone (suspectLocalToUtc), as
 *  every local date of WAC.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One section of the log: one operation on one device or driver. */
struct SetupApiSection {
	std::wstring file;              //!< the log on the examined machine
	unsigned long long line = 0;    //!< line of its header, from 1
	std::wstring operation;         //!< what was done ("Device Install (Hardware initiated)")
	std::wstring subject;           //!< on what: the device instance or the driver package
	FILETIME startLocal = { 0 };    //!< start, local time of the examined machine as written
	FILETIME endLocal = { 0 };      //!< end, idem
	std::wstring exitStatus;        //!< outcome ("SUCCESS", "FAILURE(0x…)")
	//! @return the section as a JSON object, its dates in UTC and local time
	Json toJson() const;
};

/*! Reads the sections of a log.
 *  @param text the log, decoded
 *  @param file its path on the examined machine, recorded in each section
 *  @return the sections, in the log's order */
std::vector<SetupApiSection> parseSetupApiLog(const std::wstring& text, const std::wstring& file);

/*! Reads a "2023/05/12 10:11:12.345" date of the log.
 *  @param text the date
 *  @param local receives it, local time as written
 *  @return false if the text is not such a date */
bool parseSetupApiDate(const std::wstring& text, FILETIME& local);

/*! The device installation logs (setupapi.json). */
class SetupApiLogs {
public:
	/*! Reads the extracted logs, the current one and the rotated ones.
	 *  @return ERROR_SUCCESS, even without any log */
	HRESULT getData();
	/*! Writes setupapi.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the sections read.
	void clear();
private:
	std::vector<SetupApiSection> sections_;   //!< every section of every log
};
