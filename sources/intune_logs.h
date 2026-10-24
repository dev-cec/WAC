/*! \file
 *  \brief The Intune Management Extension's logs (backlog B-052).
 *
 *  WHAT THE ARTEFACT PROVES. On a machine managed by Microsoft Intune, the
 *  management extension writes what it was told to do and did: the
 *  PowerShell scripts and Win32 applications it received from the tenant,
 *  run as SYSTEM, their outcome, the policies applied, the device's
 *  registration — ATT&CK T1098.005 (device registration) and the use of
 *  the management channel itself to run code on every managed machine.
 *  The tenant's audit log is in the cloud; this is the machine's side.
 *  The MDM enrolment's own events are in the event logs
 *  (DeviceManagement-Enterprise-Diagnostics-Provider), converted there.
 *
 *  WHERE. `ProgramData\Microsoft\IntuneManagementExtension\Logs\*.log`
 *  (IntuneManagementExtension.log, AgentExecutor.log, their rotations
 *  `-<date>.log`…), present only where the extension was installed.
 *
 *  THE FORMAT, CMTrace's: each message is
 *    <![LOG[the message, possibly on several lines]LOG]!><time="15:01:02.1234567"
 *    date="10-24-2026" component="IntuneManagementExtension" context=""
 *    type="1" thread="12" file="">
 *  the time in the machine's LOCAL time, month first in the date: converted
 *  with its time zone (suspectLocalToUtc), as every local date of WAC — or
 *  with the bias some CMTrace writers put after the time ("+300"), exact.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One message of a log. */
struct IntuneLogEntry {
	std::wstring file;              //!< the log on the examined machine
	unsigned long long line = 0;    //!< the line its message starts on, from 1
	std::wstring message;           //!< as written, its line ends kept
	FILETIME timeLocal = { 0 };     //!< date and time, local time as written; 0 if unreadable
	/*! The bias written after the time ("15:01:02.123+300", minutes, UTC =
	 *  local + bias), when there is one: the date is then exact without the
	 *  machine's time zone. */
	bool hasBias = false;
	int biasMinutes = 0;
	std::wstring component, context, type, thread, sourceFile;   //!< the attributes, as written
	Json toJson() const;            //!< @return the entry as a JSON object
};

/*! Reads the messages of a CMTrace log.
 *  @param text the log, decoded
 *  @param file its path on the examined machine, recorded in each entry
 *  @return the messages, in the log's order; a message without its closing
 *          "]LOG]!>" (a log cut short) is not given */
std::vector<IntuneLogEntry> parseCmTraceLog(const std::wstring& text, const std::wstring& file);

//! The logs' folder, as the collection takes it and the conversion reads it.
extern const wchar_t INTUNE_LOGS_FOLDER[];

/*! The Intune Management Extension's logs (intune_logs.json). */
class IntuneLogs {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any log
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<IntuneLogEntry> entries_;
};
