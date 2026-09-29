/*! \file
 *  \brief Windows Error Reporting: the `Report.wer` files of the machine and of each profile.
 *
 *  WHAT THE ARTEFACT PROVES. When a program crashes or hangs, Windows writes a
 *  report under `WER\\ReportArchive` (sent) or `WER\\ReportQueue` (waiting),
 *  in `\\ProgramData\\Microsoft\\Windows\\` for the machine and in
 *  `AppData\\Local\\Microsoft\\Windows\\` for a user. Each names the program,
 *  its path, its version, the module at fault and the instant. Malware that
 *  crashes — an injection gone wrong, a tool run on the wrong system — leaves
 *  its path and the time there, often when nothing else kept it.
 *
 *  THE FORMAT. UTF-16LE text, one `Key=Value` per line. The keys used here:
 *  EventType, EventTime (a FILETIME written in decimal, UTC), ReportType,
 *  FriendlyEventName, AppName, AppPath, NsAppName, OriginalFilename,
 *  ReportIdentifier, and the problem signature `Sig[n].Name` / `Sig[n].Value`
 *  (application, version, faulting module, offset…). Every Key=Value is also
 *  kept, in order, as a Name/Value pair of `Values`, so that nothing the report
 *  says is lost.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One error report. */
struct ErrorReport {
	std::wstring file;               //!< the Report.wer on the examined machine
	FILETIME eventTimeUtc = { 0 };   //!< the instant of the problem, UTC
	std::vector<std::pair<std::wstring, std::wstring>> values;     //!< every Key=Value, in order
	std::vector<std::pair<std::wstring, std::wstring>> signature;  //!< Sig[n].Name / Sig[n].Value, by n
	//! @return the report as a JSON object
	Json toJson() const;
};

/*! Reads a Report.wer.
 *  @param text the file, decoded
 *  @param report receives the values, the signature and the event time
 *  @return false if the file holds no Key=Value at all */
bool parseErrorReport(const std::wstring& text, ErrorReport& report);

/*! The error reports (error_reports.json). */
class ErrorReports {
public:
	/*! Reads the Report.wer collected, from the exhibit store.
	 *  @return ERROR_SUCCESS, even without any */
	HRESULT getData();
	/*! Writes error_reports.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the reports read.
	void clear();
private:
	std::vector<ErrorReport> reports_;   //!< one per Report.wer
};
