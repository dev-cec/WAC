/*! \file
 *  \brief Microsoft Defender's support logs: `\\ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-*.log`.
 *
 *  WHAT THE ARTEFACT PROVES. The antivirus writes there, line by line, what
 *  its engine did: files scanned at run time with the process that opened
 *  them, detections, exclusions applied, engine and signature updates, and
 *  its own tampering alerts. A detection since cleaned from the event log, a
 *  program scanned on the day of the intrusion, an exclusion added by an
 *  intruder all show there. The file is readable by SYSTEM only: the raw
 *  reading of the volume takes it without asking for that right.
 *
 *  THE FORMAT. UTF-16LE text; most lines start with an ISO 8601 date in UTC
 *  ("2023-05-12T10:11:12.345Z"), some with no date. Every line is kept, as
 *  written: which of them matter is the analysis's decision (WAE).
 *
 *  NOT HERE YET: DetectionHistory (binary) and the quarantine (encrypted).
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One line of a log. */
struct DefenderLogLine {
	unsigned long long line = 0;   //!< line of the file, from 1
	FILETIME timeUtc = { 0 };      //!< its date, when the line starts with one in UTC
	std::wstring text;             //!< the line, as written, date included
	//! @return the line as a JSON object
	Json toJson() const;
};

/*! Reads the lines of a log; blank lines are left out.
 *  @param text the log, decoded
 *  @return the lines, in the file's order */
std::vector<DefenderLogLine> parseDefenderLog(const std::wstring& text);

/*! Reads a "2023-05-12T10:11:12.345Z" date at the start of a line.
 *  @param text the line
 *  @param utc receives the date
 *  @return false if the line does not start with a UTC date */
bool parseDefenderDate(const std::wstring& text, FILETIME& utc);

/*! One log file and its lines. */
struct DefenderLog {
	std::wstring path;                     //!< the log on the examined machine
	FILETIME sourceModifiedUtc = { 0 };    //!< its last write, UTC
	std::vector<DefenderLogLine> lines;    //!< its lines
	//! @return the log as a JSON object
	Json toJson() const;
};

/*! Defender's support logs (defender_log.json). */
class DefenderLogs {
public:
	/*! Reads the MPLog files collected, from the exhibit store.
	 *  @return ERROR_SUCCESS, even without any */
	HRESULT getData();
	/*! Writes defender_log.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the logs read.
	void clear();
private:
	std::vector<DefenderLog> logs_;   //!< one per MPLog file
};
