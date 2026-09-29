/*! \file
 *  \brief PowerShell command history: the PSReadLine files of each profile.
 *
 *  WHAT THE ARTEFACT PROVES. PSReadLine, the line editor of every interactive
 *  PowerShell console since Windows 10, appends each command typed to
 *  `%AppData%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\<host>_history.txt`
 *  — ConsoleHost for the console, other names for the ISE or VS Code. The
 *  file survives the session and is rarely cleaned: it is the plainest record
 *  of what an intruder typed.
 *
 *  WHAT IT DOES NOT HOLD. No date per command: only the file's own dates say
 *  when the last one was written (SourceModified). A command run by a script
 *  (-File, -Command) is not recorded, nor one typed while PSReadLine was
 *  unloaded or its history switched off.
 *
 *  MULTI-LINE COMMANDS. PSReadLine ends each line of a command typed on
 *  several lines with a backtick (`) before the newline: those lines are
 *  joined back into one command, the backticks kept, as typed.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One command of the history. */
struct PowerShellCommand {
	unsigned long long number = 0;  //!< rank in the file, from 1: the order the commands were typed in
	unsigned long long line = 0;    //!< line of the file its first line is on, from 1
	std::wstring command;           //!< the command, as typed, its lines joined by a newline
	//! @return the command as a JSON object
	Json toJson() const;
};

/*! Splits a history file into its commands.
 *  @param text the file, decoded
 *  @return the commands, in the file's order; empty lines are not commands */
std::vector<PowerShellCommand> parsePowerShellHistory(const std::wstring& text);

/*! One history file, of one profile and one host. */
struct PowerShellHistory {
	std::wstring sid;               //!< SID of the profile the file belongs to
	std::wstring path;              //!< the file on the examined machine
	std::wstring host;              //!< the PowerShell host, from the file name (ConsoleHost…)
	FILETIME sourceCreatedUtc = { 0 };   //!< creation of the file, UTC (the first command recorded)
	FILETIME sourceModifiedUtc = { 0 };  //!< last write, UTC (the last command recorded)
	FILETIME sourceAccessedUtc = { 0 };  //!< last access, UTC
	std::vector<PowerShellCommand> commands;   //!< the commands, in order
	//! @return the file and its commands as a JSON object
	Json toJson() const;
};

//! Folder of the PSReadLine histories, relative to a profile.
extern const wchar_t PSREADLINE_FOLDER[];

/*! The PowerShell histories of every profile (powershell_history.json). */
class PowerShellHistories {
public:
	/*! Reads the history files extracted from every profile.
	 *  @return ERROR_SUCCESS, even without any file: none is an answer */
	HRESULT getData();
	/*! Writes powershell_history.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the histories read.
	void clear();
private:
	std::vector<PowerShellHistory> histories_;   //!< one per file found
};
