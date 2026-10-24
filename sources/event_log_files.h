/*! \file
 *  \brief The event logs the examined machine keeps outside their default
 *         folder (backlog B-053).
 *
 *  WHY. A log's file is a setting: the `File` value of its channel
 *  (SOFTWARE `…\WINEVT\Channels\<channel>`, what `wevtutil sl /lfn` writes)
 *  or of its classic log (SYSTEM `…\Services\EventLog\<log>`). Moved —
 *  by an administrator for room, or by an intruder for a log nobody looks
 *  at —, a log WAC looked for in `winevt\Logs` only was neither collected
 *  nor converted, and its absence read as "no events". Sysmon's own log,
 *  the best source of detection where it runs, is one a hardened
 *  configuration often moves.
 *
 *  The values are read in the examined machine's hives, expanded as Windows
 *  does (`%SystemRoot%`, normalizeFilePath): the collection takes these
 *  files raw, the conversion reads them with the others.
 */
#pragma once

#include <string>
#include <vector>

/*! A log kept outside its default folder. */
struct MovedEventLog {
	/*! Its channel (or classic log), the name of its registry key: the file's
	 *  own name, chosen by whoever moved it, does not tell it. */
	std::wstring channel;
	std::wstring file;      //!< absolute path, "D:\\Logs\\Sysmon.evtx"
};

/*! The log files the registry places outside `winevt\Logs` (and, before
 *  Vista, outside `System32\config`): each file once, case ignored. Needs
 *  conf.Software and conf.CurrentControlSet open (either missing: its logs
 *  are not listed).
 *  @return the logs, in the registry's order */
std::vector<MovedEventLog> movedEventLogFiles();
