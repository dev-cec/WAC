/*! \file
 *  \brief Replay of an ESE database's transaction logs into its working copy,
 *         by Windows' own engine (esent.dll) — the WebCache, SRUM.
 *
 *  WHY. An ESE database in use — the WebCache of Internet Explorer and Edge,
 *  SRUDB.dat — keeps its latest changes in its transaction logs until a
 *  checkpoint writes them into the database file. Read alone, the copied
 *  database misses them: a page an HTA opened a minute before the collection
 *  was in V01.log only (backlog B-046). The logs are collected with the
 *  database; this replays them, as the hives' logs are (hive_recover.h).
 *
 *  THE ENGINE. The replay is done by esent.dll, the engine that wrote the logs:
 *  reimplementing the physical redo of ESE would be a whole database engine,
 *  and a database rebuilt slightly wrong would read as a valid one. esent.dll
 *  is loaded from System32 only when a database to replay is met, as WinHTTP is
 *  for --update-trust: it is not in WAC.exe's import table.
 *
 *  WHERE. During the conversion only (--convert), on the analysis
 *  workstation: WAC never converts on the examined machine, so esent.dll is
 *  never loaded there.
 *
 *  WHAT IT TOUCHES. Only the working copy: the recovery runs in the copy's
 *  folder (system, log and temporary paths), and the restore map sends the
 *  database the logs name — its path on the examined machine — to the copy; a
 *  database the map does not name is treated as missing, never opened. The
 *  copy as collected is kept aside during the replay (`.as-collected`) and
 *  put back if the replay is not applied: the engine rewrites pages as it
 *  goes, and one stopped partway left a state the database never had. The
 *  exhibit store is not read. The engine's events (Application log) and its
 *  performance counters are switched off.
 */
#pragma once

#include <string>
#include "ese_database.h"
#include <windows.h>

/*! The outcome of one replay. */
struct EseReplay {
	bool attempted = false;   //!< logs were found beside the copy, and a replay tried
	bool applied = false;     //!< the engine recovered the copy
	long jetError = 0;        //!< the engine's error, if any (JET_err…, negative)
	std::wstring baseName;    //!< the logs' base name (V01, SRU)
	std::wstring detail;      //!< what was done or why not, for the log and the audit
};

/*! Replays the transaction logs found beside a working copy of an ESE database,
 *  once per copy and per run: a second call returns the first outcome.
 *  @param workingDatabase the copy, in the working directory
 *  @param originalDatabase the database's path on the examined machine, as its
 *         logs name it (the exhibit's source path)
 *  @return the outcome; the copy is left as it was when nothing is applied */
EseReplay ReplayEseLogsOnce(const std::wstring& workingDatabase, const std::wstring& originalDatabase);

/*! Opens the working copy of an ESE database once its logs are replayed into
 *  it (ReplayEseLogsOnce): every ESE artefact goes through here, none reads a
 *  database without its latest changes unsaid. A replay not applied is logged.
 *  @param database receives the opened database
 *  @param workingDatabase the copy, in the working directory
 *  @param originalDatabase its path on the examined machine
 *  @return the result of EseDatabase::open */
HRESULT OpenRecoveredEseDatabase(EseDatabase& database, const std::wstring& workingDatabase, const std::wstring& originalDatabase);
