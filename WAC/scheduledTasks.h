/*! \file
 *  \brief Scheduled tasks, read OFFLINE: what the machine runs on its own.
 *
 *  WHAT IT SHOWS. A scheduled task runs a command without a user being there,
 *  at a date, at every logon, or on an event. It is therefore both an
 *  administration tool and one of the most common persistences: the task
 *  survives reboots, runs as the account it names — often SYSTEM — and hides
 *  among the two hundred tasks Windows installs. Each task carries WHO created
 *  it, WHAT it runs, WHEN, and the result of its last run.
 *
 *  WHY OFFLINE. The previous version went through the Task Scheduler COM
 *  interface (`CoCreateInstance(CLSID_TaskScheduler)`), which cost two things:
 *    - a trace of the collection — the Schedule service being asked, and
 *      entries in `Microsoft-Windows-TaskScheduler/Operational`;
 *    - time: several interface calls per task, over 217 tasks.
 *  `scheduledTasks` was moreover the ONLY consumer of COM in WAC (audit of
 *  2026-09-15): switching it over allowed COM to be dropped entirely.
 *
 *  DATA SOURCES
 *    - definition: one XML file per task under `\\Windows\\System32\\Tasks\\`,
 *      extracted raw; the directory tree gives the task's path;
 *    - history: the binary value `DynamicInfo` under
 *      `SOFTWARE\\…\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{GUID}`, tied to
 *      the task by `TaskCache\\Tree\\<path>\\Id`.
 *
 *  WHAT IS LOST, AND WHY THAT IS ACCEPTABLE
 *  `NextRun` and `NumberOfMissedRuns` are not stored: the scheduler computes
 *  them at run time. They are PROJECTIONS, not traces of past activity: they
 *  have no probative value. The fields are therefore NOT emitted at all — an
 *  empty key in the JSON would read as a failed read, whereas the data simply
 *  does not exist offline.
 *  `State` is now only "enabled / disabled" (read from the XML): the "running"
 *  state is volatile by nature.
 */
#pragma once

#include "binaires.h"
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "json.h"
#include "trans_id.h"
#include "quickdigest5.h"

/*! What sets a scheduled task off: a date, a logon, an event. */
struct Trigger {
	std::wstring type;      //!< name of the XML element (TimeTrigger, LogonTrigger…)
	std::wstring interval;  //!< repetition (ISO 8601 duration, e.g. "PT1H")
	std::wstring start;     //!< StartBoundary: the first time it was due
	bool         active = true; //!< the trigger's Enabled flag
};

/*! What a scheduled task runs: a command, or a COM handler. */
struct Action {
	std::wstring type;       //!< "Exec" or "ComHandler"
	std::wstring command;    //!< the executable (Exec)
	BinaryFingerprint fingerprint; //!< fingerprints of that executable, if `--binary` was given
	std::wstring arguments;  //!< command-line arguments
	std::wstring workingDir; //!< working directory
	std::wstring classId;    //!< CLSID of the handler (ComHandler)
	std::wstring data;       //!< data passed to the COM handler
};

/*! One scheduled task, rebuilt from its XML and the TaskCache. */
struct ScheduledTask {
	std::wstring name;                 //!< name of the task, that is its file name
	std::wstring path;                 //!< path in the tree (ex. \\Microsoft\\Windows\…)
	std::wstring description;          //!< description the author gave it
	std::wstring author;               //!< who registered the task, as the XML declares it
	std::wstring runAs;                //!< account it runs as (the principal's UserId)
	std::wstring runAsSid;             //!< SID, when that UserId is one
	std::wstring state;                //!< "Enabled" / "Disabled"
	bool         enabled = true;       //!< the same, as a boolean
	FILETIME     lastRunTimeUtc = { 0 };   //!< last run, UTC, as DynamicInfo stores it
	LONG         lastTaskResult = 0;       //!< value the last run returned
	std::wstring registrationDate;         //!< the XML's Date, as written
	std::wstring sourceXml;                //!< path of the source XML, for traceability
	std::vector<Action>  actions;          //!< what the task runs
	std::vector<Trigger> triggers;         //!< what sets it off

	/*! Converts the task to JSON, actions and triggers included.
	 *  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the task.
	void clear();
};

/*! All the scheduled tasks of the examined machine. */
struct ScheduledTasks {
	std::vector<ScheduledTask> scheduledTasks; //!< the tasks, as the XML files were listed

	/*! Reads the tasks from the extracted XML files and enriches them with the
	 *  TaskCache. Uses neither COM nor the Schedule service.
	 *  @return S_OK, or the failure of the last read attempted.
	 */
	HRESULT getData();

	/*! Writes `ScheduledTasks.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the tasks.
	void clear();
};
