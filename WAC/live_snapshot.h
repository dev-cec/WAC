/*! \file
 *  \brief Snapshot of the LIVE state: what WAC observes on the running system
 *         (processes, sessions, service states, clock and boot time), recorded
 *         as sealed exhibits, and read back by the conversion.
 *
 *  WHY. The conversion into JSON can run elsewhere than on the examined
 *  machine (--collect there, --convert on an analysis workstation). Everything
 *  it reads must therefore be in the exhibit store — including what can only
 *  be observed live and will never be observable again. Each observation is
 *  written AS READ, in `exhibits\live\<name>.json`, and registered in the
 *  manifest with its fingerprints: the seal covers it like any exhibit, and a
 *  retouched snapshot is detected before any conversion.
 *
 *  What is interpretation — naming the owner of a process, merging a service's
 *  state with its configuration — is left to the conversion, which reads the
 *  snapshot back. The full mode (collection and conversion in one run) goes
 *  through the same snapshot: one code path for both.
 */
#pragma once
#include <windows.h>
#include <string>
#include "json.h"

/*! Folder of the snapshots: `<output>\exhibits\live`. */
std::wstring liveSnapshotFolder();

/*! Writes a snapshot and registers it in the exhibit store manifest, with its
 *  MD5, SHA-1 and SHA-256 fingerprints.
 *  @param name file name, e.g. "processes.json"
 *  @param value the observation, as read
 *  @param what what was observed, for the manifest (e.g. L"running processes")
 *  @return ERROR_SUCCESS, or the error of the write */
HRESULT writeLiveSnapshot(const std::string& name, const Json& value, const std::wstring& what);

/*! Reads a snapshot back.
 *  @param name file name, e.g. "processes.json"
 *  @param value receives the observation
 *  @return ERROR_SUCCESS, ERROR_FILE_NOT_FOUND if the collection holds none
 *          (an observation that failed at collection time), or ERROR_INVALID_DATA
 *          if the file is not valid JSON */
HRESULT readLiveSnapshot(const std::string& name, Json& value);

/*! An integer member of a snapshot object.
 *  @param object the object
 *  @param key the member
 *  @param out receives its value
 *  @return false if absent, not a number, or out of range (out untouched) */
bool snapshotInteger(const Json& object, const wchar_t* key, long long& out);
