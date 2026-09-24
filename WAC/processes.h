/*! \file
 *  \brief Running processes: the instantaneous state of the machine.
 *
 *  WHAT IT SHOWS. What is running AT THIS INSTANT, under which account, in
 *  which session, started by which parent, and which DLLs each process has
 *  loaded. That last list is what exposes an injection or a hijacked library:
 *  a legitimate process holding a module it has no reason to load.
 *
 *  It stays a LIVE collection on purpose: its subject is a state that exists
 *  nowhere on the disk.
 *
 *  WHY THERE IS NO `OpenProcess` LEFT. The original version opened a handle per
 *  process with `PROCESS_ALL_ACCESS`, then its token with `TOKEN_ALL_ACCESS`,
 *  while only the owner's SID was read. Two consequences:
 *    - PROTECTED processes refused to open — on a Windows 11 VM, 16 processes
 *      out of 125 (System, Registry, smss, csrss, wininit, services, lsass,
 *      MsMpEng, NisSrv, SecurityHealthService…) came out WITHOUT an owner,
 *      precisely the ones whose impersonation matters most;
 *    - asking for full write and injection access on every process is the
 *      heaviest footprint there is, and the very pattern the protections in
 *      place watch for.
 *
 *  The SID and the session now come from a SINGLE `WTSEnumerateProcessesExW`
 *  call, which returns them for ALL processes without opening any handle. Less
 *  footprint, and more data.
 *
 *  The module list goes through `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)`,
 *  which never needed the handle. It is therefore collected even when the owner
 *  is unknown: the two reads are independent, and chaining them lost the
 *  modules on every token failure.
 */
#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <map>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include "tools.h"
#include "quickdigest5.h"
#include "binaires.h"



/*! One running process, and the modules it has loaded. */
struct Process {
	std::wstring processName = L""; //!< name of the executable
	DWORD processId = 0;            //!< identifier of the process
	BinaryFingerprint fingerprint;     //!< fingerprints of that executable, if `--binary` was given
	DWORD processParentId = 0;      //!< identifier of the process that started it
	DWORD processThreadCount = 0;   //!< number of threads it holds
	std::wstring processSidName = L"";//!< name of the account it runs as
	std::wstring processSID = L"";    //!< SID of that account
	DWORD sessionId = 0;              //!< session the process belongs to
	bool  sessionKnown = false;      //!< true if that session could be read
	std::wstring processModulesAccess = L"OK"; //!< outcome of the module listing, for
	                                  //!< the processes it could not be read on
	std::vector<std::wstring> processModules; //!< the DLLs loaded by the process. The
	                                  //!< first entry is the executable's own path

	/*! Reads a process from a Toolhelp snapshot entry.
	* @param pe32 the entry describing the process.
	*/
	explicit Process(const PROCESSENTRY32W* pe32);

	/*! Lists the modules (DLLs) the process has loaded. Needs no handle on the
	 *  process, so it works on protected processes too.
	 *  @return the result of the listing.
	*/
	HRESULT ListProcessModules();

	/*! Converts the process to JSON, modules included.
	 *  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the process.
	void clear();
};

/*! All the processes running while the collection runs. */
struct Processes {
	std::vector<Process> processes; //!< the processes, as the snapshot listed them


	/*! Takes a Toolhelp snapshot, then reads the owners and sessions in a single
	 *  `WTSEnumerateProcessesExW` call.
	 *  @return S_OK, or the failure of the snapshot.
	*/
	HRESULT getData();

	/*! Writes `processes.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the processes.
	void clear();
};





