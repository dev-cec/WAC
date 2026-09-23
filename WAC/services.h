/*! \file
 *  \brief Services and drivers of the examined machine.
 *
 *  WHAT IT SHOWS. What the machine runs without a user: services, and the
 *  KERNEL DRIVERS. A service starts on its own, often as SYSTEM, and survives
 *  every reboot — which makes it a persistence of choice, and a driver the most
 *  privileged of all. Each entry carries what is really executed, under which
 *  account, and WHEN the service was registered or last modified.
 *
 *  WHY THE HIVE RATHER THAN THE SERVICE MANAGER.
 *  The original version called `OpenServiceW` then `QueryServiceConfigW` for
 *  EACH service, that is several hundred handle openings on the SCM. All that
 *  configuration is written in `SYSTEM\\CurrentControlSet\\Services`, already
 *  extracted raw: reading it offline removes those calls and brings, on top of
 *  that, what the SCM does not give.
 *
 *  WHAT THE HIVE ADDS
 *    - the DRIVERS (`SERVICE_KERNEL_DRIVER`, `SERVICE_FILE_SYSTEM_DRIVER`): the
 *      original enumeration filtered on `SERVICE_WIN32` and excluded all of
 *      them, while a malicious driver is a major persistence vector;
 *    - the key's `LastWriteTime`: the instant the service was created or
 *      modified. No SCM API gives it, and it is often the most telling piece of
 *      the artefact;
 *    - `ServiceDll` (under `Parameters`): for a service hosted in svchost.exe,
 *      `ImagePath` only names svchost — the code really executed is that DLL;
 *    - `FailureCommand`: the command run when the service fails, which is
 *      diverted as a persistence mechanism;
 *    - the services still registered in the hive but absent from the SCM.
 *
 *  WHAT IS STILL MEASURED LIVE, AND WHY
 *  `Status` and `ProcessId` do not exist on the disk: they describe the instant
 *  of the collection. A SINGLE enumeration (`EnumServicesStatusExW`) reads them
 *  for all services at once, without any `OpenServiceW` — the footprint is
 *  therefore lighter than before the switch, not heavier. Dropping them would
 *  have cost the correlation with processes.json, which nothing replaces.
 *  `LiveStatusAvailable` says whether that reading succeeded, so that a stopped
 *  service is not confused with a service whose state could not be read.
 */
#pragma once

#include "binaires.h"
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include "trans_id.h"
#include "tools.h"
#include "quickdigest5.h"
#include "json.h"

/*! One service or driver, as the hive declares it. */
struct ServiceStruct
{
	std::wstring serviceName;               //!< internal name, that is the subkey's name
	std::wstring serviceDisplayName;        //!< name shown to the user
	std::wstring serviceDescription;        //!< description (sometimes "@dll,-id")
	std::wstring serviceType;               //!< type flags, spelled out
	std::wstring serviceStartType;          //!< when it starts: boot, automatic, on demand…
	std::wstring serviceErrorControl;       //!< what the system does if it fails to start
	std::wstring serviceOwner;              //!< account it runs as (ObjectName)
	std::wstring serviceBinary;             //!< ImagePath, as written in the hive
	std::wstring serviceDll;                //!< Parameters\\ServiceDll, if present
	std::wstring serviceFailureCommand;     //!< command run when the service fails
	std::wstring serviceGroup;              //!< load-order group it belongs to
	std::vector<std::wstring> dependances;  //!< services it depends on (DependOnService)
	EmpreinteBinaire serviceEmpreinte;      //!< fingerprints of the binary, if `--binary`
	EmpreinteBinaire serviceDllEmpreinte;   //!< fingerprints of the ServiceDll, if `--binary`
	FILETIME lastWriteTimeUtc = { 0, 0 };   //!< last write to the key, in UTC
	FILETIME lastWriteTime = { 0, 0 };      //!< the same instant, suspect's local time

	// --- volatile state, measured live ---
	bool         etatReleve = false;        //!< true if the SCM answered for this service
	std::wstring serviceStatus;             //!< current state: running, stopped…
	DWORD        serviceProcessId = 0;      //!< PID hosting the service, 0 if stopped

	/*! Converts the service to JSON.
	 *  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the service.
	void clear();
};

//! Volatile state of a service, read in a single enumeration of the SCM.
struct EtatService {
	std::wstring status;      //!< current state, spelled out
	DWORD processId = 0;      //!< PID hosting the service, 0 if stopped
};

/*! All the services and drivers of the examined machine. */
struct Services
{
	std::vector<ServiceStruct> services; //!< the services, as the hive lists them

	/*! Reads the services in `SYSTEM\CurrentControlSet\\Services`, then
	* completes their current state from the service manager.
	* @return S_OK, or the failure of the hive read.
	*/
	HRESULT getData();

	/*! Writes `services.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the services.
	void clear();
};
