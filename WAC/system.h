#pragma once

#include <string>
#include <windows.h>
#include "tools.h"
#include "trans_id.h"

/*! \file
*  \brief System information of the examined machine.
*
*  WHY OFFLINE. The original version queried the live machine:
*  `GetComputerNameExW`, `RtlGetVersion` and above all `BrandingFormatString` —
*  which means LOADING `winbrand.dll` into the collecting process. Loading a
*  module and resolving the domain name through DNS are solicitations of the
*  examined system, and they are avoidable: everything that describes the
*  installation is already written in the hives already extracted raw.
*
*  REGISTRY SOURCES
*    - identity   : `SYSTEM\CurrentControlSet\\Control\\ComputerName\\ComputerName`
*                   and `Services\Tcpip\\Parameters` (Hostname, Domain / NV Domain)
*    - OS         : `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`
*    - architecture : `SYSTEM\CurrentControlSet\\Control\Session Manager\Environment`
*    - machine identifier : `SOFTWARE\\Microsoft\Cryptography\MachineGuid`
*    - time zone  : already read by `loadSuspectTimeZone()` (see tools.h)
*
*  WHAT IS STILL MEASURED LIVE, AND WHY THAT IS LEGITIMATE
*  `LocalDateTime` and `LastBootUpTime` do not describe the installation but the
*  INSTANT of the collection: no hive can provide them, and reading them leaves
*  no trace (`GetSystemTime`, `GetTickCount64`).
*
*  THE `ProductName` TRAP (fixed here). Under Windows 11, `ProductName` still
*  holds "Windows 10 …": Microsoft never updated it. The only reliable
*  discriminant is `CurrentBuild` >= 22000. Without that correction, the report
*  would name the wrong OS — that is, an error of fact in a piece of evidence.
*  `ProductNameRaw` keeps the hive's raw value so that the correction stays
*  verifiable.
*/

/*! Observes the system clock live — instant of the collection, boot time
 *  (kernel, or estimated from the uptime), clock correction, uptime — and
 *  records it as a snapshot (live_snapshot.h), which SystemInfo::getData reads
 *  back. To be called in the live phase: the conversion may run elsewhere.
 *  @return the result of the snapshot's write */
HRESULT snapshotSystemClock();

/*! System information of the examined machine: identity, installation, and
 *  the instant of the collection. */
struct SystemInfo {
	// --- identity of the machine (SYSTEM hive) ---
	std::wstring computerName;              //!< name of the computer
	std::wstring netbiosName;               //!< NetBIOS name (Control\\ComputerName)
	std::wstring domainName;                //!< DNS domain, or "WORKGROUP" outside a domain
	std::wstring osArchitecture;            //!< architecture of the OS

	// --- installation (SOFTWARE hive) ---
	std::wstring osName;                    //!< label of the OS, corrected for Windows 11
	std::wstring productNameRaw;            //!< ProductName as written in the hive
	std::wstring version;                   //!< "major.minor.build" (+ ".UBR" if known)
	std::wstring displayVersion;            //!< DisplayVersion / ReleaseId, ex. "23H2"
	std::wstring editionId;                 //!< EditionID, ex. "Professional"
	std::wstring installationType;          //!< "Client" or "Server"
	std::wstring buildLabEx;                //!< full build fingerprint
	std::wstring servicePack;               //!< CSDVersion, if present
	std::wstring registeredOwner;           //!< owner declared at installation time
	std::wstring registeredOrganization;    //!< organisation declared at installation time
	std::wstring productId;                 //!< identifier of the product
	std::wstring systemRoot;                //!< installation path, e.g. "C:\\Windows"
	std::wstring machineGuid;               //!< unique identifier of the installation
	FILETIME     installDateUtc = { 0, 0 }; //!< installation date of the OS (UTC)
	Precision    installDatePrecision = Precision::HundredNanoseconds; //!< the second when read from the Unix-time fallback

	// --- instant of the collection (measured live) ---
	FILETIME collectionTimeUtc = { 0, 0 };  //!< instant of the run (UTC)
	FILETIME lastBootUpTimeUtc = { 0, 0 };  //!< instant of the last boot (UTC)
	unsigned long long uptimeSeconds = 0;   //!< uptime since the boot
	/*! Total of the clock corrections applied since the boot, in 100 ns units
	 *  (the kernel's BootTimeBias). Positive: the clock was moved forward. A gap
	 *  of a few seconds is the ordinary adjustment (NTP synchronisation, a VM
	 *  resuming from suspension); a large gap signals a modified clock — and
	 *  therefore timestamps to be interpreted with care. */
	long long clockCorrection100ns = 0;
	bool bootFromKernel = false;               //!< true: time read in the kernel, otherwise estimated

	/*! Reads the system information in the hives already open.
	* Requires `conf.System`; `conf.Software` and `conf.CurrentControlSet` are
	* used if available. A field without a source stays empty and is not emitted.
	*/
	HRESULT getData();

	/*! Writes `OperatingSystem.json` into the output directory.
*  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the information.
	void clear();
};
