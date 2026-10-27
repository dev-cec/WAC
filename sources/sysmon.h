/*! \file
 *  \brief SYSMON, where it runs: its configuration, read in the examined
 *         SYSTEM hive, and the files it archived (backlog B-053).
 *
 *  WHY. Sysmon (Sysinternals) is not part of Windows, but where it is
 *  installed its log is often the best detection source of the machine:
 *  processes with their command line and fingerprints, connections, drivers
 *  loaded, accesses to LSASS. Its log is converted with the others
 *  (events.json), even moved (event_log_files.h). What it does not say is
 *  what Sysmon was told to watch — so what its silence proves —, nor what
 *  it kept of the files deleted under a FileDelete rule: their content
 *  itself, an intruder's tool erased from the disk.
 *
 *  WHERE. Two keys of SYSTEM\\<ControlSet>\\Services, both renamable at
 *  installation (`sysmon -i -d <driver>`, a renamed executable):
 *    - the service (Sysmon64, Sysmon): ImagePath, and Parameters\\DriverName,
 *      the name of its driver's key;
 *    - the driver (SysmonDrv): Parameters holds the configuration — Rules
 *      (the rules compiled, a binary format Sysinternals does not document,
 *      given as stored with its SHA-256), HashingAlgorithm, Options,
 *      ArchiveDirectory, ConfigFile (the XML installed from) and ConfigHash
 *      (its fingerprint then).
 *  An installation is told by that link — a service whose DriverName names a
 *  key whose Parameters hold Rules —, not by a name: renamed, it is found
 *  all the same.
 *
 *  THE ARCHIVES. ArchiveDirectory is a folder at the root of the system
 *  volume ("\\Sysmon\\", the default, when the value is absent); each file
 *  is named by its fingerprint, with its extension. Taken whole, raw, with
 *  the XML of ConfigFile when it is still there.
 *
 *  The version of Sysmon is not read here: its event 4 ("Sysmon service
 *  state changed") carries it, and the binary of the service is fingerprinted
 *  with the other binaries.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "registry_common.h"

/*! One installation of Sysmon, as the examined registry describes it. */
struct SysmonInstallation {
	std::wstring service;       //!< the service's key ("Sysmon64")
	std::wstring serviceImagePath;      //!< its ImagePath, as stored
	FILETIME serviceLastWriteUtc = { 0 };   //!< last write of the service's key
	std::wstring driver;        //!< the driver's key ("SysmonDrv"), the service's DriverName
	std::wstring driverImagePath;       //!< its ImagePath, as stored
	FILETIME parametersLastWriteUtc = { 0 };   //!< last write of the driver's Parameters: the last configuration change
	std::vector<std::pair<std::wstring, Json>> parameters; //!< every value of the driver's Parameters, as stored (Rules in hexadecimal)
	std::wstring rulesSha256;   //!< SHA-256 of Rules, uppercase hexadecimal
	std::wstring archiveFolder; //!< the archive folder, absolute ("C:\\Sysmon"); empty if the value names none
	std::wstring configFile;    //!< ConfigFile, absolute; empty if absent or not a local path
};

/*! The installations of Sysmon the examined SYSTEM hive describes. Needs
 *  conf.CurrentControlSet open (missing: none).
 *  @return each installation once, in the order of the services */
std::vector<SysmonInstallation> sysmonInstallations();

/*! A file Sysmon archived, as the collection took it. */
struct SysmonArchivedFile {
	std::wstring path;          //!< its path on the examined machine
	unsigned long long size = 0;
	std::wstring sha256;        //!< of its bytes, uppercase hexadecimal; empty if unreadable
};

/*! What one installation gives in sysmon.json. */
struct SysmonEntry {
	SysmonInstallation installation;
	std::vector<SysmonArchivedFile> archivedFiles;
	std::wstring configFileSha256;      //!< of the ConfigFile collected; empty if it was not there
	Json toJson() const;        //!< @return the entry as a JSON object
};

//! The installations of Sysmon (sysmon.json).
class Sysmon {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any installation; why SYSTEM is missing
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases what was read
private:
	std::vector<SysmonEntry> entries_;
};
