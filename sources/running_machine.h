/*! \file
 *  \brief What the conversion needs to know of the RUNNING examined machine,
 *         observed live and recorded as a sealed snapshot.
 *
 *  WHY. A few facts are read from the running system and not from the
 *  evidence: the system drive, the volumes by serial number (to restore the
 *  drive letter a Prefetch file cites), and — when the SYSTEM hive cannot be
 *  read — the time zone and the ANSI code page. Read at conversion time, they
 *  would be those of the ANALYSIS workstation under --convert: a Prefetch
 *  path on the wrong letter, dates shifted by the analyst's offset, all of it
 *  valid JSON and false. They are therefore observed once, in the live phase,
 *  written to `exhibits\live\running-machine.json`, and every mode reads them
 *  back from there: one code path for the three.
 */
#pragma once
#include <windows.h>
#include <map>
#include <string>
#include <vector>

/*! The running examined machine, as read back from its snapshot. */
struct RunningMachine {
	bool read = false;                   //!< the snapshot exists and was read
	std::wstring systemDrive;            //!< "C:"; empty if not observed
	UINT ansiCodePage = 0;               //!< GetACP(); 0 if not observed
	/*! Time zone, as GetTimeZoneInformation returned it; `timeZoneId` stays
	 *  TIME_ZONE_ID_INVALID if not observed. */
	TIME_ZONE_INFORMATION timeZone = {};
	DWORD timeZoneId = TIME_ZONE_ID_INVALID;
	std::map<std::wstring, std::wstring> volumeBySerial;   //!< "0A1B2C3D" -> "C:"
	/*! A mounted volume, as observed. */
	struct Volume {
		std::wstring mountPoint;   //!< "C:"
		UINT driveType = DRIVE_UNKNOWN;   //!< GetDriveTypeW: DRIVE_FIXED, DRIVE_REMOVABLE…
		std::wstring fileSystem;   //!< "NTFS", "FAT32"…
	};
	std::vector<Volume> volumes;   //!< every volume with a mount point
};

/*! Observes the running machine and writes its snapshot (live_snapshot.h).
 *  To be called in the live phase, like the other snapshots.
 *  @return the result of the snapshot's write */
HRESULT snapshotRunningMachine();

/*! The snapshot, read back once on first call.
 *  @return the machine; `read` false if there is no usable snapshot */
const RunningMachine& runningMachine();
