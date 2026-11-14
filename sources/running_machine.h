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
		std::wstring serial;       //!< "60E59B9E": what shortcuts and Prefetch cite
		std::wstring deviceName;   //!< "\Device\HarddiskVolume3": what BAM and SRUM cite (B-079)
		std::wstring guid;         //!< "{5e0a…}": what \\?\Volume{…} and VSS cite (B-079)
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

/*! The fixed NTFS volumes of the examined machine, as observed: those WAC
 *  reads raw beyond the system volume (binaries, recycle bins). Removable
 *  volumes — the collection medium among them — are left out.
 *  @return their mount points, "C:", "D:"…; the system drive alone if none
 *          was observed */
std::vector<std::wstring> fixedNtfsVolumes();

/*! A path as the examined machine cites it, on its drive letter: a volume
 *  named by its device ("\Device\HarddiskVolume3\Windows\…", BAM, SRUM)
 *  or by its GUID ("\\?\Volume{…}\…"), resolved by the volumes the
 *  collection observed (B-079). Read at conversion from the snapshot: the
 *  analysis workstation's volumes are never consulted.
 *  @param cited the path as written
 *  @return the path on its letter; `cited` unchanged when its volume is not
 *          one of those observed (a volume gone, another machine's) */
std::wstring onDriveLetter(const std::wstring& cited);

/*! onDriveLetter among \a volumes given: what the tests call. */
std::wstring onDriveLetterAmong(const std::wstring& cited, const std::vector<RunningMachine::Volume>& volumes);
