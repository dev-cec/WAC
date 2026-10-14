/*! \file
 *  \brief Shared tools: configuration, console display, log, registry reads, time formatting, path rules, JSON output.
 */
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <functional>
#include <type_traits>
#include <iomanip>
#include <sstream>
#include "offline_registry.h"
#include "time_zone.h"
#include "translations.h"
#include <vector>
#include <filesystem>
#include <time.h>
#include "json.h"
#include "conversions.h"
#include "whole_file.h"
#include "artefact_catalogue.h"
#include <set>

// global constants
#define MAX_KEY_NAME 255 //!< longest key name in the registry
#define MAX_VALUE_NAME 16383 //!< longest value name in the registry
#define MAX_DATA 1024000 //!< largest data a registry value can hold

// kind of log entry
#define LOG_TYPE_ARTEFACT_TYPE 0//!< log of artefact type
#define LOG_TYPE_ARTEFACT 1//!< log of new artefact
#define LOG_TYPE_INFO 2//!< log of type info to describe artefact
#define LOG_TYPE_ERROR 3//!< log of type error
#define LOG_TYPE_DEBUG 4 //!< name of function called for debug purpose

/*! Time zone of the EXAMINED machine.
*
* WHY THE HIVE RATHER THAN THE API. The Windows artefacts that store a local
* time (dates of FAT volumes, setupapi.dev.log, OLE dates) — and the local
* dates WAC derives from every UTC one — can only be interpreted with the
* **suspect's** time zone. `GetTimeZoneInformation()`
* returns that of the machine running WAC: the same in a live collection, but
* wrong as soon as an image is analysed elsewhere. The source of authority is
* therefore `SYSTEM\CurrentControlSet\\Control\TimeZoneInformation`.
*
* A divergence between the two is a signal in itself: an image analysed on
* another machine, or a time zone changed since the collection. Both are
* therefore recorded in `investigation.json`.
*/
struct TimeZoneInfo {
	std::wstring keyName;          //!< TimeZoneKeyName, ex. "Romance Standard Time"
	std::wstring standardName;     //!< name in standard time
	std::wstring daylightName;     //!< name in daylight saving time
	TimeZoneRules rules;           //!< daylight saving rules, year by year: the offset of EACH date
	int firstRuleYear = 0;         //!< first year of the rules per year ("Dynamic DST"), 0 if none
	int lastRuleYear = 0;          //!< last year of the rules per year, 0 if none
	long activeBiasMinutes = 0;    //!< offset at collection time: minutes to ADD to the local time to obtain UTC
	long standardBiasMinutes = 0;  //!< offset outside daylight saving time (the hive's `Bias` value)
	bool  daylightInEffect = false;//!< true if daylight saving time was in force at collection time
	bool  fromHive = false;        //!< true if read in the suspect's SYSTEM hive
	bool  valid = false;           //!< true if the reading succeeded
};

/*! What a run of WAC does: it collects, or it converts — never both.
 *
 *  WHY. Good forensic practice separates the collection, on the examined
 *  machine, from the analysis, on a controlled workstation (ISO/IEC 27037 and
 *  27042): the fewer actions on the examined system, the fewer traces; and a
 *  conversion made from the sealed exhibit store can be redone, by anyone,
 *  with a corrected WAC. A mode that converted on the examined machine as well
 *  (--full, convert: true) is gone (backlog B-047). */
enum class RunMode {
	Collect,  //!< the default, or --collect: live snapshots, raw extraction, sealed exhibit store; nothing converted
	Convert   //!< --convert=<folder>: conversion of a collection made earlier, from its checked exhibit store
};

//! Holds the application's configuration.
struct AppliConf {
	/*! Diagnostic mode (--debug). Turns on the detailed trace of the NTFS parser
	* (path resolution, index blocks, data runs) on STDERR.
	* Separate from --loglevel: that one logs the COLLECTION (which artefacts,
	* which values), whereas --debug lights up the LOW-LEVEL READING of the
	* volume. Mixing the two drowned the console in ordinary use, while that
	* trace is precisely what allowed the split `$INDEX_ALLOCATION` defect to be
	* located. */
	bool _debug = false;
	bool _dump = false;//!< True if dump is active
	std::wstring name = L""; //!< name of the program, obtained from the command line
	std::wstring _outputDir = L"output"; //!< directory to store output JSON (UTF-16: any name the command line can carry)
	std::wstring mountpoint = L""; //!< mount point path to access the snapshot made during execution
	ORHKEY CurrentControlSet = { 0 }; //!< Reg Key to access Current Control Set Hive
	ORHKEY System = { 0 }; //!< Reg Key to access to System Hive
	ORHKEY Software = { 0 };//!< Reg Key to access CurrentControlSet/Software hive
	std::vector<std::tuple<std::wstring, std::wstring>> profiles;//!< vector to store SID and profiles of users present on the machine
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);//!< handle of the console
	std::ofstream log;//!< handle of the output log file, for the debug mode (UTF-8 bytes)
	int loglevel = 0; //!< log level (0 by default), set on the command line
	bool binary = false; //!< --binary: fingerprints of the cited files, and collection of the binaries
	/*! --binary-all: every executable is collected, authenticated or not;
	 *  the signature is still checked and its verdict recorded. For the cases
	 *  where the content itself must be in the exhibit store. Implies binary. */
	bool binaryAll = false;
	/*! --threads=N: threads analysing the executables of --collect --binary
	 *  (PE, Authenticode, catalogs, fingerprints); 0 = the processor's
	 *  threads minus one, the reading of the volume keeping its own. */
	unsigned threads = 0;
	/*! Language of the console (wac.yml, language:). The command line's
	 *  --language= overrides it; the JSON files and the logs stay in English. */
	Language language = Language::French;
	/*! The artefacts to collect, one switch each (wac.yml, section
	 *  `artefacts:`), all on by default: a key missing from the file is on.
	 *  No artefact is collected without its key. The hives, the event logs and
	 *  the $MFT are not artefacts but DEPENDENCIES, copied when an artefact
	 *  asked for reads them (needsUserHives, rdp_server and the logs…). */
	struct CollectedArtefacts {
		bool events = true;           //!< the event logs, with their messages
		bool operatingSystem = true;  //!< version, installation, computer name, uptime (SYSTEM, SOFTWARE)
		bool usbstor = true;          //!< USB mass storage devices (Enum\USBSTOR)
		bool mountedDevices = true;   //!< volumes and drive letters the machine knew (MountedDevices)
		bool bam = true;              //!< last execution of each program per user (Background Activity Moderator)
		bool muiCache = true;         //!< names of the programs each user launched (usrClass.dat)
		bool amcache = true;          //!< Amcache.hve: applications, executables and drivers seen
		bool userAssist = true;       //!< programs each user launched from Explorer, with count and date
		bool runKeys = true;          //!< Run and RunOnce keys of the machine and of each user
		bool shimcache = true;        //!< application compatibility cache (AppCompatCache)
		bool shellbags = true;        //!< folders each user browsed in Explorer
		bool mru = true;              //!< files each user opened or saved through the common dialogs
		bool mruApps = true;          //!< programs used to open or save those files
		bool users = true;            //!< local accounts (SAM): logons, failures, flags, password hashes
		bool localGroups = true;      //!< members of each local group (SAM)
		bool registryBackups = true;  //!< RegBack: the machine's older hives, raw copy only
		bool scheduledTasks = true;
		bool services = true;         //!< services and drivers: configuration and live states
		bool processes = true;        //!< live
		bool sessions = true;         //!< live
		bool network = true;          //!< live: connections, neighbours, interfaces, routes
		bool prefetch = true;
		bool jumpLists = true;
		bool recentDocuments = true;
		bool mft = true;              //!< $MFT, raw, and mft.json: every file with its dates
		bool usnJournal = true;       //!< $UsnJrnl:$J, raw, and usn_journal.json: the change journal
		bool logFile = true;          //!< $LogFile and $TxfLog, raw only: the NTFS and transactional NTFS journals
		bool powershellHistory = true; //!< PSReadLine histories of every profile
		bool setupApi = true;         //!< setupapi.dev.log: device installations, first USB connections
		bool recycleBin = true;       //!< the $I of every volume's recycle bin
		bool hosts = true;            //!< the hosts file
		bool errorReports = true;     //!< Windows Error Reporting: Report.wer of the machine and of each profile
		bool defender = true;         //!< Microsoft Defender: support logs (MPLog), detection history, quarantine
		bool startupFolders = true;   //!< startup folders of all users and of each profile
		bool shortcuts = true;        //!< shortcuts outside Recent: Start menu, desktops, Quick Launch, pinned task bar
		bool securityDescriptors = true; //!< $Secure:$SDS of every NTFS volume: owner and ACLs of every file
		bool ntfsVolumes = true;      //!< $Boot and $UsnJrnl:$Max of every NTFS volume: serial, geometry, journal creation
		bool dpapiMasterKeys = true;  //!< DPAPI master keys of each profile and of the system, copied encrypted; their metadata
		bool userShellFolders = true; //!< each user's shell folders (User Shell Folders): where desktop and documents really are
		bool webClient = true;        //!< the browsers: visits, downloads, searches (Chromium History), their databases raw
		bool zoneIdentifiers = true;  //!< Zone.Identifier streams, read in the $MFT copy
		bool security = true;         //!< SECURITY hive: LSA secrets' names and dates, cached logons, audit policy
		bool persistence = true;      //!< registry persistence beyond Run: IFEO, AppInit, Winlogon, LSA, COM…
		bool officeTrustRecords = true;          //!< Office trusted documents: macros enabled by the user, and when
		bool typedPaths = true;          //!< paths typed in Explorer's address bar
		bool wordWheelQuery = true;          //!< terms searched in Explorer
		bool rootCertificates = true;          //!< root certificates of the machine and of each user
		bool internetSettings = true;          //!< each user's proxy and automatic configuration script
		bool firewall = true;          //!< firewall rules and profiles
		bool wmi = true;               //!< WMI repository: event subscriptions (filters, consumers, bindings), read offline
		bool srum = true;              //!< SRUDB.dat: network and resource usage per application and user, 30 to 60 days
		bool bits = true;              //!< qmgr.db: BITS jobs, their files and notification command lines
		bool fatVolumes = true;        //!< FAT and exFAT volumes (a suspect's keys included): entries, deleted ones too
		bool installedPrograms = true;  //!< installed programs: Uninstall keys of the machine and of each user
		bool defenderConfiguration = true;  //!< Defender configuration: exclusions and protection settings (registry)
		bool explorerRecentDocs = true;  //!< files each user opened, by extension (Explorer's RecentDocs)
		bool mountPoints = true;  //!< volumes and network shares each user's Explorer saw (MountPoints2)
		bool knownNetworks = true;  //!< networks the machine joined (NetworkList): name, kind, gateway, first and last connection
		bool programUsages = true;  //!< what each user launched or used: FeatureUsage, JumplistData, compatibility store and layers, RADAR, pinned items
		bool devices = true;  //!< devices the machine knew: Enum USB and SCSI with their dates, portable devices, volume labels, DeviceClasses
		bool networkShares = true;  //!< folders the machine shares (LanmanServer Shares)
		bool networkConfiguration = true;  //!< network configuration read offline: adapters, last IPv4 and IPv6 settings, DHCP leases
		bool eventLogConfiguration = true;  //!< configuration of each event log channel: enabled, size, retention, access
		bool activitiesCache = true;  //!< Windows Timeline: ActivitiesCache.db of every profile
		bool searchIndex = true;  //!< Windows Search index: what the indexer recorded of each file
		bool rdpClient = true;  //!< outgoing RDP connections: servers, connection files, bitmap cache
		bool rdpServer = true;  //!< incoming RDP connections, from the collected event logs
		bool thumbcache = true; //!< Explorer's thumbnail and icon caches: what each user had on screen
		bool emails = true;     //!< Outlook's PST and OST: messages, recipients, attachments

		/*! Whether an artefact asked for reads the users' hives (ntuser.dat,
		 *  usrClass.dat): they are a dependency, copied then. They used to be
		 *  copied only with the former `registry` key — typed_paths alone gave an
		 *  empty typed_paths.json, read as "nothing typed". A new artefact read
		 *  in a user's hive is added here.
		 *  @return true if one of them is switched on */
		bool needsUserHives() const {
			return muiCache || userAssist || runKeys || shellbags || mru || mruApps
			    || persistence || officeTrustRecords || typedPaths || wordWheelQuery
			    || rootCertificates || internetSettings || installedPrograms || explorerRecentDocs || mountPoints || programUsages
			    || userShellFolders || webClient   // web client: TypedURLs
			    || rdpClient   // the servers reached, in NTUSER.DAT
			    || shortcuts;   // a desktop redirected elsewhere is read in NTUSER.DAT (user_shell_folders.h)
		}

		/*! Whether an artefact asked for reads the event logs: they are a
		 *  dependency of `events` and of `rdp_server`, which finds the incoming
		 *  connections in them.
		 *  @return true if one of them is switched on */
		bool needsEventLogs() const { return events || rdpServer; }
	} artefacts;
	/*! The version of the examined Windows, read in its SOFTWARE hive once it
	 *  is open (applyArtefactCatalogue); build 0 until then, or if unreadable. */
	WindowsVersion examinedVersion;
	/*! The artefacts asked for that this version of Windows does not have
	 *  (keys of wac.yml): switched off by applyArtefactCatalogue, never
	 *  launched, and declared so in their file — not a failure, not a refusal
	 *  of the configuration. */
	std::set<std::string> absentFromVersion;
	/*! The artefacts asked for whose form on this version of Windows WAC has
	 *  no decoder for (undecodedOn, keys of wac.yml): collected as usual, their
	 *  conversion replaced by "unsupported format" (applyArtefactCatalogue). */
	std::set<std::string> undecodedOnVersion;
	RunMode mode = RunMode::Collect; //!< what this run does (see RunMode)
	TimeZoneInfo timeZone; //!< time zone of the examined machine (SYSTEM hive if available)
	/*! System drive of the examined machine, with its colon ("C:").
	*
	* Read at run time rather than hard-coded: Windows is not always installed on
	* C:. The value serves both the raw extraction (volume letter) and the
	* restitution of the artefacts' original paths. */
	std::wstring systemDrive = L"C:";
	/*! ANSI code page of the EXAMINED machine, read in its SYSTEM hive
	* (`Control\Nls\CodePage`, value `ACP`). 0 until read: the running
	* machine's is used meanwhile — the same in a live collection. */
	UINT ansiCodePage = 0;
};

/*! Reads the machine's system drive and fills `conf.systemDrive`.
* To be called at startup, before any extraction.
* On failure, `conf.systemDrive` keeps its default value ("C:").
*/
void loadSystemDrive();

/*! Reads the user profiles and fills `conf.profiles` (SID, path).
*
* OFFLINE. The source is `Microsoft\\Windows NT\\CurrentVersion\\ProfileList`,
* read in the EXTRACTED SOFTWARE hive (`conf.Software`). That key used to be
* read in the live registry: it was the last key WAC opened on the examined
* machine's registry.
*
* AN IMPOSED ORDER. The per-user hives (`ntuser.dat`, `usrClass.dat`) live in
* the profile folder: those paths must be known to extract them. Hence the
* sequence ExtractSystemHivesRaw → OROpenHive(SOFTWARE) → loadProfileList →
* ExtractUserHivesRaw (see raw_collect.h).
*
* The variables of `ProfileImagePath` (REG_EXPAND_SZ) are expanded from
* `conf.systemDrive`, and not from the process's environment: the value belongs
* to the examined machine, not to the one running WAC.
*
* @return ERROR_SUCCESS if at least one profile was read, ERROR_EMPTY if the key
*         holds no usable profile, ERROR_INVALID_HANDLE if the SOFTWARE hive is
*         not open, or the hive reader's code
*/
HRESULT loadProfileList();

/*! SID given to the Default profile (`\\Users\\Default`), the template of
*  every new profile, which belongs to no account: "S-0-0-0", zeros only. It
*  has a SID's form, so the readers that link entries by SID keep working, and
*  its revision 0 makes it no real SID. Not S-1-0-0: that is Windows' NULL SID,
*  a real one. Its entries also carry `Profile: "Default"` (see addUser). */
extern const wchar_t DEFAULT_PROFILE_SID[];

/*! Volume letter of an absolute path, without the colon ("C").
*
* WHY THIS FUNCTION EXISTS. WAC assumed ONE SINGLE volume, the Windows one. But
* `ProfileImagePath` may name another disk — a common setup on a workstation
* with a system SSD and a data disk: Windows on `C:`, the profiles on `D:`. The
* code then stripped the "C:" prefix from a path starting with "D:", found
* nothing to strip, and looked for `D:\Users\jean\ntuser.dat` **in C:'s file
* table**. The hive was not extracted, and ALL of that user's artefacts came out
* with "0 entries" — indistinguishable from "no trace".
*
* @param absolute absolute path, with or without a drive letter
* @return the letter in upper case, or that of the system volume if the path
*         carries none (a path already relative to the root)
*/
std::wstring volumeOfPath(const std::wstring& absolute);

/*! Returns an absolute path relative to the root of ITS volume.
*
* `D:\Users\jean` -> `\Users\jean`. The letter is stripped whatever it is, and
* at the HEAD only: `replaceAll()`, used until now, stripped every occurrence,
* so that a path holding the letter followed by a colon again was silently
* altered.
*
* @param absolute absolute path
* @return the path without its drive letter
*/
std::wstring pathRelativeToVolume(const std::wstring& absolute);

/*! Path, on the collection medium, of the extracted copy of a file.
*
* Centralises the naming convention of the raw extraction, which nine
* collectors each rebuilt on their own with
* `replaceAll(path, conf.systemDrive, L"")` — hence with the same
* multi-volume defect (see `volumeOfPath`).
*
* The files of the SYSTEM volume keep their original location under
* `conf.mountpoint`, so that nothing changes for the common case. Those of
* another volume are stored under `\_volume_X\`, without which two disks
* carrying the same relative path (`\Users\jean` on C: and on D:) would
* overwrite each other's copies.
*
* @param absolute path of the file on the examined machine
* @return the path of its copy on the collection medium
*/
std::wstring extractedPath(const std::wstring& absolute);

/*! Canonical "X:\\…" form of a file path found in an artefact.
*
* THE path normalisation rule: NT object prefixes (`\\??\\`, `\\\\?\\`), the
* kernel prefix `\\SystemRoot\\`, the system volume `SYSVOL\\` (ShimCache of
* Windows 8 and 8.1), system variables (`%windir%`,
* `%ProgramFiles%`…) expanded from `conf.systemDrive`, surrounding quotes and
* spaces, drive letter in upper case. `binaryPath` and the expansion of profile
* paths both come back to it: one single rule, no variant per artefact.
*
* @return the normalised path, or an EMPTY string if it does not name a
*         determinable local file: network share, relative path, variable
*         specific to a user, or unknown variable
*/
std::wstring normalizeFilePath(std::wstring path);

/*! Resolves a binary path as the registry writes it.
*
*  Registry paths are not directly usable: they may be quoted and followed by
*  options, start with an NT object prefix (`\SystemRoot\`, `%SystemRoot%\`,
*  `\??\`), or be relative — and a relative path is relative to `%SystemRoot%`,
*  not to the current directory.
*
*  Serves the service binaries and the resource files of the event providers,
*  two uses that read the same kind of value.
*
*  @param imagePath the raw registry value
*  @return the absolute path, or an empty string if it does not name a file
*          (a kernel object such as `\Driver\xxx`, for instance)
*  @see the implementation, in tools.cpp, documents the forms met
*/
std::wstring binaryPath(std::wstring imagePath);

/*! Path of an extracted file under a given root.
*
*  Same rule as `extractedPath`, but the root is passed as a parameter: the
*  extraction writes under the exhibit store, the work happens under another
*  root, and both must store the files identically for one to be the verifiable
*  copy of the other.
*
*  @param root destination directory
*  @param absolute original path, with its volume letter or relative to the
*         system volume
*  @return root + [\_volume_X] + path relative to the volume
*/
std::wstring pathUnder(const std::wstring& root, const std::wstring& absolute);

/*! ORIGINAL path of a file, from its extracted copy.
*
* The inverse of `extractedPath()`, used to publish in the JSON the path the
* file had on the examined machine — and not that of its copy on the collection
* medium.
*
* The naive replacement used until now, `replaceAll(path, conf.mountpoint,
* conf.systemDrive)`, ignored the volume subfolder: a file coming from `D:` came
* out as `C:\_volume_D\Users\…`, that is a path that exists on no disk.
*
* @param extracted path of the copy, under `conf.mountpoint`
* @return the original path, with its real drive letter
*/
std::wstring originalPath(const std::wstring& extracted);

extern AppliConf conf; //!< the application's configuration, shared by every collector

///////////////////////////////////////////////////////
// Data formats
//////////////////////////////////////////////////////

/*! Holds a date in the FAT DOS time format.
*
* A note on dates and times:
*
* DOS stores a file's modification date and time as a pair of 16-bit numbers:
*
* 	7 bits for the year, 4 bits for the month, 5 bits for the day of the month
* 	5 bits for the hour, 6 bits for the minutes, 5 bits for the seconds (x2)
*
* Every file system uses dates relative to an epoch (time zero). For DOS, the
* epoch is midnight, New Year's Eve, 1 January 1980. A seven-bit field for the
* years means that the DOS calendar only works up to 2107.
*/
struct FatDateTime {

	unsigned int i =0; //!< the original integer the constructor took, that is the two 16-bit halves concatenated
	unsigned short int date =0; //!< first 16-bit half, the date: 7 bits for the year, 4 for the month, 5 for the day of the month
	unsigned short int time =0 ; //!< second 16-bit half, the time: 5 bits for the hour, 6 for the minutes, 5 for the seconds (x2)

	//! Builds from a timestamp, which parses the date.
	FatDateTime(unsigned int _i); 
	//! Converts FAT DOS TIME to SYSTEMTIME.
	SYSTEMTIME toSystemTime(); 
	/*! Converts FAT DOS TIME to FILETIME.
	 *  @return the instant, or a null FILETIME (not emitted) for the zero
	 *          value and for an impossible date (month 13, 30 February, hour
	 *          25...) — the bits are hostile input. */
	FILETIME toFileTime(); 
};

///////////////////////////////////////////////////////
// display
///////////////////////////////////////////////////////

//! Prints the word OK in green on the console.
void printSuccess();

/*! The steps printed so far and their time, from printStep to their OK or
 *  their error (backlog B-033): where a collection's time goes, artefact by
 *  artefact.
 *  @return "label 12.31 s; label 0.04 s…", every step, in the order of the run */
std::wstring stepTimes();

/*! Prints a progress line rewritten in place (carriage return).
*
* WHY. On a real system, extracting a large hive or reading the System log takes
* several minutes without displaying anything: the operator cannot tell a
* collection that is progressing from one that is stuck, and may interrupt it —
* which loses the collection under way.
*
* Writes ONLY if the standard output is a console: redirected to a file, the
* progress would bring nothing and would pollute the log with thousands of
* lines.
*
* The progress rewrites the CURRENT LINE, so it erases the step label (those are
* written without a newline, waiting for their "OK"). That is why the label must
* be set by printStep(): printSuccess() and printError() then restore it
* automatically, and no collector has to care.
*
* @param label what is under way (e.g. a file or channel name)
* @param done quantity processed
* @param total total quantity expected, or 0 if unknown
* @param unit unit to display (e.g. L"KiB", L"evt")
*/
void printProgress(const std::wstring& label, unsigned long long done,
                   unsigned long long total, const std::wstring& unit);

/*! Ends a progress line and restores the step label.
* Called automatically by printSuccess() and printError(): to be called directly
* only to take back the display in the middle of a treatment.
*/
void printProgressEnd();

/*! Prints the label of a step and remembers it.
*
* To be used instead of a direct wprintf for any step that may display a
* progress: the label is printed again afterwards, so that the "OK" or the error
* stays attached to its step.
* @param label e.g. L" - Extracting SHIMCACHE Registry Keys : "
*/
void printStep(const std::wstring& label);

/*! Prints the label of a step, in the console's language, as " - label : ".
* The log keeps its English label (time per step, investigation.json).
* @param step the step
* @param qualifier what the step bears on, after the label (" (C:)"); none by default
*/
void printStep(Text step, const std::wstring& qualifier = L"");

/*! Prints the heading of a phase, in yellow, in the console's language.
* @param heading the heading, e.g. Text::HeadingRawExtraction
*/
void printHeading(Text heading);

/*! Writes text to the console, accents included (see writeConsole in tools.cpp).
* @param text the text, newlines included
*/
void writeConsole(const std::wstring& text);

/*! Progress of an artefact, rate-limited.
*
* Meant for the collection loops. The rate limiting is done by printProgress, BY
* TIME: a fixed step in number of elements cannot suit both the 38 shellbags of
* several seconds each and the 3,032 instantaneous amcache entries (measured on
* a real workstation).
* @param artefact name of the artefact under way
* @param done number of elements processed
* @param total total number expected, or 0 if unknown
*/
void printProgressStep(const std::wstring& artefact, unsigned long long done,
                       unsigned long long total);

/*! Prints the error message of an HRESULT in RED on the console, in the
* console's language when Windows has it.
* @param hresult the result a command returned
*/
void printError( HRESULT  hresult);

/*! Prints errorText in RED on the console.
* @param errorText the text to print
*/
void printError( std::wstring  errorText);

/*! Extracts the error message of an HRESULT returned by a command, in
* English — the message that goes into the JSON files and the logs.
* @param hresult the result a command returned
* @return the text attached to that HRESULT error code
*/
std::wstring getErrorMessage(HRESULT hresult);

/*! The error message of an HRESULT in a given language, English when Windows
* does not have it, the system's own language failing that.
* @param hresult the result a command returned
* @param language the language wanted
* @return the text attached to that HRESULT error code
*/
std::wstring getErrorMessage(HRESULT hresult, Language language);

/*! Records a message in the output log file.
* log(0, L""); => plain message
* log(0, L"ℹ️"); => new kind of artefact
* log(1, L"➕"); => new artefact
* log(2, L"🔥"); => error
* log(2, L"❇️"); => identification of an artefact
* log(3, L"🔈"); => name of the function called
* @param loglevel log level, which also decides the emoji
* @param message the message to record, giving the context
*/
void log(int loglevel, std::wstring message);

/*! Records a message in the log file, completed by an error code.
* @param loglevel log level, which also decides the emoji
* @param message the message to record, giving the context
* @param result error code, turned into an error message
*/
void log(int loglevel, std::wstring message, HRESULT result);


/*! Extracts the error message of an HRESULT returned by a command.
* @param hresult the result a command returned
* @return the text attached to that HRESULT error code
*/
std::wstring getErrorMessage(HRESULT hresult);

/*! Prints the content of a buffer in hexadecimal on the console.
* @param buffer pointer to a buffer holding the data to print
* @param start position of the first byte to print in the buffer
* @param end position of the last byte to print in the buffer.
*/
void dump(LPBYTE buffer, int start, int end);

/*! Returns a memory area in hexadecimal, byte by byte.
*
* MIND THE SEMANTICS, corrected on 2026-09-15. The third parameter was named
* `end` and the loop went up to `x <= end` — an INCLUSIVE end index. But all
* five callers passed it a SIZE: each therefore read one byte past the intended
* area. It is now a length, and the bound is exclusive.
*
* @param buffer start of the area
* @param start offset of the first byte to return
* @param length number of bytes to return from `start`
* @return the bytes in hexadecimal, separated by spaces
*/
std::wstring dump_wstring(LPBYTE buffer, int start, int length);


///////////////////////////////////////////////////////
// strings
///////////////////////////////////////////////////////

/*! In a string, replaces every occurrence of a string by another.
* @param src the starting string, holding the string to look for
* @param search the string to look for in `src`; empty, nothing is replaced
* @param replacement the string to put in place of `search`
* @return the string that results from the replacement
*/
std::wstring replaceAll(std::wstring src, std::wstring search, std::wstring replacement);

/*! ROT13 operation on a string.
* @param source the string to process
* @return the string that results from the operation
*/
std::wstring ROT13(std::wstring source);

/*! URL decoding.
* @param encoded the URL to decode
* @return the string that results from the operation
*/
std::string decodeURIComponent(std::string encoded);

/*! Inserts n tabulations in a string. Used to lay out the output JSON.
* @return a string holding the wanted number of tabulations
*/
std::wstring tab(int i);

///////////////////////////////////////////////////////
//conversion
///////////////////////////////////////////////////////

/*! Name of a SID, resolved OFFLINE from the examined machine's hives (see
* account_names.h): never by asking the running system or the network.
* Implemented in account_names.cpp; the table is filled by loadAccountNames.
* @param _sid the SID, as text
* @return its name, or "" if the evidence does not name it (not emitted)
*/
std::wstring getNameFromSid(std::wstring _sid);

/*! Adds the user an entry belongs to: `SID`, and `SIDName` as resolved
 *  offline in the examined machine's hives — or, for the Default profile,
 *  `Profile: "Default"` (see DEFAULT_PROFILE_SID). The one place that writes
 *  them, for every artefact.
 *  @param o the entry's object
 *  @param sid the user's SID; empty for an entry of the machine (nothing emitted)
 *  Implemented in account_names.cpp. */
void addUser(Json& o, const std::wstring& sid);


/*! Converts a boolean to the string "true" or "false".
* @param b the boolean to convert
* @return "true" or "false"
*/
std::wstring bool_to_wstring(bool b);


/*! Converts a Unix time (seconds since 1970, UTC: a PE TimeDateStamp, a clock
*  read in C) to a FILETIME.
* @param seconds the Unix time
* @return the same instant as a FILETIME */
FILETIME unixToFiletime(unsigned long long seconds);

/*! A registry value as JSON, as the hive stores it: a string (REG_SZ,
*  REG_EXPAND_SZ), a list of strings (REG_MULTI_SZ), a number (REG_DWORD,
*  REG_QWORD), or the bytes in hexadecimal (any other type).
* @param type the value's registry type
* @param data its bytes
* @return its JSON form */
Json registryValueToJson(DWORD type, const std::vector<BYTE>& data);

/*! A registry value's type as its name ("REG_SZ", "REG_DWORD"…), or its number
*  in hexadecimal for a type without one.
* @param type the value's registry type
* @return its name */
std::wstring registryTypeName(DWORD type);

/*! A registry value name as a JSON key, PascalCase like every key WAC writes:
*  the separators dropped, each word capitalised ("Audio_CaptureDriver" ->
*  "AudioCaptureDriver"); the key's default value, which has no name, is
*  "DefaultValue".
* @param valueName the registry name
* @return the JSON key */
std::wstring registryNameToJsonKey(const std::wstring& valueName);

///////////////////////////////////////////////////////
// Horodatages ISO 8601
///////////////////////////////////////////////////////
/*  WHY THIS FORMAT. The dates used to be emitted as "15/9/2026 5h43m32s":
 *  neither sortable lexicographically, nor correlatable between tools,
 *  ambiguous on the day and the month, and above all SILENT on the time zone —
 *  and a timestamp without a time zone cannot be used in a timeline.
 *
 *  ISO 8601 settles all four problems at once: "2026-09-15T05:43:32Z" for UTC,
 *  "2026-09-15T07:43:32+02:00" for a local time. The date then carries its own
 *  time zone: no external convention is needed to read it.
 *
 *  TWO FUNCTIONS, NOT A FLAG. The suffix ("Z" or "+HH:MM") must tell the truth
 *  about the value. Only the caller knows what it holds, and a parameter with a
 *  default value would produce falsely labelled dates whenever it was
 *  forgotten — a serious fault in an expert report. Hence two named functions,
 *  with no possible default.
 *
 *  A null date returns an empty string: without that
 *  one would emit "1601-01-01T00:00:00Z" as if it were a real date.
 */

/*! The precision a date source really has. The fraction written says no more
*  than it: a FAT date, precise to two seconds, used to come out as
*  "…:30.0000000", which claims a precision to the ten-millionth of a second —
*  an analyst would order on digits that the source never held.
*  The default of the functions below, HundredNanoseconds, is that of a
*  FILETIME, the native form of almost every Windows date; a source of coarser
*  precision says so explicitly. */
enum class Precision {
	HundredNanoseconds, //!< FILETIME: seven digits of fraction
	Millisecond,        //!< SYSTEMTIME (event data): three digits
	Second,             //!< FAT date (2 s), Unix time, text date, OLE date as converted: no fraction
	Minute              //!< text date without seconds (Windows XP's archive items): no seconds written
};

/*! Converts a string holding a date ("month/day/year hour:minute:second")
* to a FILETIME. A two-digit year is one of a FAT date's, 1980 to 2079
* (Windows XP's archive items: "11/26/04  21:00").
* @param input the string to convert
* @param precision when given, the seconds may be absent, and it receives the
*        precision written: Precision::Minute without them, Precision::Second
*        with them; when not, a date without seconds is refused
* @return the instant, or a null FILETIME (not emitted) if the string does not
*         hold a valid date
*/
FILETIME wstring_to_filetime(std::wstring input, Precision* precision = nullptr);

/*! Formats a FILETIME **already expressed in UTC** as ISO 8601, suffix "Z".
* @param filetime the instant, in UTC
* @param precision the precision of the source (see Precision): the digits of fraction written
* @return "YYYY-MM-DDTHH:MM:SSZ", or "" if the date is null
*/
std::wstring timeToIso8601Utc(const FILETIME& filetime, Precision precision = Precision::HundredNanoseconds);

/*! Reverse of timeToIso8601Utc: "YYYY-MM-DDTHH:MM:SS[.f…]Z" to a FILETIME,
 *  exactly, to the 100 ns. Used to read back the dates of the manifest
 *  (--convert). Anything else — an offset instead of "Z", a digit missing, a
 *  month 13 — is refused.
 *  @param text the date
 *  @param filetime receives it
 *  @return false if the text is not such a date (filetime untouched) */
bool iso8601UtcToFiletime(const std::wstring& text, FILETIME& filetime);

/*! Formats a FILETIME **expressed in local time** as ISO 8601, with the
* offset in force at that local time on the examined machine (e.g. "+01:00" in
* winter, "+02:00" in summer) — the one suspectLocalToUtc applies.
* For a value the artefact stores in LOCAL time; a value stored in UTC is
* formatted by utcTimeToIso8601Local, which knows its exact offset even in the
* hour repeated in autumn.
* @param filetime the instant, in the examined machine's local time
* @param precision the precision of the source (see Precision): the digits of fraction written
* @return "YYYY-MM-DDTHH:MM:SS+HH:MM", or "" if the date is null
*/
std::wstring timeToIso8601Local(const FILETIME& filetime, Precision precision = Precision::HundredNanoseconds);

/*! Converts a FILETIME **expressed in local time** to UTC, then formats it as
* ISO 8601 with the "Z" suffix.
* For the dates really stored in local time: the dates of FAT volumes,
* setupapi.dev.log, OLE dates. Most Windows artefacts store UTC — BAM,
* UserAssist, USBSTOR, Amcache, ShimCache, and the FAT-format dates of shell
* items (shortcuts, jump lists, shellbags) were all once read as local time
* by mistake, each shifted by the time-zone offset; each is now confronted
* with an independent source by check-json.py or the test VM.
* The offset is the suspect's (suspectLocalToUtc), not the running machine's.
* @param filetimeLocal the instant, in the examined machine's local time
* @param precision the precision of the source (see Precision): the digits of fraction written
* @return "YYYY-MM-DDTHH:MM:SSZ", or "" if the date is null
*/
std::wstring localTimeToIso8601Utc(const FILETIME& filetimeLocal, Precision precision = Precision::HundredNanoseconds);

/*! Converts a FILETIME **expressed in UTC** to the local time of the EXAMINED
* machine, then formats it as ISO 8601 with the offset in force AT THAT DATE.
*
* WHY NOT `FileTimeToLocalFileTime` FOLLOWED BY `timeToIso8601Local`. That
* combination, used until now, applies the offset of the machine RUNNING WAC
* while attaching the label of the SUSPECT's time zone: the same in a live
* collection, contradictory as soon as an image is analysed elsewhere — the
* value and its label would no longer speak of the same time zone.
* Here, the offset applied and the label come from the SAME source.
*
* @param filetimeUtc the instant, in UTC
* @param precision the precision of the source (see Precision): the digits of fraction written
* @return "YYYY-MM-DDTHH:MM:SS+HH:MM", or "" if the date is null
*/
std::wstring utcTimeToIso8601Local(const FILETIME& filetimeUtc, Precision precision = Precision::HundredNanoseconds);

/*! Adds a date in both forms: `<key>Utc` in UTC and `<key>` in the SUSPECT's
* local time (utcTimeToIso8601Local). Nothing is written for a null date: a
* "1601-01-01" would read as a real date the format never carried.
* @param o the object
* @param key the name of the local form; the UTC form is `key` + "Utc"
* @param utc the date, UTC */
void addDate(Json& o, const std::wstring& key, const FILETIME& utc);

/*! Converts a UTC FILETIME to the local time of the EXAMINED machine.
*
* Replaces `FileTimeToLocalFileTime()`, which applies the time zone of the
* RUNNING machine. The two coincide in a live collection, but diverge as soon as
* an image is analysed elsewhere: the time would then be shifted by the
* examiner's time zone while carrying the label of the suspect's — two time
* zones in one value. A single point of truth, `conf.timeZone`, avoids that
* trap; the fallback on the running machine applies only if the SYSTEM hive
* could not (yet) be read. The offset is the one in force AT THAT DATE
* (daylight saving time, rules of the year), not the offset of the collection
* day.
*
* NO RETURN CODE. The result is null (1601), hence not emitted, when the
* input is null or the shift leaves the FILETIME range: the caller has nothing
* to check and nothing to ignore — a failure cannot turn into a wrong date.
*
* @param filetimeUtc the instant, in UTC
* @return the instant in the suspect's local time, or a null FILETIME
*/
FILETIME utcToSuspectLocal(const FILETIME& filetimeUtc);

/*! Converts a FILETIME in the local time of the EXAMINED machine to UTC: the
* reverse of utcToSuspectLocal, with the same offset.
*
* Replaces `LocalFileTimeToFileTime()`, which applies the time zone of the
* RUNNING machine — the trap described above, in the other direction.
*
* @param filetimeLocal the instant, in the suspect's local time
* @return the instant in UTC, or a null FILETIME (input null or out of range)
*/
FILETIME suspectLocalToUtc(const FILETIME& filetimeLocal);

/*! Reads the examined machine's time zone in the suspect's SYSTEM hive.
*
* Reads `Control\TimeZoneInformation` under `conf.CurrentControlSet` and fills
* `conf.timeZone`. To be called as soon as `conf.CurrentControlSet` is open:
* every local timestamp formatted AFTERWARDS will carry the suspect's offset.
*
* The daylight saving rules come from the same key (the rule Windows applies
* now) and, unless `DynamicDaylightTimeDisabled` is set, from the rules per
* year of the zone in the SOFTWARE hive (`Time Zones\<key>\Dynamic DST`),
* which must therefore be open: a date of 2005 in the United States follows
* the rules of 2005, not those of today.
*
* On failure, `conf.timeZone.valid` stays false and the formatting falls back on
* `GetTimeZoneInformation()` — which is right in a live collection, since the
* examined machine is then the running machine.
*
* @return ERROR_SUCCESS if the time zone was read, an error code otherwise
*/
HRESULT loadSuspectTimeZone();



/*! Decodes bytes into UTF-16 text — THE conversion from bytes to text in WAC.
*
* The code page is a parameter, not a function name: there used to be six
* conversions, two of them wrong. mbstowcs / wcstombs in the "C" locale mapped
* each byte to the character of the same value (Latin-1): the characters
* 0x80-0x9F of the Windows code pages (’ “ ” – € …) came out as control
* characters — "d’orientation" as "d\x92orientation" on a real machine — and
* a path outside Latin-1 could not be narrowed at all.
*
* By default, the EXAMINED machine's ANSI code page: shortcuts, shell items,
* DestList host names and ANSI event data store their non-Unicode strings in
* "the system default code page" (MS-SHLLINK) of the machine that wrote them.
* WAC's own narrow strings (JSON file names, build date) are pure ASCII,
* identical in every code page; the command line is read in UTF-16.
* @param bytes the bytes
* @param codePage CP_UTF8, a Windows code page, or 0 for the examined
*        machine's ANSI code page (`conf.ansiCodePage`; the running machine's
*        until the SYSTEM hive is read)
* @return the text; bytes invalid for the code page are widened one by one
*         rather than lost */
std::wstring decodeText(const std::string& bytes, UINT codePage = 0);

/*! Encodes UTF-16 text into bytes — the reverse of decodeText.
* @param text the text
* @param codePage CP_UTF8 by default: the encoding of every file WAC writes
* @return the bytes */
std::string encodeText(const std::wstring& text, UINT codePage = CP_UTF8);

/*! Reads the examined machine's ANSI code page in its SYSTEM hive and fills
* `conf.ansiCodePage`. To be called as soon as `conf.CurrentControlSet` is
* open, like loadSuspectTimeZone.
* @return ERROR_SUCCESS, or why the code page was not read (the running
*         machine's then stays in use) */
HRESULT loadSuspectAnsiCodePage();

/*! Lowercases a string, to compare without regard to case.
*
* WHY IT IS NECESSARY. Windows does not agree with itself on case: on a Windows
* 11 VM, the NTFS index carries "…\\Windows\\Input\…" where the registry writes
* "…\\windows\\input\…". Any match by path or by service name done
* case-sensitively then fails IN SILENCE — and a task without history reads
* wrongly as "never run".
* @param s the string to normalise
* @return the string in lower case
*/
std::wstring toLower(std::wstring s);

/*! Splits a text file into its lines, "\r\n" or "\n", the end-of-line
* characters removed; line n of the file is element n - 1.
* @param text the text
* @return its lines; a last line without a newline is a line */
std::vector<std::wstring> splitLines(const std::wstring& text);

/*! Says whether a registry value is a MUI resource REFERENCE rather than a
* readable text.
*
* Windows stores most displayed names in the form
* `@%SystemRoot%\system32\schedsvc.dll,-100` or `@tzres.dll,-301`: a file and
* the identifier of a string inside it. Only `LoadStringW` on the module
* resolves it — hence by loading that module into the collecting process, which
* is precisely what the offline reading seeks to avoid.
*
* The reference is therefore kept as it is, but in a field that says what it is:
* presenting `@tzres.dll,-301` as a time-zone name would amount to displaying a
* reading defect in place of a piece of data.
*
* @param value the value read in the hive
* @return true if it is a resource reference
*/
bool isMuiReference(const std::wstring& value);

/*! Converts a string of several concatenated wstrings to a vector of wstring.
* Each string must be separated from the previous one by \0.
* @param data pointer to the array holding the strings
* @param size size of the block, in bytes: nothing beyond it is read
* @return the non-empty strings, in order
*/
std::vector<std::wstring> multiWstring_to_vector(LPBYTE data, int size);

/*! Reads a zero-terminated UTF-16 string, never past a bound.
*
* WHY. The artefact parsers read many strings "up to the first zero". In a
* truncated or forged file the zero may be missing, and the read then went on
* past the buffer — reading, and publishing, whatever memory followed. The
* bound is the size of the structure being read (a shell item, an extension
* block, a file), itself checked against the real buffer by the caller.
*
* The units are read two bytes at a time, little-endian: no cast to wchar_t,
* whose size differs between Windows and Linux.
*
* @param base start of the structure
* @param limit size of the structure, in bytes: nothing at or beyond
*        `base + limit` is read
* @param offset position of the string in the structure
* @return the string, without its terminator; empty if `offset` is out of range
*/
std::wstring readWideZ(const BYTE* base, size_t limit, size_t offset);

/*! True if `length` bytes starting at `offset` lie inside a structure of `size`
*  bytes. Written so that no addition can wrap around — the form every bound
*  check on data read from a file takes.
*  @param size size of the structure (or buffer)
*  @param offset position of the field
*  @param length size of the field
*  @return true if the field is entirely inside */
inline bool fits(size_t size, size_t offset, size_t length) {
	return offset <= size && length <= size - offset;
}

/*! Reads a zero-terminated single-byte string (ANSI), never past a bound.
* Same rule as readWideZ().
* @param base start of the structure
* @param limit size of the structure, in bytes
* @param offset position of the string in the structure
* @return the string, without its terminator; empty if `offset` is out of range
*/
std::string readNarrowZ(const BYTE* base, size_t limit, size_t offset);


/*! What a version-1 GUID (RFC 4122, time-based) carries: the instant it was
*  made and the hardware address of the machine that made it. The link
*  tracking service makes such GUIDs (DROID) when it first tracks a file: the
*  instant is that of the tracking's birth, UTC, and the address that of the
*  machine — the one where the file was then. */
struct GuidV1 {
	bool valid = false;         //!< version 1 and RFC 4122 variant; the rest is meaningless otherwise
	FILETIME createdUtc = { 0, 0 }; //!< instant the GUID was made, UTC
	uint8_t node[6] = { 0 };    //!< hardware address of the machine that made it
};

/*! Reads the time and hardware address of a version-1 GUID.
* @param guid the GUID
* @return its content; `valid` false if it is not a version-1 GUID */
GuidV1 decodeGuidV1(const GUID& guid);

/*! Text form of a binary SID ("S-1-5-21-…"), as ConvertSidToStringSidW writes
* it — which this replaces — without any system call: an identifier authority
* of 2^32 or more is written in hexadecimal without padding ("0x9B63132D1D0"),
* as Windows does (checked by system_conversions_test.cpp).
* @param sid the binary SID
* @param size the bytes available: nothing beyond is read
* @return the text, or "" if the SID does not fit in `size` */
std::wstring sidToText(const BYTE* sid, size_t size);

/*! A self-relative security descriptor as JSON: its owner and group (SID, and
*  name as resolved offline), and each access control entry of its DACL and
*  SACL — type ("Allow", "Deny", "Audit", or the number), flags, access mask,
*  SID and name. An ACE of another kind (object ACEs…) is given by its type
*  and size. Every read is bounded by `size` and by the sizes the descriptor
*  declares; what does not fit is left out.
* @param sd the descriptor's bytes
* @param size their number
* @return the JSON object, empty if the descriptor's header does not fit */
Json securityDescriptorToJson(const BYTE* sd, size_t size);

/*! Binary form of a SID written as text — the reverse of sidToText, replacing
* ConvertStringSidToSidW.
* @param text "S-1-…"
* @return the binary SID, or empty if the text is not a well-formed SID */
std::vector<BYTE> textToSid(const std::wstring& text);

/*! Converts an OLE automation date (VT_DATE: days since 30 December 1899, the
* fraction being the time of day, positive even for a negative date) to a
* SYSTEMTIME, as VariantTimeToSystemTime (oleaut32) does — which this replaces:
* same range and same rounding to the second; NaN is refused.
* @param date the OLE date
* @param st receives the date
* @return false if the date is outside the range */
bool oleDateToSystemTime(double date, SYSTEMTIME& st);

///////////////////////////////////////////////////////
//Registry
///////////////////////////////////////////////////////


/*! Reads an SZ value in the registry and converts it to a wstring.
* @param key the registry key
* @param subKey the registry subkey
* @param valueName name of the value to read
* @param ws pointer to a wstring receiving the value read
* @return ERROR_SUCCESS on success, an error code otherwise.
*/
HRESULT getRegSzValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::wstring* ws);

/*! Reads a FILETIME in the registry.
* @param key the registry key
* @param subKey the registry subkey
* @param valueName name of the value to read
* @param filetime pointer to a FILETIME receiving the value read
* @return ERROR_SUCCESS on success, an error code otherwise.
*/
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, FILETIME* filetime);

/*! Reads the value of rank `index` of a key: its name, type and bytes.
* The buffers are sized by the reader itself (the name to its maximum length,
* the data to the size the hive declares), so that the caller never guesses a
* size, never reads past the value, and has nothing to release.
* @param key an open key
* @param index rank of the value
* @param name receives its name
* @param type receives its type
* @param data receives its bytes (data.size() is the only bound to read by)
* @return ERROR_SUCCESS, ERROR_NO_MORE_ITEMS past the last value, or a registry error
*/
HRESULT enumRegistryValue(ORHKEY key, DWORD index, std::wstring& name, DWORD& type, std::vector<BYTE>& data);

/*! Reads a value of the registry, whatever its type, as its bytes.
* @param key the registry key
* @param subKey the registry subkey
* @param valueName name of the value to read
* @param bytes receives the value, exactly its size; emptied on failure
* @return ERROR_SUCCESS on success, a registry error code otherwise
*/
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::vector<BYTE>& bytes);

/*! Reads the MRUListEx value of a key: the ranks of its values, most recent
* first, up to the 0xFFFFFFFF that ends the list. Each rank is read within the
* value: a length that is not a multiple of 4 leaves the last bytes unread.
* @param key the key holding MRUListEx
* @param ids receives the ranks
* @return ERROR_SUCCESS, or the error of the read */
HRESULT readMruListEx(ORHKEY key, std::vector<unsigned int>& ids);

/*! Opens a hive of each profile in the working copy, hands it over, closes it.
* @param relativeHive the hive's file, relative to the profile
*        (L"\\ntuser.dat", L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat")
* @param visit called with the hive's root and the profile's SID; a hive that
*        cannot be opened is skipped (logged) */
void forEachProfileHive(const std::wstring& relativeHive,
                        const std::function<void(ORHKEY root, const std::wstring& sid)>& visit);

/*! Reads a boolean in the registry.
* @param key the registry key
* @param subKey the registry subkey
* @param valueName name of the value to read
* @param value pointer to a boolean receiving the value read
* @return ERROR_SUCCESS on success, an error code otherwise.
*/
HRESULT getRegboolValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, bool* value);

/*! Reads a REG_DWORD (32-bit) value in the registry.
* @param key an open key
* @param subKey the subkey (may be NULL)
* @param valueName name of the value
* @param pdword receives the value read
* @return ERROR_SUCCESS, or an error code
*/
HRESULT getRegDwordValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, DWORD* pdword);

/*! Reads a REG_QWORD (64-bit) value in the registry.
* Useful for the values that carry a raw FILETIME, such as `InstallTime` under
* `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion`.
* @param key an open key
* @param subKey the subkey (may be NULL)
* @param valueName name of the value
* @param pqword receives the value read
* @return ERROR_SUCCESS, or an error code
*/
HRESULT getRegQwordValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, unsigned long long* pqword);

/*! Reads a MULTI_SZ (several concatenated strings) in the registry.
* @param key the registry key
* @param subKey the registry subkey
* @param valueName name of the value to read
* @param out pointer to an array of wstring receiving the values read
* @return ERROR_SUCCESS on success, an error code otherwise.
*/
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::vector<std::wstring>* out);


/*! Drive letter a volume of the examined machine was mounted on at
* collection time, from its serial number (snapshot of the running machine).
* @param searchSerial serial number of the volume, "%08X"
* @return its mount point ("C:"), or an empty string if none matched
*/
std::wstring getVolumeLetter(std::wstring searchSerial);

/*! Writes a JSON value into `_outputDir`/`name`, in UTF-8.
* Centralises the creation of the output directory, the encoding and the path,
* so that each artefact no longer has to do it again.
* @param name name of the file (e.g. "bams.json")
* @param value the root JSON value (usually a Json::arr())
* @return ERROR_SUCCESS, or an error code
*/
HRESULT writeJsonFile(const std::string& name, const Json& value);

/*! Writes a JSON array as it goes, without building it in memory.
*
*  WHY. `writeJsonFile` serialises an already complete value: for the event
*  logs, that meant keeping a hundred thousand records in memory, then their
*  whole serialisation, then its conversion to UTF-8 — a peak of several hundred
*  megabytes. On an examined machine, such a peak does not only cost time: it
*  causes paging, hence writes into `pagefile.sys`, on the very disk one strives
*  not to modify. Here each element is written then forgotten.
*
*  The file produced is identical to `writeJsonFile`'s on the same array: same
*  tabulations, no trailing comma.
*
*  An empty array gives `[]`, as `writeJsonFile` does.
*/
class JsonArrayWriter {
public:
	/*! Opens `_outputDir`/`name` and writes the opening of the array.
	*  @param name name of the output file, without a path */
	explicit JsonArrayWriter(const std::string& name);

	/*! Closes the array and the file. Called by the destructor if it was forgotten,
	*  so that an early exit does not leave a truncated JSON.
	*  @return ERROR_SUCCESS, or E_FAIL if the write failed */
	HRESULT close();

	~JsonArrayWriter();

	/*! Adds an element. Does nothing if the file could not be opened. */
	void add(const Json& element);

	//! True if the file is open for writing.
	bool isOpen() const { return open_; }
	//! Number of elements written.
	unsigned long long written() const { return written_; }

private:
	std::ofstream f_;   //!< the file, written in UTF-8 bytes
	unsigned long long written_ = 0;
	bool open_ = false;
	bool closed_ = false;
	std::string name_;
};

/*! Writes an artefact that was NOT COLLECTED, recording the reason of the
* failure.
*
* WHY. When `getData()` failed, the JSON file was not written at all. In
* analysis, a missing file does not distinguish "the reading failed" from
* "there was nothing to collect" — and an analyst may wrongly conclude there is
* no trace. Writing the file with the reason removes the ambiguity.
*
* @param name name of the file (e.g. "Usbstor.json")
* @param artefact label of the artefact concerned
* @param result error code met
* @return ERROR_SUCCESS if the file could be written
*/
HRESULT writeNotCollected(const std::string& name, const std::wstring& artefact,
                          HRESULT result);

/*! Writes an artefact the configuration switched off (wac.yml,
 *  `artefacts:`): not collected on purpose — neither a failure nor an absence
 *  of traces, and the file says which.
 * @param name name of the file (e.g. "prefetchs.json")
 * @param artefact label of the artefact
 * @param key the configuration key, e.g. L"artefacts.prefetch"
 * @return ERROR_SUCCESS if the file could be written */
HRESULT writeNotRequested(const std::string& name, const std::wstring& artefact, const std::wstring& key);

/*! Writes an artefact that the examined version of Windows does not have
 *  (artefact_catalogue.h): nothing to collect there, and nothing to conclude
 *  from the absence of data — neither a failure nor "no trace".
 * @param name name of the file
 * @param artefact label of the artefact
 * @param key the configuration key, e.g. L"artefacts.srum"
 * @return ERROR_SUCCESS if the file could be written */
HRESULT writeAbsentFromVersion(const std::string& name, const std::wstring& artefact, const std::wstring& key);

/*! Whether WAC runs with administrator rights. From Windows Vista on, the
 *  token says whether it is elevated; Windows XP and Server 2003 have no
 *  elevation — the question is refused there ("the parameter is incorrect",
 *  which stopped WAC at its first check) —, and the answer is whether the
 *  token belongs to the Administrators group.
 * @param elevated receives the answer
 * @return ERROR_SUCCESS, or why the token could not be read */
HRESULT processElevated(bool& elevated);

/*! Whether a result says the source itself was not there — file or folder —,
 *  whichever way the collector returned it (a Win32 code or its HRESULT).
 * @param result the collector's result */
bool sourceNotFound(HRESULT result);

/*! Writes an artefact whose source was not found where the examined version
 *  of Windows always has one (expectedOn, artefact_catalogue.h): "expected
 *  but missing". The absence is itself a finding — a file erased, a service
 *  switched off —, neither a failed reading nor an absence of activity, and
 *  the file says where the source should have been.
 * @param name name of the file
 * @param artefact label of the artefact
 * @param key the configuration key, e.g. L"artefacts.srum"
 * @param result the collector's result, a "not found"
 * @return ERROR_SUCCESS if the file could be written */
HRESULT writeExpectedButMissing(const std::string& name, const std::wstring& artefact, const std::wstring& key,
                                HRESULT result);

/*! Marks the JSON of ONE PIECE that WAC collected and has no decoder for
 *  (pieceFormat, artefact_catalogue.h): `DecodingStatus` "UnsupportedFormat",
 *  the signature met (`FormatSignature`) and, when the table knows the form,
 *  its name (`FormatName`). The piece
 *  is in the exhibit store, to be decoded by another tool: nothing was
 *  converted, and the entry says so instead of being left out.
 * @param o the piece's JSON, already carrying its path
 * @param key the key of the artefact table, e.g. "prefetch"
 * @param signature the internal version or magic number read on the piece */
void addUnsupportedFormat(Json& o, const std::string& key, unsigned signature);

/*! Writes an artefact whose single source is in a format WAC has no decoder
 *  for — a ShimCache value of Windows 7 —: `CollectionStatus`
 *  "UnsupportedFormat", with the signature met. Neither an empty list nor a
 *  failed reading.
 * @param name name of the file
 * @param artefact label of the artefact
 * @param key the key of the artefact table, e.g. "shimcache"
 * @param signature the internal version or magic number read on the source
 * @return ERROR_SUCCESS if the file could be written */
HRESULT writeUnsupportedFormat(const std::string& name, const std::wstring& artefact, const std::string& key,
                               unsigned signature);

/*! Writes an artefact whose form on the examined version of Windows is one
 *  WAC has no decoder for (undecodedOn, artefact_catalogue.h): the format is
 *  told by the version, the piece carrying no signature. `CollectionStatus`
 *  "UnsupportedFormat", with the version, the format and where the source
 *  lies; the exhibit store holds it.
 * @param name name of the file
 * @param artefact label of the artefact
 * @param key the configuration key, e.g. L"artefacts.amcache"
 * @return ERROR_SUCCESS if the file could be written */
HRESULT writeUndecodedOnVersion(const std::string& name, const std::wstring& artefact, const std::wstring& key);

/*! The key of the artefact table for a configuration key: L"artefacts.srum"
 *  gives "srum".
 * @param key the configuration key */
std::string catalogueKey(const std::wstring& key);

/*! WAC's version, <major>.<minor>.<bugfix>, read in the program's own
 *  version resource (WAC.rc): the one place it is written, the one Windows
 *  shows in the executable's properties.
 * @return e.g. L"1.4.0"; empty if the resource cannot be read */
std::wstring WacVersion();

/*! Lists the regular files of a directory, filtered by extension.
* Never throws: a missing or unreadable directory returns an empty list. That is
* the nominal case in a collection (not every profile has every folder, and the
* raw copy holds only what was extracted); an uncaught exception there would
* stop the whole collection.
* The extension comparison is case-insensitive.
* @param directory directory to walk (not recursive)
* @param extensions accepted extensions, dot included (e.g. { L".lnk", L".url" })
* @return the paths kept, in the order they were walked; possibly empty
*/
std::vector<std::filesystem::path> listFilesByExtension(const std::filesystem::path& directory,
	const std::vector<std::wstring>& extensions);

