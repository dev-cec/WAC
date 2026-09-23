/*! \file
 *  \brief Shared tools: configuration, console display, log, registry reads, time formatting, path rules, JSON output.
 */
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <type_traits>
#include <iomanip>
#include <sstream>
#include "offline_registry.h"
#include <vector>
#include <filesystem>
#include <time.h>
#include "json.h"

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
* time (FAT dates, Amcache, BAM, shimcache, USBSTOR, UserAssist) can only be
* interpreted with the **suspect's** time zone. `GetTimeZoneInformation()`
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
	long activeBiasMinutes = 0;    //!< minutes to ADD to the local time to obtain UTC
	long standardBiasMinutes = 0;  //!< offset outside daylight saving time (the hive's `Bias` value)
	bool  daylightInEffect = false;//!< true if daylight saving time was in force at collection time
	bool  fromHive = false;        //!< true if read in the suspect's SYSTEM hive
	bool  valid = false;           //!< true if the reading succeeded
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
	bool _events = false;//!< True is events must be extracted
	std::string name = ""; //!< name of the program, obtained from command line
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
* kernel prefix `\\SystemRoot\\`, system variables (`%windir%`,
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
	//! Converts FAT DOS TIME to FILETIME.
	FILETIME toFileTime(); 
};

///////////////////////////////////////////////////////
// display
///////////////////////////////////////////////////////

//! Prints the word OK in green on the console.
void printSuccess();

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
                   unsigned long long total, const wchar_t* unit);

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

/*! Prints the error message of an HRESULT in RED on the console.
* @param hresult the result a command returned
*/
void printError( HRESULT  hresult);

/*! Prints errorText in RED on the console.
* @param errorText the text to print
*/
void printError( std::wstring  errorText);

/*! Extracts the error message of an HRESULT returned by a command.
* @param hresult the result a command returned
* @return the text attached to that HRESULT error code
*/
std::wstring getErrorMessage(HRESULT hresult);

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

/*! Writes an integer in lower-case hexadecimal, on the WIDTH OF ITS TYPE.
*
* A template rather than one `long long` signature: every value used to be
* widened to 64 bits first, so a negative 32-bit value — an HRESULT such as
* 0x80070005 — came out as "ffffffff80070005". The value is now read as the
* unsigned type of the same width. A `char` is written as a number, never as
* a character.
* @param value the integer
* @param minDigits minimum number of digits, left-padded with zeros (2 by
*        default; 1 for no padding, e.g. the stream names of a jump list)
* @return the digits, without a "0x" prefix */
template <typename T>
std::wstring to_hex(T value, int minDigits = 2) {
	static_assert(std::is_integral_v<T>, "to_hex: integer types only");
	const unsigned long long bits = static_cast<std::make_unsigned_t<T>>(value);
	std::wstringstream ss;
	ss << std::setw(minDigits) << std::setfill(L'0') << std::hex << bits;
	return ss.str();
}

/*! Inserts n tabulations in a string. Used to lay out the output JSON.
* @return a string holding the wanted number of tabulations
*/
std::wstring tab(int i);

///////////////////////////////////////////////////////
//conversion
///////////////////////////////////////////////////////

/*! Converts a SID to a user name.
* @param _sid the user's SID
*/
std::wstring getNameFromSid(std::wstring _sid);


/*! Converts a boolean to the string "true" or "false".
* @param b the boolean to convert
* @return "true" or "false"
*/
std::wstring bool_to_wstring(bool b);

/*! Converts a time_t to a FILETIME.
* @param t the time_t to convert
* @return the FILETIME that results from the conversion
*/
FILETIME timet_to_fileTime(time_t t);

/*! Converts a string holding a date to a FILETIME.
* @param input the string to convert
* @return the FILETIME that results from the conversion
*/
FILETIME wstring_to_filetime(std::wstring input);

/*! Converts a FILETIME to a string.
* @param filetime the FILETIME to convert
* @param convertUtc if true, the date is converted to UTC
* @return the string that results from the conversion
*/
std::wstring time_to_wstring(const FILETIME filetime, bool convertUtc = false);

/*! Converts a SYSTEMTIME to a string.
* @param systemtime the SYSTEMTIME to convert
* @return the string that results from the conversion
*/
std::wstring time_to_wstring(const SYSTEMTIME systemtime);

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
 *  A null date returns an empty string, as time_to_wstring does: without that
 *  one would emit "1601-01-01T00:00:00Z" as if it were a real date.
 */

/*! Formats a FILETIME **already expressed in UTC** as ISO 8601, suffix "Z".
* @param filetime the instant, in UTC
* @return "YYYY-MM-DDTHH:MM:SSZ", or "" if the date is null
*/
std::wstring timeToIso8601Utc(const FILETIME& filetime);

/*! Formats a FILETIME **expressed in local time** as ISO 8601, with the
* machine's time-zone offset (e.g. "+02:00").
* @param filetime the instant, in the examined machine's local time
* @return "YYYY-MM-DDTHH:MM:SS+HH:MM", or "" if the date is null
*/
std::wstring timeToIso8601Local(const FILETIME& filetime);

/*! Converts a FILETIME **expressed in local time** to UTC, then formats it as
* ISO 8601 with the "Z" suffix.
* Useful for the artefacts that store dates in local time (Amcache, BAM,
* shimcache, USBSTOR, UserAssist) and whose UTC version is also wanted.
* @param filetimeLocal the instant, in the examined machine's local time
* @return "YYYY-MM-DDTHH:MM:SSZ", or "" if the date is null
*/
std::wstring localTimeToIso8601Utc(const FILETIME& filetimeLocal);

/*! Converts a FILETIME **expressed in UTC** to the local time of the EXAMINED
* machine, then formats it as ISO 8601 with the time-zone offset.
*
* WHY NOT `FileTimeToLocalFileTime` FOLLOWED BY `timeToIso8601Local`. That
* combination, used until now, applies the offset of the machine RUNNING WAC
* while attaching the label of the SUSPECT's time zone: the same in a live
* collection, contradictory as soon as an image is analysed elsewhere — the
* value and its label would no longer speak of the same time zone.
* Here, the offset applied and the label come from the SAME source.
*
* @param filetimeUtc the instant, in UTC
* @return "YYYY-MM-DDTHH:MM:SS+HH:MM", or "" if the date is null
*/
std::wstring utcTimeToIso8601Local(const FILETIME& filetimeUtc);

/*! Converts a UTC FILETIME to the local time of the EXAMINED machine.
*
* Replaces `FileTimeToLocalFileTime()`, which applies the time zone of the
* RUNNING machine. The two coincide in a live collection, but diverge as soon as
* an image is analysed elsewhere: the time would then be shifted by the
* examiner's time zone while carrying the label of the suspect's — two time
* zones in one value. A single point of truth, `conf.timeZone`, avoids that
* trap; the fallback on the running machine applies only if the SYSTEM hive
* could not (yet) be read.
*
* @param filetimeUtc the instant, in UTC
* @param filetimeLocal receives the instant in the suspect's local time
* @return true if the conversion succeeded
*/
bool utcToSuspectLocal(const FILETIME& filetimeUtc, FILETIME* filetimeLocal);

/*! Reads the examined machine's time zone in the suspect's SYSTEM hive.
*
* Reads `Control\TimeZoneInformation` under `conf.CurrentControlSet` and fills
* `conf.timeZone`. To be called as soon as `conf.CurrentControlSet` is open:
* every local timestamp formatted AFTERWARDS will carry the suspect's offset.
*
* On failure, `conf.timeZone.valid` stays false and the formatting falls back on
* `GetTimeZoneInformation()` — which is right in a live collection, since the
* examined machine is then the running machine.
*
* @return ERROR_SUCCESS if the time zone was read, an error code otherwise
*/
HRESULT loadSuspectTimeZone();

/*! Time-zone offset used to format local times, as "+HH:MM".
* Comes from the suspect's hive if it could be read, otherwise from the running
* machine.
* @return the offset, e.g. L"+02:00"
*/
std::wstring localUtcOffsetString();

/*! Formats a SYSTEMTIME as ISO 8601.
* @param systemtime the instant
* @param utc true if the value is in UTC (suffix "Z"), false if it is in local
*        time (suffix of the machine's time zone)
* @return the formatted date, or "" if it is null
*/
/*! @param fraction100ns fraction of a second, in hundreds of nanoseconds
*         (0..9999999), or -1 not to write it.
*
*  WHY THIS PARAMETER. A SYSTEMTIME only carries the millisecond, a FILETIME
*  goes down to a hundred nanoseconds. The callers that hold the original
*  FILETIME pass the real fraction; the others pass -1, and the timestamp stops
*  at the second rather than displaying a precision it does not have.
*/
std::wstring timeToIso8601(const SYSTEMTIME& systemtime, bool utc, long fraction100ns = -1);

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

/*! Converts a GUID to a wstring. The output is of the form
* "{20D04FE0-3AEA-1069-A2D8-08002B30309D}".
* @param guid the GUID to convert
* @return the wstring that results from the conversion
*/
std::wstring guid_to_wstring(GUID guid);

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

/*! Reads a binary value in the registry.
* The caller must `delete[] bytes` to release the memory.
* @param key the registry key
* @param subKey the registry subkey
* @param valueName name of the value to read
* @param bytes pointer to an array of BYTE receiving the value read
* @param size on input the size of the buffer, on output that of the value read
* @return ERROR_SUCCESS on success, a registry error code otherwise
*/
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, LPBYTE* bytes, DWORD* size);

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


/*! Drive letter a volume is mounted on, from its serial number.
* @param searchSerial serial number of the volume to look for
* @return the drive letter of the volume's mount point.
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
