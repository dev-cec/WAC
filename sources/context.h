/*! \file
 *  \brief The linking context of a record (`Context`): what the record
 *         attests, of which object, who acted, how, and where WAC read it —
 *         backlog B-079, schema validated in B-078 (2026-11-14).
 *
 *  WHY. WAE opens the file of any object (an executable, a script, a document,
 *  an account, a software, a device…): everything that relates to it, across
 *  artefacts. The same object is named differently by each artefact
 *  (\Device\HarddiskVolume3\… in BAM, C:\… in Prefetch, a folder id in
 *  UserAssist, a command line in a Run key); WAC alone knows the machine —
 *  its volumes, its profiles —, so WAC writes, in every record, the objects it
 *  names in one form. WAE only relates.
 *
 *  WHAT IT HOLDS: identities only. The instants stay in the record's own
 *  fields, which WAE's timeline already reads.
 *
 *  ONE WRITER for every collector, as Json::add is: a member without value is
 *  not emitted (shared rule n° 1), a Context with nothing is not emitted.
 */
#pragma once
#include <string>
#include <vector>
#include "json.h"

struct BinaryFingerprint;   // binaires.h

/*! What a record attests: one value per record. */
enum class ContextKind {
	None,           //!< not said: no Kind written
	Execution,      //!< a program ran
	Arrival,        //!< a file came: a download, an attachment, a copy
	Presence,       //!< a file existed (MFT, Amcache, ShimCache): not an execution
	Creation,
	Modification,
	Deletion,
	Access,         //!< a file or a folder was opened
	Persistence,    //!< something is set to start again
	Installation,   //!< a software, a service, a driver, a device was installed
	Account,        //!< an account was created or changed, a group's members
	Logon,          //!< a session opened or closed
	Network,
	Detection,      //!< an antivirus detection
	Configuration   //!< a setting of the machine
};

/*! The name a kind is written with ("Execution"); "" for None. */
const wchar_t* contextKindName(ContextKind kind);

/*! A process, as an actor or as a parent. */
struct ContextProcess {
	std::wstring path;          //!< the image, normalised
	unsigned long long pid = 0;
	bool pidKnown = false;      //!< a pid of 0 is System Idle's: known apart
	std::wstring guid;          //!< Sysmon's ProcessGuid
};

/*! An object a record names: one kind of identity per object. */
struct ContextObject {
	std::wstring role;          //!< in Related only: "LoadedFile", "Target", "Attachment", "Member"…
	// A file
	std::wstring path;          //!< normalised (normalizeFilePath), on its drive letter
	std::wstring ntfs;          //!< "C:|entry|sequence"
	std::wstring sha1, sha256, md5;   //!< of the WHOLE file only
	// An account
	std::wstring sid;
	std::wstring user;          //!< "DOMAIN\name", when the record gives a name
	// The others
	std::wstring software;      //!< an installation's identifier
	std::wstring device;        //!< a device's instance identifier (contextDevice)
	std::wstring serial;        //!< a device's or a volume's serial number (contextSerial)
	std::wstring volume;        //!< a volume's GUID, "{…}" in lower case (contextVolumeGuid)
	std::wstring address;       //!< an IP address
	std::wstring host;          //!< a host name
	std::wstring name;          //!< a task's, a service's name

	/*! @return the object as JSON; empty members not emitted */
	Json toJson() const;
};

/*! The linking context of one record. */
struct RecordContext {
	ContextKind kind = ContextKind::None;
	ContextObject subject;                //!< the object the record is about
	std::vector<ContextObject> related;   //!< the other objects it names, each with its role
	struct {
		std::wstring sid;
		std::wstring user;                //!< when only a name is given
		std::wstring logonId;             //!< "0x3e7"
		ContextProcess process;
	} actor;                              //!< who acted
	struct {
		ContextProcess parent;
		std::wstring commandLine;
		std::wstring url;
		std::wstring host;
		std::wstring remoteAddress;
		unsigned remotePort = 0;
		bool remotePortKnown = false;     //!< a port of 0 is a value: known apart
		unsigned logonType = 0;
		bool logonTypeKnown = false;      //!< type 0 is SYSTEM's own logon at boot: known apart
		std::wstring volumeSerial;        //!< the volume the subject came from
		std::wstring device;              //!< the device it came from
	} how;                                //!< how
	std::wstring evidence;                //!< the file WAC read the record in — never the subject

	/*! @return the "Context" object; empty members, and an empty Context,
	 *          not emitted by Json::add */
	Json toJson() const;
};

/*! THE form of a file path in a Context: its volume on its drive letter
 *  (onDriveLetter: \Device\HarddiskVolumeN, \\?\Volume{…}), then
 *  normalizeFilePath. One function, so that the same file has one form
 *  whatever artefact names it.
 *  @param cited the path as the record cites it
 *  @return the path, or "" when it names no determinable local file */
std::wstring contextPath(const std::wstring& cited);

/*! THE form of an NTFS identity in a Context: "C:|entry|sequence", the
 *  volume taken from the path's drive letter.
 *  @param path the file's path, with its drive letter
 *  @return the identity, or "" when the path has no drive letter */
std::wstring contextNtfs(const std::wstring& path, unsigned long long entry, unsigned sequence);

/*! THE Evidence of what is read raw on a volume, outside any file (a FAT
 *  directory entry, free clusters carved): the volume's device, \\.\C:.
 *  @param volume "C:"… */
std::wstring rawVolumeEvidence(const std::wstring& volume);

/*! Fills a file object: its path (contextPath) and the fingerprints WAC
 *  computed on the whole file (binaires.h), never a partial one.
 *  @param object the object
 *  @param cited the path as the record cites it
 *  @param fingerprint the file's fingerprints, empty when not read */
void setFileObject(ContextObject& object, const std::wstring& cited, const BinaryFingerprint& fingerprint);

/*! The bitness of the examined Windows, which a few known folders depend on. */
enum class WindowsBits { Unknown, Bits32, Bits64 };

/*! The examined Windows' bitness, from PROCESSOR_ARCHITECTURE in its SYSTEM
 *  hive (Session Manager\Environment): AMD64, ARM64 and IA64 are 64-bit,
 *  x86 and ARM 32-bit. Read once the hive is open; Unknown before, or when
 *  the value cannot be read — never the analysis workstation's. */
WindowsBits examinedWindowsBits();

/*! The examined machine's NetBIOS name (Control\ComputerName in its SYSTEM
 *  hive), read once the hive is open; "" before — never the analysis
 *  workstation's. */
std::wstring examinedComputerName();

/*! The SID of the examined machine's local account a record names by
 *  "MACHINE\name" (localAccountSid with examinedComputerName).
 *  @return the SID; "" for another domain's account, or an unknown one */
std::wstring contextAccountSid(const std::wstring& account);

/*! A path that begins with a known folder's identifier, as UserAssist and
 *  jump lists write it ("{1AC14E77-…}\cmd.exe"), on its real folder: the
 *  machine's folders from the system drive, a user's from the profile of
 *  \a sid (Host.Profiles). WAC's display name of the folder is not enough:
 *  {1AC14E77-…} (System32) and {D65231B0-…} (SystemX86) were both named
 *  "System32", and SystemX86 is SysWOW64 on a 64-bit Windows.
 *  @param cited the path as written, its folder an identifier in braces
 *  @param sid the account whose profile a user folder is in
 *  @return the path (contextPath), or "" when the identifier is not one
 *          of those known here */
std::wstring knownFolderPath(const std::wstring& cited, const std::wstring& sid);

/*! knownFolderPath for a Windows of the bitness given: SystemX86
 *  ({D65231B0-…}) is SysWOW64 on a 64-bit Windows, System32 on a 32-bit one,
 *  and gives no path when the bitness is not known. What the tests call. */
std::wstring knownFolderPathFor(const std::wstring& cited, const std::wstring& sid, WindowsBits bits);

/*! The program a command line runs, its arguments left: what is between
 *  the quotes when it is quoted; otherwise up to the first executable
 *  extension (.exe, .com, .bat, .cmd, .dll, .sys, .ps1, .vbs, .js, .scr)
 *  followed by a space or the end — "C:\Program Files\A B\x.exe -s" keeps
 *  its spaces —; otherwise up to the first space.
 *  @param command the command as written (a service's ImagePath, a Run value)
 *  @return the program's path, not yet normalised */
std::wstring commandProgram(const std::wstring& command);

/*! The host of a URL: after "scheme://", without user@ nor :port, in lower
 *  case ("http://User@Example.com:8080/x" gives "example.com"); "" when the
 *  text is no URL. The same host whatever artefact cites it (B-087).
 *  @param url the URL as written */
std::wstring urlHost(const std::wstring& url);

/*! The program of a service, as Windows reads its ImagePath: its command's
 *  program (commandProgram), and a path with neither drive nor leading
 *  backslash relative to the Windows folder — a driver's
 *  "system32\drivers\x.sys" is %SystemRoot%\system32\drivers\x.sys.
 *  @param imagePath the service's ImagePath, as written
 *  @return the program's path, normalised (contextPath); "" if none */
std::wstring serviceProgram(const std::wstring& imagePath);

/*! A path a user's hive or file holds: its variables of that user
 *  (%USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %TEMP%, %TMP%) on the profile
 *  of \a sid (Host.Profiles), then contextPath — which expands the
 *  machine's own (%windir%…). A document's path keeps its spaces.
 *  @param cited the path as written
 *  @param sid the account; empty for the machine
 *  @return the path; "" if it names no determinable file */
std::wstring userPath(const std::wstring& cited, const std::wstring& sid);

/*! What an access names, in whatever form a source writes it, set on a
 *  context: a path (its user's variables expanded, "/" read as "\" — Office
 *  writes "%USERPROFILE%/Documents/x.docm"); a file: URL as that path —
 *  file:///C:/x decoded, the indexer's file:C:/x raw; another URL as How.Url and How.Host; a share (\\server\share)
 *  by its host, a path WAC cannot place on a local volume left unwritten.
 *  One function, so that the same document has one form whatever names it.
 *  @param context receives Subject.Path, or How.Url and How.Host
 *  @param cited the location as written
 *  @param sid the account whose variables apply; empty for the machine */
void setCitedLocation(RecordContext& context, const std::wstring& cited, const std::wstring& sid);

/*! A remote machine as an object: an IP address in Address, a name in Host
 *  (lower case), from what a record writes — "host", "host:3389",
 *  "user@host", "[::1]:3389", "10.0.0.5". Told apart by the text alone: no
 *  resolution, no network library.
 *  @param object receives Address or Host
 *  @param cited the machine as written */
void setRemoteObject(ContextObject& object, const std::wstring& cited);

/*! THE form of a device's instance identifier, whatever names it: the
 *  registry's key ("USBSTOR\Disk&Ven_QEMU&…\WACUSB0001&0"), a PnP event,
 *  Amcache's ("usbstor/disk&ven_qemu&…/wacusb0001&0"), an interface path
 *  ("\\?\USBSTOR#Disk&…#WACUSB0001&0#{53f56307-…}"), a portable device's
 *  ("SWD#WPDBUSENUM#_??_USBSTOR#…"): enumerator\device\instance, in upper
 *  case — Windows compares them so. A path ("C:\Windows\INF\x.inf") is none.
 *  @param cited the identifier as written
 *  @return the identifier; "" when the text names none */
std::wstring contextDevice(const std::wstring& cited);

/*! The serial number a device's instance carries: its instance part before
 *  its last "&" ("WACUSB0001&0" gives WACUSB0001), or whole without one;
 *  none when its second character is "&" — an identifier Windows made up
 *  for a device without serial ("5&1e461e56&0&0").
 *  @param device an instance identifier, enumerator\device\instance
 *  @return the serial, in the case written; "" when it carries none */
std::wstring deviceSerial(const std::wstring& device);

/*! THE form of a serial number in a Context: trimmed, in upper case. */
std::wstring contextSerial(const std::wstring& cited);

/*! THE form of a volume's GUID: "{…}" in lower case, from
 *  "\??\Volume{…}", "\\?\Volume{…}\", a MountPoints2 key, or the
 *  GUID alone.
 *  @return the GUID; "" when the text holds none */
std::wstring contextVolumeGuid(const std::wstring& cited);

/*! The program of a command a user's hive or task holds: userPath of its
 *  commandProgram.
 *  @param command the command as written
 *  @param sid the account; empty for the machine
 *  @return the program's path; "" if it names no determinable file */
std::wstring userCommandProgram(const std::wstring& command, const std::wstring& sid);

/*! The Evidence of a record read in a hive by its name: SOFTWARE, SYSTEM,
 *  SAM, SECURITY, DEFAULT in System32\config; NTUSER.DAT and UsrClass.dat
 *  in the profile of \a sid.
 *  @param hive the hive's name, as records write it
 *  @param sid the account of a user hive */
std::wstring hiveEvidence(const std::wstring& hive, const std::wstring& sid);

/*! The Evidence of a record read in a system hive: its file on the examined
 *  machine ("C:\Windows\System32\config\SYSTEM").
 *  @param hive "SYSTEM", "SOFTWARE", "SAM"… */
std::wstring systemHiveEvidence(const wchar_t* hive);

/*! The Evidence of a record read in a user's hive: NTUSER.DAT of the
 *  profile of \a sid (Host.Profiles); "" when its profile is not known. */
std::wstring userHiveEvidence(const std::wstring& sid);

/*! Adds `Context` to a record's object, when it holds anything.
 *  @param record the record's JSON object
 *  @param context its context */
void addContext(Json& record, const RecordContext& context);
