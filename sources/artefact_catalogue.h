/*! \file
 *  \brief THE table of the artefacts by version of Windows: where each one
 *         exists, where it lies and in which format, version after version.
 *
 *  WHY ONE TABLE (backlog B-039). An artefact exists only on some versions of
 *  Windows, at a place and in a format that change from one to the next:
 *  `.evt` then `.evtx`, Prefetch 17 then 30, `index.dat` then the WebCache,
 *  SRUM and Amcache from Windows 8, jump lists from 7, the search index in
 *  ESE then in SQLite. That knowledge was scattered in each collector. Here
 *  it is one table: adding a version of Windows is adding its line to
 *  RELEASES and, where something changed, a form to the artefacts concerned;
 *  nothing else in the code names a version.
 *
 *  THE ORDER OF THE VERSIONS IS THE BUILD NUMBER, client and server alike:
 *  2600 (XP) < 3790 (Server 2003) < 6000 (Vista) < 7600 (7) < 9200 (8)
 *  < 9600 (8.1) < 10240 (10) < 22000 (11). An artefact is given its first
 *  build and, when it was withdrawn, the first build without it.
 *
 *  PRUDENCE. An absence is stated only when it is certain: one stated wrongly
 *  would lose an exhibit, a presence stated wrongly only costs an "expected
 *  but missing". Doubtful cases (Server Core, a service of the client
 *  editions on a server) stay present, their note saying what remains to be
 *  measured in the virtual machines of the compatibility items.
 *
 *  "EXPECTED" IS AS PRUDENT (ArtefactEntry::expectedSinceBuild). It is set
 *  only for a file or a key that every installation has AND that can be
 *  removed while Windows goes on: the hosts file, Amcache.hve, SRUDB.dat, the
 *  event logs, the Services key. It is NOT set for what exists only once
 *  something happened (USBSTOR, before the first USB storage), for the state
 *  of the running system (processes, sessions, connections) nor for the
 *  volume's own metadata ($MFT, $LogFile, $Secure): those cannot be missing
 *  from a running Windows, so one not read is a failed reading, never a trace.
 *
 *  A FORMAT IS RECOGNISED ON THE PIECE, by its signature or internal version
 *  (pieceFormat): the version of Windows says where to look, the piece says
 *  what it is. No collector keeps a version number of its own.
 *
 *  A VERSION NEWER THAN THE TABLE is treated as the last one known, and said
 *  so (WindowsRelease::known): the collection goes on.
 *
 *  Portable C++, without windows.h: tested natively (artefact_catalogue_test),
 *  which also writes the table of the documentation.
 */
#pragma once

#include <string>
#include <vector>

/*! The version of an examined Windows, as its SOFTWARE hive states it. */
struct WindowsVersion {
	unsigned build = 0;      //!< CurrentBuildNumber: 2600, 7601, 19045, 26200…
	bool server = false;     //!< InstallationType "Server" or "Server Core", or a server ProductType
	bool serverCore = false; //!< InstallationType "Server Core": no graphical shell
};

/*! A release of Windows the table knows. */
struct WindowsRelease {
	unsigned firstBuild;     //!< its first build
	unsigned lastBuild;      //!< the last build of it the table knows
	bool server;             //!< a server release
	const wchar_t* name;     //!< "Windows 10", "Windows Server 2019"…
};

/*! One form of an artefact: where it lies and in which format, from a build on. */
struct ArtefactForm {
	unsigned sinceBuild;      //!< first build with this form
	const wchar_t* location;  //!< the file, folder or registry key
	const wchar_t* format;    //!< the format, with its internal version when it has one
	bool decoded;             //!< whether WAC converts this form (false: collected raw at most)
	/*! What a piece of this form states OF ITSELF — its internal version or
	 *  its magic number (Prefetch 30 and 31, `$I` 2, ShimCache 0xBADC0FEE):
	 *  what pieceFormat recognises it by. Empty when the format carries none,
	 *  or while no collector asks. */
	std::vector<unsigned> signatures = {};
};

/*! What WAC does of a piece, judged on what the piece states of itself. */
struct PieceFormat {
	bool decoded;              //!< WAC has a decoder for it: anything else is collected raw and declared "unsupported format"
	const ArtefactForm* form;  //!< the form it is; nullptr when no form of the artefact carries this signature — a format the table does not know yet
};

/*! One artefact — one key of wac.yml — through the versions of Windows. */
struct ArtefactEntry {
	const char* key;                   //!< the key under `artefacts:` in wac.yml
	unsigned sinceBuild;               //!< first build where it exists
	unsigned untilBuild;               //!< first build where it no longer exists; 0 if it still does
	unsigned expectedSinceBuild;       //!< from this build on, its source is ALWAYS there on a client edition: missing, it is a trace (expectedOn); 0 if never certain
	std::vector<ArtefactForm> forms;   //!< its successive forms, oldest first; at least one
	const wchar_t* note;               //!< what remains to be measured, or a precision; "" for none
};

/*! Whether an artefact exists on a version. */
enum class Availability {
	Present,                 //!< it exists on this version
	AbsentFromThisVersion    //!< this version never had it, or no longer has it: nothing to collect, nothing to report
};

//! The releases known, oldest first within clients then within servers.
const std::vector<WindowsRelease>& windowsReleases();

//! Every artefact, in the order of wac.yml (alphabetical).
const std::vector<ArtefactEntry>& artefactCatalogue();

/*! The release of a version.
 *  @param version the examined machine's
 *  @param known receives false when the build is newer than every release of
 *         its family (client or server): the last one is then returned
 *  @return the release; the oldest of the family for a build older than all */
const WindowsRelease& releaseOf(const WindowsVersion& version, bool& known);

/*! An artefact's entry.
 *  @param key the key of wac.yml
 *  @return the entry, or nullptr for a key the table does not hold */
const ArtefactEntry* artefactEntry(const std::string& key);

/*! Whether an artefact exists on a version of Windows. A key the table does
 *  not hold, or a version without a build (hive unreadable), is Present:
 *  the collection is never held back by what is not known.
 *  @param key the key of wac.yml
 *  @param version the examined machine's */
Availability availabilityOf(const std::string& key, const WindowsVersion& version);

/*! THE GUARD'S DECISION: among the artefacts asked for, those the examined
 *  version does not have — to switch off before anything is collected,
 *  neither launched nor counted as failures.
 *  @param asked the keys of wac.yml that are switched on
 *  @param version the examined machine's
 *  @return the keys absent from this version, in the order given */
std::vector<std::string> absentAmong(const std::vector<std::string>& asked, const WindowsVersion& version);

/*! THE GUARD ON THE MACHINE'S SIDE: whether an artefact's source must be
 *  there on a version. One that is not found then is "expected but missing":
 *  itself a trace (a file erased, a service switched off), not a failed
 *  reading and not an absence of activity. Client editions only, until the
 *  server editions are measured; a key the table does not hold, or a version
 *  without a build, is never expected — nothing is concluded from what is not
 *  known.
 *  @param key the key of wac.yml
 *  @param version the examined machine's */
bool expectedOn(const std::string& key, const WindowsVersion& version);

/*! THE FORMAT A PIECE STATES OF ITSELF. A collector asks it of every piece
 *  before decoding: the answer comes from the piece's own signature or
 *  internal version, never from the version of Windows — a Vista Prefetch
 *  found on a Windows 10 is a Vista Prefetch, and a `$I` of a version nobody
 *  has seen yet is not a `$I` version 2. A signature no form carries, or one
 *  of a form WAC does not convert, is NOT decoded: the piece stays collected
 *  raw and its JSON says "unsupported format" with the signature met — never
 *  a wrong conversion, never a silence. Adding a format is adding its form,
 *  with its signature, to the table.
 *  @param key the key of wac.yml
 *  @param signature the internal version or magic number read on the piece */
PieceFormat pieceFormat(const std::string& key, unsigned signature);

/*! THE FORMAT TOLD BY THE VERSION, when the piece cannot tell it itself:
 *  whether the form an artefact takes on a version is one WAC has no decoder
 *  for, while it converts another form of it — Amcache.hve without its
 *  Inventory keys before Windows 10 1607, BITS in qmgr0.dat before 1709, the
 *  search index in ESE before Windows 11. The piece is collected all the
 *  same; its conversion is replaced by "unsupported format" — it used to
 *  give an empty list, or "file not found". Never true for an artefact whose
 *  forms carry a signature (the piece decides, pieceFormat), for one that is
 *  only ever copied raw, nor when the version or the key is not known.
 *  @param key the key of wac.yml
 *  @param version the examined machine's */
bool undecodedOn(const std::string& key, const WindowsVersion& version);

/*! The form an artefact takes on a version.
 *  @param entry the artefact
 *  @param version the examined machine's
 *  @return its latest form not newer than the version; the oldest one for an
 *          older build */
const ArtefactForm& formOf(const ArtefactEntry& entry, const WindowsVersion& version);
