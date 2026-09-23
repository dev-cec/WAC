/*! \file
 *  \brief Investigation log: what WAC did, when, and what it left behind.
 *
 *  WHY. Any collection on a live system leaves traces. Good forensic practice
 *  is not to erase them — that would be anti-forensics, and it would compromise
 *  admissibility — but to DOCUMENT them, so that an analyst can tell apart, in
 *  the artefacts, what comes from the suspect and what comes from the tool.
 *
 *  Without this log, a 7036 event or a file access timestamped during the
 *  collection is indistinguishable from an action of the suspect. That is a
 *  source of misinterpretation, and a handle for contesting an expert report.
 *
 *  The log covers three things:
 *    1. the CONTEXT of the collection (tool, version, command line, machine,
 *       operator, time zone, start/end) — the chain of custody;
 *    2. every OPERATION carried out, timestamped in UTC and in local time, with
 *       its result;
 *    3. the expected FOOTPRINT of each operation: which trace it leaves and
 *       where to find it. That is what makes the log usable in analysis.
 *
 *  Output: `investigation.json`, in the output directory, in the same format as
 *  the other artefacts (see json.h).
 *
 *  References: RFC 3227 (evidence collecting and archiving), ISO/IEC 27037
 *  (identification, collection and preservation of digital evidence).
 */
#pragma once
#include "json.h"
#include <windows.h>
#include <string>

/*! Expected footprint of an operation: the trace it leaves on the examined
 *  system. Used to fill the log's `Footprint` field.
 *
 *  The values are descriptive rather than coded on purpose: they are meant to
 *  be read by a human analyst in the report.
 */
namespace Footprint {
	//! Raw read of the volume: no file access, hence no timestamp changed;
	//! an object-access audit (if enabled) may log it.
	extern const wchar_t* VOLUME_BRUT;
	//! Opening an extracted hive (the copy on the USB medium): leaves the
	//! original untouched.
	extern const wchar_t* RUCHE_COPIE;
	//! Reading an extracted artefact file (the copy on the USB medium): event
	//! logs, Prefetch, jump lists. No access to the original.
	extern const wchar_t* FICHIER_COPIE;
	//! Documented change to the base block of a COPIED hive (see hive_recover.h).
	extern const wchar_t* RUCHE_PATCH;
	//! Replay of the transaction logs into a COPIED hive, with an undo journal
	//! (see hive_recover.h).
	extern const wchar_t* RUCHE_REJEU;
	//! A single read-only enumeration of the service manager: reads the current
	//! state without opening a handle per service.
	extern const wchar_t* SCM;
	//! Process enumeration: opens process handles (which can be audited).
	extern const wchar_t* PROCESSUS;
	//! Query of the open sessions through LSA / Terminal Services.
	extern const wchar_t* SESSIONS;
	//! Write to the collection medium (the USB key), never to the target.
	extern const wchar_t* ECRITURE_USB;
}

/*! Opens the log: reads the context of the collection (machine, operator, time
 *  zone, command line) and the start timestamp.
 *  To be called once, as early as possible in `main`.
 *  @param argc number of command-line arguments
 *  @param argv the command-line arguments
 */
void auditInit(int argc, char* argv[]);

/*! Records an operation.
 *  @param operation what was done, e.g. L"EnumServicesStatusExW"
 *  @param cible on what, e.g. L"\\Windows\\System32\\config\\SYSTEM" (may be empty)
 *  @param resultat HRESULT of the operation
 *  @param footprint expected trace (one of the `Footprint` constants)
 */
void auditRecord(const std::wstring& operation,
                 const std::wstring& cible,
                 HRESULT resultat,
                 const wchar_t* footprint);

/*! Closes the log (end timestamp, duration) and writes `investigation.json`.
 *  To be called at the very end of the collection, after the last collector.
 *  @return ERROR_SUCCESS, or a write error code
 */
HRESULT auditWrite();

/*! Context of the collection: tool, examined machine, time zones, operator.
*
*  Exposed because the exhibit manifest must carry EXACTLY the same context as
*  the investigation log. Building it twice would open the possibility of two
*  documents of the same collection contradicting each other — which would be
*  enough to discredit both.
*
*  @return a JSON object { Tool, Host, Operator }
*/
Json auditContexte();

/*! Start of the collection, in UTC (ISO 8601).
*  The exhibit manifest must date the extraction.
*  @return the timestamp, as text. */
std::wstring auditDebutUtc();
/*! Start of the collection, in the suspect's local time (ISO 8601).
*  @return the timestamp, as text.
*  @see auditDebutUtc */
std::wstring auditDebutLocal();
