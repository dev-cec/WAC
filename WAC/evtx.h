#pragma once

/*  evtx.h — READING WINDOWS EVENT LOGS (.evtx), OFFLINE.
 *
 *  WHY THIS PARSER EXISTS. `events` was the last collector going through an API
 *  of the examined system: `wevtapi` solicits the EventLog service, which can
 *  write its own entries WHILE being read. Yet the logs are plain files, under
 *  `\Windows\System32\winevt\Logs\*.evtx`: extracting them raw like the hives
 *  and parsing them here removes the last avoidable solicitation.
 *
 *  Three benefits add up, which is rare:
 *    - footprint: no service of the examined system is solicited any more;
 *    - time: the API takes some twenty minutes on Windows 11, against two on
 *      Windows 10, for the same machine;
 *    - memory: API-based reading built every record before writing, up to
 *      1.4 GiB of working set — enough to cause paging, hence writes to
 *      `pagefile.sys`, on the very disk one tries not to modify.
 *
 *  FORMAT STRUCTURE (libyal's libevtx specification)
 *
 *    file header          4096 bytes, signature "ElfFile\0"
 *    chunk                64 KiB: 512-byte header ("ElfChnk\0") then a
 *                         sequence of records
 *    record               signature 0x2a2a0000, size, identifier, FILETIME,
 *                         then the BinXML body
 *
 *  BinXML is binarised XML: tokens describe elements, attributes and values.
 *  Its difficulty lies in two mechanisms:
 *
 *    - NAMES ARE SHARED. An element name is not written in place but designated
 *      by an offset relative to the START OF THE CHUNK; several records point
 *      to the same name. Hence the need to keep the whole chunk at hand while
 *      decoding a record.
 *
 *    - TEMPLATES. A record generally holds not its XML but a reference to a
 *      definition placed elsewhere in the chunk, plus an array of typed values
 *      to substitute into it. That is what makes the format compact — and why a
 *      naive parser returns nothing usable.
 *
 *  WHAT THIS PARSER RETURNS: the XML of each record, as text. `events` then
 *  parses it with `xml_light` — already written for scheduled tasks — rather
 *  than with a second specific decoder.
 *
 *  ROBUSTNESS. The data come from the examined machine: sizes, offsets and
 *  counters are therefore to be treated as untrusted. Every read is bounded by
 *  the buffer's real size, recursion by a maximum depth, and an unreadable
 *  record interrupts neither its chunk nor its file — it is reported and
 *  reading goes on. A partially corrupt log is a common case in forensics, not
 *  an exception.
 */

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

//! One event record, as read from the file.
struct EvtxEnregistrement {
	unsigned long long identifiant = 0;   //!< record number
	FILETIME ecritUtc = { 0, 0 };         //!< time written (UTC)
	std::wstring xml;                     //!< event body, as XML
};

/*! Result of reading an .evtx file: enough to tell, in the report, an empty
*  log from an unreadable one.
*/
struct EvtxBilan {
	unsigned long long chunks = 0;        //!< chunks parcourus
	unsigned long long lus = 0;           //!< decoded records
	unsigned long long illisibles = 0;    //!< discarded records
	unsigned long long chunksIgnores = 0; //!< damaged chunks skipped (no signature)
	bool enteteValide = false;            //!< "ElfFile\0" signature found
	bool sale = false;                    //!< log marked "dirty"
	std::wstring diagnostic;              //!< sentence for the audit log
};

/*! Reads an .evtx file and hands each record to the given callback.
*
*  The callback is called as reading goes, record by record: nothing is
*  accumulated here. That is deliberate — it lets the caller stream its output
*  instead of keeping a hundred thousand events in memory, the flaw of
*  API-based reading.
*
*  @param chemin path of the .evtx file (the extracted copy, never the original)
*  @param surEnregistrement callback invoked for each decoded record; returning
*         false stops the reading
*  @param bilan receives the count and the diagnosis (optional)
*  @return ERROR_SUCCESS if the file was walked, an error code if it is
*          inaccessible; S_FALSE if records were discarded
*/
HRESULT EvtxLireFichier(const std::wstring& chemin,
                        const std::function<bool(const EvtxEnregistrement&)>& surEnregistrement,
                        EvtxBilan* bilan = nullptr);

/*! Channel name from the log's file name.
*
*  Windows encodes the channel in the name: "Microsoft-Windows-Kernel-Boot%4Operational.evtx"
*  designates the channel "Microsoft-Windows-Kernel-Boot/Operational". "%4" is
*  an escaped slash, that character being forbidden in a file name.
*
*  @param nomFichier file name, with or without a path
*  @return the channel name
*/
std::wstring EvtxCanalDepuisNomFichier(const std::wstring& nomFichier);
