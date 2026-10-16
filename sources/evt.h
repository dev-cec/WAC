/*! \file
 *  \brief Classic event logs (.evt) of Windows XP and Server 2003, read
 *         into the same XML as the .evtx records.
 *
 *  THE FORMAT. A header of 0x30 bytes — its size, "LfLe", version 1.1, the
 *  offsets of the oldest record and of the end-of-file record, the next and
 *  the oldest record numbers, the maximum size, flags, retention — then a
 *  circular area of records. Each record: its length, "LfLe", its number,
 *  the time it was generated and written (Unix seconds, UTC), the event
 *  identifier (its low 16 bits; the high 16, the qualifiers), its type,
 *  number of strings, category, the offsets and lengths of the user's SID,
 *  the strings and the binary data, then the source and computer names
 *  (UTF-16, null-terminated), the SID, the strings, the data, and its length
 *  again. A record that reaches the end of the file goes on right after the
 *  header. The walk starts at the oldest record and ends at the end-of-file
 *  record (0x28 bytes, 0x11111111 … 0x44444444).
 *
 *  WHY THE XML OF AN .EVTX. A record becomes the XML Windows Vista and later
 *  render for a classic source (Provider Name, EventID and its Qualifiers,
 *  Level, Task, TimeCreated, EventRecordID, Channel, Computer, Security
 *  UserID, EventData with its Data and its Binary): events.cpp builds the
 *  event, its message (from the source's message files declared in SYSTEM)
 *  and its JSON as for an .evtx — one events.json, one form.
 *
 *  Every offset and length comes from the file: each is bounded by the
 *  record, the record by the file; a forged length ends the walk, the
 *  records before kept.
 */
#pragma once

#include <functional>
#include <string>
#include <windows.h>
#include "evtx.h"
#include "offline_registry.h"

/*! Reads a classic .evt log and hands each record, rendered as XML, to the
 *  callback, oldest first.
 *  @param path the log (the working copy, never the original)
 *  @param channel the log's name (Application, Security, System…), its Channel
 *  @param onRecord callback for each record; returning false stops the reading
 *  @param summary receives the count and the diagnosis (optional)
 *  @return ERROR_SUCCESS if the file was walked, an error code if it is not
 *          a classic log or cannot be read */
HRESULT EvtReadFile(const std::wstring& path, const std::wstring& channel,
                    const std::function<bool(const EvtxRecord&)>& onRecord, EvtxSummary* summary = nullptr);

/*! The log a classic .evt file holds: the subkey of
 *  SYSTEM\\…\\Services\\Eventlog whose File value names it; without one, the
 *  name Windows XP gives its three logs (AppEvent: Application, SecEvent:
 *  Security, SysEvent: System), else the file's name without extension.
 *  @param controlSet the examined machine's CurrentControlSet, or nullptr
 *  @param fileName the file's name (AppEvent.Evt…)
 *  @return the log's name */
std::wstring EvtChannelFromFile(ORHKEY controlSet, const std::wstring& fileName);
