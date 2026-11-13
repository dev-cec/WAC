/*! \file
 *  \brief The examined machine's time zone over time, read in its System log:
 *         the offset in force when each local time was written.
 *
 *  WHY. The current zone's rules (loadSuspectTimeZone) know each date's
 *  daylight saving time, not that the zone itself changed. Measured on
 *  Server 2025 (2026-11-09): installed in the default Pacific time, set to
 *  Paris afterwards, its NetSetup.LOG dated its lines at UTC-7 — read at the
 *  offset of Paris, 8 h off. Windows writes every change of offset while it
 *  runs (Kernel-General 22), the offset at each boot (24) and at each setting
 *  of the clock (1): the System log tells the offset of every instant it covers.
 *
 *  BEFORE WINDOWS 10. Neither 22 nor 24 (measured on Server 2008 R2,
 *  2026-11-10): the zone in force at each boot and once a day (EventLog 6013),
 *  a zone set by tzutil (TZUtil's log, 20001) or through the API
 *  (Kernel-General 1, times equal), each zone's rules read in the SOFTWARE
 *  hive. A change seen only between two 6013 has no instant: the interval is
 *  said (timeZoneHistoryFromObservations).
 *
 *  SERVER 2003 (and XP's family, .evt logs). No 6013 in the log (measured
 *  2026-11-10, ten boots): the zone is in EventLog 6005 and 6006 instead —
 *  the log service started, at each boot, and stopped, at each shutdown —,
 *  in the same last datum. No TZUtil, no Kernel-General: a change between two
 *  of them has no instant.
 *
 *  READ IN THE WORKING COPY. The log is read from `<output>\working`, as every
 *  conversion reads a collected file; the exhibit store is never read.
 */
#pragma once
#include <windows.h>
#include <string>
#include "xml_light.h"

/*! The zone an EventLog 6013 (Server 2008 R2), 6005 or 6006 (Server 2003)
 *  says in force: its last datum, "<standard offset> <standard name>" ("-60
 *  Romance Standard Time", "-60 Paris, Madrid" in French) — the Binary after
 *  it is not a datum (measured on both, 2026-11-10).
 *  @param event the event, parsed
 *  @param standardBias receives the standard offset, in minutes: UTC = local + bias
 *  @param standardName receives the standard name
 *  @return false for another event, or a datum not of that form */
bool zoneInForceOf(const XmlNode& event, long& standardBias, std::wstring& standardName);

/*! Reads the offsets the System log holds (its working copy, archives and a
 *  moved log included: workingEventLogs), and TZUtil's log, and fills
 *  conf.timeZone.history.
 *  To be called after loadSuspectTimeZone, which clears it, and before any
 *  local time is converted.
 *  @return ERROR_SUCCESS; ERROR_FILE_NOT_FOUND (as HRESULT) when the
 *          collection holds no System log — the rules alone then apply;
 *          S_FALSE when records of it could not be read */
HRESULT loadSuspectTimeZoneHistory();
