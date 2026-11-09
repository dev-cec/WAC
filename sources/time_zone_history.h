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
 *  READ IN THE WORKING COPY. The log is read from <output>\working, as every
 *  conversion reads a collected file; the exhibit store is never read.
 */
#pragma once
#include <windows.h>

/*! Reads the offsets the System log holds (its working copy, archives and a
 *  moved log included: workingEventLogs) and fills conf.timeZone.history.
 *  To be called after loadSuspectTimeZone, which clears it, and before any
 *  local time is converted.
 *  @return ERROR_SUCCESS; ERROR_FILE_NOT_FOUND (as HRESULT) when the
 *          collection holds no System log — the rules alone then apply;
 *          S_FALSE when records of it could not be read */
HRESULT loadSuspectTimeZoneHistory();
