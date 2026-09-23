/*! \file
 *  \brief Makes a hive copied live ("dirty") usable.
 *
 *  PROBLEM. A raw copy of a hive of a running system is always marked "dirty":
 *  in its base block (`regf`), the primary sequence number differs from the
 *  secondary one. WAC's hive reader (offline_registry.cpp) refuses such a hive
 *  with ERROR_BADDB (1009), as Microsoft's offreg did when this was measured on
 *  Windows 11 25H2: read as is, it would give stale keys without any error. VSS
 *  hid this problem: the snapshot triggered the *registry writer*, which
 *  flushed the hives.
 *
 *  TWO LEVELS OF REPAIR, from the most complete to the most minimal:
 *
 *    1. ReplayHiveLogs() applies the transaction logs. That is what Windows does
 *       at boot: the `.LOG1/.LOG2` hold the pages changed since the hive's last
 *       full write, and applying them gives the machine's real state at the
 *       time of the copy. Measured on a real machine: 452 KiB for SYSTEM,
 *       1,172 KiB for SOFTWARE, 600 KiB for one ntuser.dat — and three
 *       `MountPoints2` keys the raw copy alone did not hold. The rebuilt hive is
 *       clean by construction, so no patch is needed afterwards.
 *
 *    2. MakeHiveLoadable() is now only a fallback: no log, empty log, or
 *       unusable chain of entries. It sets secondary := primary and recomputes
 *       the base block checksum, which is what the field's tools do to "load a
 *       dirty hive". The changes left in the logs are then NOT applied.
 *
 *  ETHICS. Both operations write to the COPY, never to the original — which is
 *  never opened for writing anyway. And the raw copy stays rebuildable to the
 *  byte: the patch only touches 8 bytes, fully recorded, and the replay writes
 *  beside the hive an undo log holding the ORIGINAL content of every
 *  replaced page (see ReplayHiveLogs). The `.LOG1/.LOG2` are extracted in every
 *  case: they are artefacts in themselves and the record of what was applied.
 */
#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

/*! Result of repairing a hive. */
struct HiveFixInfo {
    bool     ok            = false; //!< base block read and processed without error
    bool     wasDirty      = false; //!< primary/secondary sequences differ
    bool     patched       = false; //!< the patch was applied
    uint32_t primarySeq    = 0;     //!< primary sequence (unchanged)
    uint32_t secondarySeq  = 0;     //!< secondary sequence BEFORE the patch
    uint32_t oldChecksum   = 0;     //!< checksum before the patch
    uint32_t newChecksum   = 0;     //!< recomputed checksum
    std::wstring hiveName;          //!< internal name of the hive (offset 0x30)
    std::wstring error;             //!< message if ok == false
};

/*! Makes the hive usable by the hive reader, in place, if it is "dirty".
 *  Touches nothing if the hive is already clean (primary == secondary).
 *  @param hive path of the extracted hive (modified in place if dirty)
 *  @return details of the operation, to be recorded in the report
 */
HiveFixInfo MakeHiveLoadable(const std::filesystem::path& hive);

/*! Readable details for the log/report (one line). */
std::wstring HiveFixInfoToString(const HiveFixInfo& i);

/*! A transaction log entry, kept or discarded. */
struct HiveLogEntry {
    uint32_t sequence = 0;      //!< sequence number of the entry
    uint32_t pages    = 0;      //!< number of modified pages
    uint64_t bytes   = 0;      //!< size of those pages
    bool     applique = false;  //!< true if it was written into the hive
    std::wstring reason;         //!< why it was discarded, if it was
};

/*! Result of replaying the transaction logs. */
struct HiveReplayInfo {
    bool ok       = false;      //!< operation carried out without an I/O error
    bool logs = false;      //!< at least one usable `.LOG1/.LOG2` found
    bool applique = false;      //!< at least one entry written into the hive
    uint32_t hiveSequence   = 0;  //!< hive sequence before replay
    uint32_t sequenceFinale  = 0;  //!< sequence after replay
    unsigned keptEntries = 0;  //!< chain entries applied
    unsigned discardedEntries = 0;  //!< invalid entries (checksum, bounds)
    unsigned leftoverEntries   = 0;  //!< entries outside the chain (earlier generation)
    unsigned pages           = 0;  //!< pages written
    uint64_t bytes          = 0;  //!< bytes written
    std::wstring undoJournal; //!< path of the undo log produced
    std::wstring error;             //!< message if ok == false
    std::vector<HiveLogEntry> entries; //!< details, for the report
};

/*! Applies the transaction logs to an extracted hive.
*
*  TWO TRAPS, both met on real data and both decisive for the report's
*  accuracy:
*
*  - **FILE ORDER, NOT SEQUENCE ORDER.** A log is reused in place: entries from
*    an earlier generation survive AFTER the end of the current chain. Sorting
*    them by sequence number brings a stale entry to the front, whose pages are
*    OLDER than the hive. Measured: BAM timestamps — execution evidence — moved
*    fifteen minutes backwards. Each log is therefore walked in file order,
*    stopping at the first break in the sequence, as Windows' recovery does;
*    what follows is leftover.
*
*  - **EVERY ENTRY IS CHECKED BEFORE BEING APPLIED.** The header's two Marvin32
*    checksums cover the header (first 32 bytes) and the body (offset 40 to the
*    end). Verified correct on 60 entries from 11 logs of a real machine. An
*    entry that fails ends the chain: applying doubtful pages to evidence would
*    be worse than applying nothing.
*
*  An undo log `<hive>.undo` is written beside the hive, holding the
*  ORIGINAL content of every replaced page. Its format is deliberately trivial,
*  so that a third party can undo the operation:
*
*      0   8   "WACUNDO1"
*      8  32   MD5 of the hive BEFORE replay, as ASCII hexadecimal
*     40   4   number of pages
*     44   8   size of the hive before replay
*     52   4   reserved (0)
*     56  12×N page table: offset (8 bytes), size (4 bytes)
*     ...      original content of the pages, in table order
*
*  @param hive path of the extracted hive (modified in place if the replay succeeds)
*  @param md5Before fingerprint of the hive before replay, recorded in the undo
*         log; the caller already computed it during extraction
*  @return details of the operation, to be recorded in the report
*/
HiveReplayInfo ReplayHiveLogs(const std::filesystem::path& hive,
                              const std::wstring& md5Before);

/*! Readable details for the log/report (one line). */
std::wstring HiveReplayInfoToString(const HiveReplayInfo& i);
