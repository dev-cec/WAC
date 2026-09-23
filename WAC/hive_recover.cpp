/*  hive_recover.cpp — see hive_recover.h.
 *  Portable C++ (no Windows dependency): testable on Linux too.
 */
#include "hive_recover.h"
#include <fstream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <iterator>

namespace {

constexpr size_t BASE_BLOCK = 4096;   // size of a hive's base block
constexpr size_t OFF_PRIMARY   = 0x04;
constexpr size_t OFF_SECONDARY = 0x08;
constexpr size_t OFF_FILETYPE  = 0x1C;  // 0 = primary hive, 6 = log
constexpr size_t OFF_NAME      = 0x30;  // internal name, UTF-16, 64 bytes
constexpr size_t OFF_CHECKSUM  = 508;   // XOR of the first 127 uint32

inline uint32_t rd32(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline void wr32(uint8_t* p, uint32_t v){
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Base block checksum: XOR of the first 127 uint32.
   0 and 0xFFFFFFFF are forbidden and replaced (format specification). */
uint32_t baseBlockChecksum(const uint8_t* bb){
    uint32_t x = 0;
    for (int i = 0; i < 127; ++i) x ^= rd32(bb + i * 4);
    if (x == 0)          return 1;
    if (x == 0xFFFFFFFF) return 0xFFFFFFFE;
    return x;
}

} // namespace

HiveFixInfo MakeHiveLoadable(const std::filesystem::path& hive){
    HiveFixInfo r;
    std::fstream f(hive, std::ios::in | std::ios::out | std::ios::binary);
    if (!f){ r.error = L"cannot be opened"; return r; }

    std::vector<uint8_t> bb(BASE_BLOCK);
    f.read(reinterpret_cast<char*>(bb.data()), BASE_BLOCK);
    if (f.gcount() != (std::streamsize)BASE_BLOCK){ r.error = L"base block truncated"; return r; }

    if (std::memcmp(bb.data(), "regf", 4) != 0){ r.error = L"regf signature absent"; return r; }
    if (rd32(bb.data() + OFF_FILETYPE) != 0){ r.error = L"is not a primary hive"; return r; }

    r.primarySeq   = rd32(bb.data() + OFF_PRIMARY);
    r.secondarySeq = rd32(bb.data() + OFF_SECONDARY);
    r.oldChecksum  = rd32(bb.data() + OFF_CHECKSUM);

    // internal name (UTF-16, terminated or full)
    for (size_t i = 0; i < 32; ++i){
        wchar_t c = (wchar_t)(bb[OFF_NAME + i * 2] | (bb[OFF_NAME + i * 2 + 1] << 8));
        if (!c) break;
        r.hiveName.push_back(c);
    }

    r.wasDirty = (r.primarySeq != r.secondarySeq);
    if (!r.wasDirty){ r.ok = true; r.newChecksum = r.oldChecksum; return r; }

    // Set secondary := primary, then recompute the checksum.
    wr32(bb.data() + OFF_SECONDARY, r.primarySeq);
    r.newChecksum = baseBlockChecksum(bb.data());
    wr32(bb.data() + OFF_CHECKSUM, r.newChecksum);

    f.seekp(0, std::ios::beg);
    f.write(reinterpret_cast<const char*>(bb.data()), BASE_BLOCK);
    f.flush();
    if (!f){ r.error = L"cannot write the base block"; return r; }

    r.patched = true; r.ok = true;
    return r;
}

std::wstring HiveFixInfoToString(const HiveFixInfo& i){
    auto hex = [](uint32_t v){
        wchar_t b[16];
        const wchar_t* d = L"0123456789abcdef";
        b[0] = L'0'; b[1] = L'x';
        for (int k = 0; k < 8; ++k) b[2 + k] = d[(v >> ((7 - k) * 4)) & 0xF];
        b[10] = 0; return std::wstring(b);
    };
    if (!i.ok) return L"FAILED (" + i.error + L")";
    if (!i.wasDirty) return i.hiveName + L": already clean (seq " + hex(i.primarySeq) + L")";
    return i.hiveName + L" : dirty séq " + hex(i.primarySeq) + L"/" + hex(i.secondarySeq)
         + L" -> aligned " + hex(i.primarySeq) + L", checksum " + hex(i.oldChecksum)
         + L" -> " + hex(i.newChecksum)
         + (i.patched ? L" [patch appliqué]" : L" [NON appliqué]");
}

// ---------------------------------------------------------------------------
//  Replaying the transaction logs
// ---------------------------------------------------------------------------
/*  See hive_recover.h for the approach and the two traps. Here, the format.
 *
 *  Log (.LOG1/.LOG2): 512-byte base block of type "regf", then a sequence of
 *  contiguous entries.
 *
 *  Entry ("HvLE"):
 *      0   4   signature "HvLE"
 *      4   4   size of the entry
 *      8   4   flags
 *     12   4   sequence number
 *     16   4   size of the bins data AFTER this entry
 *     20   4   number of modified pages
 *     24   8   Marvin32 of the body (offset 40 → end of the entry)
 *     32   8   Marvin32 of the header (first 32 bytes)
 *     40  8×N  page references: offset (4), size (4)
 *    ...       page content, in the order of the references
 *
 *  Page offsets are relative to the START OF THE BINS DATA, i.e. to offset
 *  4096 of the hive file.
 */
namespace {

constexpr size_t LOG_HEADER      = 512;        // base block of a log
constexpr size_t ENTRY_HEADER   = 40;         // before the page references
constexpr uint64_t MARVIN_SEED = 0x82EF4D887A4E55C5ULL;

inline uint32_t rotl32(uint32_t v, int n){ return (uint32_t)((v << n) | (v >> (32 - n))); }

/*  Marvin32, as the format uses it. The result is returned on 8 bytes: the
 *  low half then the high half, little-endian. */
uint64_t marvin32(const uint8_t* data, size_t size){
    uint32_t lo = (uint32_t)MARVIN_SEED;
    uint32_t hi = (uint32_t)(MARVIN_SEED >> 32);
    auto mix = [&](){
        hi ^= lo; lo = rotl32(lo, 20); lo += hi;
        hi = rotl32(hi, 9);  hi ^= lo; lo = rotl32(lo, 27); lo += hi;
        hi = rotl32(hi, 19);
    };
    size_t i = 0;
    for (; size - i >= 4; i += 4){ lo += rd32(data + i); mix(); }
    // Finalisation: the remaining bytes followed by a 0x80.
    uint32_t rest = 0;
    size_t k = 0;
    for (; i + k < size; ++k) rest |= (uint32_t)data[i + k] << (8 * k);
    rest |= (uint32_t)0x80 << (8 * k);
    lo += rest; mix(); mix();
    return ((uint64_t)hi << 32) | lo;
}

inline uint64_t rd64(const uint8_t* p){
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}
inline void wr64(uint8_t* p, uint64_t v){ wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

//! An entry read from a log, with its position and its verdict.
struct ReadEntry {
    uint32_t sequence = 0;
    uint32_t nbPages  = 0;
    uint64_t bytes   = 0;
    uint32_t binsSize = 0;
    std::vector<std::pair<uint32_t, uint32_t>> pages; //!< offset, size
    std::vector<uint8_t> corps;                       //!< the whole entry
    size_t   dataStart = 0;                        //!< within `corps`
    std::wstring reason;                               //!< empty if valid
};

/*! Entries of a log, IN FILE ORDER, up to the first break.
 *
 *  The chain stops at the first entry that is invalid or whose sequence does
 *  not follow: what comes after is leftover from an earlier generation of the
 *  log, and applying it would move the data backwards (see hive_recover.h).
 */
std::vector<ReadEntry> readString(const std::filesystem::path& log,
                                  unsigned* leftover){
    std::vector<ReadEntry> string;
    std::error_code ec;
    if (!std::filesystem::exists(log, ec)) return string;
    std::ifstream f(log, std::ios::binary);
    if (!f) return string;
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
    if (d.size() < LOG_HEADER || std::memcmp(d.data(), "regf", 4) != 0) return string;

    size_t off = LOG_HEADER;
    bool broken = false;
    uint32_t expected = 0;
    bool first = true;
    while (off + ENTRY_HEADER <= d.size()){
        if (std::memcmp(d.data() + off, "HvLE", 4) != 0) break;
        const uint32_t size = rd32(d.data() + off + 4);
        if (size < LOG_HEADER || off + size > d.size()) break;

        if (broken){ ++*leftover; off += size; continue; }

        ReadEntry e;
        e.sequence   = rd32(d.data() + off + 12);
        e.binsSize = rd32(d.data() + off + 16);
        e.nbPages    = rd32(d.data() + off + 20);
        const uint64_t h1 = rd64(d.data() + off + 24);
        const uint64_t h2 = rd64(d.data() + off + 32);

        // Bounds BEFORE any other read: nbPages comes from the examined file.
        if (e.nbPages > (size - ENTRY_HEADER) / 8) e.reason = L"inconsistent number of pages";
        else if (marvin32(d.data() + off, 32) != h2)  e.reason = L"header digest";
        else if (marvin32(d.data() + off + ENTRY_HEADER, size - ENTRY_HEADER) != h1)
                                                      e.reason = L"body digest";
        else {
            uint64_t sum = 0;
            for (uint32_t i = 0; i < e.nbPages; ++i){
                const uint32_t o = rd32(d.data() + off + ENTRY_HEADER + 8 * i);
                const uint32_t t = rd32(d.data() + off + ENTRY_HEADER + 8 * i + 4);
                e.pages.emplace_back(o, t);
                sum += t;
            }
            if (ENTRY_HEADER + 8ULL * e.nbPages + sum > size)
                e.reason = L"pages outside the entry";
            else e.bytes = sum;
        }

        if (e.reason.empty() && !first && e.sequence != expected)
            e.reason = L"sequence broken (leftover)";

        if (!e.reason.empty()){
            broken = true;
            // A broken entry is not counted as leftover if it is invalid in
            // itself: the caller tells the two cases apart.
            if (e.reason == L"sequence broken (leftover)") ++*leftover;
            else string.push_back(std::move(e));   // kept for the report
            off += size;
            continue;
        }

        e.corps.assign(d.begin() + off, d.begin() + off + size);
        e.dataStart = ENTRY_HEADER + 8ULL * e.nbPages;
        expected = e.sequence + 1;
        first = false;
        string.push_back(std::move(e));
        off += size;
    }
    return string;
}

} // namespace

HiveReplayInfo ReplayHiveLogs(const std::filesystem::path& hive,
                              const std::wstring& md5Before){
    HiveReplayInfo r;

    std::fstream f(hive, std::ios::in | std::ios::out | std::ios::binary);
    if (!f){ r.error = L"cannot be opened"; return r; }

    std::vector<uint8_t> bb(BASE_BLOCK);
    f.read(reinterpret_cast<char*>(bb.data()), BASE_BLOCK);
    if (f.gcount() != (std::streamsize)BASE_BLOCK){ r.error = L"base block truncated"; return r; }
    if (std::memcmp(bb.data(), "regf", 4) != 0){ r.error = L"regf signature absent"; return r; }
    if (rd32(bb.data() + OFF_FILETYPE) != 0){ r.error = L"is not a primary hive"; return r; }

    const uint32_t primarySeq   = rd32(bb.data() + OFF_PRIMARY);
    const uint32_t secondarySeq = rd32(bb.data() + OFF_SECONDARY);
    r.hiveSequence  = primarySeq;
    r.sequenceFinale = primarySeq;

    unsigned leftover = 0;
    std::vector<ReadEntry> string = readString(hive.wstring() + L".LOG1", &leftover);
    for (ReadEntry& e : readString(hive.wstring() + L".LOG2", &leftover))
        string.push_back(std::move(e));
    r.leftoverEntries = leftover;
    if (string.empty()){ r.ok = true; return r; }   // no log: the nominal case
    r.logs = true;

    // The two logs follow each other; sequence order joins them.
    std::sort(string.begin(), string.end(),
              [](const ReadEntry& a, const ReadEntry& b){ return a.sequence < b.sequence; });

    // Current file size, to bound the writes.
    f.seekg(0, std::ios::end);
    const uint64_t hiveSize = (uint64_t)f.tellg();

    /*  Two passes. The first one decides and gathers the ORIGINAL content of
     *  the pages: the undo log must be complete BEFORE the slightest write,
     *  otherwise an interruption would leave a modified hive that could no
     *  longer be rebuilt. */
    struct Page { uint64_t offset; uint32_t size; std::vector<uint8_t> origin; };
    std::vector<Page> undo;
    std::vector<const ReadEntry*> toApply;
    uint32_t expected = 0;
    bool first = true;

    for (ReadEntry& e : string){
        HiveLogEntry trace;
        trace.sequence = e.sequence;
        trace.pages    = e.nbPages;
        trace.bytes   = e.bytes;

        if (!e.reason.empty()){ trace.reason = e.reason; ++r.discardedEntries; r.entries.push_back(trace); continue; }
        if (e.sequence <= secondarySeq){
            trace.reason = L"already in the hive";
            r.entries.push_back(trace);
            continue;
        }
        if (!first && e.sequence != expected){
            // Gap between the two logs: stop there. Beyond, the state would be a
            // mix of generations, with no guarantee of consistency.
            trace.reason = L"hole in the chain";
            ++r.discardedEntries;
            r.entries.push_back(trace);
            break;
        }
        expected = e.sequence + 1;
        first = false;

        bool boundsOk = true;
        for (const std::pair<uint32_t, uint32_t>& p : e.pages)
            if (BASE_BLOCK + (uint64_t)p.first + p.second > hiveSize) boundsOk = false;
        if (!boundsOk){
            trace.reason = L"page outside the hive";
            ++r.discardedEntries;
            r.entries.push_back(trace);
            break;
        }

        for (const std::pair<uint32_t, uint32_t>& p : e.pages){
            Page pg{ BASE_BLOCK + (uint64_t)p.first, p.second, {} };
            pg.origin.resize(p.second);
            f.seekg((std::streamoff)pg.offset, std::ios::beg);
            f.read(reinterpret_cast<char*>(pg.origin.data()), p.second);
            if (f.gcount() != (std::streamsize)p.second){ boundsOk = false; break; }
            undo.push_back(std::move(pg));
        }
        if (!boundsOk){
            trace.reason = L"lecture de la page d'origine impossible";
            ++r.discardedEntries;
            r.entries.push_back(trace);
            break;
        }

        trace.applique = true;
        toApply.push_back(&e);
        r.entries.push_back(trace);
        ++r.keptEntries;
        r.pages  += e.nbPages;
        r.bytes += e.bytes;
        r.sequenceFinale = e.sequence;
    }

    if (toApply.empty()){ r.ok = true; return r; }

    /*  The base block is part of the undo: the replay rewrites the sequence
     *  numbers and the checksum in it. Without it, the raw copy could only be
     *  restored in its data area, and the "rebuildable to the byte" promise
     *  would be false by 4096 bytes. */
    undo.insert(undo.begin(), Page{ 0, (uint32_t)BASE_BLOCK,
                      std::vector<uint8_t>(bb.begin(), bb.end()) });

    // Undo log, written BEFORE any change to the hive.
    const std::filesystem::path chemUndo = hive.wstring() + L".undo";
    {
        std::ofstream u(chemUndo, std::ios::binary | std::ios::trunc);
        if (!u){ r.error = L"undo journal not written: replay abandoned"; return r; }
        std::vector<uint8_t> ent(56, 0);
        std::memcpy(ent.data(), "WACUNDO1", 8);
        for (size_t i = 0; i < 32; ++i)
            ent[8 + i] = (uint8_t)(i < md5Before.size() ? (char)md5Before[i] : ' ');
        wr32(ent.data() + 40, (uint32_t)undo.size());
        wr64(ent.data() + 44, hiveSize);
        u.write(reinterpret_cast<const char*>(ent.data()), (std::streamsize)ent.size());
        for (const Page& p : undo){
            uint8_t line[12];
            wr64(line, p.offset);
            wr32(line + 8, p.size);
            u.write(reinterpret_cast<const char*>(line), 12);
        }
        for (const Page& p : undo)
            u.write(reinterpret_cast<const char*>(p.origin.data()), (std::streamsize)p.size);
        u.flush();
        if (!u){ r.error = L"undo journal incomplete: replay abandoned"; return r; }
    }
    r.undoJournal = chemUndo.wstring();

    // Apply the pages, then align the base block on the last applied
    // sequence: the hive becomes clean by construction.
    for (const ReadEntry* e : toApply){
        size_t pos = e->dataStart;
        for (const std::pair<uint32_t, uint32_t>& p : e->pages){
            f.seekp((std::streamoff)(BASE_BLOCK + (uint64_t)p.first), std::ios::beg);
            f.write(reinterpret_cast<const char*>(e->corps.data() + pos), (std::streamsize)p.second);
            pos += p.second;
        }
    }
    wr32(bb.data() + OFF_PRIMARY,   r.sequenceFinale);
    wr32(bb.data() + OFF_SECONDARY, r.sequenceFinale);
    wr32(bb.data() + OFF_CHECKSUM,  baseBlockChecksum(bb.data()));
    f.seekp(0, std::ios::beg);
    f.write(reinterpret_cast<const char*>(bb.data()), BASE_BLOCK);
    f.flush();
    if (!f){ r.error = L"cannot write the hive"; return r; }

    r.applique = true;
    r.ok = true;
    return r;
}

std::wstring HiveReplayInfoToString(const HiveReplayInfo& i){
    auto hex = [](uint32_t v){
        wchar_t b[16];
        const wchar_t* d = L"0123456789abcdef";
        b[0] = L'0'; b[1] = L'x';
        for (int k = 0; k < 8; ++k) b[2 + k] = d[(v >> ((7 - k) * 4)) & 0xF];
        b[10] = 0; return std::wstring(b);
    };
    if (!i.ok) return L"rejeu : FAILED (" + i.error + L")";
    if (!i.logs) return L"replay: no usable transaction log";
    if (!i.applique) return L"replay: nothing to apply (hive up to date, seq "
                          + hex(i.hiveSequence) + L")";
    std::wstring s = L"rejeu : " + std::to_wstring(i.keptEntries) + L" entree(s), "
                   + std::to_wstring(i.pages) + L" page(s), "
                   + std::to_wstring(i.bytes / 1024) + L" Kio, seq "
                   + hex(i.hiveSequence) + L" -> " + hex(i.sequenceFinale);
    if (i.discardedEntries) s += L", " + std::to_wstring(i.discardedEntries) + L" discarded";
    if (i.leftoverEntries)   s += L", " + std::to_wstring(i.leftoverEntries) + L" out of the chain";
    return s;
}
