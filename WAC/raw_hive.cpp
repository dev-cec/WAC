/*! \file
 *  \brief Raw NTFS reader: $MFT, attributes, data runs, directory indexes.
 *
 *  See raw_hive.h.
 *  Minimal NTFS parser: VBR, $MFT (fragmented), attributes, data runs,
 *  directory indexes ($INDEX_ROOT + $INDEX_ALLOCATION), $DATA extraction.
 *  Built for hives/EVTX/Tasks: non-resident, medium-sized files.
 */
#include "raw_hive.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <map>
#include <memory>
#include <ostream>
#include <unordered_map>
#include "quickdigest5.h"
#include "sha.h"
#include "lznt1.h"
#include "xpress.h"

namespace {

bool g_verbose = false;
//! Trace of the NTFS parser on stderr, printed only in --debug mode.
#define RVLOG(...) do{ if(g_verbose) fwprintf(stderr, __VA_ARGS__); }while(0)

RawHiveProgressFn g_progress = nullptr;      // progress reporter, optional

// --- little-endian integer reads ------------------------------------------
inline uint16_t rd16(const uint8_t* p){ return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t rd32(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
inline uint64_t rd64(const uint8_t* p){
    uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v;
}

// case-insensitive name comparison (ASCII/BMP is enough for these paths)
bool iequals(const std::wstring& a, const std::wstring& b){
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (towlower(a[i]) != towlower(b[i])) return false;
    return true;
}

struct Run { int64_t lcn; uint64_t count; }; // lcn == -1: sparse run (zeros)

/*! The three fingerprints of a content, computed on the bytes as they pass —
 *  or none, when the caller asked only for the content
 *  (RawHiveFingerprints::computeHashes false: authenticating an executable
 *  needs its Authenticode digest, not MD5, SHA-1 and SHA-256, and those three
 *  cost most of the time of a whole-volume reading). One object for the four
 *  ways a content is read: resident, WOF, NTFS-compressed, ordinary. */
class ContentHashes {
public:
    //! @param emp where the fingerprints go; nullptr for none.
    explicit ContentHashes(const RawHiveFingerprints* emp) : on_(emp && emp->computeHashes) {}
    //! Adds bytes. @param data,length the bytes.
    void update(const uint8_t* data, size_t length){
        if (!on_) return;
        md5_.update(data, length); sha1_.update(data, length); sha256_.update(data, length);
    }
    //! Writes the fingerprints, if computed. @param emp their destination (may be null).
    void finish(RawHiveFingerprints* emp){
        if (!on_ || !emp) return;
        emp->md5 = md5_.hexDigest(); emp->sha1 = sha1_.hexDigest(); emp->sha256 = sha256_.hexDigest();
    }
private:
    bool on_;
    Md5Stream md5_;
    Sha1Stream sha1_;
    Sha256Stream sha256_;
};

/*! Buffer that discards what is written to it. Used to fingerprint a file
 *  without copying it: the three reading paths (plain, LZNT1, WOF) write to a
 *  stream and hash on the way, so giving them a stream that leads nowhere is
 *  enough. */
class NullBuffer : public std::streambuf {
protected:
    int overflow(int c) override { return traits_type::not_eof(c); }
    std::streamsize xsputn(const char*, std::streamsize n) override { return n; }
};

// Decodes an NTFS data run list.
std::vector<Run> decodeRuns(const uint8_t* p, const uint8_t* end){
    std::vector<Run> runs; int64_t prev = 0;
    while (p < end) {
        uint8_t hdr = *p++; if (hdr == 0) break;
        int lenSz = hdr & 0x0F, offSz = (hdr >> 4) & 0x0F;
        if (p + lenSz + offSz > end) break;
        uint64_t count = 0;
        for (int i = 0; i < lenSz; ++i) count |= (uint64_t)p[i] << (8 * i);
        p += lenSz;
        Run r; r.count = count;
        if (offSz == 0) { r.lcn = -1; }                 // sparse
        else {
            int64_t off = 0;
            for (int i = 0; i < offSz; ++i) off |= (int64_t)p[i] << (8 * i);
            if (p[offSz - 1] & 0x80)                     // sign extension
                for (int i = offSz; i < 8; ++i) off |= (int64_t)0xFF << (8 * i);
            prev += off; r.lcn = prev; p += offSz;
        }
        runs.push_back(r);
    }
    return runs;
}

class NtfsVolume {
public:
    ~NtfsVolume(){ close(); }

    HRESULT open(const std::wstring& volumeLetter){
        std::wstring path = L"\\\\.\\" + volumeLetter + L":";
        h_ = CreateFileW(path.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, 0, NULL);
        if (h_ == INVALID_HANDLE_VALUE){
            DWORD e = GetLastError();
            RVLOG(L"[raw] open %ls: error %lu (admin rights needed?)\n", path.c_str(), e);
            return HRESULT_FROM_WIN32(e);
        }
        uint8_t vbr[512];
        if (!readBytes(0, vbr, 512)) return E_FAIL;
        if (memcmp(vbr + 3, "NTFS    ", 8) != 0){
            RVLOG(L"[raw] NTFS signature absent\n"); return E_FAIL;
        }
        bytesPerSector_    = rd16(vbr + 0x0B);
        sectorsPerCluster_ = vbr[0x0D];
        bytesPerCluster_   = bytesPerSector_ * sectorsPerCluster_;
        mftLcn_            = rd64(vbr + 0x30);
        int8_t cpr = (int8_t)vbr[0x40];   // clusters/record, or 2^(-cpr) bytes
        bytesPerRecord_ = (cpr >= 0) ? (uint32_t)cpr * bytesPerCluster_
                                     : (uint32_t)(1u << (-cpr));
        if (!bytesPerSector_ || !bytesPerCluster_ || !bytesPerRecord_) return E_FAIL;
        RVLOG(L"[raw] bps=%u spc=%u bpc=%u bpr=%u mftLcn=%llu\n",
              bytesPerSector_, sectorsPerCluster_, bytesPerCluster_,
              bytesPerRecord_, (unsigned long long)mftLcn_);
        return bootstrapMft() ? S_OK : E_FAIL;
    }

    void close(){ if (h_ != INVALID_HANDLE_VALUE){ CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; } }

    /*! Keeps in memory the index of each directory walked. For reading
     *  thousands of scattered files: without a cache, each System32 file re-read
     *  its 4,659 entries, i.e. 256 index blocks (1 MiB). Reserved to RawReader,
     *  whose lifetime is that of one collection phase: a file created later in
     *  an already-read directory would not be seen. */
    void enableCache(){ cacheActive_ = true; }

    // Resolves a path (\a\b\c) into a MFT record index.
    bool resolvePath(const std::wstring& path, uint64_t& outIndex){
        uint64_t cur = 5; // root \ = MFT #5
        size_t i = 0;
        while (i < path.size()){
            while (i < path.size() && (path[i] == L'\\' || path[i] == L'/')) ++i;
            size_t j = i;
            while (j < path.size() && path[j] != L'\\' && path[j] != L'/') ++j;
            if (j == i) break;
            std::wstring comp = path.substr(i, j - i);
            i = j;
            RVLOG(L"[raw] looking for \"%ls\" in MFT#%llu\n", comp.c_str(), (unsigned long long)cur);
            bool found = false;
            if (cacheActive_){
                auto it = cacheRep_.find(cur);
                if (it == cacheRep_.end()){
                    std::vector<RawDirEntry> entries;
                    if (!listDir(cur, entries)) return false;
                    std::unordered_map<std::wstring, uint64_t> index;
                    for (const RawDirEntry& e : entries) index.emplace(lowercase(e.name), e.mftIndex);
                    it = cacheRep_.emplace(cur, std::move(index)).first;
                }
                const auto it2 = it->second.find(lowercase(comp));
                if (it2 != it->second.end()){ cur = it2->second; found = true; }
            }
            else {
                std::vector<RawDirEntry> entries;
                if (!listDir(cur, entries)) return false;
                for (const RawDirEntry& e : entries)
                    if (iequals(e.name, comp)){ cur = e.mftIndex; found = true; break; }
            }
            if (!found){ RVLOG(L"[raw] component not found: %ls\n", comp.c_str()); return false; }
        }
        outIndex = cur; return true;
    }

    // Extracts the (unnamed) $DATA attribute of the record to a file.
    /* Gathers the $DATA data runs when the attribute is SPLIT over several
       MFT records, through $ATTRIBUTE_LIST (type 0x20).
       NTFS resorts to this when a file is too fragmented for its data runs to
       fit in a single record — seen on the SOFTWARE hive of a real system, which
       therefore failed to extract.

       Each list entry is: type (4), length (2), name length (1), name offset
       (1), starting VCN (8), MFT reference (8), id (2).
       The unnamed $DATA entries are kept, the referenced record is loaded, and
       its runs are concatenated in VCN order.
       @param realSize receives the real size, read on the VCN 0 fragment
       @param compressionUnit if not null, receives the compression unit size in
       clusters (0 = not compressed), also read on the VCN 0 fragment: only
       that one carries the full header.
       @param validDataLength if not null, receives the valid data length, read at
       the same place (see extractData). */
    bool collectRunsFromAttributeList(const std::vector<uint8_t>& rec,
                                      std::vector<Run>& runs, uint64_t& realSize,
                                      uint32_t wantedType = 0x80,
                                      uint32_t* compressionUnit = nullptr,
                                      uint64_t* validDataLength = nullptr){
        // List content: resident, or to be read through its own runs (bounded).
        std::vector<uint8_t> content;
        if (!readListContent(rec, content)) return false;

        // VCN -> runs, to reassemble in order even if the entries are not.
        std::vector<std::pair<uint64_t, std::vector<Run>>> fragments;
        size_t pos = 0;
        while (pos + 0x1A <= content.size()){
            const uint32_t type = rd32(content.data() + pos);
            const uint16_t len  = rd16(content.data() + pos + 4);
            if (len < 0x1A || pos + len > content.size()) break;
            const uint8_t nameLen = content[pos + 6];
            /* The name is ignored in the comparison: $INDEX_ALLOCATION always
               carries the name "$I30", unlike $DATA which is unnamed. */
            if (type == wantedType && (wantedType != 0x80 || nameLen == 0)){
                const uint64_t vcn = rd64(content.data() + pos + 8);
                const uint64_t ref = rd64(content.data() + pos + 0x10) & 0x0000FFFFFFFFFFFFULL;
                std::vector<uint8_t> frag;
                if (readMftRecord(ref, frag)){
                    // The fragment carries the non-resident attribute covering this VCN.
                    const uint8_t* d = findAttr(frag, wantedType, wantedType == 0x80);
                    if (d && d[8] != 0){
                        /* NTFS COMPRESSION IN A FRAGMENT. Used to be refused:
                           Application.evtx, Security.evtx and two other logs of a
                           Windows 11 VM were not extracted at all. The most active
                           compressed file is also the most fragmented, hence the first
                           to switch to an $ATTRIBUTE_LIST. */
                        if ((rd16(d + 0x0C) & 0x0001) && !compressionUnit){
                            RVLOG(L"[raw] NTFS-compressed $DATA in a fragment: not supported here\n");
                            return false;
                        }
                        if (vcn == 0){
                            realSize = rd64(d + 0x30);
                            if (validDataLength) *validDataLength = rd64(d + 0x38);
                            if (compressionUnit)
                                *compressionUnit = (rd16(d + 0x0C) & 0x0001)
                                                  ? (uint32_t)1u << rd16(d + 0x22) : 0;
                        }
                        fragments.emplace_back(vcn, decodeRuns(d + rd16(d + 0x20), d + rd32(d + 0x04)));
                    }
                }
                else RVLOG(L"[raw] MFT fragment #%llu unreadable\n", (unsigned long long)ref);
            }
            pos += len;
        }
        if (fragments.empty() || realSize == 0) return false;

        std::sort(fragments.begin(), fragments.end(),
                  [](const auto& a, const auto& b){ return a.first < b.first; });
        for (auto& f : fragments)
            runs.insert(runs.end(), f.second.begin(), f.second.end());

        RVLOG(L"[raw] $ATTRIBUTE_LIST: %llu fragment(s), %llu run(s), size %llu\n",
              (unsigned long long)fragments.size(), (unsigned long long)runs.size(),
              (unsigned long long)realSize);
        return true;
    }

    //! What is needed to read a file stored by WOF, wherever it comes from.
    struct WofContext {
        bool     present = false;
        uint32_t algorithm = 0;
        std::vector<Run> runs;      //!< runs of the WofCompressedData stream
        uint64_t streamSize = 0;
    };

    /*! A RESIDENT attribute, looked for in the base record, then through the
     *  $ATTRIBUTE_LIST in the extension records.
     *
     *  WHY. When a record is full, NTFS moves attributes — resident ones too —
     *  to extension records and leaves a list in the base record. Seen on
     *  Windows 11: directories carrying a $TXF_DATA (SysWOW64\zh-TW, thousands
     *  of WinSxS components) have their $INDEX_ROOT in an extension record.
     *  Looked for in the base record alone, 4,569 directories of the volume
     *  were reported unreadable, and their files never collected.
     *  @param rec the base record
     *  @param type the attribute's type
     *  @param holder keeps the extension record the result points into
     *  @return the resident attribute, or nullptr */
    const uint8_t* findResidentAttr(const std::vector<uint8_t>& rec, uint32_t type,
                                    std::vector<uint8_t>& holder){
        const uint8_t* a = findAttr(rec, type, false);
        if (a) return a[8] == 0 ? a : nullptr;
        std::vector<uint8_t> content;
        if (!readListContent(rec, content)) return nullptr;
        for (size_t pos = 0; pos + 0x1A <= content.size();){
            const uint16_t len = rd16(content.data() + pos + 4);
            if (len < 0x1A || pos + len > content.size()) break;
            if (rd32(content.data() + pos) == type){
                const uint64_t ref = rd64(content.data() + pos + 0x10) & 0x0000FFFFFFFFFFFFULL;
                if (readMftRecord(ref, holder)){
                    a = findAttr(holder, type, false);
                    if (a && a[8] == 0) return a;
                }
            }
            pos += len;
        }
        return nullptr;
    }

    //! Content of the $ATTRIBUTE_LIST, resident or not.
    bool readListContent(const std::vector<uint8_t>& rec, std::vector<uint8_t>& content){
        const uint8_t* al = findAttr(rec, 0x20, false);
        if (!al) return false;
        if (al[8] == 0){
            const uint32_t vlen = rd32(al + 0x10);
            const uint16_t voff = rd16(al + 0x14);
            if (voff + (size_t)vlen > rec.size()) return false;
            content.assign(al + voff, al + voff + vlen);
            return true;
        }
        const uint64_t size = rd64(al + 0x30);
        if (size == 0 || size > (16ULL << 20)) return false;
        const std::vector<Run> alRuns = decodeRuns(al + rd16(al + 0x20), al + rd32(al + 0x04));
        content.resize((size_t)size);
        return readVirtual(alRuns, 0, (uint32_t)size, content.data());
    }

    /*! Gathers what is needed to read a WOF file, walking the $ATTRIBUTE_LIST
     *  when needed.
     *
     *  WHY THIS WALK IS ESSENTIAL. When a file has too many attributes to fit in
     *  one $MFT record, NTFS splits them over several records and leaves only a
     *  LIST in the first one. Looking for the reparse point and the
     *  "WofCompressedData" stream in the base record alone then misses them
     *  entirely, and the file is read from its sparse $DATA: the right size, and
     *  empty.
     *  Measured on a Windows 11 VM: 56 event-provider binaries were in that case,
     *  including Microsoft-Windows-System-Events.dll and its 1,286 messages.
     */
    bool resolveWof(const std::vector<uint8_t>& rec, WofContext& ctx){
        // 1. The reparse point: in the base record, or in a fragment.
        const uint8_t* rp = findAttr(rec, 0xC0);
        std::vector<uint8_t> fragRp;
        if (!rp){
            std::vector<uint8_t> content;
            if (readListContent(rec, content)){
                size_t pos = 0;
                while (pos + 0x1A <= content.size()){
                    const uint32_t type = rd32(content.data() + pos);
                    const uint16_t len  = rd16(content.data() + pos + 4);
                    if (len < 0x1A || pos + len > content.size()) break;
                    if (type == 0xC0){
                        const uint64_t ref = rd64(content.data() + pos + 0x10) & 0x0000FFFFFFFFFFFFULL;
                        if (readMftRecord(ref, fragRp)){
                            rp = findAttr(fragRp, 0xC0);
                            if (rp) break;
                        }
                    }
                    pos += len;
                }
            }
        }
        if (!rp || rp[8] != 0) return false;
        const uint8_t* reparseContent = rp + rd16(rp + 0x14);
        if (rd32(rp + 0x10) < 24) return false;
        if (rd32(reparseContent) != 0x80000017u) return false;     // not WOF
        if (rd32(reparseContent + 12) != 2) return false;          // provider not handled
        ctx.algorithm = rd32(reparseContent + 20);

        // 2. The named stream: in the base record, or in fragments.
        const uint8_t* stream = findNamedAttr(rec, 0x80, L"WofCompressedData");
        if (stream && stream[8] != 0){
            ctx.streamSize = rd64(stream + 0x30);
            ctx.runs = decodeRuns(stream + rd16(stream + 0x20), stream + rd32(stream + 0x04));
            ctx.present = !ctx.runs.empty() && ctx.streamSize > 0;
            return ctx.present;
        }

        std::vector<uint8_t> content;
        if (!readListContent(rec, content)) return false;
        std::vector<std::pair<uint64_t, std::vector<Run>>> fragments;
        size_t pos = 0;
        while (pos + 0x1A <= content.size()){
            const uint32_t type = rd32(content.data() + pos);
            const uint16_t len  = rd16(content.data() + pos + 4);
            if (len < 0x1A || pos + len > content.size()) break;
            if (type == 0x80 && content[pos + 6] != 0){       // NAMED $DATA
                const uint64_t vcn = rd64(content.data() + pos + 8);
                const uint64_t ref = rd64(content.data() + pos + 0x10) & 0x0000FFFFFFFFFFFFULL;
                std::vector<uint8_t> frag;
                if (readMftRecord(ref, frag)){
                    const uint8_t* d = findNamedAttr(frag, 0x80, L"WofCompressedData");
                    if (d && d[8] != 0){
                        if (vcn == 0) ctx.streamSize = rd64(d + 0x30);
                        fragments.emplace_back(vcn, decodeRuns(d + rd16(d + 0x20), d + rd32(d + 0x04)));
                    }
                }
            }
            pos += len;
        }
        if (fragments.empty() || ctx.streamSize == 0) return false;
        std::sort(fragments.begin(), fragments.end(),
                  [](const std::pair<uint64_t, std::vector<Run>>& a,
                     const std::pair<uint64_t, std::vector<Run>>& b){ return a.first < b.first; });
        for (std::pair<uint64_t, std::vector<Run>>& f : fragments)
            ctx.runs.insert(ctx.runs.end(), f.second.begin(), f.second.end());
        RVLOG(L"[raw] WOF via $ATTRIBUTE_LIST : %llu fragment(s), stream of %llu bytes\n",
              (unsigned long long)fragments.size(), (unsigned long long)ctx.streamSize);
        ctx.present = true;
        return true;
    }

    //! Reads a non-resident attribute into a buffer (its runs, its real size).
    bool readNonResidentAttribute(const uint8_t* a, std::vector<uint8_t>& out){
        if (a[8] == 0) return false;                 // resident: no runs
        const uint64_t size = rd64(a + 0x30);
        if (size == 0 || size > (256ULL << 20)) return false;   // guard
        const std::vector<Run> runs = decodeRuns(a + rd16(a + 0x20), a + rd32(a + 0x04));
        out.assign((size_t)size, 0);
        uint64_t written = 0;
        for (const Run& r : runs){
            if (written >= size) break;
            const uint64_t n = std::min<uint64_t>(r.count * bytesPerCluster_, size - written);
            // A sparse run stays at zero; an allocated one is read whole, in large requests.
            if (r.lcn >= 0 && !readClusters((uint64_t)r.lcn, n, out.data() + written)) return false;
            written += n;
        }
        return written == size;
    }

    /*! Extracts a file whose content is stored by WOF ("Compact OS").
     *
     *  The unnamed $DATA attribute is SPARSE: reading it returns zeros. The
     *  content lives in the named stream "WofCompressedData", cut into chunks of
     *  fixed size preceded by an offset table — the same layout as in a WIM
     *  image.
     *
     *  The reparse point gives the algorithm: 0, 2 and 3 are XPRESS Huffman on
     *  4, 8 and 16 KiB chunks; 1 is LZX, a distinct format which is not
     *  implemented. A file in LZX is therefore REPORTED as unsupported, not
     *  returned wrong.
     *
     *  @return S_OK, or an error code
     */
    HRESULT extractWof(const WofContext& ctx, uint64_t actualSize,
                        std::ostream& out, const std::wstring& label,
                        RawHiveFingerprints* emp){
        const uint32_t algorithm = ctx.algorithm;
        size_t chunkSize = 0;
        switch (algorithm){
        case 0: chunkSize = 4096;  break;   // XPRESS4K
        case 2: chunkSize = 8192;  break;   // XPRESS8K
        case 3: chunkSize = 16384; break;   // XPRESS16K
        default:
            // 1 = LZX: a distinct format, not implemented. Better to say so.
            RVLOG(L"[raw] WOF: algorithm %lu (LZX?) not implemented\n",
                  (unsigned long)algorithm);
            return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        }

        // The named stream, already located by resolveWof.
        if (ctx.streamSize == 0 || ctx.streamSize > (256ULL << 20)) return E_FAIL;
        std::vector<uint8_t> data((size_t)ctx.streamSize, 0);
        {
            std::vector<uint8_t> cl(bytesPerCluster_);
            uint64_t read = 0;
            for (const Run& r : ctx.runs){
                for (uint64_t k = 0; k < r.count && read < ctx.streamSize; ++k){
                    if (r.lcn < 0) std::fill(cl.begin(), cl.end(), (uint8_t)0);
                    else if (!readCluster((uint64_t)r.lcn + k, cl.data())) return E_FAIL;
                    const uint64_t n = std::min<uint64_t>(bytesPerCluster_, ctx.streamSize - read);
                    std::memcpy(data.data() + read, cl.data(), (size_t)n);
                    read += n;
                }
            }
            if (read != ctx.streamSize){
                RVLOG(L"[raw] WOF: stream truncated (%llu out of %llu)\n",
                      (unsigned long long)read, (unsigned long long)ctx.streamSize);
                return E_FAIL;
            }
        }

        // 3. The offset table: one per chunk, except the first one.
        const size_t nChunks = (size_t)((actualSize + chunkSize - 1) / chunkSize);
        if (nChunks == 0) return E_FAIL;
        const size_t inputSize = (actualSize > 0xFFFFFFFFULL) ? 8 : 4;
        const size_t tableSize  = (nChunks - 1) * inputSize;
        if (data.size() < tableSize) return E_FAIL;

        std::vector<uint64_t> starts(nChunks + 1, 0);
        for (size_t i = 1; i < nChunks; ++i)
            starts[i] = (inputSize == 4) ? (uint64_t)rd32(data.data() + (i - 1) * 4)
                                            : rd64(data.data() + (i - 1) * 8);
        starts[nChunks] = data.size() - tableSize;

        std::vector<uint8_t> chunk(chunkSize);
        ContentHashes hashes(emp);
        uint64_t written = 0, nextReport = 0;

        for (size_t i = 0; i < nChunks; ++i){
            if (starts[i + 1] < starts[i]) return E_FAIL;              // inconsistent table
            const size_t packedSize = (size_t)(starts[i + 1] - starts[i]);
            const size_t start   = tableSize + (size_t)starts[i];
            if (start + packedSize > data.size()) return E_FAIL;
            const size_t expected = (size_t)std::min<uint64_t>(chunkSize, actualSize - written);

            size_t product = 0;
            if (packedSize >= expected){
                /*  Chunk STORED AS IS: compression gained nothing.
                    Expanding it would return wrong data without an error. */
                std::memcpy(chunk.data(), data.data() + start, expected);
                product = expected;
            }
            else {
                product = XpressHuffmanInflate(data.data() + start, packedSize,
                                                chunk.data(), expected);
                if (product == 0){
                    RVLOG(L"[raw] WOF: chunk %zu unreadable\n", i);
                    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                }
            }

            out.write((const char*)chunk.data(), (std::streamsize)product);
            hashes.update(chunk.data(), product);
            written += product;
            if (g_progress && !label.empty() && written >= nextReport){
                g_progress(label.c_str(), written, actualSize);
                nextReport = written + (1ULL << 20);
            }
        }
        if (g_progress && !label.empty()) g_progress(label.c_str(), written, actualSize);

        hashes.finish(emp);
        if (emp){
            emp->bytes = written;
            emp->declaredSize = actualSize;
        }
        RVLOG(L"[raw] WOF: %llu bytes decompressed out of %llu declared (algorithm %lu)\n",
              (unsigned long long)written, (unsigned long long)actualSize,
              (unsigned long)algorithm);
        return (written == actualSize) ? S_OK : S_FALSE;
    }

    /*! Extracts an NTFS-compressed stream, compression unit by unit.
     *
     *  Each unit is independent and comes in three forms, which the run list is
     *  enough to tell apart:
     *    - all clusters allocated: the unit is stored AS IS, compression having
     *      gained nothing;
     *    - all sparse: zeros;
     *    - partially allocated: the present clusters carry the compressed form,
     *      to be expanded up to the unit size.
     *
     *  Not telling the first case apart is the classic mistake: expanding a unit
     *  stored as is returns wrong data without any error.
     */
    HRESULT extractCompressed(const std::vector<Run>& runs, uint64_t realSize,
                              uint64_t validDataLength,
                              uint32_t unitInClusters, std::ostream& out,
                              const std::wstring& label, RawHiveFingerprints* emp){
        const uint64_t unitSize = (uint64_t)unitInClusters * bytesPerCluster_;

        // VCN -> LCN table: units are read by position, not by run.
        std::vector<int64_t> lcnParVcn;
        for (const Run& r : runs){
            for (uint64_t k = 0; k < r.count; ++k){
                if (lcnParVcn.size() > (1ULL << 26)) break;   // guard (256 MiB of VCN)
                lcnParVcn.push_back(r.lcn < 0 ? -1 : (int64_t)(r.lcn + (int64_t)k));
            }
        }

        std::vector<uint8_t> unit((size_t)unitSize);
        std::vector<uint8_t> rawUnit((size_t)unitSize);
        std::vector<uint8_t> cl(bytesPerCluster_);
        ContentHashes hashes(emp);
        uint64_t written = 0, nextReport = 0;

        for (uint64_t vcn = 0; written < realSize; vcn += compressionUnitStep(unitInClusters)){
            // State of the unit: how many clusters allocated, and are they at the start?
            uint32_t allocated = 0;
            for (uint32_t k = 0; k < unitInClusters; ++k){
                const uint64_t v = vcn + k;
                if (v < lcnParVcn.size() && lcnParVcn[v] >= 0) ++allocated;
            }

            size_t product = 0;
            const uint64_t unitStart = vcn * bytesPerCluster_;
            // Unit entirely beyond the valid data: zeros, without reading the
            // clusters — which only hold leftovers (see extractData).
            if (allocated != 0 && unitStart >= validDataLength) allocated = 0;
            if (allocated == 0){
                // Sparse unit: zeros, without reading anything.
                std::fill(unit.begin(), unit.end(), (uint8_t)0);
                product = (size_t)unitSize;
            }
            else {
                // The allocated clusters of a unit are contiguous at its start.
                size_t read = 0;
                bool error = false;
                for (uint32_t k = 0; k < allocated; ++k){
                    const uint64_t v = vcn + k;
                    if (v >= lcnParVcn.size() || lcnParVcn[v] < 0){ error = true; break; }
                    if (!readCluster((uint64_t)lcnParVcn[v], cl.data())){ error = true; break; }
                    std::memcpy(rawUnit.data() + read, cl.data(), bytesPerCluster_);
                    read += bytesPerCluster_;
                }
                if (error) return E_FAIL;

                /* UNIT STORED AS IS only if ALL its nominal clusters are
                   allocated — including the last unit, even when the file only takes
                   part of it. A rule based on the clusters actually needed was tried
                   and dropped: NTFS does compress a last unit of 4,096 bytes into a
                   single cluster (LZNT1 header 0xB4C2 seen in
                   Microsoft-Windows-WMI-Activity%4Operational.evtx), and copying it raw
                   returned wrong data WITHOUT ANY ERROR — caught by the CRC32 of the
                   EVTX chunks. It is ntfs-3g's criterion. The 19 failures that had
                   prompted it actually came from clusters beyond the valid data. */
                if (allocated == unitInClusters){
                    std::memcpy(unit.data(), rawUnit.data(), (size_t)unitSize);
                    product = (size_t)unitSize;
                }
                else {
                    product = Lznt1Inflate(rawUnit.data(), read, unit.data(), (size_t)unitSize);
                    if (product == 0){
                        RVLOG(L"[raw] LZNT1: unit at VCN %llu unreadable\n",
                              (unsigned long long)vcn);
                        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                    }
                    // An incomplete expanded unit is only normal at the end of the file;
                    // elsewhere, it is a damaged stream.
                    if (product < unitSize && written + product < realSize)
                        std::fill(unit.begin() + product, unit.end(), (uint8_t)0);
                }
            }

            // Unit straddling the valid data limit: zeros beyond it.
            if (validDataLength < unitStart + unitSize && validDataLength > unitStart)
                std::fill(unit.begin() + (size_t)(validDataLength - unitStart), unit.end(), (uint8_t)0);

            const uint64_t rest = realSize - written;
            const size_t toWrite = (size_t)((rest < unitSize) ? rest : unitSize);
            if (toWrite > product && allocated != 0 && allocated != unitInClusters){
                // Less data than the announced size: write what we have.
                out.write((const char*)unit.data(), (std::streamsize)product);
                hashes.update(unit.data(), product);
                written += product;
            }
            else {
                out.write((const char*)unit.data(), (std::streamsize)toWrite);
                hashes.update(unit.data(), toWrite);
                written += toWrite;
            }

            if (g_progress && !label.empty() && written >= nextReport){
                g_progress(label.c_str(), written, realSize);
                nextReport = written + (1ULL << 20);
            }
            if (vcn >= lcnParVcn.size()) break;      // beyond the table
        }
        if (g_progress && !label.empty()) g_progress(label.c_str(), written, realSize);

        hashes.finish(emp);
        if (emp){
            emp->bytes = written;
            emp->declaredSize = realSize;
        }
        RVLOG(L"[raw] compressed: %llu bytes decompressed out of %llu declared\n",
              (unsigned long long)written, (unsigned long long)realSize);
        return (written == realSize) ? S_OK : S_FALSE;
    }

    //! VCN step: the compression unit size.
    static uint64_t compressionUnitStep(uint32_t unitInClusters){ return unitInClusters; }

    /*! Lists a record's attributes, interpreting nothing.
     *  Used to understand a file that extraction returns empty (see raw_hive.h). */
    HRESULT listAttributes(uint64_t index, std::vector<RawAttribute>& out){
        std::vector<uint8_t> rec;
        if (!readMftRecord(index, rec)) return E_FAIL;
        if (rec.size() < 0x30) return E_FAIL;

        size_t off = rd16(rec.data() + 0x14);        // first attribute
        while (off + 4 <= rec.size()){
            const uint32_t type = rd32(rec.data() + off);
            if (type == 0xFFFFFFFFu) break;          // end of the list
            if (off + 16 > rec.size()) break;
            const uint32_t size = rd32(rec.data() + off + 4);
            if (size < 16 || off + size > rec.size()) break;

            RawAttribute a;
            a.type = type;
            a.resident = (rec[off + 8] == 0);
            const uint8_t nameLength = rec[off + 9];
            const uint16_t nameOffset  = rd16(rec.data() + off + 10);
            a.flags = rd16(rec.data() + off + 12);
            for (uint8_t k = 0; k < nameLength; ++k){
                const size_t p = off + nameOffset + 2ULL * k;
                if (p + 2 > rec.size()) break;
                a.name.push_back((wchar_t)rd16(rec.data() + p));
            }
            if (a.resident){
                a.actualSize = rd32(rec.data() + off + 0x10);
                const uint16_t contentOffset = rd16(rec.data() + off + 0x14);
                const size_t start = off + contentOffset;
                const size_t n = (a.actualSize < 64) ? (size_t)a.actualSize : 64;
                for (size_t k = 0; k < n && start + k < rec.size(); ++k)
                    a.preview.push_back(rec[start + k]);
                // A reparse point carries its tag at the start of its content.
                if (type == 0xC0 && a.preview.size() >= 4)
                    a.tagReparse = rd32(a.preview.data());
            }
            else if (off + 0x40 <= rec.size()){
                a.actualSize      = rd64(rec.data() + off + 0x30);
                a.initializedSize = rd64(rec.data() + off + 0x38);
            }

            out.push_back(std::move(a));
            off += size;
        }
        return ERROR_SUCCESS;
    }

    HRESULT extractData(uint64_t index, const std::wstring& outFile,
                        const std::wstring& label = std::wstring(),
                        RawHiveFingerprints* emp = nullptr,
                        std::streambuf* observer = nullptr){
        std::vector<uint8_t> rec;
        if (!readMftRecord(index, rec)) return E_FAIL;

        if (emp){
            emp->mftEntry = index;
            /* Timestamp of THIS exhibit, not of the batch: that is what the
               exhibit store must date. Taken before the read, so never later than
               what it dates. */
            FILETIME now = { 0, 0 };
            GetSystemTimeAsFileTime(&now);
            emp->extractedUtc = ((uint64_t)now.dwHighDateTime << 32)
                            | now.dwLowDateTime;
            /* $STANDARD_INFORMATION (type 0x10): the four timestamps of the
               SOURCE file. They describe the target, not the copy — and that is
               precisely what attests that a raw read changes no date: the copy
               will carry the current dates. */
            const uint8_t* si = findAttr(rec, 0x10, false);
            if (si && si[8] == 0){                        // always resident
                const uint8_t* d = si + rd16(si + 0x14);
                emp->creeUtc       = rd64(d + 0x00);
                emp->modifiedUtc    = rd64(d + 0x08);
                emp->mftModifiedUtc = rd64(d + 0x10);
                emp->accedeUtc     = rd64(d + 0x18);
            }
        }

        std::vector<Run> runs;
        uint64_t realSize = 0;
        bool resident = false;
        const uint8_t* residentData = nullptr;
        uint32_t residentLen = 0;
        uint32_t compressionUnit = 0;     // in clusters; 0 = data not compressed
        /*  VALID DATA LENGTH ("valid data length", offset 0x38).
            A file can be grown without its new clusters being written: NTFS
            allocates them without erasing them, and returns ZEROS for everything
            beyond that length. The disk itself still holds the leftovers of the
            files that used those clusters.
            Ignoring this field copied those leftovers as content: seen on the
            event logs, preallocated to their maximum size — x64 machine code of a
            vanished DLL in place of empty chunks in
            Microsoft-Windows-CodeIntegrity%4Operational.evtx, 135,168 valid bytes
            out of 1,052,672. The content was therefore NOT the file's, and its
            fingerprint differed from that of any ordinary acquisition. */
        uint64_t validDataLength = UINT64_MAX;

        const uint8_t* a = findAttr(rec, 0x80 /*$DATA*/);
        if (a){
            if (a[8] == 0){                       // resident: the data is inside the record
                resident = true;
                residentLen  = rd32(a + 0x10);
                residentData = a + rd16(a + 0x14);
            }
            else {
                /*  NTFS COMPRESSION. Windows 11 turns it on for
                    \Windows\System32\winevt\Logs: refusing it made every event log
                    unusable (400 out of 404 measured on a Windows 11 VM). The attribute
                    declares the compression unit size as a power of two of clusters;
                    the format's details are in lznt1.h. */
                if (rd16(a + 0x0C) & 0x0001)
                    compressionUnit = (uint32_t)1u << rd16(a + 0x22);
                realSize = rd64(a + 0x30);
                validDataLength = rd64(a + 0x38);
                runs = decodeRuns(a + rd16(a + 0x20), a + rd32(a + 0x04));

            }
        }
        else if (!collectRunsFromAttributeList(rec, runs, realSize, 0x80,
                                               &compressionUnit, &validDataLength)){
            RVLOG(L"[raw] no usable $DATA attribute\n");
            return E_FAIL;
        }
        if (validDataLength > realSize) validDataLength = realSize;
        if (emp && !resident) emp->validDataLength = validDataLength;

        // Empty output: fingerprints only, nothing is written (see NullBuffer).
        NullBuffer null_;
        std::ostream nullOutput(&null_);
        std::ofstream file;
        if (!outFile.empty()){
            file.open(std::filesystem::path(outFile), std::ios::binary | std::ios::trunc);
            if (!file){ RVLOG(L"[raw] cannot open the output\n"); return E_FAIL; }
        }
        // Empty output with an observer: the content is handed to it, nothing is written.
        std::ostream observedOutput(observer);
        std::ostream& out = !outFile.empty() ? static_cast<std::ostream&>(file)
                          : observer ? observedOutput : nullOutput;

        if (resident){
            out.write((const char*)residentData, residentLen);
            ContentHashes hashes(emp);
            hashes.update(residentData, residentLen);
            hashes.finish(emp);
            if (emp){
                emp->bytes = residentLen;
                emp->declaredSize = residentLen;
                emp->resident = true;
            }
            return S_OK;
        }

        /*  EXTRACTING A COMPRESSED STREAM. The file is cut into independent
            compression units; each is either fully allocated (stored as is),
            fully sparse (zeros), or partially allocated — its present clusters
            then carry the compressed form, to be expanded up to the unit size. */
        /*  WOF ("Compact OS") FIRST, and detection covers the WHOLE file, not
            just the base record: a file whose attributes are split into an
            $ATTRIBUTE_LIST has neither its reparse point nor its named stream in
            the base record. Its $DATA is sparse, so neither plain reading nor NTFS
            decompression would return anything but zeros (see xpress.h). */
        {
            WofContext wof;
            if (resolveWof(rec, wof) && wof.present){
                const HRESULT h = extractWof(wof, realSize, out, label, emp);
                if (SUCCEEDED(h)) return h;
                // Unsupported (LZX): a file of zeros is not written.
                RVLOG(L"[raw] WOF : extraction impossible\n");
                return h;
            }
        }

        if (compressionUnit > 1){
            const HRESULT h = extractCompressed(runs, realSize, validDataLength,
                                                compressionUnit, out, label, emp);
            return h;
        }

        const uint64_t batchClusters = std::max<uint64_t>(1, READ_BATCH / bytesPerCluster_);
        std::vector<uint8_t> batch((size_t)(batchClusters * bytesPerCluster_));
        uint64_t written = 0;
        uint64_t nextReport = 0;
        // Fingerprints computed on the bytes already passing through memory:
        // avoids reading the copy back from the collection medium, and they
        // bear on what was read from the VOLUME, not on a re-read.
        ContentHashes hashes(emp);
        for (const Run& r : runs){
            for (uint64_t k = 0; k < r.count && written < realSize;){
                uint64_t clusters = std::min<uint64_t>(batchClusters, r.count - k);
                const size_t batchBytes = (size_t)(clusters * bytesPerCluster_);
                // Sparse, or beyond the valid data: zeros, without reading.
                if (r.lcn < 0 || written >= validDataLength) std::fill(batch.begin(), batch.begin() + batchBytes, (uint8_t)0);
                else {
                    // Not past the valid data: the clusters beyond it hold leftovers.
                    const uint64_t valid = validDataLength - written;
                    clusters = std::min<uint64_t>(clusters, (valid + bytesPerCluster_ - 1) / bytesPerCluster_);
                    const size_t readBytesCount = (size_t)(clusters * bytesPerCluster_);
                    if (!readClusters((uint64_t)r.lcn + k, readBytesCount, batch.data())) return E_FAIL;
                    if (valid < readBytesCount)
                        std::fill(batch.begin() + (size_t)valid, batch.begin() + readBytesCount, (uint8_t)0);
                }
                const uint64_t chunk = std::min<uint64_t>(clusters * bytesPerCluster_, realSize - written);
                out.write((const char*)batch.data(), (std::streamsize)chunk);
                hashes.update(batch.data(), (size_t)chunk);
                written += chunk;
                k += clusters;
                // Report every 1 MiB: often enough to show progress, rarely enough not
                // to cost in display.
                if (g_progress && !label.empty() && written >= nextReport){
                    g_progress(label.c_str(), written, realSize);
                    nextReport = written + (1ULL << 20);
                }
            }
        }
        if (g_progress && !label.empty()) g_progress(label.c_str(), written, realSize);
        hashes.finish(emp);
        if (emp){
            emp->bytes = written;
            emp->declaredSize = realSize;
        }
        RVLOG(L"[raw] extracted %llu bytes\n", (unsigned long long)written);
        return (written == realSize) ? S_OK : S_FALSE;
    }

private:
    static std::wstring lowercase(const std::wstring& s){
        std::wstring r(s);
        for (wchar_t& c : r) c = (wchar_t)towlower(c);
        return r;
    }
    bool cacheActive_ = false;
    std::map<uint64_t, std::unordered_map<std::wstring, uint64_t>> cacheRep_;
    HANDLE   h_ = INVALID_HANDLE_VALUE;
    uint32_t bytesPerSector_ = 0, sectorsPerCluster_ = 0, bytesPerCluster_ = 0, bytesPerRecord_ = 0;
    uint64_t mftLcn_ = 0;
    std::vector<Run> mftRuns_;

    // sector-aligned raw read (volume handles require it)
    bool readBytes(uint64_t off, void* dst, uint32_t len){
        uint32_t sec = bytesPerSector_ ? bytesPerSector_ : 512;
        uint64_t start = off - (off % sec);
        uint64_t end   = off + len;
        if (end % sec) end += sec - (end % sec);
        uint32_t total = (uint32_t)(end - start);
        std::vector<uint8_t> tmp(total);
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)start;
        if (!SetFilePointerEx(h_, li, NULL, FILE_BEGIN)) return false;
        uint32_t done = 0;
        while (done < total){
            DWORD got = 0;
            if (!ReadFile(h_, tmp.data() + done, total - done, &got, NULL) || got == 0) return false;
            done += got;
        }
        memcpy(dst, tmp.data() + (off - start), len);
        return true;
    }
    bool readCluster(uint64_t lcn, void* dst){
        return readBytes(lcn * bytesPerCluster_, dst, bytesPerCluster_);
    }

    //! Largest single read of contiguous clusters.
    static const uint32_t READ_BATCH = 1u << 20;

    /*! Reads `length` bytes from cluster `lcn` on, in large requests.
     *
     *  WHY. One ReadFile per 4 KiB cluster — with its seek, its allocation and
     *  its copy — cost some 4.5 million system calls to read the executables
     *  of a Windows 11 volume, at 15 MB/s. The clusters of a run are
     *  contiguous on the disk: they are read in requests of up to 1 MiB.
     *  @param lcn first cluster
     *  @param length bytes to read
     *  @param dst destination, `length` bytes
     *  @return false on a read error */
    bool readClusters(uint64_t lcn, uint64_t length, uint8_t* dst){
        for (uint64_t done = 0; done < length;){
            const uint32_t n = (uint32_t)std::min<uint64_t>(READ_BATCH, length - done);
            if (!readBytes(lcn * bytesPerCluster_ + done, dst + done, n)) return false;
            done += n;
        }
        return true;
    }

    // Reads `len` bytes at virtual offset `fileOff` of a file described by `runs`.
    bool readVirtual(const std::vector<Run>& runs, uint64_t fileOff, uint32_t len, uint8_t* dst){
        uint32_t got = 0;
        while (got < len){
            uint64_t cur   = fileOff + got;
            uint64_t vcn   = cur / bytesPerCluster_;
            uint32_t inClu = (uint32_t)(cur % bytesPerCluster_);
            uint64_t vbase = 0; int64_t lcn = -2;
            uint64_t contiguous = 0;                 // clusters left in the run from `vcn`
            for (auto& r : runs){
                if (vcn < vbase + r.count){
                    lcn = (r.lcn < 0) ? -1 : (int64_t)((uint64_t)r.lcn + (vcn - vbase));
                    contiguous = vbase + r.count - vcn;
                    break;
                }
                vbase += r.count;
            }
            if (lcn == -2) return false; // outside the runs
            // As far as the run goes, in one request (see readClusters).
            const uint64_t reachable = contiguous * bytesPerCluster_ - inClu;
            const uint32_t chunk = (uint32_t)std::min<uint64_t>(std::min<uint64_t>(len - got, reachable), READ_BATCH);
            if (lcn < 0) memset(dst + got, 0, chunk);
            else if (!readBytes((uint64_t)lcn * bytesPerCluster_ + inClu, dst + got, chunk)) return false;
            got += chunk;
        }
        return true;
    }


    // Bootstrap: reads record #0 ($MFT) to get its own runs.
    bool bootstrapMft(){
        std::vector<uint8_t> rec(bytesPerRecord_);
        if (!readBytes(mftLcn_ * bytesPerCluster_, rec.data(), bytesPerRecord_)) return false;
        if (memcmp(rec.data(), "FILE", 4) != 0){ RVLOG(L"[raw] MFT#0: FILE signature absent\n"); return false; }
        if (!applyNtfsFixup(rec.data(), bytesPerRecord_)){ RVLOG(L"[raw] MFT#0: torn record (fixups)\n"); return false; }
        const uint8_t* a = findAttr(rec, 0x80);
        if (!a || a[8] == 0){ RVLOG(L"[raw] $MFT $DATA not found / resident\n"); return false; }
        uint16_t runsOff = rd16(a + 0x20);
        uint32_t attrLen = rd32(a + 0x04);
        mftRuns_ = decodeRuns(a + runsOff, a + attrLen);
        RVLOG(L"[raw] $MFT: %u runs, 1er lcn=%lld count=%llu\n", (unsigned)mftRuns_.size(),
              mftRuns_.empty()?0:(long long)mftRuns_[0].lcn, mftRuns_.empty()?0ULL:(unsigned long long)mftRuns_[0].count);
        return !mftRuns_.empty();
    }

    // Reads and un-fixes the MFT record of the given index.
    bool readMftRecord(uint64_t index, std::vector<uint8_t>& rec){
        rec.assign(bytesPerRecord_, 0);
        if (!readVirtual(mftRuns_, index * bytesPerRecord_, bytesPerRecord_, rec.data())){
            RVLOG(L"[raw] MFT#%llu: readVirtual failed\n", (unsigned long long)index); return false; }
        if (memcmp(rec.data(), "FILE", 4) != 0){
            RVLOG(L"[raw] MFT#%llu: magic FILE absent (%02x%02x%02x%02x)\n",
                  (unsigned long long)index, rec[0], rec[1], rec[2], rec[3]); return false; }
        if (!applyNtfsFixup(rec.data(), bytesPerRecord_)){
            RVLOG(L"[raw] MFT#%llu: torn record (fixups): not used\n", (unsigned long long)index);
            return false;
        }
        return true;
    }

    // Finds the first attribute of the given type in a record.
    // unnamedOnly: only accepts the UNNAMED attribute. True for $DATA (we want
    // the main stream, not an ADS) but FALSE for directory indexes:
    // $INDEX_ROOT / $INDEX_ALLOCATION always carry the name "$I30".
    /*! Attribute of a given type carrying a precise NAME.
     *  Named data streams are not a curiosity: that is where WOF stores the real
     *  content of a system binary (see xpress.h). */
    static const uint8_t* findNamedAttr(const std::vector<uint8_t>& rec, uint32_t type,
                                        const wchar_t* wantedName){
        const size_t wantedLength = wcslen(wantedName);
        uint16_t off = rd16(rec.data() + 0x14);
        const uint8_t* p = rec.data() + off;
        const uint8_t* end = rec.data() + rec.size();
        while (p + 16 <= end){
            const uint32_t t = rd32(p);
            if (t == 0xFFFFFFFF) break;
            const uint32_t len = rd32(p + 4);
            if (len < 16 || p + len > end) break;
            if (t == type && p[9] == wantedLength){
                const uint16_t nameOffset = rd16(p + 10);
                bool same = true;
                for (size_t k = 0; k < wantedLength; ++k){
                    if (p + nameOffset + 2 * k + 2 > end){ same = false; break; }
                    if ((wchar_t)rd16(p + nameOffset + 2 * k) != wantedName[k]){ same = false; break; }
                }
                if (same) return p;
            }
            p += len;
        }
        return nullptr;
    }

    static const uint8_t* findAttr(const std::vector<uint8_t>& rec, uint32_t type,
                                   bool unnamedOnly = true){
        uint16_t off = rd16(rec.data() + 0x14);
        const uint8_t* p = rec.data() + off;
        const uint8_t* end = rec.data() + rec.size();
        while (p + 8 <= end){
            uint32_t t = rd32(p);
            if (t == 0xFFFFFFFF) break;
            uint32_t len = rd32(p + 4);
            if (len < 8 || p + len > end) break;
            if (t == type && (!unnamedOnly || p[9] == 0)) return p;
            p += len;
        }
        return nullptr;
    }

    // Parses the entries of an index node (base = start of the node header).
    /* Decodes the entries of a directory index node.
       Structure of the $FILE_NAME key (fn = entry + 0x10): attributes at 0x38,
       real size at 0x30, name length at 0x40, namespace at 0x41, then the name
       in UTF-16.
       Namespace 2 is an 8.3 short name: NTFS often stores TWO entries for one
       file (one DOS, one Win32). Pure DOS names are discarded, otherwise each
       file would be extracted twice, under two names. */
    static void parseIndexNode(const uint8_t* nodeHdr, const uint8_t* limit,
                               std::vector<RawDirEntry>& out){
        uint32_t firstOff = rd32(nodeHdr);
        const uint8_t* e = nodeHdr + firstOff;
        while (e + 0x10 <= limit){
            uint64_t ref   = rd64(e) & 0x0000FFFFFFFFFFFFULL;
            uint16_t eLen  = rd16(e + 8);
            uint16_t flags = rd16(e + 0x0C);
            if (!(flags & 0x02)){ // not the last entry -> has a $FILE_NAME key
                const uint8_t* fn = e + 0x10;
                if (fn + 0x42 <= limit){
                    uint32_t fileAttrs = rd32(fn + 0x38);
                    uint64_t realSize  = rd64(fn + 0x30);
                    uint8_t  nameLen   = fn[0x40];
                    uint8_t  nameSpace = fn[0x41];
                    const uint8_t* nm  = fn + 0x42;
                    if (nameSpace != 2 && nm + 2 * nameLen <= limit){   // 2 = 8.3 short name
                        RawDirEntry entry;
                        entry.name.resize(nameLen);
                        for (uint8_t k = 0; k < nameLen; ++k) entry.name[k] = (wchar_t)rd16(nm + 2 * k);
                        entry.mftIndex    = ref;
                        entry.isDirectory = (fileAttrs & 0x10000000u) != 0; // FILE_ATTRIBUTE_DIRECTORY
                        entry.size        = entry.isDirectory ? 0 : realSize;
                        out.push_back(std::move(entry));
                    }
                }
            }
            if (flags & 0x02) break;      // last entry
            if (eLen == 0) break;
            e += eLen;
        }
    }

public:
    // Lists a directory's entries (name, MFT index, type, size).
    // Public: also used by ListDirectoryRaw / ExtractDirectoryRaw.
    bool listDir(uint64_t dirIndex, std::vector<RawDirEntry>& out){
        std::vector<uint8_t> rec;
        if (!readMftRecord(dirIndex, rec)){
            RVLOG(L"[raw] listDir(%llu): record unreadable\n", (unsigned long long)dirIndex);
            return false; }

        // $INDEX_ROOT (0x90) — resident, always present, possibly in an extension record
        std::vector<uint8_t> extension;
        const uint8_t* ir = findResidentAttr(rec, 0x90, extension);   // "$I30"
        if (!ir){ RVLOG(L"[raw] listDir(%llu): resident $INDEX_ROOT absent\n", (unsigned long long)dirIndex); return false; }
        uint32_t irValLen = rd32(ir + 0x10); uint16_t irValOff = rd16(ir + 0x14);
        // The value must hold the index root header (0x10) and the node header (0x10).
        if (irValLen < 0x20 || (uint64_t)irValOff + irValLen > rd32(ir + 4)){
            RVLOG(L"[raw] listDir(%llu): $INDEX_ROOT inconsistent\n", (unsigned long long)dirIndex);
            return false;
        }
        const uint8_t* val = ir + irValOff;
        uint32_t idxBlockSize = rd32(val + 8);
        const uint8_t* nodeHdr = val + 0x10;
        uint32_t usedSize = rd32(nodeHdr + 4);
        const uint8_t* irEnd = val + irValLen;
        const uint8_t* limit = nodeHdr + usedSize;
        if (limit > irEnd) limit = irEnd;
        parseIndexNode(nodeHdr, limit, out);
        const size_t fromRoot = out.size();

        // $INDEX_ALLOCATION (0xA0) — non-resident, present if the index overflows
        const uint8_t* ia = findAttr(rec, 0xA0, false);   // "$I30"
        // Only an index with blocks has a $BITMAP: read when $INDEX_ALLOCATION is.
        std::vector<uint8_t> bits;
        auto bitmap = [&]() -> const std::vector<uint8_t>* {
            if (indexBitmap(rec, bits)) return &bits;
            RVLOG(L"[raw] listDir(%llu): $BITMAP unreadable, every index block read\n",
                  (unsigned long long)dirIndex);
            return nullptr;
        };

        /* If the attribute is not in the base record, it can be SPLIT through
           $ATTRIBUTE_LIST — the same mechanism as for the SOFTWARE hive's $DATA.
           Seen on a very busy `Recent` folder: the index overflowed but
           $INDEX_ALLOCATION could not be found here, so listDir returned
           "0 entries" on a full folder. */
        if (!ia && idxBlockSize){
            std::vector<Run> splitRuns;
            uint64_t splitSize = 0;
            if (collectRunsFromAttributeList(rec, splitRuns, splitSize, 0xA0)
                && !splitRuns.empty()){
                RVLOG(L"[raw] listDir(%llu): $INDEX_ALLOCATION via $ATTRIBUTE_LIST\n",
                      (unsigned long long)dirIndex);
                readIndexBlocks(splitRuns, splitSize, idxBlockSize, bitmap(), out);
                return true;
            }
        }
        /* A large directory keeps in $INDEX_ROOT only a leaf node pointing to
           the index blocks: ALL its entries then come from $INDEX_ALLOCATION.
           Hence the separate trace of both sources — without it, "0 entries"
           does not say which of the two failed. */
        RVLOG(L"[raw] listDir(%llu): %llu entry/entries from $INDEX_ROOT, "
              L"$INDEX_ALLOCATION %ls (blockSize=%u)\n",
              (unsigned long long)dirIndex, (unsigned long long)fromRoot,
              ia ? (ia[8] != 0 ? L"non-resident" : L"RESIDENT (unexpected)") : L"absent",
              idxBlockSize);
        if (ia && ia[8] != 0 && idxBlockSize){
            uint64_t realSize = rd64(ia + 0x30);
            std::vector<Run> runs = decodeRuns(ia + rd16(ia + 0x20), ia + rd32(ia + 0x04));
            readIndexBlocks(runs, realSize, idxBlockSize, bitmap(), out);
        }
        return true;
    }

    /*! Allocation bitmap of a directory's index ($BITMAP "$I30", type 0xB0):
     *  bit n says whether index block n is in use.
     *
     *  WHY IT IS READ. A block the directory released stays on the disk, and
     *  can keep its INDX signature and its former entries. Read as if in use,
     *  it would list STALE entries: names of deleted files, pointing to $MFT
     *  records reused since by other files. The bitmap is resident (in the
     *  base record or an extension record) or non-resident for a large index.
     *  @param rec the directory's base record
     *  @param bits receives the bitmap
     *  @return false if it could not be found or read */
    bool indexBitmap(const std::vector<uint8_t>& rec, std::vector<uint8_t>& bits){
        const uint64_t MAX_BITMAP = 64ULL * 1024 * 1024;   // 2^29 blocks: beyond, a forged size
        std::vector<Run> runs;
        uint64_t size = 0;
        std::vector<uint8_t> extension;
        const uint8_t* b = findAttr(rec, 0xB0, false);    // "$I30"
        // Not in the base record: non-resident through the list, or resident in an extension.
        if (!b && !collectRunsFromAttributeList(rec, runs, size, 0xB0))
            b = findResidentAttr(rec, 0xB0, extension);
        if (b){
            const uint32_t attributeLength = rd32(b + 4);
            if (b[8] == 0){
                const uint32_t vlen = rd32(b + 0x10);
                const uint16_t voff = rd16(b + 0x14);
                if ((uint64_t)voff + vlen > attributeLength) return false;
                bits.assign(b + voff, b + voff + vlen);
                return true;
            }
            if (attributeLength < 0x40) return false;
            size = rd64(b + 0x30);
            runs = decodeRuns(b + rd16(b + 0x20), b + attributeLength);
        }
        if (runs.empty() || size == 0 || size > MAX_BITMAP) return false;
        bits.resize((size_t)size);
        return readVirtual(runs, 0, (uint32_t)size, bits.data());
    }

    /*! Walks the index blocks (INDX) described by `runs` and extracts their
     *  entries. Shared by both ways of reaching $INDEX_ALLOCATION: from the base
     *  record, or through $ATTRIBUTE_LIST when it is split.
     *  @param bitmap the index's allocation bitmap (see indexBitmap); nullptr if
     *         it could not be read, every block with a signature is then read */
    void readIndexBlocks(const std::vector<Run>& runs, uint64_t realSize,
                        uint32_t idxBlockSize, const std::vector<uint8_t>* bitmap,
                        std::vector<RawDirEntry>& out){
        if (!idxBlockSize) return;
        std::vector<uint8_t> blk(idxBlockSize);
        uint64_t blocksRead = 0, blocksWithoutIndx = 0, blocksTorn = 0, blocksFree = 0;
        for (uint64_t pos = 0; pos + idxBlockSize <= realSize; pos += idxBlockSize){
            const uint64_t block = pos / idxBlockSize;
            if (bitmap && (block / 8 >= bitmap->size() || !((*bitmap)[block / 8] & (1u << (block % 8))))){
                ++blocksFree;
                continue;
            }
            ++blocksRead;
            if (!readVirtual(runs, pos, idxBlockSize, blk.data())){
                RVLOG(L"[raw] index block at offset %llu unreadable\n",
                      (unsigned long long)pos);
                break;
            }
            if (memcmp(blk.data(), "INDX", 4) != 0){ ++blocksWithoutIndx; continue; }
            // A torn index block would list entries of two versions of the directory.
            if (!applyNtfsFixup(blk.data(), idxBlockSize)){ ++blocksTorn; continue; }
            const uint8_t* nh = blk.data() + 0x18;      // node header after the INDX header
            uint32_t used = rd32(nh + 4);
            const uint8_t* lim = nh + used;
            if (lim > blk.data() + idxBlockSize) lim = blk.data() + idxBlockSize;
            parseIndexNode(nh, lim, out);
        }
        RVLOG(L"[raw] index blocks: realSize=%llu, %llu free (bitmap %ls), %llu read, "
              L"%llu without INDX signature, %llu torn, total %llu entry(ies)\n",
              (unsigned long long)realSize, (unsigned long long)blocksFree,
              bitmap ? L"read" : L"UNREADABLE", (unsigned long long)blocksRead,
              (unsigned long long)blocksWithoutIndx, (unsigned long long)blocksTorn,
              (unsigned long long)out.size());
    }
};

} // namespace

/*! What the reader keeps between calls: the volumes it has opened, and the
 *  letters it has already failed to open. */
struct RawReader::Impl {
    std::map<std::wstring, std::unique_ptr<NtfsVolume>> volumes;  //!< by volume letter
    std::map<std::wstring, HRESULT> failures;    //!< volume inaccessible: do not retry
    /*! Returns the volume of a letter, opening it on first use.
     *  @param letter the volume letter ("X:")
     *  @param hr receives the result of the opening
     *  @return the volume, or nullptr if it cannot be opened */
    NtfsVolume* volume(const std::wstring& letter, HRESULT& hr);
};

RawReader::RawReader() : impl_(new Impl) {}
RawReader::~RawReader() = default;

unsigned RawReader::openVolumes() const { return (unsigned)impl_->volumes.size(); }

NtfsVolume* RawReader::Impl::volume(const std::wstring& letter, HRESULT& hr) {
    const auto failure = failures.find(letter);
    if (failure != failures.end()){ hr = failure->second; return nullptr; }
    auto it = volumes.find(letter);
    if (it == volumes.end()){
        std::unique_ptr<NtfsVolume> v(new NtfsVolume);
        hr = v->open(letter);
        if (FAILED(hr)){ failures.emplace(letter, hr); return nullptr; }
        v->enableCache();
        it = volumes.emplace(letter, std::move(v)).first;
    }
    hr = S_OK;
    return it->second.get();
}

HRESULT RawReader::list(const std::wstring& absoluteFolder, std::vector<RawDirEntry>& entries){
    entries.clear();
    if (absoluteFolder.size() < 3 || absoluteFolder[1] != L':' || absoluteFolder[2] != L'\\')
        return HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME);
    HRESULT hr;
    NtfsVolume* v = impl_->volume(std::wstring(1, (wchar_t)towupper(absoluteFolder[0])), hr);
    if (!v) return hr;
    uint64_t index = 0;
    if (!v->resolvePath(absoluteFolder.substr(2), index)) return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    return v->listDir(index, entries) ? S_OK : E_FAIL;
}

HRESULT RawReader::read(const std::wstring& absolutePath, const std::wstring& output,
                          RawHiveExtraction& line, std::streambuf* observer){
    line.volumePath = absolutePath;
    line.outputPath = output;
    line.result = HRESULT_FROM_WIN32(ERROR_BAD_PATHNAME);
    if (absolutePath.size() < 3 || absolutePath[1] != L':' || absolutePath[2] != L'\\')
        return line.result;
    HRESULT hr;
    NtfsVolume* v = impl_->volume(std::wstring(1, (wchar_t)towupper(absolutePath[0])), hr);
    if (!v) return line.result = hr;
    uint64_t index = 0;
    if (!v->resolvePath(absolutePath.substr(2), index))
        return line.result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    return line.result = v->extractData(index, output, std::wstring(), &line.fingerprints, observer);
}

void RawHiveSetVerbose(bool on){ g_verbose = on; }

bool applyNtfsFixup(uint8_t* record, size_t size){
    const size_t STRIDE = 512;        // fixed by NTFS, not the volume's sector size
    if (!record || size < STRIDE || size % STRIDE) return false;
    const uint16_t arrayOffset = rd16(record + 4), arrayCount = rd16(record + 6);
    /* One entry for the sequence number, then one per stride. The array lies
       in the first stride, after the signature and its own two fields, at an
       even offset (the checks of ntfs3's ntfs_fix_post_read). */
    if (arrayOffset < 8 || (arrayOffset & 1) || arrayCount != size / STRIDE + 1
        || arrayOffset + 2u * arrayCount > STRIDE) return false;
    const uint8_t* array = record + arrayOffset;
    const uint16_t sequence = rd16(array);
    // Every stride checked BEFORE anything is written: a torn record stays as read.
    for (size_t i = 1; i < arrayCount; ++i)
        if (rd16(record + i * STRIDE - 2) != sequence) return false;
    for (size_t i = 1; i < arrayCount; ++i){
        uint8_t* end = record + i * STRIDE - 2;
        end[0] = array[2 * i];
        end[1] = array[2 * i + 1];
    }
    return true;
}
void RawHiveSetProgress(RawHiveProgressFn fn){ g_progress = fn; }

HRESULT ExtractFilesRaw(const std::wstring& volumeLetter,
                        const std::vector<std::pair<std::wstring, std::wstring>>& items,
                        std::vector<HRESULT>* perItem,
                        std::vector<RawHiveExtraction>* reading){
    NtfsVolume vol;                       // volume opened ONCE for all the items
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)){ if (perItem) perItem->assign(items.size(), hr); return hr; }
    HRESULT overall = S_OK;
    for (const auto& it : items){
        uint64_t index = 0; HRESULT h;
        RawHiveExtraction line;
        line.volumePath = volumeLetter + L":" + it.first;
        line.outputPath = it.second;
        if (!vol.resolvePath(it.first, index)) h = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        else h = vol.extractData(index, it.second, it.first,
                                 reading ? &line.fingerprints : nullptr);
        line.result = h;
        if (perItem) perItem->push_back(h);
        // A FAILURE IS RECORDED TOO: an exhibit missing from the manifest would
        // read as one never looked for.
        if (reading) reading->push_back(std::move(line));
        if (FAILED(h)) overall = S_FALSE;
    }
    return overall;
}

HRESULT ListAttributesRaw(const std::wstring& volumeLetter,
                          const std::wstring& pathOnVolume,
                          std::vector<RawAttribute>& out){
    out.clear();
    NtfsVolume vol;
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)) return hr;
    uint64_t index = 0;
    if (!vol.resolvePath(pathOnVolume, index))
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    return vol.listAttributes(index, out);
}

HRESULT ExtractFileRaw(const std::wstring& volumeLetter,
                       const std::wstring& filePathOnVolume,
                       const std::wstring& outFile){
    std::vector<HRESULT> r;
    ExtractFilesRaw(volumeLetter, {{filePathOnVolume, outFile}}, &r);
    return r.empty() ? E_FAIL : r[0];
}

/* Compares two extensions, case-insensitively (ASCII). */
static bool extensionMatches(const std::wstring& name, const std::vector<std::wstring>& extensions){
    if (extensions.empty()) return true;              // no filter: everything is kept
    const size_t point = name.rfind(L'.');
    if (point == std::wstring::npos) return false;
    const std::wstring ext = name.substr(point);
    for (const std::wstring& expected : extensions)
        if (iequals(ext, expected)) return true;
    return false;
}

HRESULT ListDirectoryRaw(const std::wstring& volumeLetter,
                         const std::wstring& dirPathOnVolume,
                         std::vector<RawDirEntry>& out){
    out.clear();
    NtfsVolume vol;
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)) return hr;

    uint64_t index = 0;
    if (!vol.resolvePath(dirPathOnVolume, index))
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    if (!vol.listDir(index, out))
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    return ERROR_SUCCESS;
}

HRESULT ExtractDirectoryRaw(const std::wstring& volumeLetter,
                            const std::wstring& dirPathOnVolume,
                            const std::wstring& outDir,
                            const std::vector<std::wstring>& extensions,
                            size_t* extracted,
                            std::wstring* diagnostic,
                            std::vector<RawHiveExtraction>* reading){
    if (extracted) *extracted = 0;
    if (diagnostic) diagnostic->clear();

    NtfsVolume vol;                       // volume opened ONCE for the whole directory
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)){
        if (diagnostic) *diagnostic = L"volume inaccessible";
        return hr;
    }

    uint64_t dirIndex = 0;
    if (!vol.resolvePath(dirPathOnVolume, dirIndex)){
        // Missing directory: the nominal case during a collection, not an error.
        RVLOG(L"[raw] directory absent: %ls\n", dirPathOnVolume.c_str());
        if (diagnostic) *diagnostic = L"path not resolved (directory absent?)";
        return ERROR_SUCCESS;
    }

    std::vector<RawDirEntry> entries;
    if (!vol.listDir(dirIndex, entries)){
        RVLOG(L"[raw] enumeration impossible: %ls\n", dirPathOnVolume.c_str());
        if (diagnostic) *diagnostic = L"index enumeration impossible";
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(outDir), ec);

    size_t files = 0, kept = 0, failures = 0;
    HRESULT overall = ERROR_SUCCESS;
    for (const RawDirEntry& e : entries){
        if (e.isDirectory) continue;                       // not recursive
        if (e.name == L"." || e.name == L"..") continue;
        ++files;
        if (!extensionMatches(e.name, extensions)) continue;
        ++kept;

        const std::wstring target = outDir + L"\\" + e.name;
        RawHiveExtraction line;
        line.volumePath = volumeLetter + L":" + dirPathOnVolume + L"\\" + e.name;
        line.outputPath = target;
        HRESULT h = vol.extractData(e.mftIndex, target, std::wstring(),
                                    reading ? &line.fingerprints : nullptr);
        line.result = h;
        if (reading) reading->push_back(std::move(line));
        if (FAILED(h)){
            RVLOG(L"[raw] extraction failed: %ls\n", e.name.c_str());
            ++failures;
            overall = S_FALSE;
        }
        else if (extracted) ++*extracted;
    }

    /* The details tell apart three causes of a zero count: empty index,
       too strict an extension filter, or extraction failures. */
    if (diagnostic){
        *diagnostic = std::to_wstring(entries.size()) + L" entry(ies), "
                    + std::to_wstring(files) + L" file(s), "
                    + std::to_wstring(kept) + L" kept";
        if (failures) *diagnostic += L", " + std::to_wstring(failures) + L" failure(s)";
    }
    return overall;
}

/* Recursive extraction: the volume is opened ONCE for the whole tree, unlike
   repeated calls to ExtractDirectoryRaw, which would reopen it for each
   subdirectory. */
namespace {

HRESULT extractTree(NtfsVolume& vol, uint64_t dirIndex,
                             const std::wstring& volumePath,
                             const std::wstring& outDir,
                             const std::vector<std::wstring>& extensions,
                             size_t* extracted, unsigned depthLeft,
                             const std::wstring& volumeLetter,
                             std::vector<RawHiveExtraction>* reading){
    std::vector<RawDirEntry> entries;
    if (!vol.listDir(dirIndex, entries)){
        RVLOG(L"[raw] tree: index unreadable for %ls\n", volumePath.c_str());
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(outDir), ec);

    HRESULT global = ERROR_SUCCESS;
    for (const RawDirEntry& e : entries){
        if (e.name == L"." || e.name == L"..") continue;

        if (e.isDirectory){
            if (depthLeft == 0){
                RVLOG(L"[raw] tree: maximum depth reached at %ls\n", e.name.c_str());
                continue;
            }
            const HRESULT h = extractTree(
                vol, e.mftIndex, volumePath + L"\\" + e.name,
                outDir + L"\\" + e.name, extensions, extracted, depthLeft - 1,
                volumeLetter, reading);
            if (h == S_FALSE) global = S_FALSE;
            continue;
        }
        if (!extensionMatches(e.name, extensions)) continue;

        RawHiveExtraction line;
        line.volumePath = volumeLetter + L":" + volumePath + L"\\" + e.name;
        line.outputPath = outDir + L"\\" + e.name;
        // Fingerprints are ALWAYS computed: they cost nothing beyond the read
        // already made, and without them the exhibit is unidentified.
        line.result = vol.extractData(e.mftIndex, line.outputPath,
                                         volumePath + L"\\" + e.name, &line.fingerprints);
        if (FAILED(line.result)){
            RVLOG(L"[raw] tree: extraction failed %ls\n", e.name.c_str());
            global = S_FALSE;
        }
        else if (extracted) ++*extracted;
        if (reading) reading->push_back(std::move(line));
    }
    return global;
}

} // namespace

HRESULT ExtractDirectoryTreeRaw(const std::wstring& volumeLetter,
                                const std::wstring& dirPathOnVolume,
                                const std::wstring& outDir,
                                const std::vector<std::wstring>& extensions,
                                size_t* extracted,
                                unsigned maxDepth,
                                std::vector<RawHiveExtraction>* reading){
    if (extracted) *extracted = 0;

    NtfsVolume vol;
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)) return hr;

    uint64_t dirIndex = 0;
    if (!vol.resolvePath(dirPathOnVolume, dirIndex)){
        // Missing directory: the nominal case during a collection, not an error.
        RVLOG(L"[raw] tree: directory absent %ls\n", dirPathOnVolume.c_str());
        return ERROR_SUCCESS;
    }
    return extractTree(vol, dirIndex, dirPathOnVolume, outDir,
                                extensions, extracted, maxDepth,
                                volumeLetter, reading);
}
