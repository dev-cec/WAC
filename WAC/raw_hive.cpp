/*  raw_hive.cpp — see raw_hive.h.
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
            RVLOG(L"[raw] open %ls: erreur %lu (admin requis ?)\n", path.c_str(), e);
            return HRESULT_FROM_WIN32(e);
        }
        uint8_t vbr[512];
        if (!readBytes(0, vbr, 512)) return E_FAIL;
        if (memcmp(vbr + 3, "NTFS    ", 8) != 0){
            RVLOG(L"[raw] signature NTFS absente\n"); return E_FAIL;
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
            RVLOG(L"[raw] recherche \"%ls\" dans MFT#%llu\n", comp.c_str(), (unsigned long long)cur);
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
            if (!found){ RVLOG(L"[raw] composant introuvable: %ls\n", comp.c_str()); return false; }
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
       @param tailleValide if not null, receives the valid data length, read at
       the same place (see extractData). */
    bool collectRunsFromAttributeList(const std::vector<uint8_t>& rec,
                                      std::vector<Run>& runs, uint64_t& realSize,
                                      uint32_t wantedType = 0x80,
                                      uint32_t* compressionUnit = nullptr,
                                      uint64_t* tailleValide = nullptr){
        const uint8_t* al = findAttr(rec, 0x20, false);
        if (!al) return false;

        // List content: resident, or to be read through its own runs.
        std::vector<uint8_t> content;
        if (al[8] == 0){
            const uint32_t vlen = rd32(al + 0x10);
            const uint16_t voff = rd16(al + 0x14);
            content.assign(al + voff, al + voff + vlen);
        }
        else {
            const uint64_t size = rd64(al + 0x30);
            const std::vector<Run> alRuns = decodeRuns(al + rd16(al + 0x20), al + rd32(al + 0x04));
            content.resize((size_t)size);
            if (!readVirtual(alRuns, 0, (uint32_t)size, content.data())) return false;
        }

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
                            RVLOG(L"[raw] $DATA compresse NTFS dans un fragment : non supporte ici\n");
                            return false;
                        }
                        if (vcn == 0){
                            realSize = rd64(d + 0x30);
                            if (tailleValide) *tailleValide = rd64(d + 0x38);
                            if (compressionUnit)
                                *compressionUnit = (rd16(d + 0x0C) & 0x0001)
                                                  ? (uint32_t)1u << rd16(d + 0x22) : 0;
                        }
                        fragments.emplace_back(vcn, decodeRuns(d + rd16(d + 0x20), d + rd32(d + 0x04)));
                    }
                }
                else RVLOG(L"[raw] fragment MFT #%llu illisible\n", (unsigned long long)ref);
            }
            pos += len;
        }
        if (fragments.empty() || realSize == 0) return false;

        std::sort(fragments.begin(), fragments.end(),
                  [](const auto& a, const auto& b){ return a.first < b.first; });
        for (auto& f : fragments)
            runs.insert(runs.end(), f.second.begin(), f.second.end());

        RVLOG(L"[raw] $ATTRIBUTE_LIST : %llu fragment(s), %llu run(s), taille %llu\n",
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
        if (rd32(reparseContent + 12) != 2) return false;          // fournisseur non gere
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
            if (type == 0x80 && content[pos + 6] != 0){       // $DATA NOMME
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
        RVLOG(L"[raw] WOF via $ATTRIBUTE_LIST : %llu fragment(s), flux de %llu octets\n",
              (unsigned long long)fragments.size(), (unsigned long long)ctx.streamSize);
        ctx.present = true;
        return true;
    }

    //! Reads a non-resident attribute into a buffer (its runs, its real size).
    bool readNonResidentAttribute(const uint8_t* a, std::vector<uint8_t>& out){
        if (a[8] == 0) return false;                 // resident: no runs
        const uint64_t size = rd64(a + 0x30);
        if (size == 0 || size > (256ULL << 20)) return false;   // guard-fou
        const std::vector<Run> runs = decodeRuns(a + rd16(a + 0x20), a + rd32(a + 0x04));
        out.assign((size_t)size, 0);
        std::vector<uint8_t> cl(bytesPerCluster_);
        uint64_t written = 0;
        for (const Run& r : runs){
            for (uint64_t k = 0; k < r.count && written < size; ++k){
                if (r.lcn < 0) std::fill(cl.begin(), cl.end(), (uint8_t)0);
                else if (!readCluster((uint64_t)r.lcn + k, cl.data())) return false;
                const uint64_t n = std::min<uint64_t>(bytesPerCluster_, size - written);
                std::memcpy(out.data() + written, cl.data(), (size_t)n);
                written += n;
            }
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
            RVLOG(L"[raw] WOF : algorithme %lu (LZX ?) non implemente\n",
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
                RVLOG(L"[raw] WOF : flux tronque (%llu sur %llu)\n",
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
        Md5Stream stream5; Sha1Stream stream1; Sha256Stream stream256;
        uint64_t written = 0, nextReport = 0;

        for (size_t i = 0; i < nChunks; ++i){
            if (starts[i + 1] < starts[i]) return E_FAIL;              // table incoherente
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
                    RVLOG(L"[raw] WOF : morceau %zu illisible\n", i);
                    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                }
            }

            out.write((const char*)chunk.data(), (std::streamsize)product);
            if (emp){
                stream5.update(chunk.data(), product);
                stream1.update(chunk.data(), product);
                stream256.update(chunk.data(), product);
            }
            written += product;
            if (g_progress && !label.empty() && written >= nextReport){
                g_progress(label.c_str(), written, actualSize);
                nextReport = written + (1ULL << 20);
            }
        }
        if (g_progress && !label.empty()) g_progress(label.c_str(), written, actualSize);

        if (emp){
            emp->md5    = stream5.hexDigest();
            emp->sha1   = stream1.hexDigest();
            emp->sha256 = stream256.hexDigest();
            emp->bytes = written;
            emp->declaredSize = actualSize;
        }
        RVLOG(L"[raw] WOF : %llu octets detendus sur %llu annonces (algorithme %lu)\n",
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
                              uint64_t tailleValide,
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
        std::vector<uint8_t> brut((size_t)unitSize);
        std::vector<uint8_t> cl(bytesPerCluster_);
        Md5Stream stream; Sha1Stream stream1; Sha256Stream stream256;
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
            if (allocated != 0 && unitStart >= tailleValide) allocated = 0;
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
                    std::memcpy(brut.data() + read, cl.data(), bytesPerCluster_);
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
                    std::memcpy(unit.data(), brut.data(), (size_t)unitSize);
                    product = (size_t)unitSize;
                }
                else {
                    product = Lznt1Inflate(brut.data(), read, unit.data(), (size_t)unitSize);
                    if (product == 0){
                        RVLOG(L"[raw] LZNT1 : unite a VCN %llu illisible\n",
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
            if (tailleValide < unitStart + unitSize && tailleValide > unitStart)
                std::fill(unit.begin() + (size_t)(tailleValide - unitStart), unit.end(), (uint8_t)0);

            const uint64_t rest = realSize - written;
            const size_t toWrite = (size_t)((rest < unitSize) ? rest : unitSize);
            if (toWrite > product && allocated != 0 && allocated != unitInClusters){
                // Less data than the announced size: write what we have.
                out.write((const char*)unit.data(), (std::streamsize)product);
                if (emp){
                    stream.update(unit.data(), product);
                    stream1.update(unit.data(), product);
                    stream256.update(unit.data(), product);
                }
                written += product;
            }
            else {
                out.write((const char*)unit.data(), (std::streamsize)toWrite);
                if (emp){
                    stream.update(unit.data(), toWrite);
                    stream1.update(unit.data(), toWrite);
                    stream256.update(unit.data(), toWrite);
                }
                written += toWrite;
            }

            if (g_progress && !label.empty() && written >= nextReport){
                g_progress(label.c_str(), written, realSize);
                nextReport = written + (1ULL << 20);
            }
            if (vcn >= lcnParVcn.size()) break;      // beyond the table
        }
        if (g_progress && !label.empty()) g_progress(label.c_str(), written, realSize);

        if (emp){
            emp->md5    = stream.hexDigest();
            emp->sha1   = stream1.hexDigest();
            emp->sha256 = stream256.hexDigest();
            emp->bytes = written;
            emp->declaredSize = realSize;
        }
        RVLOG(L"[raw] compresse : %llu octets detendus sur %llu annonces\n",
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
        uint64_t tailleValide = UINT64_MAX;

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
                tailleValide = rd64(a + 0x38);
                runs = decodeRuns(a + rd16(a + 0x20), a + rd32(a + 0x04));

            }
        }
        else if (!collectRunsFromAttributeList(rec, runs, realSize, 0x80,
                                               &compressionUnit, &tailleValide)){
            RVLOG(L"[raw] pas d'attribut $DATA exploitable\n");
            return E_FAIL;
        }
        if (tailleValide > realSize) tailleValide = realSize;
        if (emp && !resident) emp->tailleValide = tailleValide;

        // Empty output: fingerprints only, nothing is written (see NullBuffer).
        NullBuffer null_;
        std::ostream nullOutput(&null_);
        std::ofstream file;
        if (!outFile.empty()){
            file.open(std::filesystem::path(outFile), std::ios::binary | std::ios::trunc);
            if (!file){ RVLOG(L"[raw] ouverture sortie impossible\n"); return E_FAIL; }
        }
        // Empty output with an observer: the content is handed to it, nothing is written.
        std::ostream observedOutput(observer);
        std::ostream& out = !outFile.empty() ? static_cast<std::ostream&>(file)
                          : observer ? observedOutput : nullOutput;

        if (resident){
            out.write((const char*)residentData, residentLen);
            if (emp){
                Md5Stream m; Sha1Stream s1; Sha256Stream s2;
                m.update(residentData, residentLen);
                s1.update(residentData, residentLen);
                s2.update(residentData, residentLen);
                emp->md5 = m.hexDigest(); emp->sha1 = s1.hexDigest(); emp->sha256 = s2.hexDigest();
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
            const HRESULT h = extractCompressed(runs, realSize, tailleValide,
                                                compressionUnit, out, label, emp);
            return h;
        }

        std::vector<uint8_t> cl(bytesPerCluster_);
        uint64_t written = 0;
        uint64_t nextReport = 0;
        // Fingerprints computed on the bytes already passing through memory:
        // avoids reading the copy back from the collection medium, and they
        // bear on what was read from the VOLUME, not on a re-read.
        Md5Stream stream;
        Sha1Stream stream1;
        Sha256Stream stream256;
        for (const Run& r : runs){
            for (uint64_t k = 0; k < r.count && written < realSize; ++k){
                // Sparse, or beyond the valid data: zeros, without reading.
                if (r.lcn < 0 || written >= tailleValide) std::fill(cl.begin(), cl.end(), 0);
                else if (!readCluster((uint64_t)r.lcn + k, cl.data())) return E_FAIL;
                if (written < tailleValide && tailleValide < written + bytesPerCluster_)
                    std::fill(cl.begin() + (size_t)(tailleValide - written), cl.end(), (uint8_t)0);
                uint64_t chunk = std::min<uint64_t>(bytesPerCluster_, realSize - written);
                out.write((const char*)cl.data(), (std::streamsize)chunk);
                if (emp){
                    stream.update(cl.data(), (size_t)chunk);
                    stream1.update(cl.data(), (size_t)chunk);
                    stream256.update(cl.data(), (size_t)chunk);
                }
                written += chunk;
                // Report every 1 MiB: often enough to show progress, rarely enough not
                // to cost in display.
                if (g_progress && !label.empty() && written >= nextReport){
                    g_progress(label.c_str(), written, realSize);
                    nextReport = written + (1ULL << 20);
                }
            }
        }
        if (g_progress && !label.empty()) g_progress(label.c_str(), written, realSize);
        if (emp){
            emp->md5    = stream.hexDigest();
            emp->sha1   = stream1.hexDigest();
            emp->sha256 = stream256.hexDigest();
            emp->bytes = written;
            emp->declaredSize = realSize;
        }
        RVLOG(L"[raw] extrait %llu octets\n", (unsigned long long)written);
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

    // Reads `len` bytes at virtual offset `fileOff` of a file described by `runs`.
    bool readVirtual(const std::vector<Run>& runs, uint64_t fileOff, uint32_t len, uint8_t* dst){
        uint32_t got = 0;
        std::vector<uint8_t> cl(bytesPerCluster_);
        while (got < len){
            uint64_t cur   = fileOff + got;
            uint64_t vcn   = cur / bytesPerCluster_;
            uint32_t inClu = (uint32_t)(cur % bytesPerCluster_);
            uint64_t vbase = 0; int64_t lcn = -2;
            for (auto& r : runs){
                if (vcn < vbase + r.count){
                    lcn = (r.lcn < 0) ? -1 : (int64_t)((uint64_t)r.lcn + (vcn - vbase));
                    break;
                }
                vbase += r.count;
            }
            if (lcn == -2) return false; // hors runs
            uint32_t chunk = std::min<uint32_t>(len - got, bytesPerCluster_ - inClu);
            if (lcn < 0) memset(dst + got, 0, chunk);
            else { if (!readCluster((uint64_t)lcn, cl.data())) return false;
                   memcpy(dst + got, cl.data() + inClu, chunk); }
            got += chunk;
        }
        return true;
    }

    // Applies the fixups (Update Sequence Array) of a FILE/INDX record.
    static void applyFixup(uint8_t* rec, uint32_t size, uint32_t sectorSize){
        uint16_t usaOff = rd16(rec + 4), usaCnt = rd16(rec + 6);
        if (usaOff + 2u * usaCnt > size) return;
        const uint8_t* usa = rec + usaOff;
        for (uint16_t i = 1; i < usaCnt; ++i){
            uint32_t secEnd = i * sectorSize;
            if (secEnd < 2 || secEnd > size) break;
            uint8_t* pos = rec + secEnd - 2;
            pos[0] = usa[2 * i]; pos[1] = usa[2 * i + 1];
        }
    }

    // Bootstrap: reads record #0 ($MFT) to get its own runs.
    bool bootstrapMft(){
        std::vector<uint8_t> rec(bytesPerRecord_);
        if (!readBytes(mftLcn_ * bytesPerCluster_, rec.data(), bytesPerRecord_)) return false;
        if (memcmp(rec.data(), "FILE", 4) != 0){ RVLOG(L"[raw] MFT#0: signature FILE absente\n"); return false; }
        applyFixup(rec.data(), bytesPerRecord_, bytesPerSector_);
        const uint8_t* a = findAttr(rec, 0x80);
        if (!a || a[8] == 0){ RVLOG(L"[raw] $MFT $DATA introuvable/résident\n"); return false; }
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
            RVLOG(L"[raw] MFT#%llu: readVirtual echec\n", (unsigned long long)index); return false; }
        if (memcmp(rec.data(), "FILE", 4) != 0){
            RVLOG(L"[raw] MFT#%llu: magic FILE absent (%02x%02x%02x%02x)\n",
                  (unsigned long long)index, rec[0], rec[1], rec[2], rec[3]); return false; }
        applyFixup(rec.data(), bytesPerRecord_, bytesPerSector_);
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
            RVLOG(L"[raw] listDir(%llu): enregistrement illisible\n", (unsigned long long)dirIndex);
            return false; }

        // $INDEX_ROOT (0x90) — resident, always present
        const uint8_t* ir = findAttr(rec, 0x90, false);   // "$I30"
        if (!ir){ RVLOG(L"[raw] listDir(%llu): $INDEX_ROOT absent\n", (unsigned long long)dirIndex); return false; }
        if (ir[8] != 0){ RVLOG(L"[raw] listDir(%llu): $INDEX_ROOT non resident\n", (unsigned long long)dirIndex); return false; }
        uint32_t irValLen = rd32(ir + 0x10); uint16_t irValOff = rd16(ir + 0x14);
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
                readIndexBlocks(splitRuns, splitSize, idxBlockSize, out);
                return true;
            }
        }
        /* A large directory keeps in $INDEX_ROOT only a leaf node pointing to
           the index blocks: ALL its entries then come from $INDEX_ALLOCATION.
           Hence the separate trace of both sources — without it, "0 entries"
           does not say which of the two failed. */
        RVLOG(L"[raw] listDir(%llu): %llu entree(s) depuis $INDEX_ROOT, "
              L"$INDEX_ALLOCATION %ls (blockSize=%u)\n",
              (unsigned long long)dirIndex, (unsigned long long)fromRoot,
              ia ? (ia[8] != 0 ? L"non resident" : L"RESIDENT (inattendu)") : L"absent",
              idxBlockSize);
        if (ia && ia[8] != 0 && idxBlockSize){
            uint64_t realSize = rd64(ia + 0x30);
            std::vector<Run> runs = decodeRuns(ia + rd16(ia + 0x20), ia + rd32(ia + 0x04));
            readIndexBlocks(runs, realSize, idxBlockSize, out);
        }
        return true;
    }

    /*! Walks the index blocks (INDX) described by `runs` and extracts their
     *  entries. Shared by both ways of reaching $INDEX_ALLOCATION: from the base
     *  record, or through $ATTRIBUTE_LIST when it is split. */
    void readIndexBlocks(const std::vector<Run>& runs, uint64_t realSize,
                        uint32_t idxBlockSize, std::vector<RawDirEntry>& out){
        if (!idxBlockSize) return;
        std::vector<uint8_t> blk(idxBlockSize);
        uint64_t blocksRead = 0, blocksWithoutIndx = 0;
        for (uint64_t pos = 0; pos + idxBlockSize <= realSize; pos += idxBlockSize){
            ++blocksRead;
            if (!readVirtual(runs, pos, idxBlockSize, blk.data())){
                RVLOG(L"[raw] bloc d'index a l'offset %llu illisible\n",
                      (unsigned long long)pos);
                break;
            }
            if (memcmp(blk.data(), "INDX", 4) != 0){ ++blocksWithoutIndx; continue; }
            applyFixup(blk.data(), idxBlockSize, bytesPerSector_);
            const uint8_t* nh = blk.data() + 0x18;      // node header after the INDX header
            uint32_t used = rd32(nh + 4);
            const uint8_t* lim = nh + used;
            if (lim > blk.data() + idxBlockSize) lim = blk.data() + idxBlockSize;
            parseIndexNode(nh, lim, out);
        }
        RVLOG(L"[raw] blocs d'index: realSize=%llu, %llu lu(s), "
              L"%llu sans signature INDX, total %llu entree(s)\n",
              (unsigned long long)realSize, (unsigned long long)blocksRead,
              (unsigned long long)blocksWithoutIndx, (unsigned long long)out.size());
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
        RVLOG(L"[raw] repertoire absent: %ls\n", dirPathOnVolume.c_str());
        if (diagnostic) *diagnostic = L"chemin non resolu (repertoire absent ?)";
        return ERROR_SUCCESS;
    }

    std::vector<RawDirEntry> entries;
    if (!vol.listDir(dirIndex, entries)){
        RVLOG(L"[raw] enumeration impossible: %ls\n", dirPathOnVolume.c_str());
        if (diagnostic) *diagnostic = L"enumeration de l'index impossible";
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
            RVLOG(L"[raw] extraction echouee: %ls\n", e.name.c_str());
            ++failures;
            overall = S_FALSE;
        }
        else if (extracted) ++*extracted;
    }

    /* The details tell apart three causes of a zero count: empty index,
       too strict an extension filter, or extraction failures. */
    if (diagnostic){
        *diagnostic = std::to_wstring(entries.size()) + L" entree(s), "
                    + std::to_wstring(files) + L" fichier(s), "
                    + std::to_wstring(kept) + L" retenu(s)";
        if (failures) *diagnostic += L", " + std::to_wstring(failures) + L" echec(s)";
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
        RVLOG(L"[raw] arbo: index illisible pour %ls\n", volumePath.c_str());
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(outDir), ec);

    HRESULT global = ERROR_SUCCESS;
    for (const RawDirEntry& e : entries){
        if (e.name == L"." || e.name == L"..") continue;

        if (e.isDirectory){
            if (depthLeft == 0){
                RVLOG(L"[raw] arbo: profondeur max atteinte a %ls\n", e.name.c_str());
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
            RVLOG(L"[raw] arbo: extraction echouee %ls\n", e.name.c_str());
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
        RVLOG(L"[raw] arbo: repertoire absent %ls\n", dirPathOnVolume.c_str());
        return ERROR_SUCCESS;
    }
    return extractTree(vol, dirIndex, dirPathOnVolume, outDir,
                                extensions, extracted, maxDepth,
                                volumeLetter, reading);
}
