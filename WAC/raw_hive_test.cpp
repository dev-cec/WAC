/*! \file
 *  \brief Validation harness for the raw NTFS reading.
 *  To be run on Windows, as an administrator (raw volume access).
 *
 * Usage: raw_hive_test.exe [volume] [path] [output] [--fix] [--list] [--attrs]
 *   --fix    applies MakeHiveLoadable() on the extracted hive
 *   --list   lists a directory instead of extracting a file
 *   --attrs  lists the $MFT ATTRIBUTES of the file, without interpreting anything
 *
 * WHY --attrs. What the Windows API shows of a file and what the disk holds can
 * differ entirely: a "Compact OS" binary presents itself as an ordinary file
 * while it carries a reparse point, a sparse $DATA and a named stream that holds
 * everything. Without that direct look, a file extracted entirely as zeros
 * stays unexplainable.
 *
 * WHY --fix. A hive copied live is always "dirty": without the patch, `reg load`
 * refuses it with ERROR_BADDB. The harness must therefore test BOTH ways —
 * without --fix the load must fail (which proves the patch is necessary), with
 * --fix it must succeed. A test that fails by construction ends up being
 * ignored, which is worse than its absence.
 */
#include "raw_hive.h"
#include "hive_recover.h"
#include <cstdio>
#include <string>
#include <vector>

/*! Runs the test.
 * @param argc,argv [volume] [path] [output] [--fix] [--list] [--attrs]
 * @return 0 if every check passed */
int wmain(int argc, wchar_t** argv){
    RawHiveSetVerbose(true);

    bool fix = false, list = false, attrs = false;
    std::vector<const wchar_t*> positionnels;
    for (int i = 1; i < argc; ++i){
        if (wcscmp(argv[i], L"--fix") == 0)       fix = true;
        else if (wcscmp(argv[i], L"--list") == 0) list = true;
        else if (wcscmp(argv[i], L"--attrs") == 0) attrs = true;
        else positionnels.push_back(argv[i]);
    }
    const wchar_t* vol  = positionnels.size() > 0 ? positionnels[0] : L"C";
    const wchar_t* path = positionnels.size() > 1 ? positionnels[1]
                                                  : L"\\Windows\\System32\\config\\SYSTEM";
    const wchar_t* out  = positionnels.size() > 2 ? positionnels[2] : L"SYSTEM.hiv";

    if (attrs){
        std::vector<RawAttribute> attributes;
        const HRESULT hr = ListAttributesRaw(vol, path, attributes);
        if (FAILED(hr)){ wprintf(L"FAILED ListAttributesRaw: 0x%08lx\n", (unsigned long)hr); return 1; }
        wprintf(L"%zu attribute(s) in the $MFT record of %ls\n", attributes.size(), path);
        for (const RawAttribute& a : attributes){
            wprintf(L"  type 0x%02X  %-18ls %-12ls size %12llu  flags 0x%04X",
                    a.type,
                    a.name.empty() ? L"(no name)" : a.name.c_str(),
                    a.resident ? L"resident" : L"non resident",
                    (unsigned long long)a.actualSize, a.flags);
            if (a.flags & 0x0001) wprintf(L" COMPRESSED");
            if (a.flags & 0x8000) wprintf(L" SPARSE");
            if (a.tagReparse)        wprintf(L"  reparse 0x%08lX", (unsigned long)a.tagReparse);
            if (!a.resident && a.initializedSize != a.actualSize)
                wprintf(L"  valid %llu", (unsigned long long)a.initializedSize);
            wprintf(L"\n");
            if (a.type == 0xC0 && !a.preview.empty()){
                wprintf(L"      content:");
                for (size_t k = 0; k < a.preview.size() && k < 24; ++k) wprintf(L" %02X", a.preview[k]);
                wprintf(L"\n");
            }
        }
        return 0;
    }

    if (list){
        wprintf(L"Enumeration brute %ls:%ls\n", vol, path);
        std::vector<RawDirEntry> entries;
        HRESULT hr = ListDirectoryRaw(vol, path, entries);
        if (FAILED(hr)){
            wprintf(L"Result: 0x%08lX (FAILED)\n", (unsigned long)hr);
            return 1;
        }
        // The total is printed FIRST: a display problem on the list must not prevent
        // the result of the test from being read.
        // msvcrt handles neither %zu nor field widths on %ls: we stick to %llu
        // with an explicit cast, and to %ls without a width.
        wprintf(L"Total: %llu entry/entries\n", (unsigned long long)entries.size());
        for (const RawDirEntry& e : entries)
            wprintf(L"  %ls %ls (%llu octets)\n", e.isDirectory ? L"[REP]" : L"     ",
                    e.name.c_str(), (unsigned long long)e.size);
        return 0;
    }

    wprintf(L"Extraction brute %ls:%ls -> %ls\n", vol, path, out);
    HRESULT hr = ExtractFileRaw(vol, path, out);
    wprintf(L"Extraction: 0x%08lX (%ls)\n", (unsigned long)hr, SUCCEEDED(hr) ? L"OK" : L"FAILED");
    if (FAILED(hr)) return 1;

    if (fix){
        HiveFixInfo info = MakeHiveLoadable(out);
        wprintf(L"Recovery: %ls\n", HiveFixInfoToString(info).c_str());
        if (!info.ok) return 1;
    }
    else {
        wprintf(L"Recovery: NOT requested (--fix absent): the hive stays dirty,\n"
                L"          so `reg load` must refuse it (ERROR_BADDB 1009).\n");
    }
    return 0;
}
