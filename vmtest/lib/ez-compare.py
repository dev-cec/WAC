#!/usr/bin/env python3
"""ez-compare.py — WAC's JSON against Eric Zimmerman's tools, on the same exhibits.

B-015: the EZ tools, run in the test VM on WAC's own exhibit store, are the
reference of the forensic community; every difference is either a defect of
WAC, a documented difference of convention, or one of theirs — each is
counted, and shown with examples.

Usage:
  ez-compare.py mft <MFTECmd csv> <WAC mft.json> [volume]

mft: record by record — paths (hard links included), deleted or not,
directory, size, and the eight dates of $STANDARD_INFORMATION and
$FILE_NAME. MFTECmd fills its 0x30 ($FILE_NAME) columns only when they differ
from the 0x10 ones: empty means "equal".
"""
import collections
import csv
import json
import sys

csv.field_size_limit(1 << 30)

DATES = (  # MFTECmd 0x10 column, 0x30 column, WAC SI key, WAC FN key
    ("Created0x10", "Created0x30", "CreatedUtc", "FileNameCreatedUtc"),
    ("LastModified0x10", "LastModified0x30", "ModifiedUtc", "FileNameModifiedUtc"),
    ("LastRecordChange0x10", "LastRecordChange0x30", "MftModifiedUtc", "FileNameMftModifiedUtc"),
    ("LastAccess0x10", "LastAccess0x30", "AccessedUtc", "FileNameAccessedUtc"),
)


def ez_date(text):
    """'2026-09-12 12:20:14.6100374' → '2026-09-12T12:20:14.6100374' (UTC, as WAC without its Z)."""
    return text.replace(" ", "T") if text else ""


def wac_date(text):
    return (text or "").rstrip("Z")


def compare_mft(ez_csv, wac_json, volume):
    ez = collections.defaultdict(list)
    with open(ez_csv, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["IsAds"] == "True":
                continue
            ez[(int(row["EntryNumber"]), int(row["SequenceNumber"]))].append(row)
    with open(wac_json, encoding="utf-8-sig") as f:
        wac = {(r["Entry"], r["Sequence"]): r for r in json.load(f)
               if isinstance(r, dict) and r.get("Volume", volume) == volume}

    diffs = collections.defaultdict(list)
    explained = collections.Counter()
    compared = collections.Counter()
    only_ez = sorted(set(ez) - set(wac))
    only_wac = [k for k in set(wac) - set(ez)]
    for key in sorted(set(ez) & set(wac)):
        rows, w = ez[key], wac[key]
        first = rows[0]
        def note(field, mine, theirs):
            compared[field] += 1
            if mine != theirs:
                diffs[field].append((key, mine, theirs))
        note("deleted", bool(w.get("Deleted")), first["InUse"] != "True")
        note("directory", bool(w.get("Directory")), first["IsDirectory"] == "True")
        if first["IsDirectory"] != "True" and w.get("Size") != int(first["FileSize"] or 0):
            # Differences of convention, each confirmed against Windows' own sizes (B-015):
            # a WOF (Compact OS) file — WAC gives its logical size, MFTECmd its
            # compressed stream's; a metadata file without an unnamed $DATA —
            # WAC gives no size; a log open for writing — MFTECmd gives 0.
            if "WofCompressedData" in (w.get("Streams") or []):
                explained["WOF file: logical size (WAC, as Windows) / compressed stream (MFTECmd)"] += 1
            elif w.get("Size") is None and str(w.get("Path", "")).startswith(volume + "\\$"):
                explained["metadata file without unnamed $DATA: no size (WAC)"] += 1
            elif first["FileSize"] in ("", "0") and w.get("Size"):
                explained["file open for writing: real size (WAC, as Windows) / 0 (MFTECmd)"] += 1
            else:
                note("size", w.get("Size"), int(first["FileSize"] or 0))
        elif first["IsDirectory"] != "True":
            note("size", w.get("Size"), int(first["FileSize"] or 0))
        # Paths: every name of the record, when both know the whole path.
        theirs = set()
        for r in rows:
            parent = r["ParentPath"]
            if "PathUnknown" in parent:
                theirs = None
                break
            parent = volume + parent[1:] if parent.startswith(".") else parent
            theirs.add((parent.rstrip("\\") + "\\" + r["FileName"]).lower())
        if key[0] == 5:                                   # the root: "C:\\" for WAC, "C:\\." for MFTECmd
            theirs = None
        if theirs is not None and not w.get("PathIncomplete"):
            mine = {str(w.get("Path", "")).lower()} | {p.lower() for p in w.get("HardLinkPaths") or []}
            note("paths", sorted(mine), sorted(theirs))
        # Each name has its own $FILE_NAME attribute and dates: those of the
        # name WAC gives as Path, i.e. MFTECmd's row for that same path.
        def row_path(r):
            parent = r["ParentPath"]
            parent = volume + parent[1:] if parent.startswith(".") else parent
            return (parent.rstrip("\\") + "\\" + r["FileName"]).lower()
        named = next((r for r in rows if row_path(r) == str(w.get("Path", "")).lower()), None)
        for si, fn, wsi, wfn in DATES:
            note(wsi, wac_date(w.get(wsi)), ez_date(first[si]))
            if named is not None:
                # 0x30 empty: $FILE_NAME equal to $STANDARD_INFORMATION.
                note(wfn, wac_date(w.get(wfn)), ez_date(named[fn]) or ez_date(named[si]))

    print(f"records: WAC {len(wac)}, MFTECmd {len(ez)}, common {len(set(ez) & set(wac))}")
    print(f"  only in MFTECmd: {len(only_ez)} e.g. {only_ez[:5]}")
    print(f"  only in WAC: {len(only_wac)} e.g. {sorted(only_wac)[:5]}")
    for reason, count in explained.items():
        print(f"  ℹ️  {count} size(s): {reason}")
    failures = 0
    for field in compared:
        wrong = diffs[field]
        mark = "✅" if not wrong else "❌"
        print(f"  {mark} {field}: {compared[field] - len(wrong)}/{compared[field]} identical")
        for key, mine, theirs in wrong[:3]:
            print(f"        {key}: WAC {mine!r}, MFTECmd {theirs!r}")
        failures += len(wrong)
    # Records 12 to 15 are reserved: WAC gives them (dates, no name), MFTECmd not.
    unexplained_wac = [k for k in only_wac if not 12 <= k[0] <= 15]
    return 1 if failures or only_ez or unexplained_wac else 0


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "mft":
        return compare_mft(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "C:")
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
