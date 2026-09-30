#!/usr/bin/env python3
"""ez-compare.py — WAC's JSON against Eric Zimmerman's tools, on the same exhibits.

B-015: the EZ tools, run in the test VM on WAC's own exhibit store, are the
reference of the forensic community; every difference is either a defect of
WAC, a documented difference of convention, or one of theirs — each is
counted, and shown with examples.

Usage: ez-compare.py <mode> <folder> — the folder ez-compare.sh brings back,
holding the EZ tool's CSV and WAC's JSON. Modes:
  mft       MFTECmd  / mft.json (volume C:)
  evtx      EvtxECmd / events.json
  prefetch  PECmd    / prefetchs.json (PECmd run with --mp, full precision)
  lnk       LECmd    / recentdocs.json
  jumplist  JLECmd   / jumplistAutomaticDestinations.json, jumplistCustomDestinations.json
  amcache   AmcacheParser / amcache_applications.json, amcache_application_files.json, amcache_inventory.json
  shimcache AppCompatCacheParser / shimcache.json
  shellbags SBECmd   / shellbags.json
  recycle_bin RBCmd  / recycle_bin.json
  srum      SrumECmd / srum.json

mft: record by record — paths (hard links included), deleted or not,
directory, size, and the eight dates of $STANDARD_INFORMATION and
$FILE_NAME. MFTECmd fills its 0x30 ($FILE_NAME) columns only when they differ
from the 0x10 ones: empty means "equal".
"""
import collections
import csv
import glob
import html
import json
import os
import re
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


LEVELS = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Info", 5: "Verbose"}


def ez_payload_values(payload):
    """Every leaf value of EvtxECmd's Payload (EventData or UserData), as text."""
    out = []
    def walk(o, key=""):
        if isinstance(o, dict):
            for k, v in o.items():
                if k.startswith("@") and k != "@Name":
                    continue
                if k == "@Name":
                    continue
                walk(v, k)
        elif isinstance(o, list):
            for v in o:
                walk(v, key)
        elif o is not None and key != "Binary":
            out.append(str(o))
    try:
        walk(json.loads(payload) if payload else {})
    except ValueError:
        return None
    return out


# EvtxECmd's conventions of output, each against the form Windows gives in the
# event's XML (and WAC with it): (description, pattern, rewrite to Windows'
# form). Applied to both sides (see payload_verdict); the XML entities EvtxECmd
# leaves escaped are undone on its side only — a text can hold "&amp;" itself.
ENTITIES = "XML entities kept escaped (&gt;, &amp;)"
EVTX_CONVENTIONS = (
    ("hexadecimal in uppercase (0x3E7 for 0x3e7)", re.compile(r"\b0x[0-9A-F]*[A-F][0-9A-F]*\b"), lambda m: m.group(0).lower()),
    ("GUID without braces", re.compile(r"(?<![{\w-])[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}(?![}\w-])"), lambda m: "{" + m.group(0).lower() + "}"),
    ("booleans True/False (true/false)", re.compile(r"\b(?:True|False)\b"), lambda m: m.group(0).lower()),
    ("date with a space, without Z", re.compile(r"\b(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d+)?)\b"), lambda m: f"{m.group(1)}T{m.group(2)}Z"),
    ("text altered: left-to-right marks (U+200E) removed, value split — WAC keeps them, as Windows", re.compile("\u200e"), lambda m: ""),
    ("binary data as AA-BB-CC (AABBCC)", re.compile(r"\b[0-9A-F]{2}(?:-[0-9A-F]{2})+\b"), lambda m: m.group(0).replace("-", "")),
)
ZERO_FILETIME = "1601-01-01T00:00:00.0000000Z"
DATE_FRACTION = re.compile(r"(T\d\d:\d\d:\d\d)(?:\.(\d+))?Z")


def canonical(text):
    """Whitespace collapsed, dates to 7 fractional digits: forms that carry the same value."""
    text = " ".join(text.split())
    return DATE_FRACTION.sub(lambda m: f"{m.group(1)}.{(m.group(2) or '').ljust(7, '0')[:7]}Z", text)


def payload_verdict(mine, theirs, valueless=0):
    """Compares WAC's EventData values with EvtxECmd's.

    Returns [] when identical, the list of EvtxECmd conventions that explain
    the difference, or None when they do not. The conventions rewrite both
    sides — a message can hold "0xC004F014" as text, on both — and one is
    attributed when it changed EvtxECmd's text alone. EvtxECmd joins some
    values with ", ", and reorders others: both sides are compared as the
    multiset of their comma-separated pieces, then as their text without
    separators. valueless: WAC's entries without a value — a zero FILETIME,
    which WAC does not emit as a date and Windows gives as 1601-01-01."""
    rules = set()
    def rewrite(values, note):
        out = []
        for value in values:
            for name, pattern, fix in EVTX_CONVENTIONS:
                new = pattern.sub(fix, value)
                if new != value:
                    note.add(name)
                    value = new
            out.append(value)
        return out
    rules_mine = set()
    unescaped = [html.unescape(v) for v in theirs]
    if unescaped != theirs:
        rules.add(ENTITIES)
    mine2, theirs2 = rewrite(mine, rules_mine), rewrite(unescaped, rules)
    def pieces(values):
        return collections.Counter(p for v in values for p in (x.strip() for x in canonical(v).split(",")) if p)
    def flat(values):
        return "".join(canonical(v).replace(",", "").replace(" ", "") for v in values)
    if pieces(mine) == pieces(theirs):
        return []
    theirs_pieces = pieces(theirs2)
    if valueless and theirs_pieces[ZERO_FILETIME]:
        theirs_pieces[ZERO_FILETIME] = max(0, theirs_pieces[ZERO_FILETIME] - valueless)
        theirs_pieces += collections.Counter()          # drops the zero counts
        rules.add("WAC convention — zero FILETIME not emitted as a date (Windows and EvtxECmd: 1601-01-01)")
    if pieces(mine2) == theirs_pieces or flat(mine2) == flat(theirs2):
        # A convention is EvtxECmd's when it rewrote its text alone: a left-to-right
        # mark, kept by WAC as Windows does, is rewritten on WAC's side only.
        rules ^= rules_mine
        if not rules:
            rules.add("values joined or reordered")
        return sorted(rules)
    return None


def compare_evtx(ez_csv, wac_json):
    ez = {}
    per_log_ez = collections.Counter()
    with open(ez_csv, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            log = row["SourceFile"].rsplit("\\", 1)[-1].lower()
            ez[(log, int(row["EventRecordId"]))] = row
            per_log_ez[log] += 1
    with open(wac_json, encoding="utf-8-sig") as f:
        wac = {}
        recovered = collections.Counter()
        per_log_wac = collections.Counter()
        for e in json.load(f):
            if not isinstance(e, dict) or "EvtSystemEventRecordId" not in e:
                continue
            log = str(e.get("EvtSourceLog", "")).lower()
            if e.get("EvtRecovered"):
                # Events of a cleared log, which neither Windows nor EvtxECmd reads.
                recovered[log] += 1
                continue
            wac[(log, e["EvtSystemEventRecordId"])] = e
            per_log_wac[log] += 1
    diffs = collections.defaultdict(list)
    compared = collections.Counter()
    conventions = collections.Counter()
    def note(field, key, mine, theirs):
        compared[field] += 1
        if mine != theirs:
            diffs[field].append((key, mine, theirs))
    for key in sorted(set(ez) & set(wac)):
        r, e = ez[key], wac[key]
        note("TimeCreated", key, str(e.get("EvtSystemTimeCreated", "")).rstrip("Z"), r["TimeCreated"].replace(" ", "T"))
        note("EventId", key, e.get("EvtSystemEventID"), int(r["EventId"]))
        note("Provider", key, e.get("EvtSystemProviderName"), r["Provider"])
        note("Channel", key, e.get("EvtSystemChannel"), r["Channel"])
        note("Computer", key, e.get("EvtSystemComputer"), r["Computer"])
        # A level outside 0–5 is given as its number by WAC, named by EvtxECmd.
        if e.get("EvtSystemLevel") in LEVELS:
            note("Level", key, LEVELS[e["EvtSystemLevel"]], r["Level"])
        note("ProcessId", key, e.get("EvtSystemProcessID"), int(r["ProcessId"] or 0))
        note("ThreadId", key, e.get("EvtSystemThreadID"), int(r["ThreadId"] or 0))
        theirs = ez_payload_values(r["Payload"])
        if theirs is not None:
            data = [d for d in e.get("EvtEventData") or [] if isinstance(d, dict) and d.get("Value") is not None]
            mine = [str(d["Value"]) for d in data if d.get("Name") != "Binary"]
            compared["EventData values"] += 1
            verdict = payload_verdict(mine, theirs, sum(1 for d in e.get("EvtEventData") or []
                                                         if isinstance(d, dict) and "Value" not in d and d.get("Name")))
            if verdict is not None and len(mine) < len(data):
                # A classic event's <Binary>, which Event Viewer shows: WAC keeps it.
                verdict.append("the classic <Binary> element left out (WAC keeps it)")
            if verdict is None:
                diffs["EventData values"].append((key, mine, theirs))
            elif verdict:
                conventions.update(verdict)
    only_ez = set(ez) - set(wac)
    only_wac = set(wac) - set(ez)
    print(f"records: WAC {len(wac)}, EvtxECmd {len(ez)}, common {len(set(ez) & set(wac))}")
    print(f"  only in EvtxECmd: {len(only_ez)}, by log: {collections.Counter(k[0] for k in only_ez).most_common(5)}")
    print(f"  only in WAC: {len(only_wac)}, by log: {collections.Counter(k[0] for k in only_wac).most_common(5)}")
    for rule, count in conventions.most_common():
        print(f"  ℹ️  {count} event(s): {rule if rule.startswith('WAC') else 'EvtxECmd convention — ' + rule}")
    print(f"  ℹ️  recovered by WAC only (cleared logs, flagged EvtRecovered): {sum(recovered.values())} {dict(recovered)}")
    failures = 0
    for field in compared:
        wrong = diffs[field]
        print(f"  {'✅' if not wrong else '❌'} {field}: {compared[field] - len(wrong)}/{compared[field]} identical")
        for key, mine, theirs in wrong[:3]:
            print(f"        {key}: WAC {str(mine)[:160]!r}, EvtxECmd {str(theirs)[:160]!r}")
        failures += len(wrong)
    return 1 if failures or only_ez or only_wac else 0


def compare_prefetch(ez_csv, wac_json):
    """File by file: executable, hash, run count, the eight run times, volumes
    (name, serial, creation), directories and files loaded. The dates of the
    .pf file itself are left out: PECmd reads them on the copy it is given,
    WAC gives the original's."""
    with open(ez_csv, encoding="utf-8-sig", newline="") as f:
        ez = {row["SourceFilename"].rsplit("\\", 1)[-1].lower(): row for row in csv.DictReader(f)}
    with open(wac_json, encoding="utf-8-sig") as f:
        wac = {str(p["Path"]).rsplit("\\", 1)[-1].lower(): p for p in json.load(f) if isinstance(p, dict) and "Path" in p}
    diffs = collections.defaultdict(list)
    compared = collections.Counter()
    explained = collections.Counter()
    def note(field, key, mine, theirs):
        compared[field] += 1
        if mine != theirs:
            diffs[field].append((key, mine, theirs))
    def split(text):
        return sorted(x for x in (text or "").split(", ") if x)
    for key in sorted(set(ez) & set(wac)):
        r, p = ez[key], wac[key]
        note("executable", key, p.get("Filename"), r["ExecutableName"])
        # PECmd drops leading zeros ("BD30981"): Windows names the file with the
        # eight digits ("CMD.EXE-0BD30981.pf"), and WAC gives them.
        if p.get("Hash") != r["Hash"] and p.get("Hash") == r["Hash"].rjust(8, "0"):
            explained["hash without its leading zeros (PECmd; WAC as the file name)"] += 1
        else:
            note("hash", key, p.get("Hash"), r["Hash"])
        note("run count", key, p.get("RunCount"), int(r["RunCount"] or 0))
        theirs = [ez_date(r[c]) for c in ["LastRun"] + [f"PreviousRun{i}" for i in range(7)] if r[c]]
        note("run times", key, sorted(wac_date(d) for d in p.get("RunsUtc") or []), sorted(theirs))
        volumes = p.get("Volumes") or []
        for i in range(2):
            if not r[f"Volume{i}Name"] and i >= len(volumes):
                continue
            v = volumes[i] if i < len(volumes) else {}
            note("volume", key, (v.get("DeviceName"), v.get("SerialNumber"), wac_date(v.get("CreationTimeUtc"))),
                 (r[f"Volume{i}Name"], r[f"Volume{i}Serial"], ez_date(r[f"Volume{i}Created"])))
        note("directories", key, sorted(d.get("Directory") for v in volumes for d in v.get("Directories") or []), split(r["Directories"]))
        note("files loaded", key, sorted(f.get("Filename") for f in p.get("FileNames") or []), split(r["FilesLoaded"]))
    only_ez, only_wac = set(ez) - set(wac), set(wac) - set(ez)
    failed = [k for k in only_ez if ez[k]["ParsingError"] == "True" or not ez[k]["ExecutableName"]]
    print(f"files: WAC {len(wac)}, PECmd {len(ez)}, common {len(set(ez) & set(wac))}")
    print(f"  only in PECmd: {len(only_ez)} {sorted(only_ez)[:5]} (of which unreadable for both: {len(failed)})")
    print(f"  only in WAC: {len(only_wac)} {sorted(only_wac)[:5]}")
    for reason, count in explained.items():
        print(f"  ℹ️  {count} file(s): {reason}")
    failures = 0
    for field in compared:
        wrong = diffs[field]
        print(f"  {'✅' if not wrong else '❌'} {field}: {compared[field] - len(wrong)}/{compared[field]} identical")
        for key, mine, theirs in wrong[:3]:
            print(f"        {key}: WAC {str(mine)[:200]!r}, PECmd {str(theirs)[:200]!r}")
        failures += len(wrong)
    return 1 if failures or only_wac or len(only_ez) != len(failed) else 0


DRIVE_TYPES = {  # LECmd's wording -> WAC's (the Win32 constant)
    "Fixed storage media (Hard drive)": "DRIVE_FIXED", "Removable storage media (Floppy, USB)": "DRIVE_REMOVABLE",
    "Remote storage": "DRIVE_REMOTE", "CD-ROM": "DRIVE_CDROM", "Ram storage": "DRIVE_RAMDISK",
    "No root directory": "DRIVE_NO_ROOT_DIR", "Unknown": "DRIVE_UNKNOWN", "(None)": None, "": None,
}


def words(text, strip=("fileattribute", "link", "_", " ")):
    """A list of flags as a set of comparable words: "HAS_LINK_INFO" and "HasLinkInfo" both give "hasinfo"."""
    out = set()
    for w in (text or "").split(","):
        w = w.strip().lower()
        for s in strip:
            w = w.replace(s, "")
        if w and w != "0":
            out.add(w)
    return out


class Comparison:
    """Counts, field by field, identical values, differences, and the differences explained."""
    def __init__(self, tool):
        self.tool = tool
        self.compared = collections.Counter()
        self.diffs = collections.defaultdict(list)
        self.explained = collections.Counter()

    def note(self, field, key, mine, theirs):
        self.compared[field] += 1
        if mine != theirs:
            self.diffs[field].append((key, mine, theirs))

    def date(self, field, key, mine, theirs):
        """A UTC date; EZ's to the second when it gives no fraction: compared to the second."""
        mine, theirs = wac_date(mine), ez_date(theirs)
        if theirs.endswith(".0000000") and "." not in mine:
            theirs = theirs[:-8]       # a date to the second, padded by the EZ tool
        if theirs and "." not in theirs and mine.startswith(theirs + "."):
            self.explained[f"{field}: to the second ({self.tool}), to the 100 ns (WAC)"] += 1
            mine = theirs
        self.note(field, key, mine, theirs)

    def report(self):
        for reason, count in self.explained.most_common():
            print(f"  ℹ️  {count}: {reason}")
        failures = 0
        for field in self.compared:
            wrong = self.diffs[field]
            print(f"  {'✅' if not wrong else '❌'} {field}: {self.compared[field] - len(wrong)}/{self.compared[field]} identical")
            for key, mine, theirs in wrong[:3]:
                print(f"        {key}: WAC {str(mine)[:200]!r}, {self.tool} {str(theirs)[:200]!r}")
            failures += len(wrong)
        return failures


def mac(text):
    return (text or "").lower().replace("-", ":")


def guid(text):
    return (text or "").strip("{}").lower()


def compare_shortcut(c, key, r, w):
    """The fields of a .lnk, as LECmd and JLECmd give them, against WAC's."""
    c.date("target created", key, w.get("TargetCreatedUtc"), r["TargetCreated"])
    c.date("target modified", key, w.get("TargetModifiedUtc"), r["TargetModified"])
    c.date("target accessed", key, w.get("TargetAccessedUtc"), r["TargetAccessed"])
    c.note("target size", key, w.get("TargetFileSize", 0), int(r["FileSize"] or 0))
    c.note("target attributes", key, words(w.get("FileAttributes")), words(r["FileAttributes"]))
    c.note("link flags", key, words(w.get("LinkFlags")), words(r["HeaderFlags"]))
    c.note("drive type", key, w.get("VolumeDriveType"), DRIVE_TYPES.get(r["DriveType"], r["DriveType"]))
    c.note("volume serial and label", key, (w.get("VolumeSerial"), w.get("VolumeLabel")),
           (r["VolumeSerialNumber"] or None, r["VolumeLabel"] or None))
    if r["LocalPath"]:
        c.note("target path", key, w.get("Target"), r["LocalPath"] + (r.get("CommonPath") or ""))
    for field, ours in (("Arguments", "Arguments"), ("RelativePath", "RelativePath"), ("WorkingDirectory", "WorkingDirectory")):
        c.note(field, key, w.get(ours), r[field] or None)
    mft = [b for i in w.get("IdList") or [] if isinstance(i, dict)
           for b in (i.get("ExtensionBlocks") or []) + [i.get("ExtensionBlock") or {}]
           if isinstance(b, dict) and b.get("MftEntryNumber") is not None]
    if r["TargetMFTEntryNumber"]:
        c.note("target MFT entry and sequence", key,
               (mft[-1].get("MftEntryNumber"), mft[-1].get("MftSequenceNumber")) if mft else None,
               (int(r["TargetMFTEntryNumber"], 16), int(r["TargetMFTSequenceNumber"], 16)))
    t = w.get("Tracker") or {}
    if r["MachineID"] or t:
        c.note("tracker: machine", key, t.get("MachineId"), r["MachineID"] or None)
        c.note("tracker: hardware address", key, mac(t.get("DroidFileHardwareAddress")), mac(r["MachineMACAddress"]))
        c.date("tracker: created", key, t.get("DroidFileCreatedUtc"), r["TrackerCreatedOn"])
    c.note("extra data blocks", key, {b.lower() for b in w.get("ExtraDataBlocks") or []},
           {b.strip().lower().replace("trackerdatabaseblock", "trackerdatablock") for b in r["ExtraBlocksPresent"].split(",") if b.strip()})


def compare_lnk(ez_csv, wac_json):
    """recentdocs.json against LECmd, shortcut by shortcut (file name)."""
    with open(ez_csv, encoding="utf-8-sig", newline="") as f:
        ez = {row["SourceFile"].rsplit("\\", 1)[-1].lower(): row for row in csv.DictReader(f)}
    with open(wac_json, encoding="utf-8-sig") as f:
        wac = {str(d["Path"]).rsplit("\\", 1)[-1].lower(): d for d in json.load(f) if isinstance(d, dict) and "Path" in d}
    c = Comparison("LECmd")
    for key in sorted(set(ez) & set(wac)):
        compare_shortcut(c, key, ez[key], wac[key])
    print(f"shortcuts: WAC {len(wac)}, LECmd {len(ez)}, common {len(set(ez) & set(wac))}")
    print(f"  only in LECmd: {sorted(set(ez) - set(wac))[:5]}; only in WAC: {sorted(set(wac) - set(ez))[:5]}")
    return 1 if c.report() or set(ez) ^ set(wac) else 0


def compare_jumplist(auto_csv, custom_csv, wac_auto, wac_custom):
    """Jump lists against JLECmd: automatic ones by (file, DestList entry), with
    the DestList fields; custom ones by (file, rank)."""
    c = Comparison("JLECmd")
    with open(auto_csv, encoding="utf-8-sig", newline="") as f:
        ez = {(r["SourceFile"].rsplit("\\", 1)[-1].lower(), int(r["EntryNumber"])): r for r in csv.DictReader(f)}
    wac = {}
    with open(wac_auto, encoding="utf-8-sig") as f:
        for j in json.load(f):
            if isinstance(j, dict):
                for item in j.get("LNKs") or []:
                    wac[(str(j["File"]).rsplit("\\", 1)[-1].lower(), item["DestList"]["EntryNumber"])] = item
    for key in sorted(set(ez) & set(wac)):
        r, w = ez[key], wac[key]
        d = w["DestList"]
        c.note("DestList: MRU position", key, d.get("MruPosition"), int(r["MRU"]))
        c.date("DestList: last modified", key, d.get("LastModificationTimeUtc"), r["LastModified"])
        c.note("DestList: host", key, d.get("Hostname"), r["Hostname"] or None)
        theirs = r["Path"]
        if " ==> " in theirs:
            # JLECmd appends the known folder's name to the path; WAC gives it apart.
            theirs, name = theirs.split(" ==> ", 1)
            if d.get("PathObjectKnownFolder") and d.get("PathObjectKnownFolder") != name:
                c.explained["known folder: registry canonical name (JLECmd, \"Personal\"), display name (WAC, \"Documents\")"] += 1
            else:
                c.note("DestList: known folder name", key, d.get("PathObjectKnownFolder"), name)
        c.note("DestList: path", key, d.get("PathObject"), theirs)
        c.note("DestList: interaction count", key, d.get("InteractionCount"), int(r["InteractionCount"] or 0))
        c.note("DestList: pinned", key, d.get("PinStatus") == "Pinned", r["PinStatus"] == "True")
        c.note("DestList: DROIDs", key, tuple(guid(d.get(k) or "") for k in ("GuidDroidVolume", "GuidDroidFile", "GuidBirthDroidVolume", "GuidBirthDroidFile")),
               tuple(guid(r[k]) for k in ("VolumeDroid", "FileDroid", "VolumeBirthDroid", "FileBirthDroid")))
        if r["CreationTime"]:
            c.date("DestList: DROID created", key, d.get("DroidFileCreatedUtc"), r["CreationTime"])
            c.note("DestList: DROID hardware address", key, mac(d.get("DroidFileHardwareAddress")), mac(r["MacAddress"]))
        compare_shortcut(c, key, r, w)
    only_ez, only_wac = set(ez) - set(wac), set(wac) - set(ez)
    print(f"automatic entries: WAC {len(wac)}, JLECmd {len(ez)}, common {len(set(ez) & set(wac))}; only JLECmd {sorted(only_ez)[:3]}, only WAC {sorted(only_wac)[:3]}")
    ez_custom = collections.defaultdict(list)
    with open(custom_csv, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            ez_custom[r["SourceFile"].rsplit("\\", 1)[-1].lower()].append(r)
    wac_custom_items = collections.defaultdict(list)
    with open(wac_custom, encoding="utf-8-sig") as f:
        for j in json.load(f):
            if isinstance(j, dict):
                wac_custom_items[str(j["Path"]).rsplit("\\", 1)[-1].lower()].extend(j.get("RecentDocs") or [])
    counts = {k: (len(wac_custom_items.get(k, [])), len(ez_custom.get(k, []))) for k in set(ez_custom) | set(wac_custom_items)}
    print(f"custom shortcuts per file (WAC, JLECmd): {counts}")
    for name in set(ez_custom) & set(wac_custom_items):
        for rank, (r, w) in enumerate(zip(ez_custom[name], wac_custom_items[name])):
            compare_shortcut(c, (name, rank), r, w)
    failures = c.report()
    return 1 if failures or only_ez or only_wac or any(a != b for a, b in counts.values()) else 0


# AmcacheParser's CSV -> (WAC's file, WAC's table, the column that pairs the entries, WAC's key for it).
AMCACHE_TABLES = {
    "ProgramEntries": ("amcache_applications.json", None, "ProgramId", "KeyName"),
    "AssociatedFileEntries": ("amcache_application_files.json", None, ("ProgramId", "SHA1", "FullPath"), ("ProgramId", "Sha1", "LongPath")),
    "UnassociatedFileEntries": ("amcache_application_files.json", None, ("ProgramId", "SHA1", "FullPath"), ("ProgramId", "Sha1", "LongPath")),
    "DriveBinaries": ("amcache_inventory.json", "InventoryDriverBinary", "KeyName", "KeyName"),
    "DevicePnps": ("amcache_inventory.json", "InventoryDevicePnp", "KeyName", "KeyName"),
    "DeviceContainers": ("amcache_inventory.json", "InventoryDeviceContainer", "KeyName", "KeyName"),
    "DriverPackages": ("amcache_inventory.json", "InventoryDriverPackage", "KeyName", "KeyName"),
    "ShortCuts": ("amcache_inventory.json", "InventoryApplicationShortcut", "KeyName", "KeyName"),
}
# AmcacheParser's column -> WAC's key, where the names differ.
AMCACHE_COLUMNS = {
    "KeyLastWriteTimestamp": "KeyLastWriteTimeUtc", "FileKeyLastWriteTimestamp": "KeyLastWriteTimeUtc",
    "SHA1": "Sha1", "FullPath": "LongPath", "LinkDate": "LinkDateUtc", "DriverTimeStamp": "DriverTimeStampUtc",
    "LnkName": "ShortcutPath", "InstallDate": "InstallDateUtc", "DriverLastWriteTime": "DriverLastWriteTimeUtc",
    ("DriveBinaries", "DriverId"): "Sha1",   # a driver's DriverId is its SHA-1: WAC names it so
}


def amcache_value(v):
    """A value as comparable text: "True"/"False" and 1/0 alike, dates without T or Z."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    t = str(v)
    if t in ("True", "False"):
        return "1" if t == "True" else "0"
    if re.match(r"^\d{4}-\d\d-\d\d[T ]\d", t):
        # A date to the second: AmcacheParser adds ".0000000", WAC gives the precision stored.
        t = t.replace("T", " ").rstrip("Z")
        return t[:-8] if t.endswith(".0000000") else t
    return t


def compare_amcache(folder):
    """Every table AmcacheParser writes, entry by entry, column by column:
    identical values, differences, and the columns one side has and the
    other not."""
    c = Comparison("AmcacheParser")
    wac_files = {}
    for name in ("amcache_applications.json", "amcache_application_files.json", "amcache_inventory.json"):
        with open(only(folder, name), encoding="utf-8-sig") as f:
            wac_files[name] = [e for e in json.load(f) if isinstance(e, dict)]
    failures = 0
    for table, (wac_file, wac_table, ez_key, wac_key) in AMCACHE_TABLES.items():
        with open(only(folder, f"*_Amcache_{table}.csv"), encoding="utf-8-sig", newline="") as f:
            ez = [r for r in csv.DictReader(f)]
        wac = [e for e in wac_files[wac_file] if wac_table is None or e.get("Table") == wac_table]
        ez_key = ez_key if isinstance(ez_key, tuple) else (ez_key,)
        wac_key = wac_key if isinstance(wac_key, tuple) else (wac_key,)
        # Several entries can share the pairing key (one binary, no path, one
        # program): among them, the one of the same key last write time.
        index = collections.defaultdict(list)
        for e in wac:
            index[tuple(str(e.get(k, "")).lower() for k in wac_key)].append(e)
        missing_columns, only_wac_keys, unmatched = collections.Counter(), collections.Counter(), 0
        for r in ez:
            candidates = index.get(tuple(r[k].lower() for k in ez_key)) or []
            stamp = r.get("FileKeyLastWriteTimestamp") or r.get("KeyLastWriteTimestamp") or ""
            w = next((e for e in candidates if amcache_value(e.get("KeyLastWriteTimeUtc", "")) == stamp), candidates[0] if candidates else None)
            if w is None:
                unmatched += 1
                continue
            lower = {k.lower(): k for k in w}
            for column, theirs in r.items():
                if not theirs or column in ("ApplicationName",):
                    continue
                ours = AMCACHE_COLUMNS.get((table, column), AMCACHE_COLUMNS.get(column, column))
                mine = w.get(lower.get(ours.lower(), ""))
                if mine is None:
                    if column == "FileExtension":
                        c.explained["FileExtension: derived from the path by AmcacheParser, not stored"] += 1
                    elif theirs in ("False", "0"):
                        c.explained["value absent from the hive: AmcacheParser writes a default (False, 0), WAC nothing"] += 1
                    else:
                        missing_columns[column] += 1
                    continue
                if table == "DriverPackages" and column == "Date" and re.match(r"^\d{4}-\d+-\d+$", str(mine)):
                    c.explained["driver package Date: the day as written (WAC), completed with 00:00:00 (AmcacheParser)"] += 1
                    continue
                c.note(f"{table}.{column}", " ".join(r[k] for k in ez_key)[:90], amcache_value(mine), amcache_value(theirs))
            columns = {AMCACHE_COLUMNS.get((table, k), AMCACHE_COLUMNS.get(k, k)).lower() for k in r}
            for k in w:
                # A local date beside its UTC form is the same value.
                if k.lower() not in columns and not k.endswith("Utc") and k + "Utc" not in w and k not in ("Table", "KeyName"):
                    only_wac_keys[k] += 1
        print(f"{table}: AmcacheParser {len(ez)}, WAC {len(wac)}, unpaired {unmatched}")
        if missing_columns:
            print(f"  ⚠️  columns of AmcacheParser absent from WAC: {dict(missing_columns)}")
        if only_wac_keys:
            print(f"  ℹ️  values given by WAC only: {sorted(only_wac_keys)}")
        failures += unmatched + sum(missing_columns.values())
    return 1 if c.report() or failures else 0


def compare_shimcache(ez_csv, wac_json):
    """The cache entry by entry, in its order: position, path, date. The
    execution flag AppCompatCacheParser gives is counted, not compared: WAC does
    not collect it (its "No" is wrong for most binaries Prefetch proves ran)."""
    with open(ez_csv, encoding="utf-8-sig", newline="") as f:
        ez = list(csv.DictReader(f))
    with open(wac_json, encoding="utf-8-sig") as f:
        wac = [e for e in json.load(f) if isinstance(e, dict)]
    c = Comparison("AppCompatCacheParser")
    for r, w in zip(ez, wac):
        key = int(r["CacheEntryPosition"])
        c.note("position", key, w.get("CachePosition"), key)
        c.note("path", key, w.get("Path"), r["Path"])
        c.date("last modification", key, w.get("LastModificationUtc"), r["LastModifiedTimeUTC"])
        c.explained[f"execution flag \"{r['Executed']}\": given by AppCompatCacheParser, not collected by WAC (unreliable)"] += 1
    print(f"entries: WAC {len(wac)}, AppCompatCacheParser {len(ez)}")
    return 1 if c.report() or len(ez) != len(wac) else 0


def compare_shellbags(ez_csv, wac_json):
    """Folder by folder, paired by key path (BagMRU\\4\\0) and slot: rank,
    NodeSlot, subfolders, key times, the last item's name, dates and MFT
    entry. SBECmd's FirstInteracted and LastInteracted are readings of key
    times: checked against the times WAC publishes, not as values of their own."""
    with open(ez_csv, encoding="utf-8-sig", newline="") as f:
        ez = {(r["BagPath"], int(r["Slot"])): r for r in csv.DictReader(f)}
    with open(wac_json, encoding="utf-8-sig") as f:
        roots = [b for b in json.load(f) if isinstance(b, dict)]
    wac = {}
    def walk(bag, path):
        wac[(path, bag["ID"])] = bag
        for child in bag.get("Children") or []:
            walk(child, f"{path}\\{bag['ID']}")
    for b in roots:
        walk(b, b.get("Source", "BagMRU"))
    c = Comparison("SBECmd")
    for key in sorted(set(ez) & set(wac)):
        r, w = ez[key], wac[key]
        c.note("MRU position", key, w.get("MruPosition"), int(r["MRUPosition"]))
        if r["BagPath"] == "BagMRU" and r["NodeSlot"] == "0" and w.get("NodeSlot"):
            # Checked in the VM's registry: BagMRU\\0 holds NodeSlot 1, BagMRU\\4 NodeSlot 6…
            c.explained["NodeSlot of a first-level folder: 0 in SBECmd, the registry's value in WAC (checked)"] += 1
        elif r["NodeSlot"] == "0" and w.get("NodeSlot") is None:
            c.explained["NodeSlot absent from the key: 0 in SBECmd, nothing in WAC"] += 1
        else:
            c.note("NodeSlot", key, w.get("NodeSlot"), int(r["NodeSlot"]) if r["NodeSlot"] else None)
        c.note("subfolders", key, len(w.get("Children") or []), int(r["ChildBags"] or 0))
        c.date("key last write", key, w.get("LastWriteTimeUtc"), r["LastWriteTime"])
        if r["FirstInteracted"]:
            c.date("FirstInteracted = the folder's own key time", key, w.get("KeyLastWriteTimeUtc"), r["FirstInteracted"])
        if r["LastInteracted"]:
            ours = w.get("LastWriteTimeUtc") if w.get("MruPosition") == 0 else w.get("KeyLastWriteTimeUtc")
            c.date("LastInteracted = a key time", key, ours, r["LastInteracted"])
        item = (w.get("ShellItems") or [{}])[-1]
        blocks = [b for b in item.get("ExtensionBlocks") or [] if isinstance(b, dict)]
        delegated = item.get("DelegatedItem") or {}
        names = {str(x).lower().rstrip("\\") for x in (item.get("Name"), item.get("Identifier"), item.get("Uri"),
                 delegated.get("Identifier"), *(b.get("LongName") for b in blocks)) if x}
        names |= {n.split(" (")[0] for n in names}
        if item.get("Type") == "ROOT_FOLDER" and r["Value"].lower().rstrip("\\") not in names:
            c.explained[f"root folder named by its GUID: \"{r['Value']}\" (SBECmd), \"{sorted(names)[0] if names else item.get('GUID')}\" (WAC)"] += 1
        else:
            c.note("name", key, r["Value"].lower().rstrip("\\") in names, True)
        if r["ModifiedOn"]:
            c.date("modified", key, item.get("ModificationDateUtc"), r["ModifiedOn"])
        for b in blocks:
            if r["CreatedOn"] and b.get("CreatedDateUtc"):
                c.date("created", key, b["CreatedDateUtc"], r["CreatedOn"])
            if r["AccessedOn"] and b.get("AccessedDateUtc"):
                c.date("accessed", key, b["AccessedDateUtc"], r["AccessedOn"])
            if r["MFTSequenceNumber"] and b.get("MftEntryNumber") is not None:
                c.note("MFT entry", key, (b["MftEntryNumber"], b.get("MftSequenceNumber")), (int(r["MFTEntry"]), int(r["MFTSequenceNumber"])))
        if r["HasExplored"] == "False":
            c.explained["HasExplored always False in SBECmd's command line (EricZimmerman/Issues#128): not compared"] += 1
    only_ez, only_wac = set(ez) - set(wac), set(wac) - set(ez)
    print(f"folders: WAC {len(wac)}, SBECmd {len(ez)}, common {len(set(ez) & set(wac))}; only SBECmd {sorted(only_ez)[:3]}, only WAC {sorted(only_wac)[:3]}")
    return 1 if c.report() or only_ez or only_wac else 0


def compare_recycle_bin(ez_csv, wac_json):
    """Each $I file: original path, size, deletion time."""
    with open(ez_csv, encoding="utf-8-sig", newline="") as f:
        ez = {r["SourceName"].rsplit("\\", 1)[-1].lower(): r for r in csv.DictReader(f)}
    with open(wac_json, encoding="utf-8-sig") as f:
        wac = {str(e["IndexFile"]).rsplit("\\", 1)[-1].lower(): e for e in json.load(f) if isinstance(e, dict) and "IndexFile" in e}
    c = Comparison("RBCmd")
    for key in sorted(set(ez) & set(wac)):
        r, w = ez[key], wac[key]
        c.note("original path", key, w.get("OriginalPath"), r["FileName"])
        c.note("size", key, w.get("Size"), int(r["FileSize"]))
        c.date("deleted", key, w.get("DeletedUtc"), r["DeletedOn"])
    only_ez, only_wac = set(ez) - set(wac), set(wac) - set(ez)
    print(f"$I files: WAC {len(wac)}, RBCmd {len(ez)}; only RBCmd {sorted(only_ez)[:3]}, only WAC {sorted(only_wac)[:3]}")
    return 1 if c.report() or only_ez or only_wac else 0


SRUM_TABLES = {  # SrumECmd's CSV -> SRUM's table
    "AppResourceUseInfo": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
    "AppTimelineProvider": "{5C8CF1C7-7257-4F13-B223-970EF5939312}",
    "EnergyUsage": "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}",
    "NetworkConnections": "{DD6636C4-8929-4683-974E-22C046A43763}",
    "NetworkUsages": "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
    "PushNotifications": "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}PN",
    "vfuprov": "{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}",
}
SRUM_COLUMNS = {  # SrumECmd's column -> WAC's key, where the names differ
    "Id": "AutoIncId", "Timestamp": "TimeStampUtc", "Sid": "UserSID", "BytesReceived": "BytesRecvd",
    "DurationMs": "DurationMS", "EndTime": "EndTimeUtc", "StartTime": "StartTimeUtc",
    "ConnectStartTime": "ConnectStartTimeUtc", "EventTimestamp": "EventTimestampUtc",
}
# SrumECmd's columns that are its readings, not SRUM's values.
SRUM_DERIVED = {"ExeInfo", "ExeInfoDescription", "ExeTimestamp", "SidType", "UserName", "InterfaceType", "IsLt", "Duration", "ProfileName"}


def compare_srum(folder):
    """Every table SrumECmd writes, row by row (AutoIncId), column by column."""
    with open(only(folder, "srum.json"), encoding="utf-8-sig") as f:
        wac = collections.defaultdict(dict)
        for e in json.load(f):
            if isinstance(e, dict) and "AutoIncId" in e:
                if "TimeStamp" in e and "TimeStampUtc" not in e:
                    e["TimeStampUtc"] = e["TimeStamp"]
                wac[e["Table"]][e["AutoIncId"]] = e
    c = Comparison("SrumECmd")
    unpaired = 0
    for name, table in SRUM_TABLES.items():
        with open(only(folder, f"*_SrumECmd_{name}_Output.csv"), encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        paired = 0
        for r in rows:
            t = table + "LT" if r.get("IsLt") == "True" else table
            w = wac.get(t, {}).get(int(r["Id"]))
            if w is None:
                unpaired += 1
                continue
            paired += 1
            lower = {k.lower(): k for k in w}
            for column, theirs in r.items():
                if column in SRUM_DERIVED or theirs in ("", None):
                    if column in SRUM_DERIVED and theirs:
                        c.explained[f"{column}: SrumECmd's reading (WAC gives the raw App, UserSID and UserName)"] += 1
                    continue
                ours = SRUM_COLUMNS.get(column, column)
                mine = w.get(lower.get(ours.lower(), ""))
                if mine is None:
                    if theirs in ("0", "False", "-1"):
                        c.explained["value absent from the row: SrumECmd writes 0 or -1, WAC nothing"] += 1
                    else:
                        c.note(f"{name}.{column}", r["Id"], None, theirs)
                    continue
                if ours.endswith("Utc"):
                    c.date(f"{name}.{column}", r["Id"], mine, theirs)
                else:
                    c.note(f"{name}.{column}", r["Id"], amcache_value(mine), amcache_value(theirs))
        print(f"{name}: SrumECmd {len(rows)}, paired {paired}")
    print("tables WAC only:", {t: len(v) for t, v in wac.items() if t not in SRUM_TABLES.values() and t[:-2] not in SRUM_TABLES.values()})
    return 1 if c.report() or unpaired else 0


def only(folder, pattern):
    """The one file of the folder matching pattern: the EZ tools prefix their CSV with a timestamp."""
    found = glob.glob(os.path.join(folder, pattern))
    if len(found) != 1:
        sys.exit(f"{pattern}: {len(found)} file(s) in {folder}")
    return found[0]


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    mode, folder = sys.argv[1:]
    if mode == "mft":
        return compare_mft(only(folder, "*_MFTECmd_*Output.csv"), only(folder, "mft.json"), "C:")
    if mode == "evtx":
        return compare_evtx(only(folder, "*_EvtxECmd_Output.csv"), only(folder, "events.json"))
    if mode == "lnk":
        return compare_lnk(only(folder, "*_LECmd_Output.csv"), only(folder, "recentdocs.json"))
    if mode == "jumplist":
        return compare_jumplist(only(folder, "*_AutomaticDestinations.csv"), only(folder, "*_CustomDestinations.csv"),
                                only(folder, "jumplistAutomaticDestinations.json"), only(folder, "jumplistCustomDestinations.json"))
    if mode == "srum":
        return compare_srum(folder)
    if mode == "recycle_bin":
        return compare_recycle_bin(only(folder, "*_RBCmd_Output.csv"), only(folder, "recycle_bin.json"))
    if mode == "shellbags":
        return compare_shellbags(only(folder, "Deduplicated.csv"), only(folder, "shellbags.json"))
    if mode == "shimcache":
        return compare_shimcache(only(folder, "*_AppCompatCache.csv"), only(folder, "shimcache.json"))
    if mode == "amcache":
        return compare_amcache(folder)
    if mode == "prefetch":
        return compare_prefetch(only(folder, "*_PECmd_Output.csv"), only(folder, "prefetchs.json"))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
