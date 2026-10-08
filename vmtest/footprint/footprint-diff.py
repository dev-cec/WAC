#!/usr/bin/env python3
"""footprint-diff.py — what each tool left on the examined machine (backlog B-027),
from the measures of run-footprint.sh.

For each run, from results/<run>/:
  - THE TOOL'S PROCESSES: Sysmon's process creations (1) give the tree that
    starts at the cmd.exe of the scheduled task (its command line names
    K:\\results\\<run>\\console.txt): every process of that tree is the tool's;
  - ITS WRITES: Sysmon's file events (11 created, 2 time changed, 15 stream,
    26 deleted) and registry events (12, 13, 14) of those processes, on C: and
    in the registry: attributed for certain;
  - THE JOURNAL: the change journal between the bounds of the run, each file
    named by its resolved parent folder. A file the tool's processes wrote
    is the tool's; the others are compared with the run "control", by a path
    whose numbers and identifiers are blurred (a temporary name changes from
    one run to the next): what the control run shows too is Windows' own
    activity or the launcher's; what it does not is listed as "not
    attributed" — Windows reacting to the tool (Prefetch, search index) or
    background work that happened to fall in this run;
  - THE EVENT LOGS: the events of the window, by log and identifier, those
    the control run has not;
  - WINDOWS NAMING THE TOOL: registry writes and files of other processes that
    name one of the tool's executables (Amcache's inventory, BAM, Prefetch);
  - THE SHIMCACHE, read after a clean restart: the executables it names that
    the control run's does not — a program of a removable medium is named
    "SIGN.MEDIA=<signature> <path on the medium>".

Writes results/<run>/summary.json and prints a comparison of the runs.

Usage: footprint-diff.py [results folder]   (default: ./results)
"""
import csv
import io
import json
import ntpath
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# USN_RECORD reasons, by their bits: fsutil's words are localised, its hexadecimal value is not.
REASONS = [
    (0x00000100, "created"), (0x00000200, "deleted"), (0x00001000, "renamed (old name)"),
    (0x00002000, "renamed (new name)"), (0x00000001, "overwritten"), (0x00000002, "extended"),
    (0x00000004, "truncated"), (0x00000010, "stream overwritten"), (0x00000020, "stream extended"),
    (0x00000040, "stream truncated"), (0x00000400, "extended attributes"), (0x00000800, "security"),
    (0x00008000, "basic information"), (0x00010000, "hard link"), (0x00080000, "object identifier"),
    (0x00100000, "reparse point"), (0x00200000, "stream added or removed"),
]
WRITE_REASONS = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000010 | 0x00000020 | 0x00000040 \
    | 0x00000100 | 0x00000200 | 0x00001000 | 0x00002000 | 0x00000400 | 0x00000800 | 0x00010000 \
    | 0x00080000 | 0x00100000 | 0x00200000

FILE_EVENTS = {"11": "created", "2": "time changed", "15": "stream created", "26": "deleted"}
REGISTRY_EVENTS = {"12", "13", "14"}


def read_text(path):
    """A file of the guest, UTF-16 (PowerShell's redirection) or UTF-8."""
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig", errors="replace")


def blur(path):
    """A path compared across runs: case folded, identifiers and numbers blurred."""
    p = path.lower()
    p = re.sub(r"wacfootprint-[a-z-]+", "wacfootprint-{run}", p)   # the launcher's task, named after the run
    p = re.sub(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", "{guid}", p)
    p = re.sub(r"[0-9a-f]{8,}", "#", p)
    p = re.sub(r"\d+", "#", p)
    return p


def reasons_of(mask):
    return [word for bit, word in REASONS if mask & bit]


def load_events(path):
    """Events of a wevtutil export: (identifier, time, data by name, system fields)."""
    if not os.path.exists(path):
        return []
    text = read_text(path).strip()
    if not text:
        return []
    root = ET.fromstring(text)
    events = []
    for e in root.findall("e:Event", NS):
        system = e.find("e:System", NS)
        data = {d.get("Name"): (d.text or "") for d in e.findall("e:EventData/e:Data", NS)}
        provider = system.find("e:Provider", NS).get("Name")
        events.append({
            "id": system.findtext("e:EventID", default="", namespaces=NS),
            "provider": provider,
            "time": system.find("e:TimeCreated", NS).get("SystemTime"),
            "data": data,
        })
    return events


def tool_tree(sysmon, run):
    """The ProcessGuids of the tool: the task's cmd.exe and its descendants."""
    marker = f"k:\\results\\{run}\\console.txt".lower()
    created = [e["data"] for e in sysmon if e["id"] == "1"]
    # The task's cmd.exe, started by the Task Scheduler (svchost.exe): a
    # command of the harness that merely names the console file is not one.
    roots = {d["ProcessGuid"] for d in created
             if marker in d.get("CommandLine", "").lower()
             and ntpath.basename(d.get("Image", "")).lower() == "cmd.exe"
             and ntpath.basename(d.get("ParentImage", "")).lower() == "svchost.exe"}
    tree = set(roots)
    grew = True
    while grew:
        grew = False
        for d in created:
            if d.get("ParentProcessGuid") in tree and d["ProcessGuid"] not in tree:
                tree.add(d["ProcessGuid"])
                grew = True
    images = {d["ProcessGuid"]: d.get("Image", "") for d in created}
    return tree, images, [d for d in created if d["ProcessGuid"] in tree]


def load_journal(folder, end_usn):
    """The journal's records between the bounds, each with its full path."""
    parents = {}
    with open(os.path.join(folder, "parents.csv"), encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            parents[row["ParentId"]] = row["Path"]
    records = []
    for row in csv.reader(io.StringIO(read_text(os.path.join(folder, "usn.csv")))):
        if not row or not row[0].isdigit():
            continue
        usn = int(row[0])
        if usn >= end_usn:
            continue
        ids = [v for v in row if re.fullmatch(r"[0-9a-f]{32}", v)]
        parent = parents.get(ids[1], "") if len(ids) > 1 else ""
        name = row[1]
        records.append({
            "usn": usn, "name": name, "mask": int(row[3], 16),
            "path": (parent + "\\" + name) if parent else ("?\\" + name),
        })
    return records


def shimcache_paths(folder):
    """The executables named in the ShimCache read after the restart."""
    path = os.path.join(folder, "appcompatcache.txt")
    if not os.path.exists(path):
        return set()
    match = re.search(r"REG_BINARY\s+([0-9A-Fa-f]+)", read_text(path))
    if not match:
        return set()
    text = bytes.fromhex(match.group(1)).decode("utf-16-le", errors="replace")
    # A path, or, for a removable medium, "SIGN.MEDIA=<signature> <path on it>".
    entry = r"(?:[A-Za-z]:\\|SIGN\.MEDIA=[0-9A-Fa-f]+ )[^\x00-\x1f\ufffd]{1,259}?\.(?:exe|dll|cmd|bat|ps1|com|sys)"
    return {m.lower() for m in re.findall(entry, text, re.I)}


def analyse(folder, run, control=None):
    meta = json.loads(read_text(os.path.join(folder, "run.json")))
    sysmon = load_events(os.path.join(folder, "sysmon.xml"))
    tree, images, processes = tool_tree(sysmon, run)

    files_by_tool = defaultdict(set)      # path -> Sysmon actions
    registry_by_tool = defaultdict(set)   # key -> actions
    raw_reads = Counter()
    accessed = Counter()
    output_files = Counter()
    for e in sysmon:
        d = e["data"]
        if d.get("ProcessGuid") not in tree and d.get("SourceProcessGUID") not in tree:
            continue
        if e["id"] in FILE_EVENTS:
            target = d.get("TargetFilename", "")
            if target[:2].upper() == "K:":
                output_files[target.split("\\")[1] if "\\" in target else target] += 1
            else:
                files_by_tool[target].add(FILE_EVENTS[e["id"]])
        elif e["id"] in REGISTRY_EVENTS:
            registry_by_tool[d.get("TargetObject", "")].add(d.get("EventType", e["id"]))
        elif e["id"] == "9":
            raw_reads[d.get("Device", "")] += 1
        elif e["id"] == "10":
            accessed[ntpath.basename(d.get("TargetImage", ""))] += 1

    # Windows reacting to the tool: what other processes wrote that names one of
    # its executables (Amcache's inventory, BAM, Prefetch).
    tool_names = {ntpath.basename(d.get("Image", "")).lower() for d in processes
                  if d.get("Image", "")[:2].upper() == "K:"}
    indirect_registry = defaultdict(set)
    for e in sysmon:
        d = e["data"]
        if e["id"] in REGISTRY_EVENTS and d.get("ProcessGuid") not in tree:
            target = d.get("TargetObject", "")
            if any(n and n in target.lower() for n in tool_names):
                indirect_registry[target].add(ntpath.basename(d.get("Image", "")))

    journal = load_journal(folder, meta["EndUsn"])
    changed = defaultdict(int)
    for r in journal:
        if r["mask"] & WRITE_REASONS:
            changed[r["path"]] |= r["mask"]
    tool_paths = {p.lower() for p in files_by_tool}
    control_blurred = set(control["journal_blurred"]) if control else set()
    attributed, background, unattributed = {}, {}, {}
    named = {}
    for path, mask in sorted(changed.items()):
        if any(n and ntpath.basename(path).lower().startswith(n.rsplit(".", 1)[0] + ".") for n in tool_names):
            named[path] = reasons_of(mask)
        elif path.lower() in tool_paths:
            attributed[path] = reasons_of(mask)
        elif blur(path) in control_blurred:
            background[path] = reasons_of(mask)
        else:
            unattributed[path] = reasons_of(mask)

    # Events: those whose data name one of the tool's processes are its own.
    pids = {int(d["ProcessId"]) for d in processes if d.get("ProcessId", "").isdigit()}
    pid_fields = ("ProcessId", "ClientProcessId", "NewProcessId", "CallerProcessId", "SubjectProcessId")
    def event_pid_is_tool(data):
        for field in pid_fields:
            value = data.get(field, "")
            try:
                if value and int(value, 16 if value.lower().startswith("0x") else 10) in pids:
                    return True
            except ValueError:
                pass
        return False
    logs, events_by_tool = {}, {}
    for name in os.listdir(folder):
        if name.startswith("events-") and name.endswith(".xml"):
            events = load_events(os.path.join(folder, name))
            counts = Counter(f"{e['provider']}/{e['id']}" for e in events)
            if counts:
                logs[name[7:-4]] = dict(counts)
            own = Counter(f"{e['provider']}/{e['id']}" for e in events if event_pid_is_tool(e["data"]))
            if own:
                events_by_tool[name[7:-4]] = dict(own)
    new_events = {}
    for log, counts in logs.items():
        known = control["event_logs"].get(log, {}) if control else {}
        extra = {k: v for k, v in counts.items() if k not in known}
        if extra:
            new_events[log] = extra

    shim = shimcache_paths(folder)
    shim_new = sorted(shim - set(control["shimcache"])) if control else []

    start = datetime.fromisoformat(meta["StartUtc"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(meta["EndUtc"].replace("Z", "+00:00"))
    summary = {
        "run": run,
        "command": meta["Command"],
        "task_result": meta["TaskResult"],
        "duration_s": round((end - start).total_seconds(), 1),
        "processes": sorted({ntpath.basename(images.get(g, "")) for g in tree} - {""}),
        "process_creations": len(processes),
        "journal_records": len(journal),
        "files_by_tool": {p: sorted(a) for p, a in sorted(files_by_tool.items())},
        "registry_by_tool": {k: sorted(a) for k, a in sorted(registry_by_tool.items())},
        "raw_reads": dict(raw_reads),
        "process_accesses": dict(accessed),
        "files_on_key": dict(output_files),
        "journal_attributed": attributed,
        "journal_naming_tool": named,
        "registry_naming_tool": {k: sorted(v) for k, v in sorted(indirect_registry.items())},
        "events_by_tool": events_by_tool,
        "journal_unattributed": unattributed,
        "journal_background": len(background),
        "event_logs": logs,
        "new_events": new_events,
        "shimcache_new": shim_new,
        "journal_blurred": sorted({blur(p) for p in changed}),
        "shimcache": sorted(shim),
    }
    with open(os.path.join(folder, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    return summary


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    runs = [r for r in ["control", "wac-collect", "wac-full", "kape-targets", "kape-modules", "ez-live"]
            if os.path.exists(os.path.join(root, r, "run.json"))]
    if "control" not in runs:
        sys.exit("no control run: nothing to subtract")
    control = analyse(os.path.join(root, "control"), "control")
    for run in runs:
        s = control if run == "control" else analyse(os.path.join(root, run), run, control)
        print(f"== {run}: {s['duration_s']} s, task result {s['task_result']}")
        print(f"   processes: {', '.join(s['processes'])}")
        print(f"   written by the tool on C: {len(s['files_by_tool'])} file(s); registry {len(s['registry_by_tool'])} value(s) or key(s)")
        print(f"   journal: {s['journal_records']} record(s); attributed {len(s['journal_attributed'])}, "
              f"not attributed {len(s['journal_unattributed'])}, as in the control run {s['journal_background']}")
        print(f"   raw reads: {s['raw_reads']}; files on the key: {s['files_on_key']}")
        print(f"   Windows naming the tool: files {s['journal_naming_tool']}, registry {s['registry_naming_tool']}")
        print(f"   events of the tool's processes: {s['events_by_tool']}")
        print(f"   new event kinds (any process): {sum(len(v) for v in s['new_events'].values())}")
        print(f"   ShimCache, new: {s['shimcache_new']}")


if __name__ == "__main__":
    main()
