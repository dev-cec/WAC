#!/usr/bin/env python3
"""timing-table.py — WAC's running times set against KAPE's and the EZ tools',
from ONE collection and ONE conversion (B-015, B-027).

WAC pays some steps once for all the artefacts — opening and checking the
collection, rebuilding the working copy, replaying the hives — where each EZ
tool, run on its own, pays its own start. Timing WAC artefact by artefact
(one conversion each) made it pay its shared steps every time: here its time
per step (investigation.json, conversion.json) is read instead, each
artefact's step set against the EZ tool that decodes it, and the shared steps
given apart.

Inputs:
  --conversion <conversion.json>   the cycle's conversion (split/conversion.json)
  --ez <results/ez>                the last timing.txt of each comparison
  --collection <investigation.json> --kape <timing.txt>   (kape-compare.sh)

Usage: timing-table.py --conversion F --ez D [--collection F --kape F]
"""
import argparse
import glob
import json
import os
import re

# Each EZ comparison, and the WAC steps that decode the same artefact.
CONVERSION = [
    ("mft", "MFTECmd", ["Reading the $MFT (C:)", "Writing the $MFT (C:)"]),
    ("events", "EvtxECmd", ["Extraction of EVENTS"]),
    ("prefetch", "PECmd", ["Extracting PREFETCHS"]),
    # LECmd reads every shortcut of the profiles: Recent and the others.
    ("recent_documents", "LECmd", ["Extracting RECENT DOCS", "Extracting SHORTCUTS"]),
    ("jump_lists", "JLECmd", ["Extracting JUMPLIST AUTOMATIC", "Extracting JUMPLIST CUSTOM"]),
    ("shellbags", "SBECmd", ["Extracting SHELLBAGS Registry Keys"]),
    ("shimcache", "AppCompatCacheParser", ["Extracting SHIMCACHE Registry Keys"]),
    ("amcache", "AmcacheParser", ["Amcache inventory (applications, executables, drivers, devices)"]),
    ("recycle_bin", "RBCmd", ["Extracting RECYCLE BIN"]),
    ("srum", "SrumECmd", ["Extracting RESOURCE USAGE (SRUM)"]),
    ("registry", "RECmd (Kroll batch)", [
        "Extracting USBSTOR Registry Keys", "Extracting the MOUNTED DEVICE registry keys", "Extracting BAM Registry Keys",
        "Extracting MUICACHE Registry Keys", "Extracting USERASSIST Registry Keys", "Extracting RUN Registry Keys",
        "Extracting MRU Registry Keys", "Extracting MRUAPPS Registry Keys",
        "Extracting REGISTRY PERSISTENCE (IFEO, AppInit, Winlogon, LSA, COM…)",
        "Extracting Office TRUSTED DOCUMENTS (macros enabled)", "Extracting Explorer TYPED PATHS",
        "Extracting Explorer SEARCHES (WordWheelQuery)", "Extracting INTERNET SETTINGS (proxy) of the users",
        "Extracting FIREWALL rules and profiles", "Extracting INSTALLED PROGRAMS (Uninstall)",
        "Extracting DEFENDER CONFIGURATION (exclusions, protection)", "Extracting EXPLORER RECENTDOCS",
        "Extracting MOUNTPOINTS2 (volumes and shares)", "Extracting KNOWN NETWORKS (NetworkList)",
        "Extraction of SYSTEM INFORMATION", "Extraction of SERVICES", "Extraction of USERS"]),
]
# The conversion's steps paid once, for every artefact.
SHARED_CONVERSION = [
    "Checking the seal and the fingerprints of the exhibits", "Rebuilding the working copy from the exhibit store",
    "Repairing the hives of the working copy", "Opening the SYSTEM hive", "Opening the SOFTWARE hive",
    "Listing USER PROFILES (SOFTWARE hive)", "Opening the CurrentControlSet subkey",
    "Reading suspect time zone (SYSTEM hive)", "Reading suspect ANSI code page (SYSTEM hive)",
    "Naming the accounts (SAM, services, profiles)",
]
# The collection's steps, by what they do; anything else is "other".
COLLECTION = [
    ("checks and trust set", ["Check administrator rights", "Checking the collection medium", "Trust set"]),
    ("live observations", ["Extraction of RUNNING MACHINE SETTINGS", "Extraction of SESSIONS", "Extraction of PROCESS",
                           "Extraction of NETWORK STATE", "Extraction of SERVICE STATES", "Extraction of SYSTEM CLOCK"]),
    ("hives, file artefacts, NTFS and FAT metadata (raw reading)", [
        "Extracting system hives (raw NTFS)", "Opening the SYSTEM hive", "Opening the SOFTWARE hive",
        "Listing USER PROFILES (SOFTWARE hive)", "Extracting user hives (raw NTFS)", "Extracting file artefacts (raw NTFS)",
        "Extracting NTFS metadata ($MFT, $UsnJrnl, $LogFile) (raw NTFS)", "Extracting BOOT RECORDS",
        "FAT and exFAT volumes (raw reading of the metadata)", "Shadow copies (raw reading, without the VSS service)"]),
    ("event providers' resource files", ["Extracting the resource files of the providers the logs cite"]),
    ("deleted files recovered (KAPE: none)", ["Recovering DELETED FILES (raw reading)"]),
    ("every executable read, signatures checked", ["Reading every executable, collecting the unauthenticated (raw NTFS)"]),
    ("sealing (manifest, three fingerprints)", ["Sealing the exhibit store (manifest + SHA-256)"]),
]


def steps(path):
    """The time of each step a WAC journal records."""
    with open(path, encoding="utf-8-sig") as f:
        log = json.load(f)
    for o in log.get("Operations", []):
        op = str(o.get("Operation", ""))
        if op.startswith("Time per step: "):
            return {m.group(1): float(m.group(2))
                    for m in re.finditer(r"(.+?) (\d+\.\d+) s(?:; |$)", op[len("Time per step: "):])}
    raise SystemExit(f"{path}: no time per step")


def last_timing(folder, key):
    """The tool's seconds of the last comparison of that key."""
    runs = sorted(glob.glob(os.path.join(folder, f"{key}-2*")))
    if not runs:
        return None
    with open(os.path.join(runs[-1], "timing.txt"), encoding="utf-8") as f:
        m = re.search(r"ez_seconds=([\d,.]+)", f.read())
    return float(m.group(1).replace(",", ".")) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conversion", required=True)
    ap.add_argument("--ez", required=True)
    ap.add_argument("--collection")
    ap.add_argument("--kape")
    a = ap.parse_args()

    conv = steps(a.conversion)
    print("== Conversion: each artefact, WAC's step and the EZ tool on the same exhibits")
    wac_total = ez_total = 0.0
    used = set(SHARED_CONVERSION)
    for key, tool, names in CONVERSION:
        mine = sum(conv.get(n, 0.0) for n in names)
        used.update(names)
        theirs = last_timing(a.ez, key)
        wac_total += mine
        ez_total += theirs or 0.0
        print(f"  {key:18} WAC {mine:7.2f} s   {tool:22} {theirs if theirs is not None else '—'} s")
    shared = sum(conv.get(n, 0.0) for n in SHARED_CONVERSION)
    others = {n: t for n, t in conv.items() if n not in used}
    print(f"  {'(sum)':18} WAC {wac_total:7.2f} s   {'the 11 tools':22} {ez_total:.1f} s")
    print(f"  WAC's shared steps, once: {shared:.2f} s — " + "; ".join(f"{n} {conv.get(n, 0):.2f}" for n in SHARED_CONVERSION if conv.get(n, 0) >= 0.05))
    print(f"  WAC's other artefacts (no EZ tool compared): {sum(others.values()):.2f} s over {len(others)} step(s); heaviest: "
          + "; ".join(f"{n} {t:.2f}" for n, t in sorted(others.items(), key=lambda x: -x[1])[:6]))
    print(f"  WAC's whole conversion: {sum(conv.values()):.2f} s")

    if a.collection and a.kape:
        coll = steps(a.collection)
        with open(a.kape, encoding="utf-8") as f:
            k = f.read()
        kape = float(re.search(r"kape_seconds=([\d,.]+)", k).group(1).replace(",", "."))
        wac = float(re.search(r"wac_seconds=([\d,.]+)", k).group(1).replace(",", "."))
        print("== Collection: WAC's steps by what they do, against KAPE's whole run")
        grouped = set()
        for label, names in COLLECTION:
            grouped.update(names)
            print(f"  {label:58} {sum(coll.get(n, 0.0) for n in names):8.2f} s")
        rest = sum(t for n, t in coll.items() if n not in grouped)
        print(f"  {'other':58} {rest:8.2f} s")
        print(f"  WAC's collection {wac:.1f} s (its steps {sum(coll.values()):.1f} s); KAPE {kape:.1f} s")


if __name__ == "__main__":
    main()
