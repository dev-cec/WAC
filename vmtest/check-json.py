#!/usr/bin/env python3
"""check-json.py — checks WAC's JSON output.

Two checks:
  1. JSON validity of every file;
  2. consistency of the Windows paths — a path that went through a double
     escaping shows up, AFTER parsing, with doubled backslashes.

What is NOT checked here: the accuracy and the completeness of the data. A valid
JSON file may hold wrong values (wrong field, misinterpreted date) or be
truncated by a premature stop of the collection — it is run-wac-test.sh that
checks WAC ran to the end.

Non-zero exit if at least one file is invalid or inconsistent.
"""
import ntpath
import json, sys, glob, os, re, collections

# A double escaping is recognised on a PATH pattern, not on free text: the
# content of an event (PowerShell script, regular expression, command line) may
# legitimately hold "\\" — for instance 'TIP\\(?:' where "\\" is PowerShell's
# escaping of a literal backslash. Only the patterns where the doubling is
# certainly wrong are therefore reported.
FAULTY_PATTERNS = (
    re.compile(r'[A-Za-z]:\\\\'),          # C:\\Windows  (drive)
    re.compile(r'^\\\\\\\\[A-Za-z0-9]'),   # \\\\server  (UNC already doubled)
    re.compile(r'\\\\\\\\(?:Device|REGISTRY|SystemRoot|\?\?)\\\\', re.I),
)

def inconsistencies(value):
    """Returns the list of doubly escaped path patterns in the value."""
    return [m.group(0) for pattern in FAULTY_PATTERNS for m in pattern.finditer(value)]

def walk(obj, path=""):
    """Yields (json_path, value) for every string, depth first."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            yield from walk(val, f"{path}.{key}")
    elif isinstance(obj, list):
        for val in obj:
            yield from walk(val, path)
    elif isinstance(obj, str):
        yield path, obj

def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    ok = invalid = inconsistent = 0

    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        name = os.path.basename(file)
        try:
            with open(file, encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  ❌ {name:<34} INVALID: {str(e)[:70]}")
            invalid += 1
            continue

        count = len(data) if isinstance(data, list) else 1

        # An artefact whose collection failed: not a format error, but it must
        # show — otherwise a missing artefact goes unnoticed.
        if isinstance(data, dict) and data.get("CollectionStatus") == "NotCollected":
            print(f"  ⏭️  {name:<34} NOT COLLECTED — {data.get('Error', '?')}")
            ok += 1
            continue

        faults = [(p, v, m) for p, v in walk(data)
                            for m in [inconsistencies(v)] if m]

        if faults:
            print(f"  ⚠️  {name:<34} {count:>6} entries — "
                  f"doubly escaped path in {len(faults)} value(s)")
            for p, v, patterns in faults[:3]:
                print(f"        {p} → {patterns[0]!r} in {v[:70]!r}")
            inconsistent += 1
        else:
            print(f"  ✅ {name:<34} {count:>6} entries")
            ok += 1

    print(f"\n{ok} passed, {inconsistent} with a doubly escaped path, "
          f"{invalid} invalid")

    inconsistent += cross_checks(folder)
    return 1 if (invalid or inconsistent) else 0


def load(folder, name):
    """Loads an output JSON file, or None if it is absent or unreadable."""
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def cross_checks(folder):
    """CONSISTENCY checks between artefacts.

    These checks catch defects that neither the syntax nor the validity of the
    paths reveal: a correctly formatted date may name the wrong instant. The case
    that motivated this block: every session started two hours BEFORE the
    system's boot — the symptom of a double time shift (a UTC value treated as
    local) on `sessions`, invisible otherwise.

    Returns the number of inconsistencies found.
    """
    print("\n-- Consistency between artefacts --")
    found = 0

    osj = load(folder, "OperatingSystem.json")
    sessions = load(folder, "Sessions.json")

    boot = (osj or {}).get("LastBootUpTimeUtc") if isinstance(osj, dict) else None
    if not boot:
        print("  ⏭️  boot time absent: sessions/boot check skipped")
    elif not isinstance(sessions, list):
        print("  ⏭️  Sessions.json absent: sessions/boot check skipped")
    else:
        # A session cannot start before the system's boot.
        # STRICT comparison: the boot time comes from the kernel (BootTime -
        # BootTimeBias), on the same clock as the logons. The comment used to
        # announce a 60 s tolerance that the code did not apply; that is what
        # revealed the GetTickCount64 estimate, 3.5 s off after a clock
        # adjustment.
        before = sorted({s.get("StartTimeUtc") for s in sessions
                         if s.get("StartTimeUtc") and instant(s["StartTimeUtc"]) < instant(boot)})
        if before:
            print(f"  ❌ {len(before)} session(s) start BEFORE the boot ({boot})")
            for v in before[:3]:
                print(f"        StartTimeUtc = {v}")
            print("        → probable time shift on sessions or on the boot")
            found += 1
        else:
            print(f"  ✅ no session earlier than the boot ({boot})")
    found += check_boot_kernel_general(folder, boot)

    # The <field>/<field>Utc pairs must name the SAME instant: if the local suffix
    # and the Z suffix carry the same wall-clock time, one of them is mislabelled.
    suspects = 0
    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        d = load(folder, os.path.basename(file))
        if d is None:
            continue
        for key, val, keyUtc, valUtc in date_pairs(d):
            # "2026-09-15T08:00:00+02:00" and "...T08:00:00Z": same wall-clock time
            if val[:19] == valUtc[:19] and not val.endswith("Z"):
                suspects += 1
                if suspects <= 3:
                    print(f"  ❌ {os.path.basename(file)}: {key}={val} "
                          f"and {keyUtc}={valUtc} carry the same wall-clock time")
    if suspects:
        print(f"  ❌ {suspects} mislabelled local/UTC pair(s)")
        found += 1
    else:
        print("  ✅ local/UTC pairs consistent")

    found += check_services(folder)
    found += check_users(folder)
    found += check_processes(folder)
    found += check_prefetchs(folder)
    found += check_shimcache_dates(folder)
    found += check_events(folder)
    found += check_hive_replay(folder)
    found += check_exhibit_store(folder)
    found += check_mft_references(folder)
    return found


def check_events(folder):
    """Consistency of the event logs, decoded offline from the .evtx files.

    BinXML decoding is WAC's most fragile part: a one-byte shift on a name offset,
    or a badly resolved template, does not produce an error — it produces events
    with empty fields or displaced values, in a perfectly valid JSON. Four
    independent checks:

      - `EvtSystemComputer` must match the name read in `OperatingSystem.json`,
        which comes from the SYSTEM hive: two unrelated sources, hence a real
        confrontation;
      - an event without a provider or a channel signals a decoding that drifted;
      - the record identifiers must be UNIQUE per file. WAC walks every physical
        chunk of the file and not those declared by the header (that is what
        makes it read the records a badly closed log does not count); the risk
        specific to that choice is re-reading a stale chunk of a circular log,
        which would show here;
      - no event can be later than the collection.
    """
    d = load(folder, "events.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  events.json absent or empty: check skipped")
        return 0
    found = 0

    # 1. machine name, confronted with an unrelated source
    osj = load(folder, "OperatingSystem.json")
    expected = {str(v).upper() for k, v in (osj or {}).items()
                if isinstance(osj, dict) and k in ("CSName", "NetbiosName", "ComputerName") and v}
    names = collections.Counter(str(e.get("EvtSystemComputer") or "").split(".")[0].upper()
                                for e in d if e.get("EvtSystemComputer"))
    if not expected:
        print("  ⏭️  machine name absent from OperatingSystem.json: check skipped")
    elif not names:
        print("  ❌ events.json: no event carries a machine name")
        found += 1
    else:
        foreign = {n: c for n, c in names.items() if n not in expected}
        share = sum(foreign.values()) / sum(names.values())
        majority = names.most_common(1)[0][0]
        if majority not in expected:
            print(f"  ❌ events.json: the MAJORITY machine name is "
                  f"{majority!r}, absent from OperatingSystem.json {sorted(expected)}")
            found += 1
        elif foreign:
            # A machine rename, or events forwarded from another workstation (WEC
            # collector), legitimately leave old names in the logs: that is
            # information, not a defect.
            print(f"  ✅ events.json: majority name matches ({majority}), "
                  f"{share:.0%} of events under {len(foreign)} other name(s) "
                  f"{list(foreign)[:2]} — rename or forwarded events")
        else:
            print(f"  ✅ events.json: machine name matches OperatingSystem.json "
                  f"({sum(names.values())} event(s))")

    # 2. structuring fields filled
    noProvider = sum(1 for e in d if not e.get("EvtSystemProviderName"))
    noChannel  = sum(1 for e in d if not e.get("EvtSystemChannel"))
    noDate     = sum(1 for e in d if not e.get("EvtSystemTimeCreated"))
    # Threshold at one per thousand: a few badly decoded records among tens of
    # thousands are to be reported but do not condemn the collection, whereas a
    # higher proportion betrays a drift of the decoding. WAC logs the raw XML of
    # those records, which makes them diagnosable one by one.
    worst = max(noProvider, noDate)
    if noChannel or worst * 1000 > len(d):
        print(f"  ❌ events.json: {noProvider} without a provider, {noChannel} without a channel, "
              f"{noDate} without a date out of {len(d)} — BinXML decoding to be checked")
        found += 1
    elif worst:
        # A record may legitimately carry NO data: its substitutions are all
        # null, and the format then prescribes omitting the matching elements.
        # Checked on a real case: the record's 18 substitution values were null.
        # So it is not a reading defect, but it must stay visible.
        print(f"  ℹ️  events.json: {worst} record(s) out of {len(d)} without an "
              f"identifier or a date — null substitutions in the log itself")
    else:
        print(f"  ✅ events.json: {len(d)} event(s), provider/channel/date filled")

    # 3. uniqueness of the identifiers per SOURCE FILE, and not per channel
    #
    # One channel can be carried by several files — the current log and its
    # archives — whose record numbers legitimately overlap. The real invariant is
    # uniqueness WITHIN ONE FILE: the same number twice in a file means a stale
    # chunk of a circular log was re-read, which is the risk specific to the
    # choice of walking every physical chunk.
    if not any(e.get("EvtSourceLog") for e in d):
        print("  ⏭️  events.json: provenance absent, uniqueness check skipped")
    else:
        seen = collections.defaultdict(set)
        duplicates = collections.Counter()
        for e in d:
            src, rid = e.get("EvtSourceLog"), e.get("EvtSystemEventRecordId")
            if src is None or rid is None:
                continue
            if rid in seen[src]:
                duplicates[src] += 1
            seen[src].add(rid)
        if duplicates:
            print(f"  ❌ events.json: identifiers repeated WITHIN ONE FILE "
                  f"({len(duplicates)} file(s)) {duplicates.most_common(3)} — "
                  f"a stale chunk was probably re-read")
            found += 1
        else:
            print(f"  ✅ events.json: identifiers unique in each of the "
                  f"{len(seen)} log file(s)")
        # Overlaps BETWEEN files of one channel are normal: they are counted for
        # information, since they signal the presence of archives.
        byChannel = set()
        overlap = 0
        for e in d:
            key = (e.get("EvtSystemChannel"), e.get("EvtSystemEventRecordId"))
            if key[0] is None or key[1] is None: continue
            if key in byChannel: overlap += 1
            byChannel.add(key)
        if overlap:
            print(f"  ℹ️  events.json: {overlap} event(s) of the same channel and "
                  f"number coming from different files (current log + archive)")

    # 4. plain-text messages: proportion and consistency
    #
    # The message is rebuilt from the provider's resources, a chain of five links
    # (registry, PE, WEVT_TEMPLATE, MESSAGETABLE, substitution). If one breaks, the
    # field disappears without an error — hence this proportion check. A message
    # that keeps an unsubstituted "%1" mark signals, for its part, missing data.
    withMsg = [e for e in d if e.get("EvtEventMessage")]
    if not withMsg:
        print("  ⚠️  events.json: no plain-text message — resolution chain "
              "to be checked (registry, PE resources, WEVT_TEMPLATE)")
    else:
        # What comes from the DATA is not a mark of the template: an encoded URL
        # ("P4=CQ%2bHw") made 47 BITS messages count wrongly. The values are
        # therefore removed from the message before the search.
        def leftover(e):
            m = str(e.get("EvtEventMessage"))
            for v in sorted((str(x.get("Value", "")) for x in (e.get("EvtEventData") or [])
                             if isinstance(x, dict)), key=len, reverse=True):
                if len(v) > 1 and not re.fullmatch(r"%%\d+", v):
                    m = m.replace(v, "")
            return m
        references = [e for e in withMsg if re.search(r"%%\d", leftover(e))]
        marks = [e for e in withMsg if re.search(r"(?<!%)%\d", leftover(e))]
        print(f"  ✅ events.json: {len(withMsg)} plain-text message(s) "
              f"({100*len(withMsg)/len(d):.0f}% of the events)")
        # "%%1842" left as it is: the label exists in the provider's parameter
        # file, and WAC did not resolve it.
        if references:
            providers = collections.Counter(e.get("EvtSystemProviderName") for e in references)
            print(f"  ❌ events.json: {len(references)} message(s) keep an unresolved "
                  f"%%nnnn reference — the provider's parameter file "
                  f"{providers.most_common(2)}")
            found += 1
        # "%3" left as it is: the event does not carry the data. A fact, not a
        # defect — the mark is kept visible so that the sentence does not look
        # complete.
        if marks:
            print(f"  ℹ️  events.json: {len(marks)} message(s) keep a %N mark "
                  f"— data absent from the event itself")

    # 5. no event later than the collection
    inv = load(folder, "investigation.json")
    # The timestamps are under "Collection", not at the root.
    coll = (inv or {}).get("Collection") if isinstance(inv, dict) else None
    end = (coll or {}).get("EndUtc") or (coll or {}).get("StartUtc") if isinstance(coll, dict) else None
    future = [e.get("EvtSystemTimeCreated") for e in d
              if end and str(e.get("EvtSystemTimeCreated") or "") > str(end)]
    if not end:
        print("  ⏭️  collection timestamp absent: future-dates check skipped")
    elif future:
        print(f"  ❌ events.json: {len(future)} event(s) later than the collection "
              f"({end}) — e.g. {future[:2]}")
        found += 1
    else:
        print("  ✅ events.json: no event later than the collection")
    return found


# The labels of the operations recorded in investigation.json. Both languages are
# recognised, so that archived results (French labels, before 2026-09-24) stay
# checkable.
REPLAY_OP = ("Replay of the transaction logs", "Rejeu des journaux")
NOT_APPLIED = ("(not applied)", "non applique")
UNDO_MARK = ("undo:", "annulation :")
PATCH_OP = ("Repair of a copied hive (patch applied)",
            "Remise en etat d'une ruche copiee (patch applique)")


def check_hive_replay(folder):
    """The replay of the logs must leave the hive clean — hence without a patch.

    A cross-check in the strong sense, on two independent operations recorded in
    `investigation.json`: if the replay succeeded, the check that follows must
    find the hive "already clean". A hive both replayed AND patched means the
    replay did not align the sequence numbers, so the state written is not the
    one it claims to be.

    Also checks that an undo journal is named for every replay: without it the
    raw copy can no longer be rebuilt, and the report's promise would be false.
    """
    inv = load(folder, "investigation.json")
    ops = (inv or {}).get("Operations") if isinstance(inv, dict) else None
    if not isinstance(ops, list) or not ops:
        print("  ⏭️  investigation.json absent: replay check skipped")
        return 0
    found = 0

    def hive_of(target):
        # The target starts with the hive's path, followed by " | ".
        return str(target or "").split(" | ")[0].strip().lower()

    replayed, patched, noUndo, replayKo = set(), set(), [], []
    for o in ops:
        op = str(o.get("Operation") or "")
        target = o.get("Target")
        if op.startswith(REPLAY_OP):
            if any(n in op for n in NOT_APPLIED) or o.get("Result") != "OK":
                replayKo.append(hive_of(target))
                continue
            replayed.add(hive_of(target))
            if not any(u in str(target or "") for u in UNDO_MARK):
                noUndo.append(hive_of(target))
        elif op.startswith(PATCH_OP):
            patched.add(hive_of(target))

    if not replayed and not patched:
        print("  ⏭️  no hive repair recorded: check skipped")
        return 0

    both = sorted(replayed & patched)
    if both:
        print(f"  ❌ {len(both)} hive(s) both replayed AND patched "
              f"{[os.path.basename(x) for x in both[:3]]} — the replay did not "
              f"align the sequence numbers")
        found += 1
    else:
        print(f"  ✅ hive replay: {len(replayed)} replayed, "
              f"{len(patched)} patched, none of them both")

    if noUndo:
        print(f"  ❌ {len(noUndo)} replay(s) without an undo journal "
              f"{[os.path.basename(x) for x in noUndo[:3]]} — raw copy "
              f"cannot be rebuilt")
        found += 1
    elif replayed:
        print(f"  ✅ hive replay: undo journal named for the "
              f"{len(replayed)} replay(s)")
    if replayKo:
        print(f"  ⚠️  {len(replayKo)} hive(s) without an applicable replay "
              f"{[os.path.basename(x) for x in replayKo[:3]]} — fallback on the patch")
    return found


def instant(text):
    """ISO 8601 timestamp (fraction of 0 to 7 digits, Z or offset) -> datetime."""
    import datetime
    t = str(text).replace("Z", "+00:00")
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(.*)$", t)
    if not m:
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    return datetime.datetime.fromisoformat(f"{m.group(1)}.{frac}{m.group(3) or '+00:00'}")


def check_boot_kernel_general(folder, boot):
    """The boot time confronted with the Kernel-General 12 event.

    At every boot, the kernel writes into System event 12 of
    Microsoft-Windows-Kernel-General, whose StartTime data is the boot time: a
    source independent of the one WAC reads (a live kernel query). Tolerated
    gap: 1 s.
    """
    if not boot:
        return 0
    ev = load(folder, "events.json")
    if not isinstance(ev, list):
        print("  ⏭️  events.json absent: boot time not confronted with Kernel-General 12")
        return 0
    starts = []
    for e in ev:
        if "Kernel-General" not in str(e.get("EvtSystemProviderName", "")) \
           or str(e.get("EvtSystemEventID")) != "12":
            continue
        for d in e.get("EvtEventData") or []:
            if isinstance(d, dict) and d.get("Name") == "StartTime" and d.get("Value"):
                starts.append(d["Value"])
    if not starts:
        print("  ⏭️  no Kernel-General 12 event: boot time not confronted")
        return 0
    last = max(starts, key=instant)
    gap = abs((instant(boot) - instant(last)).total_seconds())
    if gap > 1:
        print(f"  ❌ boot time {boot} ≠ Kernel-General 12 {last} "
              f"(gap {gap:.1f} s)")
        return 1
    print(f"  ✅ boot time matches Kernel-General 12 ({last}, gap {gap:.2f} s)")
    return 0


def store_folder(folder):
    """The exhibit store's folder in fetched results: `exhibits`, or `consigne`
    for results archived before the rename of 2026-09-24."""
    for name in ("exhibits", "consigne"):
        if os.path.isdir(os.path.join(folder, name)):
            return name
    return "exhibits"


def check_exhibit_store(folder):
    """The exhibit manifest, and its seal.

    An exhibit store without a valid manifest is worth no more than a directory
    of files: nothing identifies the exhibits. Four checks, all feasible without
    the exhibits themselves — which is what a third party would do:

      - the seal `MANIFEST.sha256` must carry the manifest's real digest. It is
        the only check that detects a retouched manifest, which is precisely
        what attests the exhibits;
      - every collected exhibit must carry its THREE fingerprints. An exhibit
        without a fingerprint is an unidentified exhibit, hence unusable;
      - the declared counts must match the content;
      - the volumes read must include the system drive read in
        `OperatingSystem.json` — two independent sources.
    """
    import hashlib
    store = store_folder(folder)
    manifest = os.path.join(folder, store, "MANIFEST.json")
    if not os.path.exists(manifest):
        manifest = os.path.join(folder, store, "MANIFESTE.json")
    seal = manifest[:-5] + ".sha256"
    if not os.path.exists(manifest):
        print("  ⏭️  exhibit manifest absent: check skipped")
        return 0
    found = 0
    try:
        with open(manifest, encoding="utf-8-sig") as f:
            m = json.load(f)
    except Exception as e:
        print(f"  ❌ {os.path.basename(manifest)} invalid: {str(e)[:70]}")
        return 1

    # 1. seal
    if not os.path.exists(seal):
        print(f"  ❌ {os.path.basename(seal)} absent: the manifest is not sealed")
        found += 1
    else:
        with open(manifest, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest().upper()
        with open(seal, encoding="utf-8-sig") as f:
            content = f.read().strip()
        declared = content.split()[0].upper() if content else ""
        if declared != actual:
            print(f"  ❌ exhibits: seal does not match — declared {declared[:16]}…, "
                  f"computed {actual[:16]}… — the manifest was modified after sealing")
            found += 1
        else:
            print(f"  ✅ exhibits: seal matches the manifest ({actual[:16]}…)")

    # 2. fingerprints of every exhibit
    items = m.get("Items") or []
    if not isinstance(items, list) or not items:
        print("  ❌ exhibits: no exhibit in the manifest")
        return found + 1
    collected = [i for i in items if i.get("Result") == "OK"]
    noFingerprint = [i.get("SourcePath") for i in collected
                     if not (i.get("MD5") and i.get("SHA1") and i.get("SHA256"))]
    if noFingerprint:
        print(f"  ❌ exhibits: {len(noFingerprint)} exhibit(s) without the three fingerprints "
              f"{[os.path.basename(str(x)) for x in noFingerprint[:3]]}")
        found += 1
    else:
        print(f"  ✅ exhibits: {len(collected)} exhibit(s) carry MD5, SHA-1 and SHA-256")

    # 3. counts
    custody = m.get("Custody") or {}
    failures = [i for i in items if i.get("Result") != "OK"]
    if custody.get("ItemCount") != len(items) or custody.get("FailedCount") != len(failures):
        print(f"  ❌ exhibits: inconsistent counts — declared "
              f"{custody.get('ItemCount')}/{custody.get('FailedCount')}, "
              f"found {len(items)}/{len(failures)}")
        found += 1
    else:
        print(f"  ✅ exhibits: consistent counts ({len(items)} exhibit(s), "
              f"{len(failures)} failure(s))")

    # 4. volumes read, confronted with an independent source
    osj = load(folder, "OperatingSystem.json")
    system = str((osj or {}).get("SystemDrive") or "")[:1].upper() if isinstance(osj, dict) else ""
    letters = {str(v.get("Letter") or "").upper() for v in (custody.get("VolumesRead") or [])}
    if not system:
        print("  ⏭️  system drive absent from OperatingSystem.json: volumes check skipped")
    elif system not in letters:
        print(f"  ❌ exhibits: the system drive {system}: is not among the volumes "
              f"read {sorted(letters)}")
        found += 1
    else:
        print(f"  ✅ exhibits: volumes read {sorted(letters)}, the system drive among them")

    # 5. match between the manifest and the real content of the exhibit store
    found += check_exhibit_store_content(folder, store, collected)
    return found


def check_exhibit_store_content(folder, store, collected):
    """Every file present in the exhibit store must appear in the manifest, and
    the reverse.

    The previous checks bear on the manifest alone: they do not see an exhibit
    put into the store AFTER the sealing. That is what happened to the resource
    binaries of the event providers, extracted during the event-log phase while
    the manifest was already written — 121 binaries present and identified by
    nothing. The list is read in the VM by `dir /s /b` (see run-wac-test.sh).
    """
    listing = os.path.join(folder, store, "LIST.txt")
    if not os.path.exists(listing):
        listing = os.path.join(folder, store, "LISTE.txt")
    if not os.path.exists(listing):
        print("  ⏭️  listing of the exhibit store absent: match not checked")
        return 0
    with open(listing, encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f if l.strip()]
    def relative(path):
        low = path.replace("/", "\\").lower()
        i = low.find("\\" + store + "\\")
        if i >= 0:
            return low[i + 1:]
        return low if low.startswith(store + "\\") else None
    present = {r for r in map(relative, lines) if r}
    present -= {f"{store}\\{n}" for n in ("manifest.json", "manifest.sha256",
                                          "manifeste.json", "manifeste.sha256")}
    declared = {str(i.get("ExhibitPath") or "").lower() for i in collected}
    declared.discard("")
    outsideManifest = sorted(present - declared)
    missing = sorted(declared - present)
    found = 0
    if outsideManifest:
        print(f"  ❌ exhibits: {len(outsideManifest)} file(s) present but absent from the "
              f"manifest — unidentified exhibits, added after the sealing? "
              f"{[ntpath.basename(x) for x in outsideManifest[:3]]}")
        found += 1
    if missing:
        print(f"  ❌ exhibits: {len(missing)} exhibit(s) in the manifest not found in the "
              f"store {[ntpath.basename(x) for x in missing[:3]]}")
        found += 1
    if not found:
        print(f"  ✅ exhibits: the {len(present)} file(s) present are exactly "
              f"those of the manifest")
    return found


def check_mft_references(folder):
    """Plausibility of the $MFT references read in the beef0004 blocks.

    A cross-check in the broad sense: those numbers come from the decoding of an
    extension block, and their plausibility is judged on known properties of
    NTFS. The first 27 entries of the MFT are reserved for the metafiles
    (`$MFT`, `$MFTMirr`, `$LogFile`…): an ordinary file cannot be there. A null
    sequence number with a non-null entry number names a FAT volume, not an
    error.
    """
    total = 0
    suspects = []
    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        d = load(folder, os.path.basename(file))
        if d is None:
            continue
        stack = [d]
        while stack:
            o = stack.pop()
            if isinstance(o, dict):
                if o.get("MftNote") == "NTFS":
                    total += 1
                    entry = o.get("MftEntryNumber") or 0
                    seq = o.get("MftSequenceNumber") or 0
                    if entry < 27 or seq == 0:
                        suspects.append((os.path.basename(file), entry, seq))
                # References of a Prefetch's metrics array: the same plausibility
                # rule, an independent source (Prefetch metrics versus a shell
                # item's extension blocks).
                ref = o.get("MftReference")
                if isinstance(ref, dict) and "EntryIndex" in ref:
                    total += 1
                    entry = ref.get("EntryIndex") or 0
                    seq = ref.get("SequenceNumber") or 0
                    if entry < 27 or seq == 0:
                        suspects.append((os.path.basename(file), entry, seq))
                stack.extend(o.values())
            elif isinstance(o, list):
                stack.extend(o)
    if total == 0:
        print("  ⏭️  no $MFT reference read: check skipped")
        return 0
    if suspects:
        print(f"  ❌ {len(suspects)}/{total} implausible $MFT reference(s) "
              f"(entry < 27 or null sequence marked NTFS)")
        for f, e, sq in suspects[:3]:
            print(f"        {f}: entry {e}, sequence {sq}")
        return 1
    print(f"  ✅ {total} plausible $MFT reference(s)")
    return 0


def check_prefetchs(folder):
    """The path hash must match the suffix of the file name.

    A cross-check in the STRONG sense: the hash is decoded from the binary header,
    the file name is independent data. If they diverge, the decoding is wrong. It
    is this check that measured the formatting defect: 65 hashes out of 270 were
    truncated, "CMD.EXE-0BD30981.pf" giving "bd3981".
    """
    d = load(folder, "prefetchs.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  prefetchs.json absent or empty: check skipped")
        return 0

    bad = []
    for p in d:
        name = (p.get("Path") or "").replace("/", "\\").split("\\")[-1]
        if "-" not in name or not name.lower().endswith(".pf"):
            continue          # name outside the convention: nothing to compare
        expected = name.rsplit("-", 1)[-1][:-3]
        if (p.get("Hash") or "").upper() != expected.upper():
            bad.append((name, p.get("Hash")))
    if bad:
        print(f"  ❌ prefetchs.json: {len(bad)}/{len(d)} hashes do not match "
              f"the file name")
        for name, h in bad[:3]:
            print(f"        {name} -> {h}")
        return 1 + check_prefetch_paths(d)
    print(f"  ✅ prefetchs.json: {len(d)} hashes match the file name")
    return check_prefetch_paths(d)


def check_shimcache_dates(folder):
    """The ShimCache modification date confronted with the file's NTFS date.

    The cache stores the file's last modification as a FILETIME, hence UTC. WAC
    formatted it as a local time, which shifted both keys by the time-zone
    offset — invisible in the JSON, where the dates stayed well formed. The
    manifest records, for every collected binary, the NTFS dates read in the
    $MFT: an independent source. For an unchanged file both dates are
    identical to the 100 ns; a gap of a whole number of hours on most entries
    betrays a time-zone shift.
    """
    sh = load(folder, "shimcache.json")
    store = store_folder(folder)
    manifest = None
    for name in ("MANIFEST.json", "MANIFESTE.json"):
        manifest = load(os.path.join(folder, store), name) or manifest
    if not isinstance(sh, list) or not sh or not isinstance(manifest, dict):
        print("  ⏭️  shimcache.json or manifest absent: ShimCache dates not confronted")
        return 0
    source = {str(i.get("SourcePath", "")).upper(): i for i in manifest.get("Items") or []
              if i.get("SourceModifiedUtc")}
    same = shifted = other = 0
    for e in sh:
        i = source.get(str(e.get("Path", "")).upper())
        if not i or not e.get("LastModificationUtc"):
            continue
        gap = (instant(e["LastModificationUtc"]) - instant(i["SourceModifiedUtc"])).total_seconds()
        if abs(gap) < 1:
            same += 1
        elif abs(gap) <= 14 * 3600 and abs(gap) % 900 < 1:
            shifted += 1          # a whole quarter of an hour: a time-zone offset
        else:
            other += 1            # file replaced since the cache entry
    if same + shifted == 0:
        print("  ⏭️  no ShimCache entry matches a collected binary: dates not confronted")
        return 0
    if shifted > same:
        print(f"  ❌ shimcache.json: {shifted} date(s) shifted by a time-zone offset against "
              f"the NTFS date, {same} identical — UTC value treated as local?")
        return 1
    print(f"  ✅ shimcache.json: {same} date(s) identical to the NTFS date of the file "
          f"({other} file(s) replaced since)")
    return 0


def check_prefetch_paths(d):
    r"""The `\VOLUME{guid}\…` paths must be resolved into real paths.

    A Prefetch names the files loaded by the program in the form
    `\VOLUME{01dd…-8c10a5a9}\WINDOWS\SYSTEM32\NTDLL.DLL`, unusable as it is. WAC
    translates them with the volume's letter. A hard-coded length comparison
    made that translation fail for EVERY file: 20,052 paths stayed empty, and
    the MD5 fingerprints with them.
    """
    total = sum(len(p.get("FilesStrings") or []) for p in d)
    if total == 0:
        print("  ⏭️  prefetchs.json: no file listed, check skipped")
        return 0
    resolved = sum(1 for p in d for f in (p.get("FilesStrings") or [])
                   if f.get("FullPath"))
    # Nearly all of them must be resolved: only the volumes absent from the
    # system at collection time (an unplugged disk) legitimately escape.
    if resolved * 10 < total * 9:
        print(f"  ❌ prefetchs.json: {total - resolved}/{total} file paths "
              f"not resolved (\\VOLUME{{…}} not translated into a volume letter)")
        return 1
    print(f"  ✅ prefetchs.json: {resolved}/{total} file paths resolved")
    return 0


def process_name(p):
    """Name of a process, whatever the version of WAC that wrote it.

    The key was called "Nom" before the harmonisation of 2026-09-15. Reading both
    makes it possible to check archived results too — and prevents a check from
    silently returning None, which would neutralise the exclusion of WAC itself
    and produce a false positive.
    """
    return p.get("Name") or p.get("Nom") or ""


def check_processes(folder):
    """Checks that processes.json does not attribute WAC's modules to others."""
    d = load(folder, "processes.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  processes.json absent or empty: check skipped")
        return 0
    found = 0

    # CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0) names the CURRENT PROCESS:
    # the Idle process inherited WAC.exe's modules. WAC itself legitimately
    # carries its own binary as its first module — it is the ONLY process that
    # may.
    culprits = [process_name(p) for p in d
                if process_name(p).lower() != "wac.exe"
                and any("wac.exe" in (m or "").lower() for m in p.get("Modules") or [])]
    if culprits:
        print(f"  ❌ processes.json: {culprits[:5]} carry WAC.exe among their "
              f"modules — the collection tool is attributed to another process")
        found += 1
    else:
        print("  ✅ processes.json: no process carries WAC.exe as a module")

    # The owner must be known for nearly all processes: a high rate of empty
    # SIDs would signal the return of OpenProcess.
    noSid = [process_name(p) for p in d if not p.get("SID")]
    # Only the Idle process (PID 0) legitimately has no token.
    pid = lambda p: p.get("ProcessId") if p.get("ProcessId") is not None else p.get("PID")
    illegitimate = [process_name(p) for p in d if not p.get("SID") and pid(p)]
    if illegitimate:
        print(f"  ❌ processes.json: {len(illegitimate)} process(es) without an owner "
              f"{illegitimate[:5]} — SID reading to be checked")
        found += 1
    else:
        print(f"  ✅ processes.json: {len(d) - len(noSid)}/{len(d)} owners read")
    return found


# States returned by the old faulty converter: they are enumeration FILTERS, not
# service states. Their return would mean serviceState_to_wstring regressed.
GHOST_STATES = {"SERVICE_ACTIVE", "SERVICE_INACTIVE", "SERVICE_STATE_ALL"}


def check_services(folder):
    """Checks that services.json carries real states, and drivers."""
    d = load(folder, "services.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  services.json absent or empty: check skipped")
        return 0
    found = 0

    ghosts = sorted({s.get("Status") for s in d
                     if s.get("Status") in GHOST_STATES})
    if ghosts:
        print(f"  ❌ services.json: state(s) coming from the enumeration filters "
              f"{ghosts} — serviceState_to_wstring regressed")
        found += 1
    else:
        print("  ✅ services.json: no ghost state")

    # A massive "SERVICE_TYPE_UNKNOWN" type would signal the return of the
    # comparison by equality on a bit field.
    unknown = sum(1 for s in d if s.get("Type") == "SERVICE_TYPE_UNKNOWN")
    if unknown > len(d) // 10:
        print(f"  ❌ services.json: {unknown}/{len(d)} unknown types "
              f"— flag decomposition to be checked")
        found += 1
    else:
        print(f"  ✅ services.json: {len(d) - unknown}/{len(d)} types recognised")

    # The offline reading must see the drivers, which the SCM enumeration
    # filtered on SERVICE_WIN32 excluded entirely.
    drivers = sum(1 for s in d if "DRIVER" in (s.get("Type") or ""))
    if drivers == 0:
        print("  ❌ services.json: no driver — the hive always holds some")
        found += 1
    else:
        print(f"  ✅ services.json: {drivers} driver(s) present")
    return found


def check_users(folder):
    """Checks that the SIDs rebuilt from the SAM are well formed."""
    d = load(folder, "users.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  users.json absent or empty: check skipped")
        return 0
    found = 0

    # SID rebuilt from the machine SID + the RID: without the machine SID, the
    # field would be empty and the account impossible to correlate.
    bad = sorted({u.get("Name") for u in d
                  if not (u.get("SID") or "").startswith("S-1-5-21-")})
    if bad:
        print(f"  ❌ users.json: SID not rebuilt for {bad[:5]} "
              f"— machine SID unreadable in SAM\\Domains\\Account")
        found += 1
    else:
        print(f"  ✅ users.json: {len(d)} well-formed SIDs")

    # The RID must be found at the end of the SID: a guard on the matching.
    mismatched = [u.get("Name") for u in d
                  if u.get("RID") and (u.get("SID") or "").rsplit("-", 1)[-1]
                  != str(u["RID"])]
    if mismatched:
        print(f"  ❌ users.json: RID absent from the end of the SID for {mismatched[:5]}")
        found += 1
    else:
        print("  ✅ users.json: RIDs consistent with the SIDs")
    return found


ISO = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d')


def date_pairs(obj):
    """Yields (key, value, keyUtc, valueUtc) for every <X>/<X>Utc pair."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            keyUtc = key + "Utc"
            other = obj.get(keyUtc)
            if (isinstance(val, str) and isinstance(other, str)
                    and ISO.match(val) and ISO.match(other)):
                yield key, val, keyUtc, other
        for val in obj.values():
            yield from date_pairs(val)
    elif isinstance(obj, list):
        for val in obj:
            yield from date_pairs(val)


if __name__ == "__main__":
    sys.exit(main())
