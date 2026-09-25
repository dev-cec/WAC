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

    found += check_date_pairs(folder, osj)

    found += check_services(folder)
    found += check_users(folder)
    found += check_processes(folder)
    found += check_prefetchs(folder)
    found += check_shimcache_dates(folder)
    found += check_jumplist_entries(folder)
    found += check_events(folder)
    found += check_hive_replay(folder)
    found += check_exhibit_store(folder)
    found += check_mft_references(folder)
    found += check_mounted_devices(folder)
    found += check_date_precision(folder)
    found += check_utc_sources(folder)
    found += check_key_names(folder)
    found += check_account_names(folder)
    found += check_guid_names(folder)
    found += check_collected_executables(folder)
    found += check_catalogs_recorded(folder)
    found += check_package_verification(folder)
    found += check_file_artefact_dates(folder)
    found += check_symbol_server_keys(folder)
    found += check_binary_all(folder)
    found += check_timestomping(folder)
    found += check_macro_document(folder)
    found += check_embedded_signers(folder)
    return found


def check_embedded_signers(folder):
    """For a collected binary signed by a third party, the manifest records who
    signed (EmbeddedSigner) and whether the file is as signed
    (EmbeddedSignatureIntact) — information for the analyst. Independent
    source: Get-AuthenticodeSignature on the third-party binaries of the VM
    (reference/third-party-signatures.txt): the signer's name must be in the
    subject Windows reads, and a file WAC says intact must not be a
    HashMismatch for Windows.
    """
    reference_path = os.path.join(folder, "reference", "third-party-signatures.txt")
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    signed = {str(i.get("SourcePath", "")).lower(): i for i in items if i.get("EmbeddedSigner")}
    if not os.path.exists(reference_path) or not signed:
        print("  ⏭️  no third-party signer recorded, or no reference: embedded signers not checked")
        return 0
    compared, wrong = 0, []
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|", 2)
            if len(parts) != 3 or parts[0].lower() not in signed:
                continue
            item = signed[parts[0].lower()]
            compared += 1
            name = str(item["EmbeddedSigner"]).split(",")[0].strip()
            if name.lower() not in parts[2].lower():
                wrong.append(f"{parts[0]}: WAC signer {name!r}, Windows {parts[2][:60]!r}")
            if item.get("EmbeddedSignatureIntact") is True and parts[1] == "HashMismatch":
                wrong.append(f"{parts[0]}: intact for WAC, HashMismatch for Windows")
    if not compared:
        print("  ⏭️  no third-party signed binary in common with the reference: not checked")
        return 0
    if wrong:
        print(f"  ❌ {len(wrong)} embedded signer(s) out of {compared} differ from Windows':")
        for w in wrong[:5]:
            print(f"        {w}")
        return 1
    print(f"  ✅ {compared} third-party signed binaries: signer and integrity agree with Get-AuthenticodeSignature")
    return 0


def check_macro_document(folder):
    """A macro document of the user must be collected by --collect --binary:
    no Microsoft catalog can list it, and a malicious macro must stay
    available to a later analysis. The harness leaves one in the test
    profile (reference/macro-document.txt).
    """
    reference_path = os.path.join(folder, "reference", "macro-document.txt")
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    if not os.path.exists(reference_path) or not any("--collect --binary" in str(i.get("Method", "")) for i in items):
        print("  ⏭️  no macro document prepared, or not a --collect --binary collection: not checked")
        return 0
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        path = f.read().strip().lower()
    item = next((i for i in items if str(i.get("SourcePath", "")).lower() == path), None)
    if not item or item.get("Result") != "OK" or item.get("ContentStored") is False \
            or not (item.get("ExhibitPath") and item.get("MD5") and item.get("SHA1") and item.get("SHA256")):
        print(f"  ❌ macro document of the user NOT collected with its three fingerprints ({path})")
        return 1
    print(f"  ✅ macro document of the user collected, with MD5, SHA-1 and SHA-256 ({ntpath.basename(path)})")
    return 0


def check_timestomping(folder):
    """Dates forged after the fact must show. The harness forges those of a
    script back to 2001 (make SetFileTime do it, as an intruder would): the
    manifest must carry 2001 in $STANDARD_INFORMATION (SourceCreatedUtc) and
    the real creation in $FILE_NAME (SourceFileNameCreatedUtc), which
    SetFileTime does not touch.
    """
    reference_path = os.path.join(folder, "reference", "stomped.txt")
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    if not os.path.exists(reference_path) or not items:
        print("  ⏭️  no timestomped file prepared: $FILE_NAME dates not checked")
        return 0
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        path = f.read().strip().lower()
    item = next((i for i in items if str(i.get("SourcePath", "")).lower() == path and i.get("Result") == "OK"), None)
    if not item:
        print(f"  ❌ timestomped file absent from the manifest ({path})")
        return 1
    standard = str(item.get("SourceCreatedUtc", ""))
    file_name = str(item.get("SourceFileNameCreatedUtc", ""))
    if not standard.startswith("2001-") or not file_name or file_name.startswith("2001-"):
        print(f"  ❌ timestomping not visible: $STANDARD_INFORMATION {standard or '-'}, $FILE_NAME {file_name or '-'}")
        return 1
    print(f"  ✅ timestomping visible: $STANDARD_INFORMATION {standard[:10]}, $FILE_NAME {file_name[:19]}")
    return 0


def check_symbol_server_keys(folder):
    """An authentic binary that was not copied must be retrievable: the
    manifest records its build (TimeDateStamp, SizeOfImage), the key of
    Microsoft's symbol server. Independent source: the same two fields read
    in the header of each executable of System32 by PowerShell
    (reference/pe-build.txt).
    """
    reference_path = os.path.join(folder, "reference", "pe-build.txt")
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    keyed = {str(i.get("SourcePath", "")).lower(): i for i in items if i.get("PeTimeDateStamp")}
    if not os.path.exists(reference_path) or not keyed:
        print("  ⏭️  no PE build in the manifest, or no reference: retrieval keys not checked")
        return 0
    compared, wrong = 0, []
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) != 3 or parts[0] not in keyed:
                continue
            compared += 1
            item = keyed[parts[0]]
            if item["PeTimeDateStamp"].upper() != parts[1].upper() or item.get("PeSizeOfImage", "").lower() != parts[2].lower():
                wrong.append(f"{parts[0]}: WAC {item['PeTimeDateStamp']}/{item.get('PeSizeOfImage')}, header {parts[1]}/{parts[2]}")
    if not compared:
        print("  ⏭️  no System32 executable in the manifest: retrieval keys not checked")
        return 0
    if wrong:
        print(f"  ❌ {len(wrong)} retrieval key(s) out of {compared} differ from the PE header:")
        for w in wrong[:5]:
            print(f"        {w}")
        return 1
    print(f"  ✅ {compared} retrieval keys (TimeDateStamp, SizeOfImage) equal to the PE headers of System32")
    return 0


def check_binary_all(folder):
    """--binary-all copies every executable, authenticated or not, and records
    the signature check of each (SignatureVerified, with Signature or
    SignatureReason) — differential files, which are no executables, apart.
    """
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    concerned = [i for i in items if "--collect --binary-all" in str(i.get("Method", "")) and i.get("Result") == "OK"]
    if not concerned:
        print("  ⏭️  not a --binary-all collection: its checks skipped")
        return 0
    not_copied = [i["SourcePath"] for i in concerned
                  if i.get("ContentStored") is False and "medium full" not in i.get("Method", "")]
    no_verdict = [i["SourcePath"] for i in concerned
                  if "SignatureVerified" not in i and "differential file" not in i.get("Method", "")]
    found = 0
    if not_copied:
        print(f"  ❌ --binary-all: {len(not_copied)} executable(s) not copied, e.g. {not_copied[:3]}")
        found += 1
    if no_verdict:
        print(f"  ❌ --binary-all: {len(no_verdict)} executable(s) without a recorded signature verdict, e.g. {no_verdict[:3]}")
        found += 1
    if not found:
        valid = sum(1 for i in concerned if i.get("SignatureVerified") is True)
        print(f"  ✅ --binary-all: {len(concerned)} executable(s) copied, each with its verdict "
              f"({valid} signature(s) valid)")
    return found


def check_file_artefact_dates(folder):
    """The dates of a file artefact are those of the file on the examined
    machine, not of its working copy. Independent source: the last write of
    each Prefetch file as Windows gives it (reference/prefetch-times.txt),
    against ModifiedUtc in prefetchs.json.

    What it caught: the dates were read on the working copy, and the 335
    Prefetch files of a collection all bore the minute of the collection.
    A Prefetch rewritten between the collection and the reference (a program
    run meanwhile) legitimately differs: 90 % must match to the 100 ns.
    """
    reference_path = os.path.join(folder, "reference", "prefetch-times.txt")
    prefetchs = load(folder, "prefetchs.json")
    if not os.path.exists(reference_path) or not isinstance(prefetchs, list):
        print("  ⏭️  Prefetch reference or prefetchs.json absent: file artefact dates not checked")
        return 0
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        windows = dict(line.strip().split("|", 1) for line in f if "|" in line)
    compared = same = 0
    examples = []
    for p in prefetchs:
        name = ntpath.basename(str(p.get("Path", "")))
        if name not in windows or not p.get("ModifiedUtc"):
            continue
        compared += 1
        if p["ModifiedUtc"] == windows[name]:
            same += 1
        elif len(examples) < 3:
            examples.append(f"{name}: WAC {p['ModifiedUtc']}, Windows {windows[name]}")
    if not compared:
        print("  ⏭️  no Prefetch in common with the reference: dates not checked")
        return 0
    if same < 0.9 * compared:
        print(f"  ❌ Prefetch dates: {same}/{compared} equal to Windows' — dates of the working copy?")
        for e in examples:
            print(f"        {e}")
        return 1
    print(f"  ✅ Prefetch dates: {same}/{compared} equal to Windows' to the 100 ns "
          f"(the others rewritten since the collection)")
    return 0


def check_package_verification(folder):
    """A file of a signed Store package is not collected when its blocks match
    the package's signed block map. The harness copies a package's signature
    and block map with three scripts (make-fake-package.ps1): the untouched one
    must be authenticated through the package, the modified one and the
    intruder — absent from the block map — must be collected.
    """
    reference_path = os.path.join(folder, "reference", "fake-package.txt")
    if not os.path.exists(reference_path):
        print("  ⏭️  reference/fake-package.txt absent: package verification not checked")
        return 0
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    by_path = {str(i.get("SourcePath", "")).lower(): i for i in items}
    faults = []
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "|" not in line:
                continue
            case, path = line.strip().split("|", 1)
            item = by_path.get(path.lower())
            if not item or item.get("Result") != "OK":
                faults.append(f"{case}: absent from the manifest ({path})")
            # The verdict decides; the copy follows it, except under --binary-all
            # where everything is copied.
            elif case == "untouched":
                if item.get("SignatureVerified") is not True or not str(item.get("Signature", "")).startswith("Package"):
                    faults.append(f"untouched: not authenticated through its package ({path})")
                elif item.get("ContentStored") is not False and "--binary-all" not in str(item.get("Method", "")):
                    faults.append(f"untouched: authenticated, yet copied without --binary-all ({path})")
            elif item.get("SignatureVerified") is not False:
                faults.append(f"{case}: authenticated, though its package does not vouch for it ({path})")
            elif item.get("ContentStored") is False:
                faults.append(f"{case}: NOT collected, though its package does not vouch for it ({path})")
    if faults:
        print(f"  ❌ package verification: {len(faults)} fault(s)")
        for fault in faults:
            print(f"        {fault}")
        return 1
    print("  ✅ package verification: untouched file authenticated, modified file and intruder collected")
    return 0


def check_catalogs_recorded(folder):
    """A binary authenticated through a catalog is not collected: the catalog
    is what justifies it, and must be in the exhibit store for a third party
    to check the decision. Every "Microsoft (catalog X)" verdict — in the
    artefacts or in the manifest — must name a catalog the manifest holds.
    What it caught: the prefix looked for ("catalogue ") no longer matched the
    label ("catalog "), and no justifying catalog was ever recorded.
    """
    import re
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    recorded = {str(i.get("SourcePath", "")).lower() for i in items
                if i.get("Result") == "OK" and i.get("ContentStored") is not False}
    recorded_names = {ntpath.basename(p) for p in recorded}
    pattern = re.compile(r"Microsoft \(catalog (.+?)\)")
    cited = set()
    sources = [i.get("Signature") for i in items]
    for file in glob.glob(os.path.join(folder, "*.json")):
        try:
            with open(file, encoding="utf-8-sig") as f:
                sources += [v for _, v in walk(json.load(f)) if isinstance(v, str)]
        except Exception:
            continue
    for value in sources:
        for match in pattern.finditer(str(value or "")):
            cited.add(match.group(1).lower())
    if not cited:
        print("  ⏭️  no catalog verdict: recording of the catalogs not checked")
        return 0
    missing = sorted(c for c in cited
                     if c not in recorded and ntpath.basename(c) not in recorded_names)
    if missing:
        print(f"  ❌ {len(missing)} catalog(s) out of {len(cited)} justify an authentication "
              f"but are not in the exhibit store, e.g. {missing[:3]}")
        return 1
    print(f"  ✅ the {len(cited)} catalog(s) that justify an authentication are all in the exhibit store")
    return 0


def check_collected_executables(folder):
    """--collect --binary must take EVERY executable of the volume: which ones
    the artefacts cite is only known at conversion, on another machine.

    Independent reference: the executables, libraries and drivers of System32
    and SysWOW64 as Windows lists them (reference/executables.txt), each of
    which must be a source path of the manifest. What it caught: directories
    whose $INDEX_ROOT NTFS had moved to an extension record (those carrying a
    $TXF_DATA, thousands in WinSxS) were reported unreadable by the raw
    reader, and their files never collected.
    """
    reference_path = os.path.join(folder, "reference", "executables.txt")
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    if not any("--collect --binary" in str(i.get("Method", "")) for i in items):
        print("  ⏭️  not a --collect --binary collection: completeness of the executables skipped")
        return 0
    if not os.path.exists(reference_path):
        print("  ⏭️  reference/executables.txt absent: completeness of the executables skipped")
        return 0
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        reference = {line.strip().lower() for line in f if line.strip()}
    collected = {str(i.get("SourcePath", "")).lower() for i in items if i.get("Result") == "OK"}
    missing = sorted(reference - collected)
    if missing:
        print(f"  ❌ {len(missing)} executable(s) of System32/SysWOW64 out of {len(reference)} "
              f"not collected, e.g.:")
        for m in missing[:5]:
            print(f"        {m}")
        return 1
    print(f"  ✅ the {len(reference)} executables of System32/SysWOW64 are all collected")
    return check_authenticated_executables(folder, items)


def check_authenticated_executables(folder, items):
    """An executable WAC authenticates as Microsoft is fingerprinted and NOT
    copied: a wrong verdict would leave an intruder's binary out of the
    exhibit store. Independent source: Windows' own verification
    (Get-AuthenticodeSignature, catalogs included) of the executables of
    System32, in reference/authenticode.txt ("path|Status|Subject").

    Every executable WAC declares authentic must be "Valid" and signed by
    Microsoft for Windows. The reverse — valid for Windows, collected by WAC —
    costs room but loses nothing: it is counted, not failed.
    """
    reference_path = os.path.join(folder, "reference", "authenticode.txt")
    if not os.path.exists(reference_path):
        print("  ⏭️  reference/authenticode.txt absent: signature verdicts not checked")
        return 0
    windows = {}
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 3:
                windows[parts[0].lower()] = (parts[1], parts[2])
    verdict = {str(i.get("SourcePath", "")).lower(): i for i in items if i.get("Result") == "OK"}
    wrong, stored_valid, compared = [], 0, 0
    for path, (status, subject) in windows.items():
        item = verdict.get(path)
        if not item:
            continue
        compared += 1
        microsoft_for_windows = status == "Valid" and "microsoft" in subject.lower()
        if item.get("ContentStored") is False and str(item.get("Signature", "")).startswith("Microsoft"):
            if not microsoft_for_windows:
                wrong.append(f"{path} ({status}, {subject[:40]})")
        elif microsoft_for_windows and item.get("ContentStored") is not False:
            stored_valid += 1
    if wrong:
        print(f"  ❌ {len(wrong)} executable(s) declared authentic Microsoft by WAC, not by Windows:")
        for w in wrong[:5]:
            print(f"        {w}")
        return 1
    print(f"  ✅ {compared} System32 executables compared with Get-AuthenticodeSignature: every one WAC "
          f"authenticated is Microsoft-valid for Windows ({stored_valid} valid for Windows yet collected)")
    return 0


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
    # Copied exhibits carry the three fingerprints; a binary authenticated as
    # Microsoft and NOT copied (ContentStored false) carries its Authenticode
    # digest (a script: its SHA-256) and the verdict, and nothing else.
    collected = [i for i in items if i.get("Result") == "OK" and i.get("ContentStored") is not False]
    fingerprintOnly = [i for i in items if i.get("Result") == "OK" and i.get("ContentStored") is False]
    noFingerprint = [i.get("SourcePath") for i in collected
                     if not (i.get("MD5") and i.get("SHA1") and i.get("SHA256"))]
    if noFingerprint:
        print(f"  ❌ exhibits: {len(noFingerprint)} exhibit(s) without the three fingerprints "
              f"{[os.path.basename(str(x)) for x in noFingerprint[:3]]}")
        found += 1
    else:
        print(f"  ✅ exhibits: {len(collected)} exhibit(s) carry MD5, SHA-1 and SHA-256")
    if fingerprintOnly:
        incomplete = [i.get("SourcePath") for i in fingerprintOnly
                      if not ((i.get("AuthenticodeSHA256") or i.get("SHA256")) and i.get("Signature"))
                      and "medium full" not in str(i.get("Method", ""))
                      and not ("differential file" in str(i.get("Method", "")) and i.get("SHA256"))]
        if incomplete:
            print(f"  ❌ exhibits: {len(incomplete)} binarie(s) fingerprinted without a copy lack their "
                  f"digest or verdict {[ntpath.basename(str(x)) for x in incomplete[:3]]}")
            found += 1
        else:
            print(f"  ✅ exhibits: {len(fingerprintOnly)} binarie(s) authenticated without a copy carry "
                  f"their digest and verdict")

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
    badNames = []
    for p in d:
        name = (p.get("Path") or "").replace("/", "\\").split("\\")[-1]
        if "-" not in name or not name.lower().endswith(".pf"):
            continue          # name outside the convention: nothing to compare
        expected = name.rsplit("-", 1)[-1][:-3]
        if (p.get("Hash") or "").upper() != expected.upper():
            bad.append((name, p.get("Hash")))
        # The executable name, decoded from the header, is the prefix of the
        # file name: read at the wrong offset, it came out as "\x11" everywhere.
        if (p.get("Filename") or "").upper() != name.rsplit("-", 1)[0].upper():
            badNames.append((name, p.get("Filename")))
    if badNames:
        print(f"  ❌ prefetchs.json: {len(badNames)}/{len(d)} executable names differ "
              f"from the file name")
        for name, f in badNames[:3]:
            print(f"        {name} -> {f!r}")
        return 1 + (1 if bad else 0) + check_prefetch_paths(d)
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


def check_jumplist_entries(folder):
    """Every DestList entry of an automatic jump list must find its shortcut.

    An entry names, by its number, the stream holding its shortcut: "1" to
    "f", then "10"… The name was built with a two-digit padding ("01"): the
    streams of entries 1 to 15 were never found, and the first fifteen files
    opened with every application disappeared without an error — on a real
    machine, 573 shortcuts published out of 1,522. The DestList and the
    shortcut are two independent records of the same file: the DestList path
    is also confronted with the shortcut's target.
    """
    d = load(folder, "jumplistAutomaticDestinations.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  jumplistAutomaticDestinations.json absent: DestList not confronted")
        return 0
    entries = orphans = compared = same = 0
    for jl in d:
        for item in jl.get("LNKs") or []:
            dest = item.get("DestList")
            if not isinstance(dest, dict):
                continue
            entries += 1
            if len(item) <= 1:              # nothing but the DestList entry
                orphans += 1
                continue
            target = str(item.get("Target") or "").lower()
            path = str(dest.get("PathObject") or "").lower()
            if target and path and "\\" in path:
                compared += 1
                same += target == path or path.endswith(target.split("\\")[-1])
    if entries == 0:
        print("  ⏭️  no DestList entry: jump lists not confronted")
        return 0
    found = 0
    if orphans * 10 > entries:
        print(f"  ❌ jumplistAutomaticDestinations.json: {orphans} DestList entries out of "
              f"{entries} without their shortcut — stream name wrong?")
        found += 1
    if compared and same * 2 < compared:
        print(f"  ❌ jumplistAutomaticDestinations.json: shortcut target and DestList path agree "
              f"for {same} of {compared} entries only — stream read wrong?")
        found += 1
    if not found:
        print(f"  ✅ jumplistAutomaticDestinations.json: {entries - orphans} of {entries} DestList "
              f"entries with their shortcut, target = DestList path for {same} of {compared}")
    return found


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


def decode_mounted_device(data):
    """Independent decoding of a MountedDevices value, from its bytes."""
    import uuid
    if len(data) == 24 and data[:8] == b"DMIO:ID:":
        return {"Type": "GPT partition",
                "PartitionGuid": "{" + str(uuid.UUID(bytes_le=data[8:24])).upper() + "}"}
    if len(data) == 12:
        return {"Type": "MBR partition",
                "DiskSignature": "0x%08x" % int.from_bytes(data[:4], "little"),
                "PartitionOffset": int.from_bytes(data[4:12], "little")}
    if len(data) >= 8 and len(data) % 2 == 0 and data[:8] in ("\\??\\".encode("utf-16-le"), "_??_".encode("utf-16-le")):
        return {"Type": "Device path", "Device": data.decode("utf-16-le").rstrip("\0")}
    return {"Type": "Unknown", "Data": " ".join("%02x" % b for b in data) + " "}


def check_mounted_devices(folder):
    """mounted_device.json against Windows' own reading of the same key, and
    against the partitions of the disks.

    WHY. WAC recognised only the old "_??_" prefix of device paths: every
    current one ("\\??\\SCSI#CdRom...") was decoded as ANSI text, stopped at
    its first zero byte and came out as "\\" — six mounts out of seven, in a
    valid JSON. Two independent references, fetched in the VM by
    run-wac-test.sh:
      - the values read by `reg query` (the live registry API; WAC reads the
        raw hive with its own reader), decoded here by a separate
        implementation: every field of every mount must match;
      - `Get-Partition`: the partition GUID of a GPT mount must be the one
        Windows gives for that letter or that volume — a check of the MEANING
        of the value, not only of its bytes.
    """
    d = load(folder, "mounted_device.json")
    ref = os.path.join(folder, "reference", "mounted-devices.txt")
    if not isinstance(d, list) or not d or not os.path.exists(ref):
        print("  ⏭️  mounted_device.json or its reference absent: mounts not confronted")
        return 0
    found = 0
    expected = {}
    with open(ref, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"^\s{4}(.+?)\s{4}REG_BINARY\s{4}([0-9A-Fa-f]*)\s*$", line)
            if m:
                expected[m.group(1)] = decode_mounted_device(bytes.fromhex(m.group(2)))
    wac = {e.get("Drive"): e for e in d if isinstance(e, dict)}
    differences = []
    for drive, fields in expected.items():
        mine = wac.get(drive)
        if mine is None:
            differences.append(f"{drive}: missing")
            continue
        for key, value in fields.items():
            if str(mine.get(key)).lower() != str(value).lower():
                differences.append(f"{drive}: {key}={mine.get(key)!r}, expected {value!r}")
    extra = set(wac) - set(expected)
    if differences or extra:
        for text in differences[:3]:
            print(f"  ❌ mounted_device.json: {text}")
        if extra:
            print(f"  ❌ mounted_device.json: {len(extra)} mount(s) Windows does not list")
        found += 1
    else:
        print(f"  ✅ mounted_device.json: {len(expected)} mount(s) identical to Windows' reading of the key")
    # The meaning: a GPT mount names the partition Windows gives for that letter or volume.
    parts = os.path.join(folder, "reference", "partitions.txt")
    if os.path.exists(parts):
        by_mount = {}
        with open(parts, encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.strip().split("|")
                if len(fields) != 4:
                    continue
                letter, guid, _, paths = fields
                if letter.strip():
                    by_mount["\\DosDevices\\" + letter.strip() + ":"] = guid.lower()
                for p in paths.split(";"):
                    v = re.search(r"Volume\{[0-9a-fA-F-]+\}", p)
                    if v:
                        by_mount["\\??\\" + v.group(0)] = guid.lower()
        gpt = [e for e in wac.values() if e.get("Type") == "GPT partition"]
        wrong = [e["Drive"] for e in gpt if e["Drive"] in by_mount
                 and e.get("PartitionGuid", "").lower() != by_mount[e["Drive"]]]
        compared = [e for e in gpt if e["Drive"] in by_mount]
        if wrong:
            print(f"  ❌ mounted_device.json: partition GUID other than Windows' for {wrong[:3]}")
            found += 1
        elif compared:
            print(f"  ✅ mounted_device.json: {len(compared)} GPT mount(s) name the partition Windows gives")
        else:
            print("  ⏭️  no GPT mount to confront with the partitions")
    return found


def check_date_precision(folder):
    """A date carries no more precision than its source.

    WHY. Every date came out with seven digits of fraction: a FAT date, precise
    to two seconds, read "…:30.0000000", which claims the ten-millionth of a
    second — digits an analyst could order events on, and that the source never
    held. Two properties of the FAT format itself are checked on the shell items
    (the beef0004 extension blocks and the file entries): no fraction, and an
    EVEN number of seconds, the format storing seconds halved — which also
    checks the decoding. The Amcache text dates (LinkDate, InstallDate) must
    carry no fraction either.
    """
    fat, wrong = 0, []
    def visit(o, name):
        nonlocal fat
        if isinstance(o, dict):
            keys = []
            if "ExtensionVersion" in o and "Signature" in o:
                keys = ["CreatedDate", "CreatedDateUtc", "AccessedDate", "AccessedDateUtc"]
            elif "Attributes" in o and "ModificationDate" in o:
                keys = ["ModificationDate", "ModificationDateUtc"]
            for k in keys:
                v = o.get(k)
                if isinstance(v, str) and ISO.match(v):
                    fat += 1
                    if "." in v[19:20] or int(v[17:19]) % 2:
                        wrong.append(f"{name}: {k}={v}")
            for k in ("LinkDate", "LinkDateUtc", "InstallDate", "InstallDateUtc"):
                v = o.get(k)
                if name.startswith("amcache") and isinstance(v, str) and v[19:20] == ".":
                    wrong.append(f"{name}: {k}={v}")
            for v in o.values():
                visit(v, name)
        elif isinstance(o, list):
            for v in o:
                visit(v, name)
    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        name = os.path.basename(file)
        if name == "events.json":
            continue
        d = load(folder, name)
        if d is not None:
            visit(d, name)
    if wrong:
        for text in wrong[:3]:
            print(f"  ❌ date more precise than its source: {text}")
        print(f"  ❌ {len(wrong)} date(s) claiming a precision their source does not have")
        return 1
    print(f"  ✅ {fat} FAT date(s) to the second, even, and text dates without a fraction")
    return 0


def check_utc_sources(folder):
    """The artefacts that store UTC are published as UTC.

    WHY. BAM, UserAssist, USBSTOR and Amcache store their dates in UTC; WAC
    read all four as LOCAL times, which shifted both keys of every date by the
    time-zone offset — two hours on the test VM, in a valid JSON, and the
    pairs X/XUtc still named the same instant. Each is confronted with a
    source independent of WAC:
      - USBSTOR: the dates Windows itself gives (Get-PnpDeviceProperty), to
        the 100 ns, for the key run-wac-test.sh attaches on every cycle;
      - Amcache LinkDate: the TimeDateStamp of the PE header of the same file
        (System32), to the second;
      - BAM: taskkill.exe, which run-wac-test.sh runs just before WAC: its last
        execution must precede the start of the collection by a few seconds;
      - UserAssist: the Prefetch run times of the same executable; a gap of a
        whole number of half hours is a time-zone shift.
    An empty BAM or UserAssist file fails too: a regression of the value
    reading emptied both, which no other check saw.
    """
    import datetime
    found = 0
    ref = os.path.join(folder, "reference")

    # USBSTOR
    usb = load(folder, "Usbstor.json")
    path = os.path.join(ref, "usbstor.txt")
    if os.path.exists(path):
        expected = {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 3:
                    expected.setdefault(parts[0], {})[parts[1]] = instant(parts[2])
        # The device is identified as Windows names it: USBSTOR\\<DeviceId>\\<InstanceId>.
        mine = {("USBSTOR\\" + (u.get("DeviceId") or "") + "\\" + (u.get("InstanceId") or "")).upper(): u
                for u in (usb if isinstance(usb, list) else [])}
        wrong = []
        for i, k in expected.items():
            u = mine.get(i.upper())
            if u is None:
                wrong.append(f"{i}: absent")
                continue
            got = (instant(u["FirstInsertionUtc"]) if u.get("FirstInsertionUtc") else None,
                   instant(u["LastInsertionUtc"]) if u.get("LastInsertionUtc") else None)
            if got != (k.get("DEVPKEY_Device_InstallDate"), k.get("DEVPKEY_Device_LastArrivalDate")):
                wrong.append(f"{i}: dates other than Windows'")
            # The key the harness attaches declares the serial number WACUSB0001.
            if "WACUSB0001" in i.upper() and u.get("SerialNumber") != "WACUSB0001":
                wrong.append(f"{i}: SerialNumber {u.get('SerialNumber')!r}, expected 'WACUSB0001'")
        if not expected:
            print("  ⏭️  no USB device in the reference: USBSTOR not confronted")
        elif wrong:
            print(f"  ❌ Usbstor.json: {wrong[0]} ({len(wrong)} difference(s))")
            found += 1
        else:
            print(f"  ✅ Usbstor.json: {len(expected)} device(s) identified as Windows names them, "
                  "serial number and insertion dates (UTC) identical")

    # Amcache LinkDate against the PE header
    path = os.path.join(ref, "pe-timestamps.txt")
    files = load(folder, "amcache_application_files.json")
    if os.path.exists(path) and isinstance(files, list):
        stamps = {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().rsplit("|", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    stamps[parts[0].lower()] = int(parts[1])
        # Many files were updated since Amcache inventoried them, and recent
        # Windows binaries carry a hash instead of a date in TimeDateStamp: an
        # unequal pair proves nothing. What proves a defect is a gap of a whole
        # number of half hours — the signature of a time-zone shift.
        equal, shifted = 0, []
        for a in files:
            p = (a.get("LongPath") or "").lower()
            if p in stamps and a.get("LinkDateUtc"):
                gap = abs(instant(a["LinkDateUtc"]).timestamp() - stamps[p])
                if gap < 1:
                    equal += 1
                elif gap <= 14 * 3600 and abs(gap / 1800 - round(gap / 1800)) * 1800 < 1:
                    shifted.append(f"{p}: {a['LinkDateUtc']}, PE header {gap:.0f} s away")
        if shifted:
            print(f"  ❌ amcache: LinkDate shifted by a time-zone offset against the PE header, e.g. {shifted[0]}")
            found += 1
        elif equal:
            print(f"  ✅ amcache: LinkDate of {equal} unchanged file(s) identical to their PE header (UTC), none shifted")
        else:
            print("  ⏭️  no Amcache file of System32 still identical: LinkDate not confronted")

    # BAM: taskkill.exe, run by the harness just before WAC
    bams = load(folder, "bams.json")
    inv = load(folder, "investigation.json")
    inv = inv[0] if isinstance(inv, list) and inv else inv
    start = ((inv or {}).get("Collection") or {}).get("StartUtc") if isinstance(inv, dict) else None
    if not isinstance(bams, list) or not bams:
        print("  ❌ bams.json empty: the BAM keys hold at least the harness's own commands")
        found += 1
    elif start:
        # "executionTimeUtc" until 2026-09-25: archived results stay checkable.
        runs = [instant(b.get("LastExecutionUtc") or b["executionTimeUtc"]) for b in bams
                if (b.get("LastExecutionUtc") or b.get("executionTimeUtc")) and (b.get("Name") or "").lower().endswith("\\taskkill.exe")]
        gaps = [(instant(start) - r).total_seconds() for r in runs]
        if any(0 <= g <= 300 for g in gaps):
            print(f"  ✅ bams.json: taskkill.exe executed {min(g for g in gaps if g >= 0):.0f} s before the collection, as the harness did")
        else:
            print(f"  ❌ bams.json: taskkill.exe, run just before the collection, found at gaps {[round(g) for g in gaps]} s")
            found += 1

    # UserAssist against the Prefetch run times
    ua = load(folder, "userassists.json")
    pf = load(folder, "prefetchs.json")
    if not isinstance(ua, list) or not ua:
        print("  ❌ userassists.json empty: the test profile holds UserAssist entries")
        found += 1
    elif isinstance(pf, list):
        runs = {}
        for p in pf:
            for r in p.get("RunsUtc") or []:
                runs.setdefault((p.get("Filename") or "").upper(), []).append(instant(r))
        agree, shifted = 0, []
        for u in ua:
            name = ntpath.basename(u.get("Name") or "").upper()
            last = u.get("LastRunUtc") or u.get("DateLocaleUtc")   # renamed on 2026-09-25
            if not name.endswith(".EXE") or name not in runs or not last:
                continue
            t = instant(last)
            gap = min((abs((t - r).total_seconds()) for r in runs[name]))
            if gap <= 120:
                agree += 1
            elif any(abs(gap - k * 1800) <= 120 for k in range(1, 49)):
                shifted.append(f"{name}: {last}, nearest Prefetch run {gap:.0f} s away")
        if shifted:
            print(f"  ❌ userassists.json: last run shifted by a time-zone offset against Prefetch, e.g. {shifted[0]}")
            found += 1
        elif agree:
            print(f"  ✅ userassists.json: last run of {agree} program(s) within 2 min of a Prefetch run")
        else:
            print("  ⏭️  no UserAssist program also in the Prefetch: last runs not confronted")
    return found


def check_key_names(folder):
    """Every key of the output is in PascalCase, English, without abbreviation.

    WHY. The output is read by other tools: a key is a contract. Keys such as
    "NbVolumes", "DateLocale" or "executionTime" had crept in — an abbreviation,
    a French word, a lower-case initial — each a name a consumer must special-case.
    Renamed on 2026-09-25; this check keeps new ones from appearing.
    """
    bad = {}
    def walk(o, name):
        if isinstance(o, dict):
            for k, v in o.items():
                if not re.match(r"^[A-Z][A-Za-z0-9]*$", k) or re.match(r"^(Nb|Num|Tmp)[A-Z]", k) \
                        or re.search(r"(Locale|Nom|Chemin|Taille|Valeur|Fichier)", k):
                    bad.setdefault(k, name)
                walk(v, name)
        elif isinstance(o, list):
            for v in o[:500]:
                walk(v, name)
    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        name = os.path.basename(file)
        d = load(folder, name)
        if d is not None:
            walk(d, name)
    if bad:
        print(f"  ❌ key names not in PascalCase English: {sorted(bad.items())[:5]}")
        return 1
    print("  ✅ every output key in PascalCase English, without abbreviation")
    return 0


def check_account_names(folder):
    """The SIDs are named from the evidence, as Windows names them.

    WHY. WAC named the SIDs with LookupAccountSidW, which queries the domain
    controller for a SID the machine does not know — a trace of the collection
    on another machine — and returns the names in the language of the machine
    asking ("Système" for S-1-5-18). They are now read offline: SAM, well-known
    SIDs, service SIDs, profiles (WAC/account_names.cpp). Checked here:
      - every local account and group named in the output carries the name
        Windows gives it (Get-LocalUser, Get-LocalGroup, fetched in the VM);
      - S-1-5-18 is "SYSTEM", its canonical name, whatever the language;
      - no local account SID of the output goes unnamed.
    """
    path = os.path.join(folder, "reference", "accounts.txt")
    if not os.path.exists(path):
        print("  ⏭️  accounts reference absent: SID names not confronted")
        return 0
    expected = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|", 1)
            if len(parts) == 2 and parts[0].startswith("S-1-"):
                expected[parts[0].upper()] = parts[1]
    pairs = set()
    def walk(o):
        if isinstance(o, dict):
            # A name absent from its object means "not named" (an empty field
            # is not emitted): it counts as a difference for a local account.
            sid = o.get("SID") or o.get("Sid")
            if isinstance(sid, str) and sid.startswith("S-1-"):
                pairs.add((sid.upper(), o.get("SIDName") or o.get("SidName") or o.get("Owner")))
            if isinstance(o.get("RunAsSid"), str):
                pairs.add((o["RunAsSid"].upper(), o.get("RunAs")))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        # users.json names its accounts from the SAM itself, Sessions.json from
        # LSA at the time of the observation, investigation.json and
        # conversion.json the operator running WAC, as HIS machine names him
        # ("Système"): none goes through the table.
        if os.path.basename(file) in ("events.json", "users.json", "Sessions.json", "investigation.json",
                                      "conversion.json"):
            continue
        d = load(folder, os.path.basename(file))
        if d is not None:
            walk(d)
    wrong = [f"{s}: {n!r}, Windows {expected[s]!r}" for s, n in pairs
             if s in expected and (n or "").lower() != expected[s].lower()]
    wrong += [f"S-1-5-18: {n!r}, expected 'SYSTEM'" for s, n in pairs if s == "S-1-5-18" and n != "SYSTEM"]
    if wrong:
        print(f"  ❌ SID names: {wrong[0]} ({len(wrong)} difference(s))")
        return 1
    named = sum(1 for s, _ in pairs if s in expected)
    print(f"  ✅ SID names: {named} local account(s)/group(s) as Windows names them, S-1-5-18 = SYSTEM, none unnamed")
    return 0


def check_guid_names(folder):
    """GUIDs the reference table does not know are named from the evidence.

    WHY. WAC named GUIDs from a table built on a reference Windows: a component
    or a folder installed on the examined machine came out as "Unmapped GUID" —
    a placeholder published as if it were the name; 18 COM handlers of the
    scheduled tasks of the test VM itself. They are now read in the examined
    machine's hives (WAC/trans_id.cpp). run-wac-test.sh registers three GUIDs,
    one per source (machine classes, user classes, known folders), each the
    COM handler of a disabled task: WAC must give exactly their names. And no
    output may carry the placeholder any more.
    """
    found = 0
    placeholder = []
    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        if os.path.basename(file) == "events.json":
            continue
        with open(file, encoding="utf-8", errors="replace") as f:
            if "Unmapped GUID\"" in f.read():
                placeholder.append(os.path.basename(file))
    if placeholder:
        print(f"  ❌ \"Unmapped GUID\" published as a name in {placeholder}")
        found += 1
    path = os.path.join(folder, "reference", "test-guids.txt")
    tasks = load(folder, "ScheduledTasks.json")
    if not os.path.exists(path) or not isinstance(tasks, list):
        print("  ⏭️  test GUIDs or scheduled tasks absent: names from the hives not confronted")
        return found
    expected = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|", 1)
            if len(parts) == 2 and parts[0].startswith("{"):
                expected[parts[0].upper()] = parts[1]
    handlers = {}
    def walk(o):
        if isinstance(o, dict):
            if o.get("Type") == "ComHandler" and o.get("ClassId"):
                handlers[o["ClassId"].upper()] = o.get("ClassIdName")
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(tasks)
    module = r" (C:\wactest\wac-test-handler.dll)"
    wrong = [f"{g}: {handlers.get(g)!r}, expected {n!r}" for g, n in expected.items()
             if handlers.get(g) not in (n, n + module)]
    if wrong:
        print(f"  ❌ GUID names from the hives: {wrong[0]} ({len(wrong)} difference(s))")
        found += 1
    else:
        print(f"  ✅ {len(expected)} test GUID(s) named from the examined machine's hives "
              "(machine classes, user classes, known folders); no placeholder name")
    return found


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
    """Yields (key, value, keyUtc, valueUtc) for every <X>/<X>Utc pair, and for
    every element of two lists <X>/<X>Utc of the same length (Prefetch Runs)."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            keyUtc = key + "Utc"
            other = obj.get(keyUtc)
            if (isinstance(val, str) and isinstance(other, str)
                    and ISO.match(val) and ISO.match(other)):
                yield key, val, keyUtc, other
            elif (isinstance(val, list) and isinstance(other, list) and len(val) == len(other)):
                for i, (v, u) in enumerate(zip(val, other)):
                    if isinstance(v, str) and isinstance(u, str) and ISO.match(v) and ISO.match(u):
                        yield f"{key}[{i}]", v, f"{keyUtc}[{i}]", u
        for val in obj.values():
            yield from date_pairs(val)
    elif isinstance(obj, list):
        for val in obj:
            yield from date_pairs(val)


# Windows time zone -> IANA zone, for the offsets check: the tz database is a
# source independent of Windows and of WAC. Only zones whose rules are the same
# in both over the years checked.
WINDOWS_TO_IANA = {
    "Romance Standard Time": "Europe/Paris",
    "W. Europe Standard Time": "Europe/Berlin",
    "GMT Standard Time": "Europe/London",
    "Eastern Standard Time": "America/New_York",
    "Central Standard Time": "America/Chicago",
    "Pacific Standard Time": "America/Los_Angeles",
    "UTC": "Etc/UTC",
}
# Years over which Windows and the tz database agree for these zones (the
# European Union's rules date from 1996; Windows' dynamic rules stop in 2037).
IANA_YEARS = range(1996, 2038)


def check_date_pairs(folder, osj):
    """Every <X>/<X>Utc pair names the SAME instant, and the offset of the local
    value is the one in force AT THAT DATE in the suspect's time zone.

    WHY. WAC used to label every local date with the offset of the collection
    day: collected in summer, a winter date read "+02:00" with a local time one
    hour off — while the pair still looked consistent to a check comparing the
    wall-clock times only. And the Prefetch "RunsUtc" carried the UTC time
    labelled "+02:00", an instant two hours off. The offsets are confronted with
    the tz database (zoneinfo), not with WAC's own rules.
    """
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        ZoneInfo = None
    key = (osj or {}).get("CurrentTimeZoneId") if isinstance(osj, dict) else None
    zone = ZoneInfo(WINDOWS_TO_IANA[key]) if ZoneInfo and key in WINDOWS_TO_IANA else None
    different = wrong_offset = nonexistent = checked = 0
    found = 0
    for file in sorted(glob.glob(os.path.join(folder, "*.json"))):
        d = load(folder, os.path.basename(file))
        if d is None:
            continue
        name = os.path.basename(file)
        for k, val, kUtc, valUtc in date_pairs(d):
            local, utc = instant(val), instant(valUtc)
            if local != utc:
                different += 1
                if different <= 3:
                    print(f"  ❌ {name}: {k}={val} and {kUtc}={valUtc} are not the same instant")
                continue
            if zone is None or val.endswith("Z") or utc.year not in IANA_YEARS:
                continue
            checked += 1
            expected = utc.astimezone(zone)
            if expected.utcoffset() == local.utcoffset():
                continue
            wall = local.replace(tzinfo=None)
            import datetime
            if wall.replace(tzinfo=zone).astimezone(datetime.timezone.utc).astimezone(zone).replace(tzinfo=None) != wall:
                # A local time the artefact stored in the hour skipped in spring:
                # it has no offset of its own. Reported, not a defect of WAC.
                nonexistent += 1
                continue
            wrong_offset += 1
            if wrong_offset <= 3:
                print(f"  ❌ {name}: {k}={val}: offset {expected.strftime('%z')} expected in {key}")
    if different:
        print(f"  ❌ {different} local/UTC pair(s) naming two different instants")
        found += 1
    else:
        print("  ✅ local/UTC pairs name the same instant")
    if zone is None:
        print(f"  ⏭️  time zone {key!r} not in the IANA table: offsets per date not checked")
    elif wrong_offset:
        print(f"  ❌ {wrong_offset} local date(s) with an offset other than the one of their date ({key})")
        found += 1
    else:
        extra = f"; {nonexistent} local time(s) of a skipped hour" if nonexistent else ""
        print(f"  ✅ {checked} local date(s) carry the offset of their own date ({key}, tz database){extra}")
    return found


if __name__ == "__main__":
    sys.exit(main())
