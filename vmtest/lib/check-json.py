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
import hashlib, json, sys, glob, os, re, collections

# A double escaping is recognised on a PATH pattern, not on free text: the
# content of an event (PowerShell script, regular expression, command line) may
# legitimately hold "\\" — for instance 'TIP\\(?:' where "\\" is PowerShell's
# escaping of a literal backslash. Only the patterns where the doubling is
# certainly wrong are therefore reported.
FAULTY_PATTERNS = (
    # A drive: one letter, not the end of a word ("Path:\\?\C:" in MPLog is a
    # label then the Win32 namespace prefix, as Defender writes it).
    re.compile(r'(?<![A-Za-z])[A-Za-z]:\\\\(?![?.]\\)'),   # C:\\Windows  (drive)
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

def check_configuration(folder):
    """A collection driven by wac.yml, WAC.exe run without any option: it must
    follow the file and record it. Independent of WAC's reading: the file's
    content recorded in investigation.json (Tool.Configuration) is read here
    line by line, its SHA-256 recomputed, and each switch checked against what
    the exhibit store holds."""
    import hashlib, re
    inv = load(folder, "investigation.json")
    cfg = ((inv or {}).get("Tool") or {}).get("Configuration") if isinstance(inv, dict) else None
    if not isinstance(cfg, dict) or cfg.get("Applied") is not True:
        print(f"  ❌ investigation.json does not record an applied configuration: {cfg!r}"[:160])
        return 1
    content = str(cfg.get("Content") or "")
    if hashlib.sha256(content.encode("utf-8")).hexdigest().upper() != str(cfg.get("SHA256")):
        print("  ❌ recorded SHA-256 is not the one of the recorded content")
        return 1
    settings, section = {}, ""
    for line in content.splitlines():
        m = re.match(r"^(\s*)([a-z_]+):\s*([^#]*?)\s*(#.*)?$", line)
        if not m:
            continue
        if not m.group(1) and not m.group(3):
            section = m.group(2) + "."
            continue
        settings[(section if m.group(1) else "") + m.group(2)] = m.group(3)
        if not m.group(1):
            section = ""
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    paths = [str(i.get("SourcePath", "")).lower() for i in items]
    wrong = []
    if settings.get("convert") == "false":
        converted = [f for f in os.listdir(folder) if f.endswith(".json") and f != "investigation.json"]
        if converted:
            wrong.append(f"convert: false, yet converted: {converted[:3]}")
    if settings.get("binary") == "none" and any("--binary" in str(i.get("Method", "")) for i in items):
        wrong.append("binary: none, yet executables collected")
    rules = [("artefacts.events", lambda p: p.endswith(".evtx")),
             ("artefacts.prefetch", lambda p: "\\windows\\prefetch\\" in p),
             ("artefacts.jump_lists", lambda p: "automaticdestinations" in p or "customdestinations" in p),
             ("artefacts.sessions", lambda p: p.startswith("live observation: logon sessions")),
             ("artefacts.network", lambda p: p.startswith("live observation: network state")),
             ("artefacts.registry", lambda p: p.endswith("\\ntuser.dat"))]
    for key, matches in rules:
        present = any(matches(p) for p in paths)
        if settings.get(key) == "false" and present:
            wrong.append(f"{key}: false, yet collected")
        if settings.get(key) == "true" and not present:
            wrong.append(f"{key}: true, yet absent")
    if not items:
        wrong.append("no exhibit store manifest")
    if wrong:
        print(f"  ❌ the collection does not follow wac.yml: {wrong}")
        return 1
    print(f"  ✅ collection follows wac.yml ({len(settings)} setting(s) checked against {len(items)} exhibit(s)), "
          f"file recorded with its SHA-256")
    return 0


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--configuration":
        sys.exit(check_configuration(sys.argv[2]))
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
        # Switched off by wac.yml (run-wac-test.sh --only): nothing to check.
        if isinstance(data, dict) and data.get("CollectionStatus") == "NotRequested":
            print(f"  ⏭️  {name:<34} not requested")
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
    """Loads an output JSON file, or None if it is absent, unreadable, or
    switched off by the configuration — its checks are then skipped, as for an
    absent file (run-wac-test.sh --only collects a few artefacts)."""
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception:
        return None
    if isinstance(data, dict) and data.get("CollectionStatus") == "NotRequested":
        return None
    return data


def switched_off(folder, *names):
    """Whether every named artefact was switched off by wac.yml (its JSON says
    NotRequested): a check that needs them is skipped, not failed — an
    absent file, on the other hand, stays a fault where a check expects it."""
    for name in names:
        try:
            with open(os.path.join(folder, name), encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception:
            return False
        if not (isinstance(data, dict) and data.get("CollectionStatus") == "NotRequested"):
            return False
    return True


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
    found += check_network(folder, boot)
    found += check_prefetchs(folder)
    found += check_shimcache_dates(folder)
    found += check_jumplist_entries(folder)
    found += check_events(folder)
    found += check_hive_replay(folder)
    found += check_exhibit_store(folder)
    found += check_mft_references(folder)
    found += check_mft_timeline(folder)
    found += check_small_file_artefacts(folder)
    found += check_mft_entries(folder)
    found += check_mounted_devices(folder)
    found += check_date_precision(folder)
    found += check_shell_item_dates(folder)
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
    found += check_third_party_chains(folder)
    found += check_vulnerable_driver(folder)
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


def check_third_party_chains(folder):
    """With a trust set next to WAC.exe (prepared in the VM by --update-trust),
    the chain of every intact third-party signature is checked against it
    (EmbeddedChainTrusted). The log must say which set was used. Independent
    source: Get-AuthenticodeSignature on the third-party binaries of the VM.
    The rule that matters: a chain WAC trusts must be Valid for Windows — the
    reverse only informs, WAC being stricter (RSA only, no machine roots).
    """
    inv = load(folder, "investigation.json")
    ops = (inv or {}).get("Operations") if isinstance(inv, dict) else None
    trust_ops = [str(o.get("Operation") or "") for o in ops or [] if "rust set" in str(o.get("Operation") or "")]
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    checked = {str(i.get("SourcePath", "")).lower(): i for i in items if "EmbeddedChainTrusted" in i}
    if not trust_ops:
        print("  ⏭️  no trust set recorded in the log (run without --binary?): third-party chains not checked")
        return 0
    if trust_ops[0].startswith("No usable trust set"):
        print(f"  ❌ the trust set was not usable: {trust_ops[0][:120]}")
        return 1
    # The third-party binaries are those the services, drivers, processes and
    # tasks name: with all of them switched off, none is fingerprinted.
    if not checked and switched_off(folder, "services.json", "processes.json", "ScheduledTasks.json"):
        print("  ⏭️  services, processes and tasks not requested: third-party chains not checked")
        return 0
    if not checked:
        # A full run records the binaries it clears in the artefacts, not in the manifest (B'6):
        # their verdict, "Third party (...)", is in the artefacts' JSON.
        cleared = 0
        for name in glob.glob(os.path.join(folder, "*.json")):
            try:
                with open(name, encoding="utf-8-sig") as f:
                    cleared += f.read().count('"Signature": "Third party (')
            except OSError:
                pass
        if cleared:
            print(f"  ✅ {cleared} third-party binaries cleared by their chain, recorded in the artefacts "
                  "(none left to collect in the manifest)")
            return 0
        print("  ❌ trust set usable, yet no third-party chain checked, in the manifest or the artefacts")
        return 1
    reference_path = os.path.join(folder, "reference", "third-party-signatures.txt")
    if not os.path.exists(reference_path):
        trusted = sum(1 for i in checked.values() if i.get("EmbeddedChainTrusted") is True)
        print(f"  ⏭️  {len(checked)} third-party chain(s) checked, {trusted} trusted; "
              "no Windows reference in this output: not compared")
        return 0
    compared, false_trust, stricter = 0, [], []
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|", 2)
            if len(parts) != 3 or parts[0].lower() not in checked:
                continue
            item = checked[parts[0].lower()]
            compared += 1
            if item.get("EmbeddedChainTrusted") is True and parts[1] != "Valid":
                false_trust.append(f"{parts[0]}: trusted by WAC ({item.get('EmbeddedChainRoot')}), {parts[1]} for Windows")
            if item.get("EmbeddedChainTrusted") is False and parts[1] == "Valid":
                stricter.append(f"{parts[0]}: {item.get('EmbeddedChainReason')}")
    trusted = sum(1 for i in checked.values() if i.get("EmbeddedChainTrusted") is True)
    print(f"  ℹ️  {len(checked)} third-party chain(s) checked, {trusted} trusted; {compared} in the reference")
    # The rule of the collection: under --binary, a chain that holds clears the binary (not copied),
    # one that does not has it copied; under --binary-all everything is copied.
    binary_all = any("--binary-all" in str(i.get("Method", "")) for i in items)
    misapplied = []
    for path, item in checked.items():
        stored = item.get("ContentStored") is not False
        if binary_all and not stored:
            misapplied.append(f"{path}: not copied under --binary-all")
        elif not binary_all and item.get("EmbeddedChainTrusted") is True and stored:
            misapplied.append(f"{path}: chain trusted, yet copied")
        elif not binary_all and item.get("EmbeddedChainTrusted") is False and not stored \
                and "medium full" not in str(item.get("Method", "")) \
                and not str(item.get("Signature", "")).startswith(("Microsoft", "Package")):
            # (authenticated otherwise — catalog, Store package — a binary is rightly not copied)
            misapplied.append(f"{path}: chain not trusted, yet not copied")
    if misapplied:
        print(f"  ❌ {len(misapplied)} third-party binaries against the collection rule:")
        for w in misapplied[:5]:
            print(f"        {w}")
        return 1
    for w in stricter[:5]:
        print(f"  ℹ️  refused by WAC, Valid for Windows: {w}")
    if false_trust:
        print(f"  ❌ {len(false_trust)} chain(s) trusted by WAC and not by Windows:")
        for w in false_trust[:5]:
            print(f"        {w}")
        return 1
    if not compared:
        print("  ⏭️  no checked chain in common with the reference")
        return 0
    print(f"  ✅ {compared} third-party chains: none trusted by WAC that Windows does not trust")
    return 0


def check_vulnerable_driver(folder):
    """A vulnerable driver placed in the VM (reference/vulnerable-driver.txt):
    signed, its chain holds — and it must still not be cleared: the manifest
    must say its chain is not trusted, because it is a listed driver."""
    reference_path = os.path.join(folder, "reference", "vulnerable-driver.txt")
    if not os.path.exists(reference_path):
        print("  ⏭️  no vulnerable driver placed: not checked")
        return 0
    with open(reference_path, encoding="utf-8", errors="replace") as f:
        path = f.read().strip().lower()
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
    found = [i for i in items if str(i.get("SourcePath", "")).lower() == path]
    if not found:
        print(f"  ⏭️  vulnerable driver absent from the manifest (removed by Defender?): {path}")
        return 0
    item = found[0]
    reason = str(item.get("EmbeddedChainReason") or "")
    if item.get("EmbeddedChainTrusted") is not False or "vulnerable" not in reason:
        print(f"  ❌ vulnerable driver not recognised: trusted={item.get('EmbeddedChainTrusted')}, reason={reason!r}")
        return 1
    if item.get("ContentStored") is False:
        print("  ❌ vulnerable driver recognised, yet not copied")
        return 1
    print(f"  ✅ vulnerable driver recognised despite its valid chain, and copied: {reason[:80]}")
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


def check_mft_entries(folder):
    """MftEntry in the manifest: present for what was read on the volume, absent
    for a live observation.

    A live observation (running-machine.json…) has no $MFT record; it used to
    carry "MftEntry": 0, which reads as the record of the $MFT itself — a
    value the source never had. The $MFT exhibit, whose record IS 0, must
    keep it.
    """
    manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
    if not isinstance(manifest, dict):
        return 0
    items = [i for i in manifest.get("Items", []) if i.get("Result") == "OK"]
    live = [i for i in items if str(i.get("Method", "")).startswith("Live observation")]
    wrong = [i.get("ExhibitPath") for i in live if "MftEntry" in i]
    mft = [i for i in items if str(i.get("SourcePath", "")).lower().endswith("\\$mft")]
    ok = not wrong and all(i.get("MftEntry") == 0 for i in mft)
    if ok:
        print(f"  ✅ MANIFEST.json: {len(live)} live observation(s) without MftEntry, the $MFT's own entry 0 kept")
    else:
        print(f"  ❌ MANIFEST.json: MftEntry on live observations {wrong[:3]}, or the $MFT's entry lost")
    return 0 if ok else 1


def check_small_file_artefacts(folder):
    """The small file artefacts against the witnesses the harness placed.

    place-file-artefacts.ps1 writes, before the collection, a PowerShell
    history, a file sent to the recycle bin, a hosts entry and a startup
    script, and counts the setupapi sections and the Defender logs: each JSON
    must hold what was placed, as it was placed — a decoder that misses a case
    gives valid JSON all the same. A JSON absent is skipped, not failed: a
    collection made before these artefacts existed has none.
    """
    reference = {}
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    if not os.path.exists(path):
        print("  ⏭️  no reference/file-artefacts.txt: small file artefacts not confronted")
        return 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            key, _, value = line.strip().partition("=")
            if value:
                reference[key] = value
    found = 0

    def report(ok, success, failure):
        nonlocal found
        print(f"  {'✅' if ok else '❌'} {success if ok else failure}")
        found += 0 if ok else 1

    history = load(folder, "powershell_history.json")
    if isinstance(history, list) and "powershell" in reference:
        host, count, first = reference["powershell"].split("|", 2)
        mine = [h for h in history if h.get("Host") == host]
        commands = mine[0].get("Commands", []) if mine else []
        report(len(commands) == int(count) and commands[0].get("Command") == first
               and "\n" in commands[1].get("Command", ""),
               f"powershell_history.json: history {host} read, {count} commands, the one on two lines joined",
               f"powershell_history.json: history {host} not as placed: {commands[:3]}")

    recycled = load(folder, "recycle_bin.json")
    if isinstance(recycled, list) and "recycled" in reference:
        match = [r for r in recycled if (r.get("OriginalPath") or "").lower() == reference["recycled"].lower()]
        report(bool(match) and match[0].get("DeletedUtc") and match[0].get("SID"),
               f"recycle_bin.json: {reference['recycled']} found, deleted {match[0].get('DeletedUtc') if match else ''}",
               f"recycle_bin.json: {reference['recycled']} missing among {len(recycled)} $I")

    hosts = load(folder, "hosts.json")
    if isinstance(hosts, dict) and "hosts" in reference:
        address, name = reference["hosts"].split("|", 1)
        report(any(e.get("Address") == address and name in (e.get("Names") or []) for e in hosts.get("Entries", [])),
               f"hosts.json: {address} {name} found",
               f"hosts.json: {address} {name} missing")

    startup = load(folder, "startup_folders.json")
    if isinstance(startup, list) and "startup" in reference:
        where, digest = reference["startup"].split("|", 1)
        match = [i for i in startup if (i.get("Path") or "").lower() == where.lower()]
        report(bool(match) and match[0].get("SHA256") == digest and match[0].get("Scope") == "AllUsers",
               "startup_folders.json: the startup witness found, its SHA-256 identical",
               f"startup_folders.json: the startup witness missing or altered: {match[:1]}")

    if "datavolume" in reference:
        letter, present, deleted = reference["datavolume"].split("|")
        mft = load(folder, "mft.json")
        usn = load(folder, "usn_journal.json")
        if isinstance(mft, list):
            report(any(r.get("Volume") == letter and (r.get("Path") or "").lower() == present.lower() and not r.get("Deleted")
                       for r in mft if isinstance(r, dict)),
                   f"mft.json: {present} found on the data volume {letter}",
                   f"mft.json: {present} missing from the data volume {letter}")
        if isinstance(usn, list):
            report(any(r.get("Volume") == letter and (r.get("Name") or "").lower() == deleted.split("\\")[-1].lower()
                       and "FILE_DELETE" in (r.get("Reasons") or "") for r in usn if isinstance(r, dict)),
                   f"usn_journal.json: the deletion of {deleted} found in {letter}'s journal",
                   f"usn_journal.json: the deletion of {deleted} missing from {letter}'s journal")

    zones = load(folder, "zone_identifiers.json")
    if isinstance(zones, list) and "zone" in reference:
        where, zone_id, host_url = reference["zone"].split("|", 2)
        match = [z for z in zones if (z.get("Path") or "").lower() == where.lower()]
        report(bool(match) and match[0].get("ZoneId") == zone_id and match[0].get("ZoneName") == "Internet"
               and match[0].get("HostUrl") == host_url,
               f"zone_identifiers.json: {where} from {host_url}, zone {zone_id} (Internet), read in the $MFT",
               f"zone_identifiers.json: {where} missing or different among {len(zones)} stream(s): {match[:1]}")

    runs = load(folder, "run.json")
    if isinstance(runs, list) and "run_default" in reference:
        name, value = reference["run_default"].split("|", 1)
        match = [r for r in runs if r.get("Hive") == "DEFAULT" and r.get("Name") == name]
        report(bool(match) and match[0].get("Type") == "REG_EXPAND_SZ" and match[0].get("Value") == value,
               f"run.json: {name} of the DEFAULT hive, REG_EXPAND_SZ, as written ({value})",
               f"run.json: {name} of the DEFAULT hive missing or different: {match[:1]}")

    persistence = load(folder, "persistence.json")
    if isinstance(persistence, list) and "ifeo" in reference:
        def find(mechanism, key_part, value):
            return [p for p in persistence if p.get("Mechanism") == mechanism
                    and key_part.lower() in (p.get("Key") or "").lower() and p.get("Value") == value]
        exe, debugger = reference["ifeo"].split("|", 1)
        report(bool(find("IFEO Debugger", exe, debugger)) and bool(find("IFEO GlobalFlag", exe, "0x00000200")),
               f"persistence.json: IFEO Debugger and GlobalFlag of {exe} found",
               f"persistence.json: IFEO witness of {exe} missing")
        exe, monitor = reference["silent"].split("|", 1)
        report(bool(find("SilentProcessExit MonitorProcess", exe, monitor)),
               f"persistence.json: SilentProcessExit MonitorProcess of {exe} found",
               "persistence.json: SilentProcessExit witness missing")
        guid, stub = reference["activesetup"].split("|", 1)
        report(bool(find("Active Setup StubPath", guid, stub)), "persistence.json: Active Setup StubPath witness found",
               "persistence.json: Active Setup witness missing")
        sid, clsid, dll = reference["comhijack"].split("|", 2)
        com = [p for p in find("COM InprocServer32 (user)", clsid, dll) if p.get("SID") == sid]
        report(bool(com), f"persistence.json: COM hijack of {clsid} in the user's classes found",
               "persistence.json: COM hijack witness missing")
        userinit = [p.get("Value") for p in persistence if p.get("Mechanism") == "Winlogon Userinit"]
        report(userinit == [reference.get("userinit")], f"persistence.json: Winlogon Userinit as Windows reads it ({reference.get('userinit')})",
               f"persistence.json: Winlogon Userinit {userinit} / Windows {reference.get('userinit')}")
        lsa = [p.get("Values") or [p.get("Value")] for p in persistence if p.get("Mechanism") == "LSA Security Packages"]
        # An empty list (Windows 11's default) leaves the reference line empty, hence absent.
        report(bool(lsa) and "|".join(v for v in lsa[0] if v) == reference.get("lsa_security", ""),
               "persistence.json: LSA Security Packages as Windows reads them",
               f"persistence.json: LSA Security Packages {lsa} / Windows {reference.get('lsa_security')}")
        monitors = sorted(p["Key"].split("\\")[-1] + "=" + (p.get("Value") or "") for p in persistence if p.get("Mechanism") == "Print monitor")
        expected = reference.get("monitors", "").split("|")
        report(sorted(monitors, key=str.lower) == sorted(expected, key=str.lower),
               f"persistence.json: the {len(monitors)} print monitors and their DLL as Windows reads them",
               f"persistence.json: print monitors {monitors} / Windows {expected}")

    def lot2(file, key, find, success, failure):
        data = load(folder, file)
        if data is not None and key in reference:
            report(bool(find(data, reference[key].split("|"))), success, failure)
    lot2("office_trust_records.json", "trust",
         lambda d, r: [t for t in d if t.get("SID") == r[0] and t.get("Document") == r[1] and t.get("MacrosEnabled") is True and t.get("TrustedUtc")],
         "office_trust_records.json: the document trusted with macros enabled found, dated",
         "office_trust_records.json: the trusted document witness missing")
    lot2("typed_paths.json", "typedpath",
         lambda d, r: [t for t in d if t.get("SID") == r[0] and str(t.get("Rank")) == r[1] and t.get("Text") == r[2]],
         "typed_paths.json: the typed path witness found at its rank", "typed_paths.json: the typed path witness missing")
    lot2("word_wheel_query.json", "search",
         lambda d, r: [t for t in d if t.get("SID") == r[0] and t.get("Rank") == 1 and t.get("Text") == r[1]],
         "word_wheel_query.json: the searched term found first (MRUListEx)", "word_wheel_query.json: the searched term missing or not first")
    lot2("internet_settings.json", "proxy",
         lambda d, r: [t for t in d if t.get("SID") == r[0] and t.get("ProxyServer") == r[1]],
         "internet_settings.json: the user's proxy found", "internet_settings.json: the user's proxy missing")
    firewall = load(folder, "firewall.json")
    if isinstance(firewall, dict) and "fwrule" in reference:
        name, action, direction, port = reference["fwrule"].split("|")
        rules = firewall.get("Rules", [])
        report(any(r.get("Name") == name and r.get("Action") == action and r.get("Direction") == direction
                   and r.get("LocalPort") == port for r in rules) and str(len(rules)) == reference.get("fwcount"),
               f"firewall.json: {len(rules)} rules as Windows counts them, the witness rule found",
               f"firewall.json: {len(rules)} rules (Windows {reference.get('fwcount')}), witness found: "
               f"{any(r.get('Name') == name for r in rules)}")
    roots = load(folder, "root_certificates.json")
    if isinstance(roots, list) and "roots" in reference:
        mine = sorted(c.get("Thumbprint", "").upper() for c in roots if c.get("Store") == "LocalMachine\\Root")
        expected = sorted(t.upper() for t in reference["roots"].split(",") if t)
        mismatched = [c.get("Thumbprint") for c in roots if c.get("ThumbprintMismatch") or c.get("CertificateUnreadable")]
        subject_ok = True
        if "rootsubject" in reference:
            thumb, subject = reference["rootsubject"].split("|", 1)
            subject_ok = any(c.get("Thumbprint", "").upper() == thumb.upper() and c.get("Subject") == subject for c in roots)
        report(mine == expected and not mismatched and subject_ok,
               f"root_certificates.json: the {len(mine)} roots of LocalMachine\\Root as Windows lists them, every SHA-1 = its thumbprint",
               f"root_certificates.json: roots {len(mine)} / Windows {len(expected)}, mismatched {mismatched[:3]}, subject {subject_ok}")

    security = load(folder, "security.json")
    if isinstance(security, dict) and "secrets" in reference:
        # Compared as sets: PowerShell sorts without case, Python with it.
        names = ",".join(sorted((s.get("Name", "") for s in security.get("LsaSecrets", [])), key=str.lower))
        report(sorted(names.lower().split(",")) == sorted(reference["secrets"].lower().split(",")),
               f"security.json: the {len(security.get('LsaSecrets', []))} LSA secret names read by Windows, no value",
               f"security.json: secret names {names} / Windows {reference['secrets']}")
        leaked = [s for s in security.get("LsaSecrets", []) if set(s) - {"Name", "KeyLastWrite", "KeyLastWriteUtc",
                  "CurrentValueSet", "CurrentValueSetUtc", "PreviousValueSet", "PreviousValueSetUtc"}]
        report(not leaked, "security.json: no field beyond names and dates", f"security.json: unexpected fields {leaked[:1]}")
        report((security.get("AuditPolicy") or {}).get("PolAdtEv") == reference.get("audit"),
               "security.json: PolAdtEv identical to Windows' byte for byte",
               "security.json: PolAdtEv differs from Windows'")
        slots = (security.get("CachedLogons") or {}).get("Slots", 0)
        report(str(slots) == reference.get("nl_slots"),
               f"security.json: {slots} cached logon slot(s), as Windows counts them",
               f"security.json: {slots} cached logon slot(s), Windows {reference.get('nl_slots')}")

    setupapi = load(folder, "setupapi.json")
    if isinstance(setupapi, list) and "setupapi" in reference:
        dated = sum(1 for s in setupapi if s.get("StartUtc"))
        report(len(setupapi) >= int(reference["setupapi"]) and dated >= len(setupapi) * 0.9,
               f"setupapi.json: {len(setupapi)} section(s), at least the {reference['setupapi']} counted before, {dated} dated",
               f"setupapi.json: {len(setupapi)} section(s) ({dated} dated), {reference['setupapi']} counted before")

    defender = load(folder, "defender_log.json")
    if isinstance(defender, list) and "mplog" in reference:
        lines = sum(len(d.get("Lines", [])) for d in defender)
        report(len(defender) >= int(reference["mplog"]) and (lines > 0 or int(reference["mplog"]) == 0),
               f"defender_log.json: {len(defender)} log(s), {lines} line(s)",
               f"defender_log.json: {len(defender)} log(s) for {reference['mplog']} present, {lines} line(s)")

    # WMI subscriptions: the harness's, and every one of every namespace as
    # Get-CimInstance counts them.
    wmi = load(folder, "wmi_persistence.json")
    if isinstance(wmi, list) and "wmi" in reference:
        def props(o):
            return {p.get("Name"): p.get("Value") for p in o.get("Properties") or []}
        def named(kind, cls, name, space="root\\subscription"):
            return next((props(o) for o in wmi if o.get("Kind") == kind and o.get("Class") == cls
                         and o.get("Namespace", "").lower() == space and props(o).get("Name") == name), None)
        f = named("Filter", "__EventFilter", "WacTestFilter")
        c = named("Consumer", "CommandLineEventConsumer", "WacTestConsumer")
        a = named("Consumer", "ActiveScriptEventConsumer", "WacTestScript")
        other = named("Filter", "__EventFilter", "WacTestFilterDefault", "root\\default")
        bound = {str(props(o).get("Consumer")) for o in wmi if o.get("Kind") == "Binding" and "WacTestFilter" in str(props(o).get("Filter"))}
        wrong = []
        if not f or f.get("Query") != reference["wmi"] or f.get("CreatorSID") != "S-1-5-18":
            wrong.append(f"filter {f}")
        if not c or c.get("CommandLineTemplate") != "cmd.exe /c echo wac-test-consumer" or c.get("Priority") != 32:
            wrong.append(f"command line consumer {c}")
        if not a or a.get("ScriptingEngine") != "VBScript" or a.get("ScriptText") != "' WAC test: never run":
            wrong.append(f"script consumer {a}")
        if not other:
            wrong.append("filter of root\\default")
        if not any("WacTestConsumer" in b for b in bound) or not any("WacTestScript" in b for b in bound):
            wrong.append(f"bindings {sorted(bound)}")
        report(not wrong, "wmi_persistence.json: the harness's filters, consumers (command line, VBScript) and bindings, as created",
               f"wmi_persistence.json: {wrong[0] if wrong else ''}")
        if "wmicount" in reference:
            expected = dict(zip(("Filter", "Consumer", "Binding", "Timer"), map(int, reference["wmicount"].split("|")[:4])))
            got = collections.Counter(o.get("Kind") for o in wmi)
            spaces = int(reference["wmicount"].split("|")[4])
            report(all(got.get(k, 0) == v for k, v in expected.items()),
                   f"wmi_persistence.json: {dict(got)} across the {spaces} namespaces, as Get-CimInstance counts them",
                   f"wmi_persistence.json: {dict(got)} for {expected} counted by Get-CimInstance")

    # FAT and exFAT: the two keys as Windows lists them, and what the harness deleted.
    fats = load(folder, "fat_volumes.json")
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    if isinstance(fats, list) and "fat" in reference and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f if l.strip()]
        volumes = [l[4:].split("|") for l in lines if l.startswith("fat=")]
        files = [l[8:].split("|") for l in lines if l.startswith("fatfile=")]
        present = {(e.get("Path") or "").lower(): e for e in fats if not e.get("Deleted")}
        wrong = []
        for letter, label, system in volumes:
            if not any(e.get("Volume") == letter and e.get("FileSystem") == system and e.get("Label") == label for e in fats):
                wrong.append(f"volume {letter} {system} {label} absent")
            # On FAT, a deleted long name may be overwritten by a later entry (the witnesses are
            # recreated at each cycle): its 8.3 name remains, first letter lost.
            deleted = [(e.get("Path") or "") + "|" + (e.get("ShortName") or "") for e in fats
                       if e.get("Volume") == letter and e.get("Deleted")]
            if not any(p.split("|")[0].endswith("eleted-file.txt") or p.endswith("ELETE~1.TXT") for p in deleted) \
                    or not any(p.split("|")[0].endswith("nner.txt") for p in deleted):
                wrong.append(f"{letter}: the deleted file or folder not found among {len(deleted)} deleted entries")
        for file, size, modified in files:
            e = present.get(file.lower())
            got = (e or {}).get("ModifiedUtc", "")[:19]
            # FAT keeps two seconds: a write at an odd second is rounded up.
            close = got and abs((instant(got + "Z") - instant(modified + "Z")).total_seconds()) <= 2
            if e is None or e.get("Size") != int(size) or not close:
                wrong.append(f"{file}: {None if e is None else (e.get('Size'), got)} for ({size}, {modified})")
        # The winter file copied in summer: its UTC date exact, the copy said (FAT).
        for letter, label, system in volumes:
            copy = present.get((letter + "\\copied-winter.txt").lower())
            if copy is None:
                continue
            if (copy.get("ModifiedUtc") or "")[:19] != "2022-01-10T12:00:00":
                wrong.append(f"{letter}\\copied-winter.txt: ModifiedUtc {copy.get('ModifiedUtc')} for 2022-01-10T12:00:00")
            if system == "FAT32" and copy.get("ModifiedWrittenAt") != "Copy":
                wrong.append(f"{letter}\\copied-winter.txt: the copy not said")
            local = str(copy.get("Modified", ""))
            if not (local.startswith("2022-01-10T13:00:00") and local.endswith("+01:00")):
                wrong.append(f"{letter}\\copied-winter.txt: local date {copy.get('Modified')} for 2022-01-10T13:00:00+01:00")
        # The program run from the key, fingerprinted there through the FAT reader (--binary).
        tool = next((l[8:].split("|") for l in lines if l.startswith("fattool=")), None)
        prefetch = load(folder, "prefetchs.json")
        if tool and isinstance(prefetch, list):
            cited = [o for p in prefetch for o in [p] + (p.get("FileNames") or []) if isinstance(o, dict)
                     and (o.get("FullPath") or "").lower() == tool[0].lower()]
            if not cited:
                wrong.append(f"{tool[0]} not cited by prefetchs.json")
            # A --collect run records only the Authenticode digest of a binary
            # authenticated as Microsoft (the collection rule): the copy of
            # whoami.exe then carries its signature, not its file hashes.
            elif not any(o.get("SHA256") == tool[1]
                         or (str(o.get("Signature", "")).startswith("Microsoft") and o.get("AuthenticodeSHA256"))
                         for o in cited):
                wrong.append(f"{tool[0]}: SHA256 {[o.get('SHA256') for o in cited]} for {tool[1]}")
        report(not wrong, f"fat_volumes.json: {len(volumes)} volume(s) (FAT32, exFAT), {len(files)} file(s) as Windows lists them, deleted entries found",
               f"fat_volumes.json: {wrong[0] if wrong else ''}")

    # The folder inside a ZIP: its shellbag item gives the entry's date as written, without zone.
    bags = load(folder, "shellbags.json")
    if isinstance(bags, list) and "zipentry" in reference:
        name, written = reference["zipentry"].split("|")
        items = []
        def archive(o):
            if isinstance(o, dict):
                if o.get("Type") == "ARCHIVE_FILE_CONTENT" and o.get("Name") == name:
                    items.append(o)
                for v in o.values():
                    archive(v)
            elif isinstance(o, list):
                for v in o:
                    archive(v)
        archive(bags)
        ok = items and all(str(i.get("ModifiedAsWritten", "")).startswith(written) and "ModifiedUtc" not in i
                           and "Modified" not in i for i in items)
        report(ok, f"shellbags.json: the ZIP entry {name} dated {written} as written, without time zone",
               f"shellbags.json: the ZIP entry {name}: {items[:1]}")

    # Event values as Windows renders them (hexadecimal integers, GUIDs, booleans, dates).
    events = load(folder, "events.json")
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    if isinstance(events, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            wanted = [l.strip()[7:].split("|", 3) for l in f if l.startswith("evtval=")]
        if wanted:
            index = {(str(e.get("EvtSourceLog", "")).lower(), e.get("EvtSystemEventRecordId")): e for e in events if isinstance(e, dict)}
            wrong, compared = [], 0
            for channel, record, name, value in wanted:
                e = index.get((channel.replace("/", "%4").lower() + ".evtx", int(record)))
                if e is None:
                    continue
                mine = next((d.get("Value") for d in e.get("EvtEventData") or [] if isinstance(d, dict) and d.get("Name") == name), None)
                compared += 1
                if " ".join(str(mine or "").split()) != value:
                    wrong.append(f"{channel} {record} {name}: WAC {mine!r}, Windows {value!r}")
            report(compared and not wrong, f"events.json: {compared} event value(s) rendered as Windows renders them",
                   f"events.json: {wrong[0] if wrong else 'no reference event found'}")

    # BITS: the harness's job, as Get-BitsTransfer gives it.
    bits = load(folder, "bits_jobs.json")
    if isinstance(bits, list) and "bits" in reference:
        job_id, description, state, created = reference["bits"].split("|")
        j = next((x for x in bits if (x.get("JobId") or "").upper() == job_id.upper()), None)
        files = (j or {}).get("Files") or []
        wrong = []
        if j is None:
            wrong.append(f"job {job_id} absent among {len(bits)}")
        else:
            if j.get("Name") != "WacTestJob" or j.get("Description") != description or j.get("State") != state:
                wrong.append(f"name/description/state {j.get('Name')!r}/{j.get('Description')!r}/{j.get('State')!r}")
            if j.get("NotifyProgram") != "C:\\Windows\\System32\\cmd.exe" or j.get("NotifyArguments") != "/c echo wac-bits-test":
                wrong.append(f"notification {j.get('NotifyProgram')!r} {j.get('NotifyArguments')!r}")
            if j.get("OwnerSID") != "S-1-5-18" or (j.get("CreatedUtc") or "")[:19] != created:
                wrong.append(f"owner/creation {j.get('OwnerSID')}/{j.get('CreatedUtc')} for {created}")
            if not files or files[0].get("Source") != "https://wac-test.invalid/wac-bits.bin" \
                    or files[0].get("Destination") != "C:\\wactest\\wac-bits.bin":
                wrong.append(f"files {files}")
        report(not wrong, f"bits_jobs.json: job {job_id} with its URL, destination and notification command, as BITS gives it",
               f"bits_jobs.json: {wrong[0] if wrong else ''}")

    # SRUM: every application and user resolved, every hour in the past.
    srum = load(folder, "srum.json")
    if isinstance(srum, list):
        inv = load(folder, "investigation.json")
        start = ((inv or {}).get("Collection") or {}).get("StartUtc") if isinstance(inv, dict) else None
        network = [r for r in srum if r.get("Provider") == "NetworkUsage"]
        # An identifier whose SruDbIdMapTable entry has no IdBlob has nothing to
        # resolve (entries 1 and 2 on the test VM, as dissect.esedb reads them too).
        with_blob = {r.get("IdIndex") for r in srum if r.get("Table") == "SruDbIdMapTable" and r.get("IdBlob")}
        unresolved = sum(1 for r in srum if r.get("AppId") in with_blob and "App" not in r)
        users = sum(1 for r in srum if r.get("UserId") in with_blob and "UserSID" not in r)
        future = sum(1 for r in srum if start and r.get("TimeStamp") and r["TimeStamp"][:19] > start[:19])
        report(network and not unresolved and not users and not future,
               f"srum.json: {len(srum)} row(s), {len(network)} of network usage, every AppId and UserId resolved, none after the collection",
               f"srum.json: {len(network)} network row(s), {unresolved} AppId and {users} UserId unresolved, {future} after the collection")

    # The EICAR detection of the cycle, against MSFT_MpThreatDetection, and
    # its quarantine against the dates and content the harness gave the file.
    detections = load(folder, "defender_detections.json")
    quarantine = load(folder, "defender_quarantine.json")
    if isinstance(detections, list) and "defender" in reference:
        detection_id, path, initial, user, process, threat, status = reference["defender"].split("|")
        d = next((x for x in detections if (x.get("DetectionId") or "").upper() == detection_id.upper()), None)
        wrong = []
        if d is None:
            wrong.append(f"detection {detection_id} absent among {len(detections)}")
        else:
            resources = [(r.get("Type"), (r.get("Path") or "").lower()) for r in d.get("Resources") or []]
            if ("file", path.lower()) not in resources:
                wrong.append(f"resource {resources}")
            if (d.get("InitialDetectionUtc") or "")[:23] != initial:
                wrong.append(f"InitialDetectionUtc {d.get('InitialDetectionUtc')} for {initial}")
            if str(d.get("ThreatId")) != threat or str(d.get("CurrentThreatExecutionStatusId")) != status:
                wrong.append(f"ThreatId/CurrentThreatExecutionStatusId {d.get('ThreatId')}/{d.get('CurrentThreatExecutionStatusId')}")
            if d.get("ProcessName") != process or (user.isascii() and d.get("DomainUser") != user):
                wrong.append(f"account/process {d.get('DomainUser')!r}/{d.get('ProcessName')!r}")
        report(not wrong, f"defender_detections.json: detection {detection_id} as MSFT_MpThreatDetection gives it",
               f"defender_detections.json: {wrong[0] if wrong else ''}")
        if d is not None and isinstance(quarantine, list):
            entry = next((q for q in quarantine if (q.get("EntryId") or "").upper() == (d.get("QuarantineEntryId") or "").upper()), None)
            r = next((r for r in (entry or {}).get("Resources") or [] if (r.get("Path") or "").lower() == path.lower()), None)
            eicar_sha1 = hashlib.sha1(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").hexdigest().upper()
            tracking = {t.get("Name"): t.get("Value") for t in d.get("ThreatTracking") or []}
            wrong = []
            if r is None:
                wrong.append(f"entry {d.get('QuarantineEntryId')} or its resource absent")
            else:
                if (r.get("CreatedUtc") or "")[:19] != "2021-01-02T03:04:05" or (r.get("ModifiedUtc") or "")[:19] != "2022-03-04T05:06:07":
                    wrong.append(f"dates {r.get('CreatedUtc')} / {r.get('ModifiedUtc')}")
                if r.get("Size") != 68 or r.get("ContentSize") != 68 or r.get("ContentSha1") != eicar_sha1:
                    wrong.append(f"size/content {r.get('Size')}/{r.get('ContentSize')}/{r.get('ContentSha1')}")
                if (tracking.get("ThreatTrackingSha1") or "").upper() != r.get("ContentSha1"):
                    wrong.append("ThreatTrackingSha1 of the detection differs from the quarantined content")
            report(not wrong, f"defender_quarantine.json: {path} with its dates, size and SHA-1, decrypted in memory only",
                   f"defender_quarantine.json: {wrong[0] if wrong else ''}")
    return found


def check_mft_timeline(folder):
    """mft.json and usn_journal.json against sources read otherwise.

    mft.json rebuilds each path from the parent references UP to the root; the
    raw extraction of the exhibits found each file by walking the directory
    indexes DOWN from the root, by name, and recorded its $MFT entry and dates
    in the manifest. Two readings of the same volume: for every exhibit of the
    system volume, the record of its entry in mft.json must carry its path and
    its creation date. Only what cannot change during the collection is
    compared: a hive in use is rewritten between its extraction and the copy
    of the $MFT, so its modification date and size may move.

    A file with hard links is one record under several names (System32 and
    WinSxS): the exhibit's path must be its Path or one of its HardLinkPaths —
    a name missing from both would be a file an analyst cannot find.

    usn_journal.json: a record's number is its offset in the journal's stream,
    so the numbers rise strictly in the order read; and no change is dated
    after the collection.
    """
    found = 0
    mft = load(folder, "mft.json")
    if not isinstance(mft, list) or not mft:
        print("  ⏭️  mft.json absent or empty: $MFT check skipped")
    else:
        # A record number only means something within its volume.
        def volume_of(r):
            return str(r.get("Volume") or str(r.get("Path", ""))[:2]).upper()
        by_entry = {(volume_of(r), r.get("Entry")): r for r in mft if isinstance(r, dict)}
        volumes = {volume_of(r) for r in mft if isinstance(r, dict)}
        manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
        items = (manifest or {}).get("Items") or [] if isinstance(manifest, dict) else []
        compared, wrong = 0, []
        for it in items:
            source = str(it.get("SourcePath") or "")
            entry = it.get("MftEntry")
            created = it.get("SourceCreatedUtc")
            # Files of a volume whose $MFT was converted, by name (not the metafiles, not a named stream).
            if source[:2].upper() not in volumes or ":" in source[2:] or not entry or not created:
                continue
            r = by_entry.get((source[:2].upper(), entry))
            compared += 1
            if r is None:
                wrong.append((source, "entry %s absent from mft.json" % entry))
            elif source.lower() not in {str(p).lower() for p in [r.get("Path", "")] + (r.get("HardLinkPaths") or [])}:
                wrong.append((source, "path %s, links %s" % (r.get("Path"), r.get("HardLinkPaths"))))
            elif r.get("CreatedUtc") != created:
                wrong.append((source, "created %s, manifest %s" % (r.get("CreatedUtc"), created)))
        deleted = sum(1 for r in mft if isinstance(r, dict) and r.get("Deleted"))
        linked = sum(1 for r in mft if isinstance(r, dict) and r.get("HardLinkPaths"))
        if compared == 0:
            print("  ⏭️  no exhibit of the system volume in the manifest: $MFT check skipped")
        elif wrong:
            print(f"  ❌ mft.json: {len(wrong)}/{compared} exhibit(s) disagree with the manifest")
            for src, why in wrong[:3]:
                print(f"        {src}: {why}")
            found += 1
        else:
            print(f"  ✅ mft.json: {compared} exhibit(s) with the manifest's path and creation date "
                  f"({len(mft)} record(s), {deleted} deleted, {linked} with hard links)")

    usn = load(folder, "usn_journal.json")
    if not isinstance(usn, list) or not usn:
        print("  ⏭️  usn_journal.json absent or empty: change journal check skipped")
        return found
    # Each volume has its own journal: the numbers rise within a volume.
    by_volume = {}
    for r in usn:
        if isinstance(r, dict):
            by_volume.setdefault(str(r.get("Volume") or str(r.get("Path", ""))[:2]).upper(), []).append(r.get("Usn"))
    falling = sum(1 for numbers in by_volume.values()
                  for a, b in zip(numbers, numbers[1:]) if not (isinstance(a, int) and isinstance(b, int) and b > a))
    inv = load(folder, "investigation.json")
    coll = (inv or {}).get("Collection") if isinstance(inv, dict) else None
    end = (coll or {}).get("EndUtc") or (coll or {}).get("StartUtc") if isinstance(coll, dict) else None
    future = [r.get("TimestampUtc") for r in usn
              if end and isinstance(r, dict) and instant(r.get("TimestampUtc") or "") > instant(end)]
    incomplete = sum(1 for r in usn if isinstance(r, dict) and r.get("PathIncomplete"))
    if falling:
        print(f"  ❌ usn_journal.json: {falling} record number(s) not above the previous one "
              "— a record read out of step, or a wrong LeadingSparseBytes")
        found += 1
    elif future:
        print(f"  ❌ usn_journal.json: {len(future)} change(s) dated after the collection ({end})")
        found += 1
    else:
        print(f"  ✅ usn_journal.json: {len(usn)} record(s) on {len(by_volume)} volume(s), numbers rising, "
              f"none after the collection ({incomplete} path(s) incomplete)")
    return found


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
    total = sum(len(p.get("FileNames") or []) for p in d)
    if total == 0:
        print("  ⏭️  prefetchs.json: no file listed, check skipped")
        return 0
    resolved = sum(1 for p in d for f in (p.get("FileNames") or [])
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


def check_shell_item_dates(folder):
    """The dates of a shortcut's target, twice: in UTC in the shortcut's
    header, and in FAT format in the shell item of its ID list (the last file
    entry, and its 0xbeef0004 block). Both describe the same instant.

    WHY. Shell item dates were read as local time, as FAT's specification
    says, when Windows writes them in UTC: every date of every shortcut, jump
    list and shellbag was one or two hours off, in valid JSON (B-028). Every
    shortcut of the machine — its own and the harness's winter witness —
    confronts the two; FAT keeps two seconds, hence the margin.
    """
    compared, wrong = 0, []
    def seconds(a, b):
        return abs((instant(a) - instant(b)).total_seconds())
    def visit(o, name):
        nonlocal compared
        if isinstance(o, dict):
            items = [i for i in o.get("IdList") or [] if isinstance(i, dict) and i.get("Type") == "FILE_ENTRY_SHELL_ITEM"]
            if items and o.get("TargetModifiedUtc"):
                last = items[-1]
                pairs = [("TargetModifiedUtc", o.get("TargetModifiedUtc"), last.get("ModificationDateUtc"))]
                for block in last.get("ExtensionBlocks") or []:
                    if isinstance(block, dict) and block.get("Signature") == "0xbeef0004":
                        pairs.append(("TargetCreatedUtc", o.get("TargetCreatedUtc"), block.get("CreatedDateUtc")))
                for key, header, item in pairs:
                    if not header or not item or header.startswith("1601"):
                        continue
                    compared += 1
                    if seconds(header, item) > 2:
                        wrong.append(f"{name}: {o.get('Path') or o.get('Target')}: {key} {header}, shell item {item}")
            for v in o.values():
                visit(v, name)
        elif isinstance(o, list):
            for v in o:
                visit(v, name)
    for name in ("recentdocs.json", "jumplistAutomaticDestinations.json", "jumplistCustomDestinations.json"):
        d = load(folder, name)
        if d is not None:
            visit(d, name)
    # Shellbags have no header: their 0xbeef0004 blocks name the folder's $MFT
    # record, whose creation mft.json gives — a second, independent source.
    mft = load(folder, "mft.json")
    bags = load(folder, "shellbags.json")
    if isinstance(mft, list) and isinstance(bags, list):
        created = {(r.get("Entry"), r.get("Sequence")): r.get("CreatedUtc") for r in mft
                   if isinstance(r, dict) and str(r.get("Volume", "C:")).upper() == "C:"}
        def bag(o):
            nonlocal compared
            if isinstance(o, dict):
                if o.get("Signature") == "0xbeef0004" and o.get("MftNote") == "NTFS" and o.get("CreatedDateUtc"):
                    record = created.get((o.get("MftEntryNumber"), o.get("MftSequenceNumber")))
                    if record:
                        compared += 1
                        if seconds(record, o["CreatedDateUtc"]) > 2:
                            wrong.append(f"shellbags.json: {o.get('LongName')}: $MFT creation {record}, shell item {o['CreatedDateUtc']}")
                for v in o.values():
                    bag(v)
            elif isinstance(o, list):
                for v in o:
                    bag(v)
        bag(bags)
    if not compared:
        print("  ⏭️  no shortcut with its target's dates: shell item dates not confronted")
        return 0
    if wrong:
        for text in wrong[:3]:
            print(f"  ❌ shell item date other than the header's: {text}")
        print(f"  ❌ {len(wrong)} of {compared} shell item date(s) other than the shortcut header's UTC")
        return 1
    print(f"  ✅ {compared} shell item date(s) identical to their UTC source — shortcut header or $MFT record (to FAT's 2 s)")
    return 0


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
    if switched_off(folder, "Usbstor.json"):
        print("  ⏭️  Usbstor.json not requested: USBSTOR not confronted")
    elif os.path.exists(path):
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
    if switched_off(folder, "bams.json"):
        print("  ⏭️  bams.json not requested: BAM not checked")
    elif not isinstance(bams, list) or not bams:
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
    if switched_off(folder, "userassists.json"):
        print("  ⏭️  userassists.json not requested: UserAssist not checked")
    elif not isinstance(ua, list) or not ua:
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
    SIDs, service SIDs, profiles (sources/account_names.cpp). Checked here:
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
    machine's hives (sources/trans_id.cpp). run-wac-test.sh registers three GUIDs,
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


def check_network(folder, boot):
    """The network state against three independent sources:
      - netstat, run by the test right after the collection (reference/
        netstat-tcp.txt): its TCP listeners, still open, must be in
        network.json with the same address, port and owner — netstat formats
        through Winsock, WAC by itself (ip_address.cpp), and the port is
        byte-swapped by WAC;
      - processes.json: the owner of nearly every connection is a process
        observed a moment earlier;
      - the boot time: no connection is created before it, and the default
        route's next hop is a gateway of an interface (two tables)."""
    d = load(folder, "network.json")
    if not isinstance(d, dict):
        print("  ⏭️  network.json absent: check skipped")
        return 0
    found = 0
    connections = d.get("Connections") or []
    if d.get("TablesNotRead"):
        print(f"  ❌ network.json: tables not read {d['TablesNotRead']}")
        found += 1
    if not connections or not d.get("Interfaces") or not d.get("Routes"):
        print("  ❌ network.json: no connection, interface or route")
        return found + 1

    ref = os.path.join(folder, "reference", "netstat-tcp.txt")
    if os.path.exists(ref):
        import re
        listeners = set()
        with open(ref, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)", line)
                if m:
                    listeners.add((m.group(1).strip("[]").split("%")[0], int(m.group(2)), int(m.group(3))))
        mine = {(c.get("LocalAddress"), c.get("LocalPort"), c.get("ProcessId"))
                for c in connections if c.get("State") == "LISTEN"}
        missing = sorted(listeners - mine)
        # A listener opened after the collection is legitimate: a few, not most.
        if not listeners or len(missing) > max(2, len(listeners) // 10):
            print(f"  ❌ network.json: {len(missing)}/{len(listeners)} netstat listener(s) absent "
                  f"(address, port, PID) {missing[:4]}")
            found += 1
        else:
            print(f"  ✅ network.json: {len(listeners) - len(missing)}/{len(listeners)} netstat listeners "
                  f"found with the same address, port and owner")
    else:
        print("  ⏭️  netstat reference absent: listener cross-check skipped")

    owned = [c for c in connections if c.get("ProcessId")]
    unnamed = [c for c in owned if not c.get("Process")]
    if os.path.exists(os.path.join(folder, "processes.json")) and len(unnamed) > max(2, len(owned) // 20):
        print(f"  ❌ network.json: {len(unnamed)}/{len(owned)} connection(s) owned by no observed process")
        found += 1
    else:
        print(f"  ✅ network.json: {len(owned) - len(unnamed)}/{len(owned)} connection owners named")

    if boot:
        early = [c for c in connections if c.get("CreatedUtc") and instant(c["CreatedUtc"]) < instant(boot)]
        if early:
            print(f"  ❌ network.json: {len(early)} connection(s) created before the boot ({boot})")
            found += 1
        else:
            print(f"  ✅ network.json: no connection created before the boot")

    gateways = {g for i in d.get("Interfaces") for g in i.get("Gateways") or []}
    hops = {r.get("NextHop") for r in d.get("Routes") if r.get("Destination") == "0.0.0.0/0"}
    if not hops & gateways:
        print(f"  ❌ network.json: default route next hop {sorted(hops)} is no interface gateway {sorted(gateways)}")
        found += 1
    else:
        print(f"  ✅ network.json: default route through {sorted(hops & gateways)}, an interface gateway")
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
