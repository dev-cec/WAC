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
import hashlib, json, sys, glob, os, re, collections, uuid, datetime

def md4(data):
    """MD4 (RFC 1320), pure Python: OpenSSL 3 drops it from hashlib, and the NT
    hash is MD4 of the password in UTF-16LE. Used only to confront WAC's
    decrypted NT hash with a witness account's known password."""
    def lrot(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
    msg = bytearray(data)
    bitlen = (8 * len(data)) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56: msg.append(0)
    msg += bitlen.to_bytes(8, "little")
    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], "little") for i in range(16)]
        aa, bb, cc, dd = a, b, c, d
        for k, s in zip(range(16), [3, 7, 11, 19] * 4):          # round 1
            v = (a + ((b & c) | (~b & d)) + x[k]) & 0xffffffff
            a, b, c, d = d, lrot(v, s), b, c
        order2 = [i + j for j in range(4) for i in (0, 4, 8, 12)]
        for k, s in zip(order2, [3, 5, 9, 13] * 4):              # round 2
            v = (a + ((b & c) | (b & d) | (c & d)) + x[k] + 0x5a827999) & 0xffffffff
            a, b, c, d = d, lrot(v, s), b, c
        order3 = [i + j for j in (0, 2, 1, 3) for i in (0, 8, 4, 12)]
        for k, s in zip(order3, [3, 9, 11, 15] * 4):             # round 3
            v = (a + (b ^ c ^ d) + x[k] + 0x6ed9eba1) & 0xffffffff
            a, b, c, d = d, lrot(v, s), b, c
        a = (a + aa) & 0xffffffff; b = (b + bb) & 0xffffffff
        c = (c + cc) & 0xffffffff; d = (d + dd) & 0xffffffff
    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))



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
    # A collection converts nothing (B-047): investigation.json is its only JSON.
    converted = [f for f in os.listdir(folder) if f.endswith(".json") and f != "investigation.json"]
    if converted:
        wrong.append(f"a collection, yet converted: {converted[:3]}")
    if settings.get("binary") == "none" and any("--binary" in str(i.get("Method", "")) for i in items):
        wrong.append("binary: none, yet executables collected")
    rules = [("artefacts.prefetch", lambda p: "\\windows\\prefetch\\" in p),
             ("artefacts.jump_lists", lambda p: "automaticdestinations" in p or "customdestinations" in p),
             ("artefacts.sessions", lambda p: p.startswith("live observation: logon sessions")),
             ("artefacts.network", lambda p: p.startswith("live observation: network state")),
             ("artefacts.amcache", lambda p: p.endswith("\\amcache.hve")),
             ("artefacts.registry_backups", lambda p: "\\config\\regback\\" in p)]
    for key, matches in rules:
        present = any(matches(p) for p in paths)
        if settings.get(key) == "false" and present:
            wrong.append(f"{key}: false, yet collected")
        if settings.get(key) == "true" and not present:
            wrong.append(f"{key}: true, yet absent")
    # Dependencies (B-042): not artefacts, taken when an artefact asked for
    # reads them — and only then. A key missing from the file is true.
    def asked(*keys):
        return any(settings.get("artefacts." + k) != "false" for k in keys)
    dependencies = [("event logs", lambda p: p.endswith(".evtx"), asked("events", "rdp_server")),
                    ("user hives", lambda p: p.endswith("\\ntuser.dat"),
                     asked("muicache", "userassist", "run_keys", "shellbags", "mru", "mru_apps", "persistence",
                           "office_trust_records", "typed_paths", "word_wheel_query", "root_certificates",
                           "internet_settings", "installed_programs", "explorer_recent_docs", "mount_points",
                           "program_usage", "user_shell_folders", "web_client", "rdp_client", "shortcuts"))]
    for name, matches, needed in dependencies:
        present = any(matches(p) for p in paths)
        if present != needed:
            wrong.append(f"{name}: {'collected' if present else 'absent'} although "
                         f"{'an' if needed else 'no'} artefact asked for reads them")
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


def guarded(check, *args):
    """Runs one check; a crash is that check's failure, shown by name — it used
    to stop the whole script, and every later check went silently unrun."""
    try:
        return check(*args)
    except Exception as e:
        print(f"  ❌ {check.__name__} crashed: {type(e).__name__}: {e}")
        return 1


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
    found += guarded(check_boot_kernel_general, folder, boot)

    found += guarded(check_date_pairs, folder, osj)

    found += guarded(check_services, folder)
    found += guarded(check_users, folder)
    found += guarded(check_local_groups, folder)
    found += guarded(check_account_rights, folder)
    found += guarded(check_processes, folder)
    found += guarded(check_network, folder, boot)
    found += guarded(check_prefetchs, folder)
    found += guarded(check_prefetch_mft_references, folder)
    found += guarded(check_shimcache_dates, folder)
    found += guarded(check_jumplist_entries, folder)
    found += guarded(check_events, folder)
    found += guarded(check_hive_replay, folder)
    found += guarded(check_exhibit_store, folder)
    found += guarded(check_mft_references, folder)
    found += guarded(check_mft_timeline, folder)
    found += guarded(check_small_file_artefacts, folder)
    found += guarded(check_mft_entries, folder)
    found += guarded(check_mounted_devices, folder)
    found += guarded(check_date_precision, folder)
    found += guarded(check_shell_item_dates, folder)
    found += guarded(check_utc_sources, folder)
    found += guarded(check_key_names, folder)
    found += guarded(check_account_names, folder)
    found += guarded(check_guid_names, folder)
    found += guarded(check_collected_executables, folder)
    found += guarded(check_catalogs_recorded, folder)
    found += guarded(check_package_verification, folder)
    found += guarded(check_file_artefact_dates, folder)
    found += guarded(check_symbol_server_keys, folder)
    found += guarded(check_binary_all, folder)
    found += guarded(check_timestomping, folder)
    found += guarded(check_macro_document, folder)
    found += guarded(check_embedded_signers, folder)
    found += guarded(check_third_party_chains, folder)
    found += guarded(check_vulnerable_driver, folder)
    found += guarded(check_web_client, folder)
    found += guarded(check_activities_cache, folder)
    found += guarded(check_search_index, folder)
    found += guarded(check_event_messages, folder)
    found += guarded(check_exhibit_reads_after_copy, folder)
    found += guarded(check_rdp, folder)
    found += guarded(check_thumbcache, folder)
    found += guarded(check_emails, folder)
    found += guarded(check_thunderbird, folder)
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
        print("  ❌ trust set usable, yet no third-party chain checked in the manifest")
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
# The hives' replays: an ESE database's replay (ese_recovery.h) keeps no undo
# journal — its raw copy stays in the exhibit store, untouched.
REPLAY_OP = ("Replay of the transaction logs of a copied hive", "Rejeu des journaux")
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
    fwcounts = []   # the firewall's rule count, read more than once (record_firewall_count)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            key, _, value = line.strip().partition("=")
            if value:
                reference[key] = value
                if key == "fwcount":
                    fwcounts.append(value)
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

    # Shortcuts outside Recent (B-032): the two witnesses with their target,
    # arguments and location; then the files themselves, the same set as the
    # .lnk and .url Windows lists in those folders, Startup aside.
    shortcuts = load(folder, "shortcuts.json")
    if isinstance(shortcuts, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        mine = {(s.get("Path") or "").lower(): s for s in shortcuts}
        for line in (l for l in lines if l.startswith("shortcut=")):
            where, target, arguments, location = line[len("shortcut="):].split("|", 3)
            s = mine.get(where.lower(), {})
            report((s.get("Target") or "").lower() == target.lower() and (s.get("Arguments") or "") == arguments
                   and s.get("Location") == location,
                   f"shortcuts.json: {location} witness found, target and arguments identical",
                   f"shortcuts.json: {location} witness missing or altered: {where} -> {s or 'absent'}")
        live = {l[len("shortcutfile="):].lower() for l in lines if l.startswith("shortcutfile=")}
        report(live and live == set(mine),
               f"shortcuts.json: the {len(live)} shortcut(s) Windows lists in the Start menus, desktops and Quick Launch, no more, no less",
               f"shortcuts.json: missing {sorted(live - set(mine))[:3]}, extra {sorted(set(mine) - live)[:3]}")

    # NTFS security descriptors (B-032): every hash NTFS stored matches its
    # descriptor; the witness file and the files Get-Acl read lead, through
    # mft.json's SecurityId, to the owner Windows gives.
    descriptors = load(folder, "security_descriptors.json")
    if isinstance(descriptors, list) and os.path.exists(path):
        mismatched = [d.get("SecurityId") for d in descriptors if d.get("HashMismatch")]
        report(descriptors and not mismatched,
               f"security_descriptors.json: {len(descriptors)} descriptor(s), every NTFS hash recomputed identical",
               f"security_descriptors.json: {len(mismatched)} hash mismatch(es) among {len(descriptors)}: {mismatched[:5]}")
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        owners = {l[len("sdsowner="):].rsplit("|", 1)[0].lower(): l.rsplit("|", 1)[1]
                  for l in lines if l.startswith("sdsowner=")}
        witness = next((l[len("sdswitness="):].split("|") for l in lines if l.startswith("sdswitness=")), None)
        if witness:
            owners[witness[0].lower()] = witness[1]
        mft_files = load(folder, "mft.json")
        if owners and isinstance(mft_files, list):
            by_id = {(d.get("Volume"), d.get("SecurityId")): d for d in descriptors}
            ids = {(r.get("Path") or "").lower(): (r.get("Volume"), r.get("SecurityId"))
                   for r in mft_files if not r.get("Deleted") and (r.get("Path") or "").lower() in owners}
            wrong = [f"{p}: Windows {o}, WAC {by_id.get(ids.get(p), {}).get('Owner')}"
                     for p, o in owners.items() if by_id.get(ids.get(p), {}).get("Owner") != o]
            report(not wrong,
                   f"security_descriptors.json: the owner of {len(owners)} file(s) as Get-Acl gives it, through mft.json's SecurityId",
                   f"security_descriptors.json: {len(wrong)} owner difference(s), {wrong[:3]}")
            if witness:
                d = by_id.get(ids.get(witness[0].lower()), {})
                report(any(a.get("Type") == "Allow" and a.get("Sid") == "S-1-1-0" for a in d.get("Dacl") or []),
                       "security_descriptors.json: the witness's DACL grants Everyone, as icacls set it",
                       f"security_descriptors.json: the witness's Everyone ACE missing: {d}")

    # NTFS volumes (B-032): $Boot and $Max read raw, against what Windows says
    # of each volume through DeviceIoControl (FSCTL_GET_NTFS_VOLUME_DATA,
    # FSCTL_QUERY_USN_JOURNAL).
    volumes = load(folder, "ntfs_volumes.json")
    if isinstance(volumes, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        mine = {v.get("Volume"): v for v in volumes}
        wrong, seen = [], 0
        for l in (l for l in lines if l.startswith("ntfsvolume=")):
            letter, serial, sector, cluster, record, mft_lcn, mirror_lcn = l[len("ntfsvolume="):].split("|")
            v, seen = mine.get(letter, {}), seen + 1
            got = (v.get("VolumeSerial64"), v.get("BytesPerSector"), v.get("BytesPerCluster"), v.get("BytesPerRecord"),
                   v.get("MftCluster"), v.get("MftMirrorCluster"))
            if got != (serial, int(sector), int(cluster), int(record), int(mft_lcn), int(mirror_lcn)):
                wrong.append(f"{letter}: Windows {serial} {sector} {cluster} {record} {mft_lcn} {mirror_lcn}, WAC {got}")
        for l in (l for l in lines if l.startswith("usnjournal=")):
            letter, journal_id, maximum, delta, lowest = l[len("usnjournal="):].split("|")
            j, seen = mine.get(letter, {}).get("UsnJournal", {}), seen + 1
            got = (j.get("UsnJournalId"), j.get("MaximumSize"), j.get("AllocationDelta"), j.get("LowestValidUsn"))
            if got != (journal_id, int(maximum), int(delta), int(lowest)):
                wrong.append(f"{letter} journal: Windows {journal_id} {maximum} {delta} {lowest}, WAC {got}")
        report(seen and not wrong,
               f"ntfs_volumes.json: serial, geometry and journal header of {len(mine)} volume(s), as DeviceIoControl gives them ({seen} reading(s))",
               f"ntfs_volumes.json: {wrong[:3]}")

    # Defender's WPP traces (B-032): copied raw, every one Windows lists.
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            traces = {l.strip()[len("defenderwpp="):].lower() for l in f if l.startswith("defenderwpp=")}
        manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
        if traces and isinstance(manifest, dict):
            copied = {(i.get("SourcePath") or "").lower() for i in manifest.get("Items", []) if i.get("Result") == "OK"}
            report(traces <= copied,
                   f"exhibits: the {len(traces)} Defender WPP trace(s) Windows lists, copied raw",
                   f"exhibits: Defender WPP traces not copied: {sorted(traces - copied)[:3]}")

    # DPAPI master keys (B-032): the key files Windows lists, each with its
    # header's GUID = its name; the key each Preferred names, and its expiry.
    keys = load(folder, "dpapi_master_keys.json")
    if isinstance(keys, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        live = {l[len("dpapikey="):].lower() for l in lines if l.startswith("dpapikey=")}
        mine = {(k.get("Path") or "").lower(): k for k in keys}
        unnamed = [p for p, k in mine.items() if k.get("Guid") != ntpath.basename(p)]
        report(live and live == set(mine) and not unnamed,
               f"dpapi_master_keys.json: the {len(live)} master key file(s) Windows lists, each header naming its file",
               f"dpapi_master_keys.json: missing {sorted(live - set(mine))[:2]}, extra {sorted(set(mine) - live)[:2]}, header not its name {unnamed[:2]}")
        wrong, count = [], 0
        for l in (l for l in lines if l.startswith("dpapipreferred=")):
            where, guid, ticks = l[len("dpapipreferred="):].split("|")
            count += 1
            expires = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(ticks) // 10)).strftime("%Y-%m-%dT%H:%M:%S")
            k = mine.get(ntpath.join(where, guid).lower(), {})
            if not k.get("Preferred") or not (k.get("PreferredExpiresUtc") or "").startswith(expires):
                wrong.append(f"{where}: {guid} expiring {expires}, WAC {k.get('Preferred')} {k.get('PreferredExpiresUtc')}")
        report(count and not wrong,
               f"dpapi_master_keys.json: the preferred key of {count} folder(s) and its expiry, as Windows reads Preferred",
               f"dpapi_master_keys.json: {wrong[:2]}")

    # User Shell Folders (B-032): every value of the hive of "wac", unexpanded,
    # as Windows reads it; its Desktop, redirected to OneDrive, resolved.
    shell = load(folder, "user_shell_folders.json")
    if isinstance(shell, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            live = [l.strip()[len("usf="):].split("|", 2) for l in f if l.startswith("usf=")]
        mine = {(s.get("SID"), s.get("Name")): s for s in shell}
        wrong = [f"{name}: Windows {value}, WAC {mine.get((sid, name), {}).get('Value')}"
                 for sid, name, value in live if mine.get((sid, name), {}).get("Value") != value]
        desktop = next((mine.get((sid, "Desktop"), {}) for sid, _, _ in live), {})
        report(live and not wrong and desktop.get("Path", "").lower().endswith("\\onedrive\\desktop"),
               f"user_shell_folders.json: the {len(live)} value(s) of User Shell Folders of wac, the redirected Desktop resolved",
               f"user_shell_folders.json: {wrong[:3]}, Desktop {desktop}")

    # Real browsing (B-016): what Chrome, Firefox and mshta.exe did as "wac".
    web = load(folder, "web_client.json")
    if isinstance(web, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        for l in (l for l in lines if l.startswith("webvisit=")):
            browser, url = l[len("webvisit="):].split("|", 1)
            report(any(r.get("Type") == "Visit" and r.get("Browser") == browser and r.get("Url") == url for r in web),
                   f"web_client.json: {browser} visit of the witness page found", f"web_client.json: {browser} visit {url} missing")
        for l in (l for l in lines if l.startswith("websearch=")):
            browser, term = l[len("websearch="):].split("|", 1)
            report(any(r.get("Type") == "SearchTerm" and r.get("Browser") == browser and r.get("Term") == term for r in web),
                   f"web_client.json: {browser} search term {term} found", f"web_client.json: {browser} search term {term} missing")
        for l in (l for l in lines if l.startswith("webdownload=")):
            browser, url, target = l[len("webdownload="):].split("|", 2)
            match = [r for r in web if r.get("Type") == "Download" and r.get("Browser") == browser and r.get("Url") == url]
            report(match and (match[0].get("TargetPath") or "").lower() == target.lower(),
                   f"web_client.json: {browser} download found, its URL and destination as the browser wrote them",
                   f"web_client.json: {browser} download {url} -> {target} missing or different: {match[:1]}")
        for l in (l for l in lines if l.startswith("webiedownload=")):
            url, target = l[len("webiedownload="):].split("|", 1)
            match = [r.get("Download", {}) for r in web if r.get("Type") == "CacheEntry" and r.get("Container") == "iedownload"
                     and r.get("Download", {}).get("Url") == url]
            report(match and (match[0].get("TargetPath") or "").lower() == target.lower() and match[0].get("FileSize") == 20
                   and match[0].get("ServerAddress") == "127.0.0.1",
                   "web_client.json: Internet Explorer's download found in iedownload — URL, saved path, size, server",
                   f"web_client.json: Internet Explorer's download {url} -> {target} missing or different: {match[:1]}")
        manifest = load(os.path.join(folder, store_folder(folder)), "MANIFEST.json")
        exhibits = {(i.get("SourcePath") or "").lower(): i for i in (manifest or {}).get("Items", [])} if isinstance(manifest, dict) else {}
        for l in (l for l in lines if l.startswith("webhta=")):
            url, digest = (l[len("webhta="):].split("|", 1) + [""])[:2]
            entry = next((r for r in web if r.get("Type") == "CacheEntry" and r.get("Url") == url), {})
            cached = exhibits.get((entry.get("CachedFile") or "").lower(), {})
            report(entry and cached.get("SHA256") == digest,
                   f"web_client.json: the HTA run by mshta.exe found in the WebCache, its cached copy {ntpath.basename(entry.get('CachedFile', ''))} collected, same SHA-256",
                   f"web_client.json: HTA {url}: entry {entry.get('CachedFile') if entry else 'missing'}, exhibit {cached.get('SHA256')}")

    # TypedURLs (B-016): the two addresses typed, their position and instant.
    web = load(folder, "web_client.json")
    if isinstance(web, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            typed = [l.strip()[len("typedurl="):].split("|") for l in f if l.startswith("typedurl=")]
        mine = {(r.get("Url"), r.get("SIDName")): r for r in web if r.get("Type") == "TypedUrl"}
        wrong = [f"{name} {url}: WAC {mine.get((url, 'wac'))}" for name, url, when in typed
                 if mine.get((url, "wac"), {}).get("MruPosition") != int(name[3:]) - 1
                 or not (mine.get((url, "wac"), {}).get("TypedUtc") or "").startswith(when)]
        report(typed and not wrong,
               f"web_client.json: the {len(typed)} TypedURLs of wac, position and instant of TypedURLsTime",
               f"web_client.json: {wrong[:2]}")

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
    # The Default profile (B-032): its NTUSER.DAT read as a profile's, under the
    # SID S-0-0-0 that cannot be one, told by Profile and without SIDName.
    if isinstance(runs, list) and "rundefault" in reference:
        name, value = reference["rundefault"].split("|", 1)
        match = [r for r in runs if r.get("Name") == name]
        report(bool(match) and match[0].get("SID") == "S-0-0-0" and match[0].get("Profile") == "Default"
               and "SIDName" not in match[0] and match[0].get("Value") == value,
               f"run.json: {name} of the Default profile, SID S-0-0-0, Profile Default ({value})",
               f"run.json: {name} of the Default profile missing or different: {match[:1]}")

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
        exefile = [p.get("Value") for p in persistence if p.get("Mechanism") == "File type open command"
                   and "exefile" in (p.get("Key") or "").lower()]
        report(exefile == [reference.get("exefile")], f"persistence.json: the open command of exefile as Windows reads it ({reference.get('exefile')})",
               f"persistence.json: exefile open command {exefile} / Windows {reference.get('exefile')}")
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
         lambda d, r: [t for t in d if t.get("SID") == r[0] and t.get("MruPosition") == int(r[1]) - 1 and t.get("Text") == r[2]],
         "typed_paths.json: the typed path witness found at its position (url25: 24)", "typed_paths.json: the typed path witness missing")
    lot2("word_wheel_query.json", "search",
         lambda d, r: [t for t in d if t.get("SID") == r[0] and t.get("MruPosition") == 0 and t.get("Text") == r[1]],
         "word_wheel_query.json: the searched term found first (MRUListEx)", "word_wheel_query.json: the searched term missing or not first")
    lot2("internet_settings.json", "proxy",
         lambda d, r: [t for t in d if t.get("SID") == r[0] and t.get("ProxyServer") == r[1]],
         "internet_settings.json: the user's proxy found", "internet_settings.json: the user's proxy missing")
    firewall = load(folder, "firewall.json")
    if isinstance(firewall, dict) and "fwrule" in reference:
        name, action, direction, port = reference["fwrule"].split("|")
        rules = firewall.get("Rules", [])
        # Every count Windows gave: at the witnesses, then after each collection.
        counts = set(fwcounts)
        report(any(r.get("Name") == name and r.get("Action") == action and r.get("Direction") == direction
                   and r.get("LocalPort") == port for r in rules) and str(len(rules)) in counts,
               f"firewall.json: {len(rules)} rules as Windows counts them, the witness rule found",
               f"firewall.json: {len(rules)} rules (Windows {'/'.join(sorted(counts))}), witness found: "
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

    # A script with many hard links, its resident $DATA in an extension
    # record (B-045): read raw, with the SHA-256 Windows gives.
    # The collection reads every executable of the volume and takes the
    # unsigned ones: the script is among them.
    manifest = load(folder, os.path.join("exhibits", "MANIFEST.json"))
    if isinstance(manifest, dict) and "links" in reference:
        path, sha256, listed = reference["links"].split("|")
        items = [o for o in manifest.get("Items", []) if str(o.get("SourcePath", "")).lower() == path.lower()]
        ok = listed == "list" and items and all(o.get("Result") == "OK" and str(o.get("SHA256", "")).upper() == sha256.upper()
                                               for o in items)
        report(ok, f"manifest: {path}, $DATA moved by $ATTRIBUTE_LIST, read with the SHA-256 of Get-FileHash",
               f"manifest: {path} ({listed}): {[(o.get('Result'), o.get('SHA256')) for o in items] or 'not collected'}")

    # A folder of a 7z and of a tar.gz (Windows 11 reads them through
    # libarchive): another layout, whose date is a UTC instant (B-029).
    if isinstance(bags, list) and "readerentry" in reference:
        name, utc = reference["readerentry"].split("|")
        entries = []
        def reader(o):
            if isinstance(o, dict):
                if o.get("Type") == "ARCHIVE_FILE_CONTENT" and o.get("Name") == name:
                    entries.append(o)
                for v in o.values():
                    reader(v)
            elif isinstance(o, list):
                for v in o:
                    reader(v)
        reader(bags)
        ok = len(entries) >= 2 and all(str(i.get("ModifiedUtc", "")).startswith(utc) and "ModifiedAsWritten" not in i
                                     for i in entries)
        report(ok, f"shellbags.json: {len(entries)} folder(s) {name} of a 7z and a tar.gz, dated {utc} UTC",
               f"shellbags.json: the libarchive folder {name}: {entries[:2]}")

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

    # Shortcut tracker block: the target's DROID against its NTFS object
    # identifier, as fsutil gives it (raw bytes: a GUID in on-disk order).
    docs = load(folder, "recentdocs.json")
    if isinstance(docs, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            objids = [l.strip()[len("lnkobjid="):].split("|") for l in f if l.startswith("lnkobjid=")]
        for link, obj, birth_volume, birth_obj in objids:
            as_guid = lambda raw: "{" + str(uuid.UUID(bytes_le=bytes.fromhex(raw))).upper() + "}"
            doc = next((d for d in docs if isinstance(d, dict) and str(d.get("Path", "")).lower() == link.lower()), None)
            t = (doc or {}).get("Tracker") or {}
            mine = (t.get("GuidDroidFile"), t.get("GuidBirthDroidVolume"), t.get("GuidBirthDroidFile"))
            theirs = (as_guid(obj), as_guid(birth_volume), as_guid(birth_obj))
            report(mine == theirs and bool(t.get("DroidFileCreatedUtc")),
                   f"recentdocs.json: tracker block of {link.rsplit(chr(92), 1)[-1]} = the target's NTFS object identifier (fsutil), dated {t.get('DroidFileCreatedUtc')}",
                   f"recentdocs.json: tracker {mine}, fsutil {theirs}")

    # Installed programs: the witness program with its values, and as many
    # programs per Uninstall key as Windows lists (B-031).
    programs = load(folder, "installed_programs.json")
    if isinstance(programs, list) and "program" in reference and "programs" in reference:
        key, name, publisher, version, date = reference["program"].split("|")
        witness = next((p for p in programs if p.get("KeyName") == key and p.get("Scope") == "Machine"), {})
        machine, machine32, sid, user = reference["programs"].split("|")
        counts = collections.Counter((p.get("Scope"), p.get("SID", "")) for p in programs)
        mine = (counts[("Machine", "")], counts[("Machine (32-bit)", "")], counts[("User", sid)])
        theirs = (int(machine), int(machine32), int(user))
        msi_theirs = {p.split(":")[0]: int(p.split(":")[1]) for p in reference.get("msiproducts", "").split("|") if ":" in p}
        msi_mine = {sid_: counts[("MSI product", sid_)] for sid_ in msi_theirs}
        report((witness.get("DisplayName"), witness.get("Publisher"), witness.get("DisplayVersion"), witness.get("InstallDate")) == (name, publisher, version, date)
               and witness.get("KeyLastWriteUtc") and mine == theirs and msi_mine == msi_theirs,
               f"installed_programs.json: the witness program with its values; programs per key {mine} and MSI products {msi_mine} as Windows lists them",
               f"installed_programs.json: witness {witness or 'absent'}; programs per key {mine}, Windows {theirs}; MSI {msi_mine}, Windows {msi_theirs}")

    # Defender exclusions: every exclusion Get-MpPreference lists, of its kind,
    # the harness's three witnesses among them (B-031).
    defender = load(folder, "defender_configuration.json")
    if isinstance(defender, dict) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            listed = [l.strip()[len("exclusions="):].split("|") for l in f if l.startswith("exclusions=")]
        mine = {(e.get("Kind"), str(e.get("Value", "")).lower()) for e in defender.get("Exclusions") or [] if e.get("Source") == "Settings"}
        theirs = {(kind, v.lower()) for kind, *values in listed for v in values if v}
        witnesses = {("Paths", "c:\\wactest\\wac-excluded"), ("Extensions", "wactestext"), ("Processes", "wac-excluded.exe")}
        report(listed and mine == theirs and witnesses <= mine,
               f"defender_configuration.json: the {len(theirs)} exclusion(s) Defender lists, of their kind, the 3 witnesses among them",
               f"defender_configuration.json: WAC only {sorted(mine - theirs)[:3]}, Defender only {sorted(theirs - mine)[:3]}")

    # Explorer's RecentDocs: the witness file, added by the shell, first of its
    # extension's list and of the list of every extension (B-031).
    recent = load(folder, "explorer_recent_docs.json")
    if isinstance(recent, list) and "recentdoc" in reference:
        sid, extension, name = reference["recentdoc"].split("|")
        mine = {(e.get("Extension", ""), e.get("MruPosition")) for e in recent
                if e.get("SID") == sid and e.get("Name") == name}
        shortcut = next((e.get("Shortcut") for e in recent if e.get("SID") == sid and e.get("Name") == name), {})
        report({(extension, 0), ("", 0)} <= mine and bool(shortcut),
               f"explorer_recent_docs.json: {name} first of the {extension} list and of the list of every extension, with its shortcut's shell item",
               f"explorer_recent_docs.json: {name} at {sorted(mine)} (expected first of {extension} and of the whole list)")

    # MountPoints2: the same entries as the live registry lists, the
    # harness's share among them, decoded as a share (B-031).
    mounts = load(folder, "mount_points.json")
    if isinstance(mounts, list) and "mountpoints" in reference:
        sid, *names = reference["mountpoints"].split("|")
        mine = {m.get("Name") for m in mounts if m.get("SID") == sid}
        share = next((m for m in mounts if m.get("SID") == sid and m.get("Name") == "##127.0.0.1#WacShare"), {})
        report(mine == set(names) and share.get("Kind") == "NetworkShare" and share.get("Share") == "\\\\127.0.0.1\\WacShare",
               f"mount_points.json: the {len(mine)} entries the live registry lists, the share witness decoded as \\\\127.0.0.1\\WacShare",
               f"mount_points.json: WAC only {sorted(mine - set(names))[:3]}, registry only {sorted(set(names) - mine)[:3]}, share {share}")

    # Known networks: the profiles and gateways the live registry lists, and
    # DateLastConnected — stored in local time — equal, in UTC, to the last
    # connection the NetworkProfile log records for that name (B-031).
    networks = load(folder, "known_networks.json")
    if isinstance(networks, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        listed = {l[len("network="):].split("|")[0].upper(): l[len("network="):].split("|") for l in lines if l.startswith("network=")}
        connected = dict(l[len("netconnected="):].rsplit("|", 1) for l in lines if l.startswith("netconnected="))
        wrong, dated = [], 0
        mine = {str(n.get("ProfileGuid", "")).upper(): n for n in networks}
        if set(mine) != set(listed):
            wrong.append(f"profiles WAC {sorted(mine)}, registry {sorted(listed)}")
        for guid, (_, name, macs) in listed.items():
            n = mine.get(guid, {})
            if n.get("ProfileName") != name:
                wrong.append(f"{guid}: name {n.get('ProfileName')!r}, registry {name!r}")
            ours = sorted(sig.get("DefaultGatewayMac", "") for sig in n.get("Signatures") or [])
            if ours != sorted(m for m in macs.split(",") if m):
                wrong.append(f"{guid}: gateways {ours}, registry {macs}")
            if name in connected and n.get("DateLastConnectedUtc"):
                dated += 1
                if n["DateLastConnectedUtc"][:19] != connected[name]:
                    wrong.append(f"{name}: DateLastConnected {n['DateLastConnectedUtc']}, event 10000 {connected[name]}Z")
        report(listed and not wrong and dated,
               f"known_networks.json: the {len(listed)} profile(s) and gateways of the registry; DateLastConnected of {dated} equal to its event 10000 (UTC)",
               f"known_networks.json: {wrong[:2] if wrong else 'no network dated by an event'}")

    # System settings (OperatingSystem.json): the values of the live registry,
    # and ShutdownTime within a minute of the System log's last shutdown (B-031).
    osj = load(folder, "OperatingSystem.json")
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    live = dict(l[len("setting="):].split("|", 1) for l in lines if l.startswith("setting="))
    # The reference is written by the registry witnesses: without them, nothing to confront.
    if isinstance(osj, dict) and live:
        mine = {st.get("Name"): str(st.get("Value")) for st in osj.get("Settings") or []}
        wrong = [f"{n}: WAC {mine.get(n)!r}, registry {v!r}" for n, v in live.items() if mine.get(n) != v]
        down = next((l[len("shutdown="):] for l in lines if l.startswith("shutdown=")), None)
        gap = abs(instant(osj["ShutdownTimeUtc"]).timestamp() - instant(down + "Z").timestamp()) if down and osj.get("ShutdownTimeUtc") else None
        if gap is None or gap > 60:
            wrong.append(f"ShutdownTime {osj.get('ShutdownTimeUtc')}, System log {down}Z")
        report(live and not wrong,
               f"OperatingSystem.json: {len(live)} setting(s) as the live registry holds them; ShutdownTime {gap:.0f} s from the System log's shutdown" if gap is not None else "",
               f"OperatingSystem.json: {wrong[:2]}")

    # Startup state (run.json): every StartupApproved and RunNotification value
    # of the live registry, with its status code or value (B-031).
    runs = load(folder, "run.json")
    if isinstance(runs, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            states = [l.strip()[len("startupstate="):].split("|") for l in f if l.startswith("startupstate=")]
        mine = {}
        for e in runs:
            owner = "HKLM" if e.get("SIDName") == "HKLM" else e.get("SID")
            value = e.get("Status") if "Status" in e else str(e.get("Notification", ""))
            mine[(owner, e.get("Key"), e.get("Name"))] = value
        wrong = [f"{owner} {key} {name}: WAC {mine.get((owner, key, name))!r}, registry {value!r}"
                 for owner, key, name, value in states if mine.get((owner, key, name)) != value]
        report(states and not wrong, f"run.json: the {len(states)} StartupApproved and RunNotification value(s) of the live registry, codes identical",
               f"run.json: {wrong[:2] if wrong else 'no startup state listed'}")

    # Program usage: per source, the names the live registry holds for the user
    # "wac", the witness layer among them; as many pinned items as
    # FavoritesResolve chains; each OpenWithList program at its MRUList
    # position, the witness extension's among them; every date in the past (B-031).
    usage = load(folder, "program_usage.json")
    if isinstance(usage, list) and "pinned" in reference:
        sid, pinned = reference["pinned"].split("|")
        with open(path, encoding="utf-8", errors="replace") as f:
            sources = {l.strip()[len("usage="):].split("|")[0]: set(l.strip()[len("usage="):].split("|")[1:]) - {""}
                       for l in f if l.startswith("usage=")}
        wrong = []
        for source, names in sources.items():
            mine = {u.get("Name") for u in usage if u.get("Source") == source and u.get("SID") == sid}
            if mine != names:
                wrong.append(f"{source}: WAC only {sorted(mine - names)[:2]}, registry only {sorted(names - mine)[:2]}")
        layer = next((u for u in usage if u.get("Name") == "C:\\wactest\\wac-layer.exe"), {})
        if layer.get("Layers") != "~ WIN7RTM":
            wrong.append(f"witness layer {layer}")
        with open(path, encoding="utf-8", errors="replace") as f:
            openwith = {tuple(l.strip()[len("openwith="):].split("|")) for l in f if l.startswith("openwith=")}
        mine_openwith = {(u.get("Extension"), u.get("Name"), str(u.get("MruPosition")))
                         for u in usage if u.get("Source") == "FileExts\\OpenWithList" and u.get("SID") == sid}
        if mine_openwith != openwith or (".wacwitness", "wordpad.exe", "0") not in openwith:
            wrong.append(f"OpenWithList: WAC only {sorted(mine_openwith - openwith)[:2]}, registry only {sorted(openwith - mine_openwith)[:2]}")
        mine_pinned = sum(1 for u in usage if u.get("Source") == "Taskband" and u.get("SID") == sid)
        if mine_pinned != int(pinned):
            wrong.append(f"pinned items {mine_pinned}, FavoritesResolve {pinned}")
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        future = [u for u in usage for k, v in u.items() if k.endswith("Utc") and isinstance(v, str) and v[:19] > now]
        if future:
            wrong.append(f"date after the collection: {future[0]}")
        report(sources and not wrong,
               f"program_usage.json: {len(sources)} source(s) as the live registry holds them, the witness layer, {mine_pinned} pinned item(s) decoded, {len(openwith)} OpenWithList program(s) in MRU order",
               f"program_usage.json: {wrong[:2]}")

    # Devices: every USB and SCSI device Windows lists, with its first install,
    # last arrival and last removal dates as Get-PnpDeviceProperty gives them (B-031).
    devices = load(folder, "devices.json")
    if isinstance(devices, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            listed = [l.strip()[len("device="):].split("|") for l in f if l.startswith("device=")]
        mine = {(d.get("Source", "")[len("Enum\\"):] + "\\" + str(d.get("Name"))).upper(): d
                for d in devices if str(d.get("Source", "")).startswith("Enum\\")}
        wrong = []
        for instance, first, arrival, removal in listed:
            d = mine.get(instance.upper())
            if d is None:
                wrong.append(f"{instance} absent")
                continue
            for field, theirs in (("FirstInstallUtc", first), ("LastArrivalUtc", arrival), ("LastRemovalUtc", removal)):
                if str(d.get(field, ""))[:19] != theirs:
                    wrong.append(f"{instance} {field}: WAC {d.get(field)}, Windows {theirs or 'none'}")
        report(listed and not wrong,
               f"devices.json: the {len(listed)} USB and SCSI device(s) Windows lists, their three dates identical (UTC)",
               f"devices.json: {wrong[:2]}")

    # Network shares: the non-administrative shares Get-SmbShare lists, with
    # their path, the witness among them (B-031).
    shares = load(folder, "network_shares.json")
    if isinstance(shares, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            theirs = {tuple(l.strip()[len("share="):].split("|", 1)) for l in f if l.startswith("share=")}
        mine = {(sh.get("Name"), sh.get("Path")) for sh in shares}
        with open(path, encoding="utf-8", errors="replace") as f:
            access = {tuple(l.strip()[len("shareaccess="):].split("|")[1:]) for l in f if l.startswith("shareaccess=")}
        witness = next((sh for sh in shares if sh.get("Name") == "WacShare"), {})
        aces = {(a.get("Sid"), a.get("Type")) for a in (witness.get("SecurityDescriptor") or {}).get("Dacl") or []}
        report(theirs and mine == theirs and ("WacShare", "C:\\wactest") in mine and access and aces == access,
               f"network_shares.json: the {len(theirs)} share(s) Get-SmbShare lists, with their path; the witness's DACL as Get-SmbShareAccess reads it",
               f"network_shares.json: WAC only {sorted(mine - theirs)}, Windows only {sorted(theirs - mine)}; DACL {sorted(aces)}, Windows {sorted(access)}")

    # Network configuration: each adapter Windows lists, with its description,
    # its hardware address and its DHCP address, from the offline hives (B-031).
    netconf = load(folder, "network_configuration.json")
    if isinstance(netconf, dict) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            live = [l.strip()[len("adapter="):].split("|") for l in f if l.startswith("adapter=")]
        mine = {str(a.get("InterfaceGuid", "")).upper(): a for a in netconf.get("Adapters") or []}
        wrong = []
        for guid, description, mac, ip, origin in live:
            a = mine.get(guid.upper(), {})
            adapter, ipv4, kernel = a.get("Adapter") or {}, a.get("Ipv4") or {}, a.get("Kernel") or {}
            if adapter.get("DriverDesc") != description:
                wrong.append(f"{guid}: description {adapter.get('DriverDesc')!r}, Windows {description!r}")
            if kernel.get("CurrentAddress") != mac:
                wrong.append(f"{guid}: hardware address {kernel.get('CurrentAddress')}, Windows {mac}")
            if origin == "Dhcp" and ipv4.get("DhcpIPAddress") != ip:
                wrong.append(f"{guid}: DHCP address {ipv4.get('DhcpIPAddress')}, Windows {ip}")
        report(live and not wrong,
               f"network_configuration.json: the {len(live)} adapter(s) Windows lists, description, hardware address and DHCP address identical",
               f"network_configuration.json: {wrong[:2]}")

    # Event log configuration: each log Windows lists, with the same state
    # (enabled or not), read from WINEVT\Channels in the offline hive; a
    # classic log (Services\EventLog) has no such switch and is always on (B-031).
    logconf = load(folder, "event_log_configuration.json")
    if isinstance(logconf, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            live = [l.strip()[len("eventlog="):].rsplit("|", 1) for l in f if l.startswith("eventlog=")]
        mine = {str(c.get("Name", "")).lower(): c for c in logconf if c.get("Source") == "WINEVT\\Channels"}
        classic = {str(c.get("Name", "")).lower() for c in logconf if c.get("Source") == "Services\\EventLog"}
        wrong = []
        for name, enabled in live:
            c = mine.get(name.lower())
            if c is None and name.lower() in classic:
                if enabled != "True":
                    wrong.append(f"{name}: classic log, Windows {enabled}")
            elif c is None:
                wrong.append(f"{name}: absent")
            elif bool(c.get("Enabled")) != (enabled == "True"):
                wrong.append(f"{name}: Enabled {c.get('Enabled')}, Windows {enabled}")
        report(live and not wrong,
               f"event_log_configuration.json: the {len(live)} log(s) Get-WinEvent lists, each with the same enabled state",
               f"event_log_configuration.json: {len(wrong)} difference(s), {wrong[:3]}")
        with open(path, encoding="utf-8", errors="replace") as f:
            sessions = [l.strip()[len("autologger="):].rsplit("|", 1) for l in f if l.startswith("autologger=")]
        boot = {str(c.get("Name", "")).lower(): c for c in logconf if c.get("Source") == "WMI\\Autologger"}
        wrong = [f"{name}: Start {boot.get(name.lower(), {}).get('Start')}, Windows {start}"
                 for name, start in sessions
                 if name.lower() not in boot or str(boot[name.lower()].get("Start", "")) != start]  # no Start value: both empty
        report(sessions and not wrong,
               f"event_log_configuration.json: the {len(sessions)} boot ETW session(s) Get-AutologgerConfig lists, same Start",
               f"event_log_configuration.json: {len(wrong)} session difference(s), {wrong[:3]}")

    # Cleared log: none live, as Windows sees it; the cleared events recovered.
    if isinstance(events, list) and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            cleared = [l.strip()[11:].split("|") for l in f if l.startswith("evtcleared=")]
        for log_name, windows_live, ids in cleared:
            mine = [e for e in events if isinstance(e, dict) and str(e.get("EvtSourceLog", "")).lower() == log_name.lower()]
            live = [e for e in mine if not e.get("EvtRecovered")]
            recovered = {e.get("EvtSystemEventID") for e in mine if e.get("EvtRecovered") is True}
            expected = {int(i) for i in ids.split(",")}
            report(len(live) == int(windows_live) and expected <= recovered,
                   f"events.json: {log_name} cleared — {len(live)} live event(s) as Windows, the {len(expected)} cleared ones recovered",
                   f"events.json: {log_name} cleared — {len(live)} live (Windows {windows_live}), recovered IDs {sorted(recovered)}")

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
        # The bound is the extraction of the SRUM database, not the start of the
        # collection: the service flushes its rows at any time, and one flush
        # fell between the two once (rows at 06:48:00, collection begun at
        # 06:47:41, database read at 06:48:40). Its end serves otherwise.
        operations = (inv or {}).get("Operations") or [] if isinstance(inv, dict) else []
        extracted = [o.get("TimestampUtc") for o in operations if "\\sru" in str(o.get("Target", "")).lower()]
        start = extracted[0] if extracted else (((inv or {}).get("Collection") or {}).get("EndUtc") if isinstance(inv, dict) else None)
        network = [r for r in srum if r.get("Provider") == "NetworkUsage"]
        # An identifier whose SruDbIdMapTable entry has no IdBlob has nothing to
        # resolve (entries 1 and 2 on the test VM, as dissect.esedb reads them too).
        with_blob = {r.get("IdIndex") for r in srum if r.get("Table") == "SruDbIdMapTable" and r.get("IdBlob")}
        unresolved = sum(1 for r in srum if r.get("AppId") in with_blob and "App" not in r)
        users = sum(1 for r in srum if r.get("UserId") in with_blob and "UserSID" not in r)
        future = sum(1 for r in srum if start and r.get("TimeStamp") and r["TimeStamp"][:19] > start[:19])
        report(network and not unresolved and not users and not future,
               f"srum.json: {len(srum)} row(s), {len(network)} of network usage, every AppId and UserId resolved, none after the database's extraction",
               f"srum.json: {len(network)} network row(s), {unresolved} AppId and {users} UserId unresolved, {future} after the database's extraction ({start})")

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


def check_web_client(folder):
    """web_client.json against Python's own SQLite reading the same History.

    The harness fetches each browser profile's History from the exhibit store
    (with its -journal or -wal); it is copied aside and read here by Python's
    sqlite3 — the journal replayed by that engine, the Chromium times
    converted here. Every URL, visit (instant and transition), download and
    search term must be in web_client.json, no more, no less: a column read
    at the wrong index, a time scaled wrongly, a join that drops rows would
    all give valid JSON.
    """
    import shutil, sqlite3, tempfile
    records = load(folder, "web_client.json")
    store = os.path.join(folder, store_folder(folder))
    databases = [p for p in glob.glob(os.path.join(store, "**", "History"), recursive=True)
                 if os.sep + "User Data" + os.sep in p]
    found_firefox = check_firefox_places(folder, store, records if isinstance(records, list) else [])
    if not isinstance(records, list) or not databases:
        print("  ⏭️  no web_client.json or no History fetched: browsers not confronted")
        return found_firefox
    found = 0
    def chromium(us):
        if not us or us <= 0:
            return None
        t = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
        return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    cores = ["link", "typed", "auto_bookmark", "auto_subframe", "manual_subframe", "generated",
             "auto_toplevel", "form_submit", "reload", "keyword", "keyword_generated"]
    for database in databases:
        source = "C:\\" + os.path.relpath(database, store).replace(os.sep, "\\")
        mine = [r for r in records if (r.get("Source") or "").lower() == source.lower()]
        with tempfile.TemporaryDirectory() as aside:
            for suffix in ("", "-journal", "-wal"):
                if os.path.exists(database + suffix):
                    shutil.copy(database + suffix, os.path.join(aside, "History" + suffix))
            db = sqlite3.connect(os.path.join(aside, "History"))
            urls = db.execute("SELECT url FROM urls").fetchall()
            visits = db.execute("SELECT v.id, u.url, v.visit_time, v.transition FROM visits v JOIN urls u ON u.id = v.url").fetchall()
            downloads = db.execute("SELECT guid, target_path, start_time, received_bytes FROM downloads").fetchall()
            terms = db.execute("SELECT term FROM keyword_search_terms").fetchall()
            db.close()
        by_type = collections.Counter(r.get("Type") for r in mine)
        counts = {"Url": len(urls), "Visit": len(visits), "Download": len(downloads), "SearchTerm": len(terms)}
        ok = all(by_type.get(t, 0) == n for t, n in counts.items())
        parts = source.split(chr(92))   # …\<browser>\User Data\<profile>\History
        print(f"  {'✅' if ok else '❌'} web_client.json: {parts[-4]}/{parts[-2]} — "
              f"{counts} as Python's SQLite reads them, WAC {dict(by_type)}")
        found += 0 if ok else 1
        wac_visits = {r.get("Id"): r for r in mine if r.get("Type") == "Visit"}
        wrong = []
        for vid, url, when, transition in visits:
            r = wac_visits.get(vid, {})
            core = transition & 0xFF
            if (r.get("Url") != url or r.get("VisitUtc") != chromium(when)
                    or r.get("Transition") != (cores[core] if core < len(cores) else str(core))):
                wrong.append(f"visit {vid}: {url} {chromium(when)}, WAC {r.get('Url')} {r.get('VisitUtc')} {r.get('Transition')}")
        wac_downloads = {r.get("Guid"): r for r in mine if r.get("Type") == "Download"}
        for guid, target, start, received in downloads:
            r = wac_downloads.get(guid, {})
            if r.get("TargetPath") != target or r.get("StartUtc") != chromium(start) or r.get("ReceivedBytes") != received:
                wrong.append(f"download {guid}: {target} {chromium(start)} {received}, WAC {r}")
        ok = not wrong
        print(f"  {'✅' if ok else '❌'} web_client.json: every visit (URL, instant, transition) and download (path, start, bytes) identical"
              + ("" if ok else f": {wrong[:3]}"))
        found += 0 if ok else 1
        # Saved logins and cookies of the same profile, when fetched: as many
        # as Python's SQLite reads, and the same sites.
        profile = os.path.dirname(database)
        for name, table, column, kind in (("Login Data", "logins", "origin_url", "SavedLogin"),
                                          (os.path.join("Network", "Cookies"), "cookies", "host_key", "Cookie")):
            path_db = os.path.join(profile, name)
            if not os.path.exists(path_db):
                continue
            source_db = "C:\\" + os.path.relpath(path_db, store).replace(os.sep, "\\")
            with tempfile.TemporaryDirectory() as aside:
                for suffix in ("", "-journal", "-wal"):
                    if os.path.exists(path_db + suffix):
                        shutil.copy(path_db + suffix, os.path.join(aside, "db" + suffix))
                db = sqlite3.connect(os.path.join(aside, "db"))
                theirs = sorted(r[0] for r in db.execute(f"SELECT {column} FROM {table}"))
                db.close()
            key = "Origin" if kind == "SavedLogin" else "Host"
            ours = sorted(r.get(key) for r in records if r.get("Type") == kind and (r.get("Source") or "").lower() == source_db.lower())
            ok = theirs == ours
            print(f"  {'✅' if ok else '❌'} web_client.json: {parts[-4]}/{parts[-2]} — {len(theirs)} {table} row(s) as Python's SQLite reads them, "
                  f"same sites in WAC ({len(ours)})" + ("" if ok else f": {sorted(set(theirs) ^ set(ours))[:3]}"))
            found += 0 if ok else 1
    return found + found_firefox + check_webcache(folder, records)


def check_activities_cache(folder):
    """activities_cache.json against Python's own SQLite on each fetched
    ActivitiesCache.db, its write-ahead log replayed by that engine: every row
    of Activity and ActivityOperation, no more, no less, with its identifier
    (GUID in .NET byte order), type, application activity and Unix times
    converted here — a time read in another unit or a GUID in the wrong order
    would be valid JSON."""
    import shutil, sqlite3, tempfile, uuid
    records = load(folder, "activities_cache.json")
    store = os.path.join(folder, store_folder(folder))
    databases = glob.glob(os.path.join(store, "**", "ConnectedDevicesPlatform", "*", "ActivitiesCache.db"), recursive=True)
    if not isinstance(records, list) or not databases:
        print("  ⏭️  no activities_cache.json or no ActivitiesCache.db fetched: Timeline not confronted")
        return 0
    def utc(seconds):
        if not seconds or seconds <= 0:
            return None
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    found = 0
    for database in databases:
        source = "C:\\" + os.path.relpath(database, store).replace(os.sep, "\\")
        mine = {(r.get("Table"), r.get("Id")): r for r in records if (r.get("Path") or "").lower() == source.lower()}
        theirs = []
        with tempfile.TemporaryDirectory() as aside:
            for suffix in ("", "-wal", "-journal"):
                if os.path.exists(database + suffix):
                    shutil.copy(database + suffix, os.path.join(aside, "ActivitiesCache.db" + suffix))
            db = sqlite3.connect(os.path.join(aside, "ActivitiesCache.db"))
            for table in ("Activity", "ActivityOperation"):
                theirs += [(table,) + row for row in db.execute(
                    f"SELECT Id, ActivityType, AppActivityId, StartTime, LastModifiedTime FROM {table}")]
            db.close()
        wrong = []
        for table, guid, kind, app_activity, start, modified in theirs:
            key = (table, "{" + str(uuid.UUID(bytes_le=guid)).upper() + "}")
            r = mine.get(key, {})
            if (r.get("ActivityType") != kind or (r.get("AppActivityId") or "") != (app_activity or "")
                    or r.get("StartTimeUtc") != utc(start) or r.get("LastModifiedTimeUtc") != utc(modified)):
                wrong.append(f"{key}: {kind} {app_activity} {utc(start)}, WAC {r.get('ActivityType')} {r.get('AppActivityId')} {r.get('StartTimeUtc')}")
        ok = len(theirs) == len(mine) and not wrong
        print(f"  {'✅' if ok else '❌'} activities_cache.json: {source.split(chr(92))[-2]} — {len(theirs)} row(s) as Python's SQLite reads them "
              f"(WAL replayed), WAC {len(mine)}, identifier, type and times identical" + ("" if ok else f": {wrong[:3]}"))
        found += 0 if ok else 1
    return found


def check_search_index(folder):
    """search_index.json against what Windows' own query of its index
    (OLE DB, Search.CollatorDSO) returned just before the collection.

    The witness document (unique name and text) must be in the property
    store with its size and its summary, and in the crawler's table. Every
    item both list must have the same modification (UTC, to the second, as
    OLE DB gives it) and size: a FILETIME or a 64-bit integer read wrongly
    would be valid JSON. Items indexed after the query, or not visible to
    it, are counted, not failed: the index lives on between the two."""
    records = load(folder, "search_index.json")
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    if not isinstance(records, list) or not os.path.exists(path):
        print("  ⏭️  no search_index.json or no reference: search index not confronted")
        return 0
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [l.rstrip("\r\n") for l in f]
    witness = [l[len("searchwitness="):].split("|", 2) for l in lines if l.startswith("searchwitness=")]
    queried = next((l[len("searchquery="):] for l in lines if l.startswith("searchquery=")), "")
    items = [l[len("searchitem="):].split("|") for l in lines if l.startswith("searchitem=")]
    if not items:
        print("  ⏭️  Windows' query of its index returned nothing: search index not confronted")
        return 0
    store = {(r.get("ItemUrl") or "").lower(): r for r in records if r.get("Table") == "PropertyStore"}
    found = 0
    if witness:
        url, size, summary = witness[0]
        r = store.get(url.lower(), {})
        name = url.rsplit("/", 1)[-1].lower()
        gathered = any((g.get("Url") or "").lower().endswith("/users/wac/documents/" + name) for g in records if g.get("Table") == "Gather")
        ok = str(r.get("Size")) == size and r.get("SearchAutoSummary") == summary and gathered
        print(f"  {'✅' if ok else '❌'} search_index.json: the witness document found with its size and summary, and in the crawler's table"
              + ("" if ok else f": {url} {size} {summary!r}, WAC {r.get('Size')} {r.get('SearchAutoSummary')!r}, gathered {gathered}"))
        found += 0 if ok else 1
    else:
        print("  ❌ search index: the witness document was not indexed in time (reference without searchwitness=)")
        found += 1
    both = wrong = later = 0
    mismatches = []
    for url, modified, size in items:
        r = store.get(url.lower())
        if r is None:
            continue
        # Indexed again after Windows was asked (a witness rewritten by this
        # cycle): Windows' answer is older than WAC's, not comparable.
        if queried and (r.get("SearchGatherTimeUtc") or "")[:19] >= queried:
            later += 1
            continue
        both += 1
        if (modified and not (r.get("DateModifiedUtc") or "").startswith(modified)) or (size and str(r.get("Size")) != size):
            wrong += 1
            mismatches.append(f"{url}: {modified} {size}, WAC {r.get('DateModifiedUtc')} {r.get('Size')}")
    ok = both > 0 and not wrong
    print(f"  {'✅' if ok else '❌'} search_index.json: {both} item(s) listed by Windows and by WAC, modification and size identical "
          f"(indexed again after Windows was asked {later}, Windows only {len(items) - both - later}, "
          f"WAC only {len(store) - both - later})" + ("" if ok else f": {mismatches[:3]}"))
    return found + (0 if ok else 1)


def check_event_messages(folder):
    """events.json's messages against the one Windows renders itself
    (EvtFormatMessage, through Get-WinEvent) for each kind of event of the
    machine — provider, identifier, version, qualifiers — on the same record.

    The dates inserted in a message are compared without Windows' direction
    marks (U+200E) and to the 100 ns (Windows writes 9 decimals, WAC 7): a
    difference of presentation, not of value. The rest must be identical,
    whitespace runs aside. A residue is explained (documented in the
    validation file: Windows' own deviations from a manifest, a satellite on
    disk older than its binary); the check fails below 90 % of identical
    kinds among those Windows gives a message — the wrong step of the
    WEVT_TEMPLATE once left 28 %."""
    import re
    path = os.path.join(folder, "reference", "event-messages.txt")
    if not os.path.exists(path):
        print("  ⏭️  reference/event-messages.txt absent: event messages not confronted")
        return 0
    def unescape(text):   # "\\" "\r" "\n", as event-messages-reference.ps1 writes them
        return re.sub(r"\\(.)", lambda m: {"r": "\r", "n": "\n"}.get(m.group(1), m.group(1)), text)
    reference = {}
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\r\n").split("|", 6)
            if len(parts) == 7:
                reference[(parts[4].lower(), parts[5])] = (parts[0], parts[1], unescape(parts[6]))
    events = load(folder, "events.json")
    if not isinstance(events, list):
        print("  ⏭️  no events.json: event messages not confronted")
        return 0
    dates = re.compile(r"\u200e?(\d{4})\u200e?-\u200e?(\d\d)\u200e?-\u200e?(\d\dT\d\d:\d\d:\d\d)\.(\d{7})\d*Z")
    def norm(text):
        text = dates.sub(lambda m: f"{m.group(1)}-{m.group(2)}-{m.group(3)}.{m.group(4)}Z", text or "")
        return re.sub(r"\s+", " ", text.replace("\u200e", "")).strip()
    counts = collections.Counter()
    differing = []
    for e in events:
        r = reference.get(((e.get("EvtSystemChannel") or "").lower(), str(e.get("EvtSystemEventRecordId"))))
        if not r or not r[2]:
            continue
        mine = e.get("EvtEventMessage") or ""
        if not mine:
            counts["missing"] += 1
        elif norm(mine) == norm(r[2]):
            counts["identical"] += 1
        else:
            counts["different"] += 1
            differing.append(f"{r[0]} {r[1]}")
    rendered = sum(counts.values())
    share = counts["identical"] / rendered if rendered else 0
    ok = rendered > 0 and share >= 0.90
    print(f"  {'✅' if ok else '❌'} events.json: {counts['identical']} kind(s) of event out of {rendered} with the message Windows renders "
          f"({share:.1%}; {counts['different']} different, {counts['missing']} without a message)"
          + ("" if ok else f": {differing[:5]}"))
    return 0 if ok else 1


def check_exhibit_reads_after_copy(folder):
    """The exhibit store is not read once copied to the working directory
    (B-040): every collected file is read in its working copy.

    The reference is Windows' own object-access audit: before the conversion
    of the separate collection, the harness puts a read audit (SACL) on its
    exhibit store and lists afterwards each read by WAC.exe (Security event
    4663, reference/exhibit-reads.txt: instant UTC|file). The conversion
    reads the store to check it and to copy it — those reads must all come
    before the last "Copy of the exhibit store into the working directory"
    of conversion.json, and none after. No read at all would mean the audit
    did not work: the check then fails rather than pass by default."""
    path = os.path.join(folder, "reference", "exhibit-reads.txt")
    log = load(folder, "conversion.json")
    if not os.path.exists(path) or not isinstance(log, dict):
        print("  ⏭️  reference/exhibit-reads.txt or conversion.json absent: reads of the exhibit store not checked")
        return 0
    copies = [o.get("TimestampUtc") for o in log.get("Operations", [])
              if str(o.get("Operation", "")).startswith("Copy of the exhibit store into the working directory")]
    if not copies:
        print("  ❌ conversion.json: no copy of the exhibit store into the working directory recorded")
        return 1
    copied = max(copies)[:27]   # to the 100 ns, as both logs write it
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        reads = [l.rstrip("\r\n").split("|", 1) for l in f if "|" in l]
    after = [r for r in reads if r[0][:27] > copied]
    ok = bool(reads) and not after
    print(f"  {'✅' if ok else '❌'} exhibit store: {len(reads)} read(s) by WAC.exe before its working copy ({copied}Z), "
          f"{len(after)} after" + ("" if ok else (": the audit recorded no read at all" if not reads else f": {after[:3]}")))
    return 0 if ok else 1


def check_thunderbird(folder):
    """emails.json against Python's own mailbox and email modules, on the
    Inbox Thunderbird wrote in the test VM (place-file-artefacts.ps1, section
    42): every message of the working copy's mbox — subject, attachments by
    name and SHA-256 — must be in emails.json, the witness among them with
    the attachment it was sent."""
    import email, email.header, email.policy, glob, hashlib, mailbox, urllib.parse
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    records = load(folder, "emails.json")
    if not os.path.exists(path) or not isinstance(records, list):
        return 0
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        witness = next((l.strip()[len("thunderbird="):].split("|") for l in f if l.startswith("thunderbird=")), None)
    if not witness:
        print("  ⏭️  no Thunderbird witness (Thunderbird not installed in the VM?): mbox not confronted")
        return 0
    token, encoded_name, sha, vm_inbox = witness
    copies = glob.glob(os.path.join(folder, "working", "**", "Thunderbird", "**", "Inbox"), recursive=True)
    mine = [r for r in records if r.get("Type") == "Message" and str(r.get("Source", "")).lower() == vm_inbox.lower()]
    if not copies:
        print("  ❌ emails.json: the Inbox's working copy was not fetched: Thunderbird not confronted")
        return 1
    expected = []
    for message in mailbox.mbox(copies[0], factory=lambda f: email.message_from_binary_file(f, policy=email.policy.default)):
        attachments = [(part.get_filename() or "", hashlib.sha256(part.get_payload(decode=True) or b"").hexdigest())
                       for part in message.walk() if part.get_filename()]
        expected.append((str(message["subject"] or ""), attachments))
    got = [(r.get("Subject", ""), [(a.get("FileName", ""), str(a.get("Sha256", "")).lower()) for a in r.get("Attachments", [])])
           for r in mine]
    name = urllib.parse.unquote(encoded_name)
    found = any(token in subject and (name, sha) in attachments for subject, attachments in got)
    if sorted(got) != sorted(expected) or not found:
        print(f"  ❌ emails.json: {len(mine)} message(s) of the Inbox, Python's mailbox reads {len(expected)}; "
              f"witness {token} {'found' if found else 'missing'}")
        for e in [e for e in expected if e not in got][:2]:
            print(f"        mailbox: {e!r}")
        for g in [g for g in got if g not in expected][:2]:
            print(f"        WAC:     {g!r}")
        return 1
    print(f"  ✅ emails.json: the {len(expected)} message(s) of the Inbox Thunderbird wrote, as Python's mailbox reads them "
          f"(subject, attachments by name and SHA-256); the witness {token} with {name}")
    return 0


def check_emails(folder):
    """emails.json against pypff, on the mail witness: a PST of the public
    corpus pst_fixtures.sh pins, placed in the Outlook Files of "wac".

    pypff (libpff, written independently of WAC) read the same file when
    pst_fixtures.sh made pst-reference.txt: for every message it reads, the
    subject, the sender, the delivery time, each attachment's name, size and
    SHA-256 and the body's SHA-256 must be WAC's. The items pypff cannot read
    must not stop WAC."""
    import datetime
    path = os.path.join(folder, "reference", "emails.txt")
    records = load(folder, "emails.json")
    if not os.path.exists(path) or not isinstance(records, list):
        print("  ⏭️  no mail witness or no emails.json: mail not confronted")
        return 0
    with open(path, encoding="utf-8") as f:
        vm_path, local = f.read().strip()[len("pst="):].split("|", 1)
    reference_file = os.path.join(os.path.dirname(local), "pst-reference.txt")
    if not os.path.exists(reference_file):
        print("  ⏭️  pst-reference.txt absent (sources/pst_fixtures.sh): mail not confronted")
        return 0
    name = os.path.basename(local)
    expected = {}
    with open(reference_file, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("|")
            if parts[0] == name and parts[1] != "-" and len(parts) == 8:
                expected[int(parts[1])] = parts[2:]
    def iso(ticks):
        if not ticks or ticks == "0":
            return None
        moment = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(ticks) // 10)
        return moment.strftime("%Y-%m-%dT%H:%M:%S")
    mine = {r.get("NodeId"): r for r in records
            if r.get("Type") == "Message" and str(r.get("Source", "")).lower() == vm_path.lower()}
    store = next((r for r in records if r.get("Type") == "Mailbox" and str(r.get("Source", "")).lower() == vm_path.lower()), {})
    wrong = []
    for nid, (subject, sender, delivered, submitted, attachments, body) in expected.items():
        r = mine.get(nid)
        if r is None:
            wrong.append((nid, "not read"))
            continue
        clean = lambda t: (t or "").replace("|", " ").replace("\n", " ").replace("\r", " ")
        got = ";".join(f"{clean(a.get('FileName'))}:{a.get('Size', 0)}:{str(a.get('Sha256', '')).lower()}"
                       for a in r.get("Attachments", []))
        when = str(r.get("DeliveredUtc", ""))[:19] or None
        if clean(r.get("Subject")) != subject: wrong.append((nid, f"subject {r.get('Subject')!r}, pypff {subject!r}"))
        if clean(r.get("SenderName")) != sender: wrong.append((nid, f"sender {r.get('SenderName')!r}, pypff {sender!r}"))
        if when != iso(delivered): wrong.append((nid, f"delivered {when}, pypff {iso(delivered)}"))
        if got != attachments: wrong.append((nid, f"attachments {got[:80]!r}, pypff {attachments[:80]!r}"))
        if str((r.get("Body") or {}).get("Sha256", "")).lower() != body: wrong.append((nid, "body differs"))
    attachments = sum(len(r.get("Attachments", [])) for r in mine.values())
    if wrong or not expected:
        print(f"  ❌ emails.json: {len(wrong)} difference(s) with pypff on {vm_path} ({len(expected)} message(s) expected)")
        for nid, why in wrong[:3]:
            print(f"        {nid}: {why}")
        return 1
    print(f"  ✅ emails.json: the {len(expected)} message(s) pypff reads in {name} identical (subject, sender, delivery, "
          f"{attachments} attachment(s) by name, size and SHA-256, body); {store.get('MessageCount')} read by WAC")
    return 0


def check_thumbcache(folder):
    """thumbcache.json: the format's own checksums, and the picture witness.

    Every entry carries two CRC-64 Windows computed when it wrote it, over
    its header and over its image: WAC recomputes them, and an entry it reads
    wrong — or reads from another file — fails them. An identifier of sixteen
    hexadecimal digits is the hash written out: the two must agree. The
    witness (place-file-artefacts.ps1, section 41) is a picture "wac" saw in
    Explorer: Windows gives its System.ThumbnailCacheId, which must be the
    hash of an entry holding an image, exported with the SHA-256 the JSON
    gives."""
    import hashlib, re
    entries = load(folder, "thumbcache.json")
    if not isinstance(entries, list):
        print("  ⏭️  thumbcache.json absent or not collected: thumbnail caches not confronted")
        return 0
    found = 0
    bad_header = [e for e in entries if e.get("HeaderChecksumValid") is not True]
    bad_data = [e for e in entries if e.get("DataSize") and e.get("DataChecksumValid") is not True]
    bad_id = [e for e in entries if re.fullmatch(r"[0-9a-f]{16}", str(e.get("Identifier", ""))) and e.get("Identifier") != e.get("Hash")]
    with_data = sum(1 for e in entries if e.get("DataSize"))
    if bad_header or bad_data or bad_id or not entries:
        print(f"  ❌ thumbcache.json: {len(entries)} entry(ies), {len(bad_header)} header and {len(bad_data)} data "
              f"checksum(s) failed, {len(bad_id)} identifier(s) not their hash")
        for e in (bad_header + bad_data + bad_id)[:3]:
            print(f"        {e.get('Cache')} @ {e.get('Offset')}: {e.get('Hash')}")
        found += 1
    else:
        print(f"  ✅ thumbcache.json: {len(entries)} entry(ies) of {len({e.get('Cache') for e in entries})} cache(s), "
              f"every header checksum and the {with_data} data checksum(s) as Windows wrote them")
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    witness = None
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            witness = next((l.strip()[len("thumbcache="):].split("|") for l in f if l.startswith("thumbcache=")), None)
    if not witness:
        print("  ⏭️  no thumbnail witness: its entry not looked for")
        return found
    cache_id, picture = witness[0], witness[1] if len(witness) > 1 else ""
    entry = next((e for e in entries if e.get("Hash") == cache_id and e.get("DataSize")), None)
    image = os.path.join(folder, str(entry.get("Image", "")).replace("\\", os.sep)) if entry and entry.get("Image") else None
    same = False
    if image and os.path.exists(image):
        with open(image, "rb") as f:
            same = hashlib.sha256(f.read()).hexdigest().upper() == str(entry.get("Sha256", "")).upper()
    if entry and same and entry.get("Format") in ("png", "jpg", "bmp"):
        print(f"  ✅ thumbcache.json: the thumbnail of {picture} (ThumbnailCacheId {cache_id}) in {entry.get('Cache')}, "
              f"{entry.get('Width')}×{entry.get('Height')} {entry.get('Format')}, exported with its SHA-256")
    else:
        print(f"  ❌ thumbcache.json: the thumbnail of {picture} (ThumbnailCacheId {cache_id}) "
              f"{'exported image missing or different' if entry else 'not found'}")
        found += 1
    return found


def check_rdp(folder):
    """rdp_client.json and rdp_server.json against the RDP witness: a real
    session of "wac" to 127.0.0.2 (place-file-artefacts.ps1, section 40).

    Outgoing: the server of known values (UsernameHint, CertHash), the MRU
    the session wrote, and the bitmap cache — bmc-tools (ANSSI, written
    independently of WAC) reads the cache's working copy, and every tile WAC
    exported must have the same pixels. Incoming: every authentication (1149),
    connection (131) and Security logon of type 10 Windows lists for the
    session is in rdp_server.json, same record, user and source."""
    import glob, subprocess, tempfile
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    client, server = load(folder, "rdp_client.json"), load(folder, "rdp_server.json")
    if not os.path.exists(path) or (not isinstance(client, list) and not isinstance(server, list)):
        print("  ⏭️  no RDP witness or no rdp_*.json: RDP not confronted")
        return 0
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        lines = [l.rstrip("\r\n") for l in f]
    def report(ok, success, failure):
        print(f"  ✅ {success}" if ok else f"  ❌ {failure}")
    found = 0
    if isinstance(client, list):
        for l in (l for l in lines if l.startswith("rdpserver=")):
            host, hint, cert = l[len("rdpserver="):].split("|")
            r = next((c for c in client if c.get("Type") == "Server" and c.get("Host") == host), {})
            ok = r.get("UsernameHint") == hint and (r.get("CertHash") or "").upper() == cert
            report(ok, f"rdp_client.json: server {host}, its user name and certificate hash",
                   f"rdp_client.json: server {host} missing or different: {r}")
            found += 0 if ok else 1
        for l in (l for l in lines if l.startswith("rdpmru=")):
            target = l[len("rdpmru="):]
            ok = any(c.get("Type") == "RecentConnection" and c.get("Target") == target and c.get("MruPosition") == 0 for c in client)
            report(ok, f"rdp_client.json: the recent connection to {target}, first of the MRU",
                   f"rdp_client.json: recent connection {target} missing")
            found += 0 if ok else 1
        bmc = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "bmc-tools", "bmc-tools.py")
        caches = glob.glob(os.path.join(folder, "working", "**", "Cache*.bin"), recursive=True)
        if not os.path.exists(bmc) or not caches:
            print("  ⏭️  bmc-tools (vmtest/tools/bmc-tools) or the cache's working copy absent: tiles not confronted")
        else:
            from PIL import Image
            for cache in caches:
                name = os.path.basename(cache)
                record = next((c for c in client if c.get("Type") == "BitmapCache" and c.get("Source", "").endswith("\\" + name)), {})
                with tempfile.TemporaryDirectory() as out:
                    subprocess.run(["python3", bmc, "-s", cache, "-d", out], capture_output=True)
                    theirs = sorted(glob.glob(os.path.join(out, name + "_*.bmp")))
                    wrong = []
                    for i, image in enumerate(theirs):
                        mine = next((t.get("Image") for t in record.get("Tiles", []) if t.get("Index") == i), None)
                        mine = os.path.join(folder, mine.replace("\\", os.sep)) if mine else None
                        if not mine or not os.path.exists(mine) \
                                or Image.open(image).convert("RGB").tobytes() != Image.open(mine).convert("RGB").tobytes():
                            wrong.append(i)
                ok = bool(theirs) and record.get("TileCount") == len(theirs) and not wrong
                report(ok, f"rdp_client.json: {name}, {len(theirs)} tile(s) as bmc-tools reads them, same pixels",
                       f"rdp_client.json: {name}: bmc-tools {len(theirs)} tile(s), WAC {record.get('TileCount')}, different: {wrong[:5]}")
                found += 0 if ok else 1
    if isinstance(server, list):
        incoming = [l[len("rdpin="):].split("|") for l in lines if l.startswith("rdpin=")]
        wrong = []
        for log, record_id, user, source in incoming:
            r = next((e for e in server if (e.get("EvtSystemChannel") or "").lower() == log.lower()
                      and str(e.get("EvtSystemEventRecordId")) == record_id), None)
            if r is None or (user and r.get("User") != user) or (source and r.get("SourceAddress") != source):
                wrong.append(f"{log} {record_id}: {user} {source}, WAC {r and (r.get('User'), r.get('SourceAddress'))}")
        ok = bool(incoming) and not wrong
        report(ok, f"rdp_server.json: the {len(incoming)} incoming trace(s) Windows lists for the session, same user and source",
               f"rdp_server.json: {len(incoming)} expected, {wrong[:3]}")
        found += 0 if ok else 1
    return found


def check_firefox_places(folder, store, records):
    """web_client.json against Python's SQLite on each fetched places.sqlite,
    its write-ahead log replayed by that engine: every place and visit
    (URL, instant), no more, no less."""
    import shutil, sqlite3, tempfile
    found = 0
    for database in glob.glob(os.path.join(store, "**", "Profiles", "*", "places.sqlite"), recursive=True):
        source = "C:\\" + os.path.relpath(database, store).replace(os.sep, "\\")
        mine = [r for r in records if (r.get("Source") or "").lower() == source.lower()]
        with tempfile.TemporaryDirectory() as aside:
            for suffix in ("", "-wal", "-journal"):
                if os.path.exists(database + suffix):
                    shutil.copy(database + suffix, os.path.join(aside, "places.sqlite" + suffix))
            db = sqlite3.connect(os.path.join(aside, "places.sqlite"))
            places = db.execute("SELECT count(*) FROM moz_places").fetchone()[0]
            visits = db.execute("SELECT v.id, p.url, v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id").fetchall()
            db.close()
        by_type = collections.Counter(r.get("Type") for r in mine)
        def iso(us):
            t = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=us)
            return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        wac_visits = {r.get("Id"): r for r in mine if r.get("Type") == "Visit"}
        wrong = [f"visit {i}: {u} {iso(t)}, WAC {wac_visits.get(i, {}).get('Url')} {wac_visits.get(i, {}).get('VisitUtc')}"
                 for i, u, t in visits if wac_visits.get(i, {}).get("Url") != u or wac_visits.get(i, {}).get("VisitUtc") != iso(t)]
        ok = by_type.get("Url", 0) == places and by_type.get("Visit", 0) == len(visits) and not wrong
        print(f"  {'✅' if ok else '❌'} web_client.json: Firefox {source.split(chr(92))[-2]} — {places} place(s), {len(visits)} visit(s) "
              f"as Python's SQLite reads them (WAL replayed), WAC {by_type.get('Url', 0)}/{by_type.get('Visit', 0)}, URL and instant identical"
              + ("" if ok else f": {wrong[:3]}"))
        found += 0 if ok else 1
    return found


def check_webcache(folder, records):
    """The WebCache entries of web_client.json against dissect.esedb (Fox-IT,
    written independently of WAC's ESE reader) on the same WebCacheV01.dat.

    Every entry of every Container_<n>, its URL and its UTC times identical;
    the modification time of the MSHist containers, written in local time,
    converted here with the tz database (zoneinfo) for the VM's time zone —
    not with WAC's rules. Skipped when dissect.esedb is not installed
    (pip install dissect.esedb).
    """
    try:
        from dissect.esedb import EseDB
        from zoneinfo import ZoneInfo
    except ImportError:
        print("  ⏭️  dissect.esedb not installed: WebCache not confronted")
        return 0
    store = os.path.join(folder, store_folder(folder))
    caches = glob.glob(os.path.join(store, "**", "WebCache", "WebCacheV01.dat"), recursive=True)
    osj = load(folder, "OperatingSystem.json")
    key = osj.get("CurrentTimeZoneId") if isinstance(osj, dict) else None
    zone = ZoneInfo(WINDOWS_TO_IANA[key]) if key in WINDOWS_TO_IANA else None
    def iso(ticks):
        if not ticks:
            return None
        t = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ticks // 10)
        return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + str(ticks % 10) + "Z"
    def local_to_utc(ticks):
        if not ticks or zone is None:
            return None
        local = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ticks // 10)
        utc = local.replace(tzinfo=zone).astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return utc.strftime("%Y-%m-%dT%H:%M:%S.%f") + str(ticks % 10) + "Z"
    found = 0
    for cache in caches:
        source = "C:\\" + os.path.relpath(cache, store).replace(os.sep, "\\")
        mine = {(r.get("ContainerId"), r.get("EntryId")): r for r in records
                if r.get("Type") == "CacheEntry" and (r.get("Source") or "").lower() == source.lower()}
        db = EseDB(open(cache, "rb"))
        names = {t.name for t in db.tables()}
        theirs, wrong, local_checked, empty = 0, [], 0, 0
        for c in db.table("Containers").records():
            cid, name = c.get("ContainerId"), c.get("Name") or ""
            if f"Container_{cid}" not in names:
                continue
            for e in db.table(f"Container_{cid}").records():
                # A leaf entry without any column (one per empty Content
                # container of the VM): dissect lists it, but cannot even
                # read its header — no entry, WAC rightly gives none.
                if e.get("EntryId") is None:
                    empty += 1
                    continue
                theirs += 1
                r = mine.get((cid, e.get("EntryId")), {})
                modified = local_to_utc(e.get("ModifiedTime")) if name.startswith("MSHist") else iso(e.get("ModifiedTime"))
                local_checked += 1 if name.startswith("MSHist") and e.get("ModifiedTime") else 0
                expected = {"Url": e.get("Url"), "AccessedUtc": iso(e.get("AccessedTime")),
                            "ExpiryUtc": iso(e.get("ExpiryTime")), "ModifiedUtc": modified}
                for field, value in expected.items():
                    if value is not None and r.get(field) != value:
                        wrong.append(f"{name} {e.get('EntryId')} {field}: dissect {value}, WAC {r.get(field)}")
        ok = theirs == len(mine) and not wrong
        print(f"  {'✅' if ok else '❌'} web_client.json: {theirs} WebCache entr(ies) as dissect.esedb reads them "
              f"(WAC {len(mine)}, {empty} empty leaf entr(ies) left out), URL and times identical, "
              f"{local_checked} MSHist local time(s) converted by zoneinfo"
              + ("" if ok else f": {wrong[:3]}"))
        found += 0 if ok else 1
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
        compared, wrong, renamed = 0, [], 0
        for it in items:
            source = str(it.get("SourcePath") or "")
            entry = it.get("MftEntry")
            created = it.get("SourceCreatedUtc")
            # Files of a volume whose $MFT was converted, by name (not the metafiles, not a named stream).
            if source[:2].upper() not in volumes or ":" in source[2:] or not entry or not created:
                continue
            r = by_entry.get((source[:2].upper(), entry))
            compared += 1
            # The same file renamed since the exhibit was taken — same record,
            # same creation date, another name: ESE rotates its logs by renaming
            # them (SRU.log -> SRU00B2B.log) while the machine keeps running, and
            # the $MFT is read later. A record that names ANOTHER file is still a
            # failure: the exhibit's content may be that file's (B-043).
            if (r is not None and r.get("CreatedUtc") == created
                    and source.lower() not in {str(p).lower() for p in [r.get("Path", "")] + (r.get("HardLinkPaths") or [])}):
                renamed += 1
                continue
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
            print(f"  ✅ mft.json: {compared - renamed} exhibit(s) with the manifest's path and creation date "
                  f"({len(mft)} record(s), {deleted} deleted, {linked} with hard links"
                  f"{f'; {renamed} renamed since their exhibit was taken' if renamed else ''})")

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


def check_prefetch_mft_references(folder):
    """A Prefetch's $MFT references against the $MFT of the same collection.

    Two independent sources: the metrics array written by the prefetcher, and
    the volume's own records (mft.json, hard links included). Where the loaded
    file's path still names the record the reference gives, the sequence must
    be the record's. A reference to another record, or to a path gone, is a
    file replaced or deleted since the prefetcher wrote it: not a defect. It is
    this check that caught the split by hand — the sequence read on four bytes
    (770 703 362 for a sequence of 2): 14 940 references out of 14 975.
    """
    prefetchs, mft = load(folder, "prefetchs.json"), load(folder, "mft.json")
    if not isinstance(prefetchs, list) or not isinstance(mft, list):
        print("  ⏭️  prefetchs.json or mft.json absent: $MFT references not cross-checked")
        return 0
    records = {}
    for e in mft:
        for path in [e.get("Path")] + (e.get("HardLinkPaths") or []):
            if path:
                records[path.lower()] = (e.get("Entry"), e.get("Sequence"))
    same, moved, wrong = 0, 0, []
    for p in prefetchs:
        for f in p.get("FileNames") or []:
            ref, path = f.get("MftReference"), f.get("FullPath")
            record = records.get((path or "").lower()) if ref else None
            if record is None or record[0] != ref.get("EntryIndex"):
                moved += record is None and ref is not None and path is not None
                continue
            if record[1] == ref.get("SequenceNumber"):
                same += 1
            else:
                wrong.append((path, ref, record))
    if wrong or not same:
        print(f"  ❌ prefetchs.json: {len(wrong)} $MFT reference(s) whose sequence is not the record's, "
              f"{same} identical")
        for path, ref, record in wrong[:3]:
            print(f"        {path}: {ref} in the Prefetch, {record} in the $MFT")
        return 1
    print(f"  ✅ prefetchs.json: {same} $MFT reference(s) identical to the $MFT's record "
          f"(entry and sequence); {moved} to a path gone since")
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

    # Amcache SHA-1 against the file's, for the executables of System32 of the
    # size and version the entry records: Windows Update rewrites some, and an
    # entry rewritten since can still describe the former version.
    path = os.path.join(ref, "sha1-system32.txt")
    files = load(folder, "amcache_application_files.json")
    if os.path.exists(path) and isinstance(files, list):
        hashes = {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 4 and len(parts[1]) == 40 and parts[2].isdigit():
                    hashes[parts[0]] = (parts[1], int(parts[2]), parts[3])
        equal, wrong = 0, []
        for a in files:
            known = hashes.get(str(a.get("LongPath") or "").lower())
            if known and a.get("AmcacheSha1") and a.get("Size") == known[1] and a.get("BinFileVersion") == known[2]:
                if a["AmcacheSha1"] != known[0]:
                    wrong.append(f"{a['LongPath']}: {a['AmcacheSha1']}, file {known[0]}")
                elif a["Size"] > 31457280 and a.get("AmcacheSha1CoversBytes") != 31457280:
                    wrong.append(f"{a['LongPath']}: larger than 30 MiB, AmcacheSha1CoversBytes absent")
                else:
                    equal += 1
        if wrong:
            print(f"  ❌ amcache: {len(wrong)} AmcacheSha1 differ from the file's SHA-1, e.g. {wrong[0]}")
            found += 1
        elif equal:
            print(f"  ✅ amcache: AmcacheSha1 of {equal} unchanged executable(s) of System32 identical to their SHA-1 (first 30 MiB, as Amcache)")
        else:
            print("  ⏭️  no Amcache executable of System32 of the size and version recorded: Sha1 not confronted")

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


# Registry value names WAC publishes as Windows writes them (registryNameToJsonKey
# only drops their separators), whose abbreviation is Windows' choice, not WAC's.
WINDOWS_VALUE_NAMES = {"NumRssQueues"}


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
                # Names of Windows' own values, kept as Windows writes them.
                if k in WINDOWS_VALUE_NAMES:
                    continue
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
        # local_groups.json, like users.json, names its groups from the SAM
        # itself (the C value), not through the table; its members' SIDName uses
        # the shared table checked on the other files, and the membership is
        # confronted with Get-LocalGroupMember in check_local_groups.
        if os.path.basename(file) in ("events.json", "users.json", "local_groups.json", "Sessions.json",
                                      "investigation.json", "conversion.json"):
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

    # A half-closed connection (FIN_WAIT2, CLOSING, LAST_ACK, TIME_WAIT)
    # outlives its process, the kernel keeping its former PID: no observed
    # process owns it, rightly — seen with Chrome's push channel (port 5228),
    # in FIN_WAIT2 after the witness's Chrome had exited.
    closing = {"FIN_WAIT1", "FIN_WAIT2", "CLOSING", "LAST_ACK", "TIME_WAIT"}
    owned = [c for c in connections if c.get("ProcessId") and c.get("State") not in closing]
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


def check_local_groups(folder):
    """Confronts local_groups.json with Get-LocalGroupMember: every group's direct
    members, by SID, must match, and the witness account wacpw must appear in the
    Administrators group (S-1-5-32-544)."""
    groups = load(folder, "local_groups.json")
    if not isinstance(groups, list) or not groups:
        print("  \u23ed\ufe0f  local_groups.json absent or empty: check skipped")
        return 0
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    if not os.path.exists(path):
        print("  \u23ed\ufe0f  no reference: local groups not confronted")
        return 0
    ref = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for l in f:
            if l.startswith("localgroup="):
                sid, members = l.strip()[len("localgroup="):].split("|", 1)
                ref[sid.lower()] = {m.lower() for m in members.split(",") if m}
    mine = {str(g.get("Sid", "")).lower():
            {str(m.get("Sid", "")).lower() for m in (g.get("Members") or [])}
            for g in groups}
    found = 0
    wrong = [f"{sid}: WAC only {sorted(mine.get(sid, set()) - want)[:3]}, "
             f"Windows only {sorted(want - mine.get(sid, set()))[:3]}"
             for sid, want in ref.items() if mine.get(sid, set()) != want]
    if wrong:
        print(f"  \u274c local_groups.json: {wrong[:3]}")
        found += 1
    else:
        print(f"  \u2705 local_groups.json: {len(ref)} group(s), members identical to Get-LocalGroupMember")
    users = load(folder, "users.json")
    wacpw = next((str(u.get("SID", "")) for u in (users or []) if u.get("Name") == "wacpw"), "")
    admins = mine.get("s-1-5-32-544", set())
    if wacpw and wacpw.lower() in admins:
        print("  \u2705 local_groups.json: witness wacpw present in Administrators")
    elif wacpw:
        print(f"  \u274c local_groups.json: witness wacpw ({wacpw}) absent from Administrators {sorted(admins)}")
        found += 1
    return found


def check_account_rights(folder):
    """Confronts security.json's AccountRights (Policy\\Accounts) with Windows'
    own user-rights export (secedit /export): every privilege and logon right
    must be held by the same SIDs on both sides."""
    sec = load(folder, "security.json")
    rights = (sec or {}).get("AccountRights") if isinstance(sec, dict) else None
    if not rights:
        print("  ⏭️  security.json AccountRights absent: check skipped")
        return 0
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    if not os.path.exists(path):
        print("  ⏭️  no reference: account rights not confronted")
        return 0
    windows = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for l in f:
            if l.startswith("userright="):
                name, sids = l.strip()[len("userright="):].split("|", 1)
                windows[name] = {s.upper() for s in sids.split(",") if s.startswith("S-1-")}
    mine = {}
    for a in rights:
        sid = str(a.get("Sid", "")).upper()
        for name in (a.get("Privileges") or []) + (a.get("LogonRights") or []):
            mine.setdefault(name, set()).add(sid)
    # WAC reads Policy\Accounts, the authoritative store; secedit is a lossy
    # export (it resolves some holders to a name it cannot always translate back,
    # e.g. virtual service accounts). So every holder Windows lists must be in
    # WAC (WAC complete and correct), and WAC's extras are allowed only for the
    # virtual/service SID ranges secedit mangles (S-1-5-6/80/82/90/96/99).
    virtual = ("S-1-5-6", "S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-", "S-1-5-99-")
    missing = {name: sorted(sids - mine.get(name, set()))
               for name, sids in windows.items() if not sids <= mine.get(name, set())}
    extra = {name: sorted(e) for name, sids in windows.items()
             for e in [mine.get(name, set()) - sids]
             if e and not all(x.startswith(virtual) for x in e)}
    if missing:
        print(f"  ❌ security.json AccountRights: holders missing {list(missing.items())[:3]}")
        return 1
    if extra:
        print(f"  ❌ security.json AccountRights: unexpected extra holders {list(extra.items())[:3]}")
        return 1
    print(f"  ✅ security.json AccountRights: {len(windows)} right(s), every holder Windows lists present (virtual service SIDs aside)")
    return 0


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

    # SAM hashes (B-034): WAC decrypts the NT hash of each account from the SAM.
    # The witness accounts have a known password, so their NT hash must equal
    # MD4 of that password in UTF-16LE — the whole boot key / AES / DES chain
    # verified end to end, against an independent computation (empty password
    # gives the well-known constant 31d6cfe0...).
    path = os.path.join(folder, "reference", "file-artefacts.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            # samhash=<name>|<current password>[|<previous password>]
            witnesses = [l.strip()[len("samhash="):].split("|")
                         for l in f if l.startswith("samhash=")]
        by_name = {str(u.get("Name", "")).lower(): u for u in d}
        wrong = []
        for parts in witnesses:
            name, current = parts[0], parts[1]
            account = by_name.get(name.lower(), {})
            expected = md4(current.encode("utf-16-le")).hex()
            got = str(account.get("NtHash", "")).lower()
            if got != expected:
                wrong.append(f"{name}: NtHash {got or '(absent)'}, expected {expected}")
            # A previous password: its hash must be somewhere in the NT history.
            if len(parts) > 2 and parts[2]:
                previous = md4(parts[2].encode("utf-16-le")).hex()
                history = {h.lower() for h in account.get("NtHashHistory") or []}
                if previous not in history:
                    wrong.append(f"{name}: previous hash {previous} not in NtHashHistory {sorted(history)}")
        if witnesses and not wrong:
            print(f"  ✅ users.json: NT hash and history of {len(witnesses)} witness account(s) match MD4 of their passwords")
        elif witnesses:
            print(f"  ❌ users.json: {wrong}")
            found += 1

        # Security questions (ResetData): the witness JSON written to wacpw must
        # come back, questions and answers, in its SecurityQuestions.
        expected_line = None
        with open(path, encoding="utf-8", errors="replace") as f:
            for l in f:
                if l.startswith("resetdata="):
                    expected_line = l.strip()[len("resetdata="):]
        if expected_line:
            try:
                want = {(q.get("question"), q.get("answer"))
                        for q in json.loads(expected_line).get("questions", [])}
            except ValueError:
                want = set()
            account = by_name.get("wacpw", {})
            got = {(q.get("Question"), q.get("Answer")) for q in account.get("SecurityQuestions") or []}
            if want and got == want:
                print(f"  ✅ users.json: {len(want)} security question(s) and answer(s) of wacpw read from ResetData")
            else:
                print(f"  ❌ users.json: security questions of wacpw {sorted(got)}, expected {sorted(want)}")
                found += 1
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
