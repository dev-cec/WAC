#!/usr/bin/env bash
# run-wac-test.sh — a fully autonomous WAC test cycle in the Windows VM.
#
# Chains, with no interaction at all: build (optional) -> upload of the binaries
# into the VM -> run of WAC as SYSTEM (admin rights, no UAC) -> fetch of the log
# and of the JSON files onto the host for inspection.
#
# Prerequisite: qemu-guest-agent installed and answering in the VM (`qga.py ping`).
# The VM is win11-test, or the one the WAC_VM variable names.
# Usage: ./run-wac-test.sh [--build] [--raw-only] [--no-split] [--binary-all]
#                          [--only=key,key…]
#
# --only=mft,usn_journal: collects only these artefacts (keys of the
# `artefacts:` section of wac.yml; the pseudo-key "binaries" adds --binary),
# through a wac.yml placed next to WAC.exe for
# steps 6 and 7 — a cycle a few minutes long to test one artefact. The checks
# of the artefacts switched off are skipped (their JSON says NotRequested).
# The hives and the event logs are dependencies, taken when an artefact named
# reads them; step 8 (wac.yml) is skipped, it tests the full configuration.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# The VM of the cycle: the Windows 11 one, or the one WAC_VM names (an older
# Windows created by `create-vm.sh win81`, `win7`…).
DOM="${WAC_VM:-win11-test}"
QGA="python3 $HERE/lib/qga.py --dom $DOM"
VMDIR='C:\wactest'
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT="$HERE/results/$STAMP"
mkdir -p "$OUTPUT"

BUILD=0; RAWONLY=0; SPLIT=1; BINARY_OPTION=--binary; ONLY=""
for a in "$@"; do
  [[ "$a" == --only=* ]] && ONLY="${a#--only=}"
  [[ "$a" == "--build"    ]] && BUILD=1
  [[ "$a" == "--raw-only" ]] && RAWONLY=1
  [[ "$a" == "--no-split" ]] && SPLIT=0
  # Step 7 with --binary-all: every executable copied, verdict recorded.
  [[ "$a" == "--binary-all" ]] && BINARY_OPTION=--binary-all
done

# A full cycle, or a --only one that asks for one of these artefacts.
wants() { local k; for k in "$@"; do [[ -z "$ONLY" || ",$ONLY," == *",$k,"* ]] && return 0; done; return 1; }
# What serves WAC's core rather than one artefact (binaries and trust set, raw
# validation, Store package, timestomping, harmlessness, tampering,
# determinism) belongs to full cycles: a --only cycle runs only what its
# artefacts need.
full_cycle() { [[ -z "$ONLY" ]]; }
# --only: no binaries collected — they are no artefact's.
# The pseudo-key "binaries" keeps them: --only=fat_volumes,prefetch,binaries.
if [[ -n "$ONLY" ]]; then
  [[ ",$ONLY," == *",binaries,"* ]] || BINARY_OPTION=""
  ONLY=$(tr ',' '\n' <<<"$ONLY" | grep -vx binaries | paste -sd, -)
fi
BINARY_FLAG=${BINARY_OPTION:+--binary}

echo "== 0. Agent == ($(date +%H:%M:%S))"
$QGA ping
# The checks must at least compile: a syntax error in check-json.py showed only
# as the generic "some checks fail", after a whole cycle.
for script in "$HERE"/lib/*.py; do
  python3 -m py_compile "$script" || { echo "   ❌ $(basename "$script") does not compile"; exit 1; }
done

# The VM's clock against the host's: after a long pause of the host, Windows 7
# caught up the lost ticks, ran 30 min ahead, then stepped back during the
# cycle — events, USN records and keys came out "after the collection".
# Set to the host's time when it is more than 5 s off (test VM only).
vmEpoch=$($QGA run -- powershell.exe -NoProfile -Command '[int64](([DateTime]::UtcNow - [DateTime]"1970-01-01").TotalSeconds)' 2>/dev/null | tr -d '\r' || true)
if [[ "$vmEpoch" =~ ^[0-9]+$ ]] && (( vmEpoch - $(date -u +%s) > 5 || $(date -u +%s) - vmEpoch > 5 )); then
  echo "   ⚠️ VM clock off by $(( vmEpoch - $(date -u +%s) )) s: set to the host's"
  $QGA run -- powershell.exe -NoProfile -Command "Set-Date ([DateTime]::Parse('$(date -u +%FT%T.%3NZ)').ToLocalTime()) | Out-Null" >/dev/null 2>&1 || true
fi

if wants mft usn_journal zone_identifiers; then
echo "== 0a. Data volume == ($(date +%H:%M:%S))"
# The second fixed disk of create-vm.sh, formatted NTFS on first use (label
# WACDATA): the $MFT and change journal of a volume other than the system's.
DATA_STATE=$($QGA run -- powershell.exe -NoProfile -Command '
  $v = Get-Volume -FileSystemLabel WACDATA -ErrorAction SilentlyContinue | Where-Object DriveLetter
  if ($v) { "ready $($v.DriveLetter):" ; exit }
  $d = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' } | Select-Object -First 1
  if (-not $d) { "absent"; exit }
  $d | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel WACDATA -Confirm:$false | Out-Null
  "formatted"' 2>/dev/null | tr -d '\r' || true)
echo "   ${DATA_STATE:-no answer} (without the disk, the second-volume checks are skipped)"
fi

if wants usbstor mounted_devices devices setupapi fat_volumes; then
echo "== 0b. USB keys == ($(date +%H:%M:%S))"
# Two virtual USB keys, attached on every run, so that USBSTOR is populated on
# any test VM — including one recreated from scratch by create-vm.sh — and the
# USB artefacts are checked on every cycle: WACUSB0001 formatted FAT32,
# WACUSB0002 exFAT by the witnesses (a suspect's keys, read raw). Attached
# live only: the VM definition is left unchanged, and a VM restart simply gets
# them attached again here.
CONN="qemu:///session"
# $1 image file, $2 serial number, $3 target device of the definition.
attach_usb_key() {
  local image="$1" serial="$2" target="$3" xml attempt
  mkdir -p "$(dirname "$image")"
  [[ -f "$image" ]] || truncate -s 64M "$image"
  if ! virsh -c "$CONN" domblklist "$DOM" 2>/dev/null | grep -qF "$image"; then
    xml="$(mktemp)"
    cat > "$xml" <<EOF
<disk type='file' device='disk'>
  <driver name='qemu' type='raw'/>
  <source file='$image'/>
  <target dev='$target' bus='usb' removable='on'/>
  <serial>$serial</serial>
</disk>
EOF
    if virsh -c "$CONN" attach-device "$DOM" "$xml" --live >/dev/null; then
      echo "   USB key $serial attached"
    else
      echo "   ⚠️ USB key $serial not attached"; rm -f "$xml"; return 1
    fi
    rm -f "$xml"
  fi
  # Windows installs the device asynchronously: wait until its disk is there.
  # Asked of WMI, which every Windows answers (Get-PnpDevice came with Windows
  # 10) — not of the registry, whose USBSTOR key stays once a key was seen
  # and said "known" of a key that was not attached.
  for attempt in $(seq 1 30); do
    $QGA run -- powershell.exe -NoProfile -Command \
      "Get-WmiObject Win32_DiskDrive | Where-Object { \$_.PNPDeviceID -like '*$serial*' } | ForEach-Object { 'present' }" 2>/dev/null \
      | grep -q present && { echo "   USB key $serial present in Windows"; return 0; }
    sleep 2
  done
  echo "   ⚠️ USB key $serial not seen by Windows"; return 1
}
# One pair of images per VM: an image attached to a running VM is locked by
# it, and a second VM could not attach it (the keys of win11-test keep their
# first names).
USB_SUFFIX=""; [[ "$DOM" != "win11-test" ]] && USB_SUFFIX="-$DOM"
USB_IMG="${WAC_USB_IMG:-$HOME/vms/wac-usb-test$USB_SUFFIX.img}"
USB_EXFAT_IMG="${WAC_USB_EXFAT_IMG:-$HOME/vms/wac-usb-exfat$USB_SUFFIX.img}"
attach_usb_key "$USB_IMG" WACUSB0001 sdz || true
attach_usb_key "$USB_EXFAT_IMG" WACUSB0002 sdy || true
fi

if [[ $BUILD -eq 1 ]]; then
  echo "== 1. Build (Linux cross-compilation) == ($(date +%H:%M:%S))"
  "$ROOT/build-windows.sh" --test >/dev/null
  echo "   WAC.exe + raw_hive_test.exe rebuilt"
fi

echo "== 2. Upload of the binaries into the VM == ($(date +%H:%M:%S))"
$QGA run --shell "if not exist $VMDIR mkdir $VMDIR" >/dev/null

# A previous run that was interrupted (Ctrl+C on the host, stuck collection,
# crash) leaves WAC.exe running in the VM. Windows then locks the file and the
# upload fails — and every following test fails until a manual clean-up.
# The leftover binaries are therefore ended before writing, silently when there
# are none.
for exe in WAC.exe raw_hive_test.exe; do
  $QGA run --shell "taskkill /f /im $exe >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
done

# taskkill.exe is the program the BAM check looks for (check-json.py). WAC reads
# the SYSTEM hive raw from the disk, with its transaction logs, and Windows keeps
# a registry change in memory before writing it: measured in the VM, a taskkill
# reached the disk 56 to 82 s after its run. RegFlushKey (RegistryKey.Flush)
# did not bring it forward — a taskkill run and flushed seconds before a
# collection was still absent from it. The harness therefore waits before a
# collection that follows a taskkill closely. WAC itself must never flush: that
# would write to the examined machine's disk.
wait_registry_on_disk() {
  sleep 90
}
# The artefacts read in the hives whose witnesses the harness writes in the
# live registry: a --only cycle of one of them waits too. The witnesses of the
# third lot (installed_programs…) were absent from their collection without it.
REGISTRY_WITNESSES="run_keys shellbags persistence office_trust_records typed_paths word_wheel_query root_certificates internet_settings firewall installed_programs defender_configuration explorer_recent_docs mount_points program_usage network_shares rdp_client"
wants_registry_witness() { wants $REGISTRY_WITNESSES; }



# A `reg load` left mounted by an interrupted run locks the extracted hive.
$QGA run --shell "reg unload HKLM\\WAC_TEST >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true

# A 32-bit Windows (8 x86, XP) runs WAC32 and the 32-bit raw_hive_test, put
# under the usual names: every path of the harness stays the same.
BITS_SUFFIX=""
[[ "$($QGA run -- powershell.exe -NoProfile -Command '[IntPtr]::Size' 2>/dev/null | tr -d '\r')" == 4 ]] && BITS_SUFFIX=32
$QGA write "$ROOT/build-windows/WAC$BITS_SUFFIX.exe" "$VMDIR\\WAC.exe"
# No configuration file left by an earlier cycle: the runs below give their
# options, and must behave as without wac.yml (step 8 tests the file).
$QGA run --shell "del $VMDIR\\wac.yml 2>nul & exit /b 0" >/dev/null 2>&1 || true
# --only: every artefact of wac.yml switched off but those named. The keys come
# from the reference wac.yml, so that a new artefact is switched off too.
# --events would override `events: false`: it is given only when asked.
EVENTS_OPTION=--events
# Every wac.yml written below carries the version of the WAC under test: WAC
# refuses a file of another version (config.cpp).
WAC_VERSION="$("$ROOT/wac-version.sh")"
if [[ -n "$ONLY" ]]; then
  KEYS="$(sed -n '/^artefacts:/,/^[^ #]/s/^  \([a-z_]*\):.*/\1/p' "$ROOT/sources/wac.yml")"
  for k in ${ONLY//,/ }; do
    grep -qx "$k" <<<"$KEYS" || { echo "❌ --only: unknown artefact $k (keys: $(echo $KEYS))"; exit 2; }
  done
  { echo "# wac.yml of a --only cycle: $ONLY"; echo "wac_version: $WAC_VERSION"; echo "artefacts:"
    for k in $KEYS; do
      if [[ ",$ONLY," == *",$k,"* ]]; then echo "  $k: true"; else echo "  $k: false"; fi
    done; } > "$OUTPUT/wac-only.yml"
  [[ ",$ONLY," == *",events,"* ]] || EVENTS_OPTION=""
  $QGA write "$OUTPUT/wac-only.yml" "$VMDIR\\wac.yml" >/dev/null
  echo "   wac.yml: only $ONLY"
fi
full_cycle && $QGA write "$ROOT/build-windows/raw_hive_test$BITS_SUFFIX.exe" "$VMDIR\\raw_hive_test.exe"

# The trust set, as the analysis workstation prepares it before a collection:
# --update-trust, into `trust` next to WAC.exe, where the collection reads it.
# Here in the VM itself, which checks the download under Windows at each cycle.
if full_cycle; then
$QGA run --shell "cd /d $VMDIR && WAC.exe --update-trust > update-trust.log 2>&1" >/dev/null 2>&1 \
  && echo "   trust set prepared (--update-trust)" || echo "   ⚠️ trust set not prepared"
$QGA read "$VMDIR\\update-trust.log" "$OUTPUT/update-trust.log" >/dev/null 2>&1 || true
fi

# GUIDs the reference table does not know, one per source WAC reads them from
# (see register-test-guids.ps1): the names it prints are those check-json.py
# expects in ScheduledTasks.json.
mkdir -p "$OUTPUT/reference"
wants scheduled_tasks && $QGA write "$HERE/guest/register-test-guids.ps1" "$VMDIR\\register-test-guids.ps1" >/dev/null
if wants scheduled_tasks; then
  $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\register-test-guids.ps1" \
    > "$OUTPUT/reference/test-guids.txt" 2>/dev/null \
    && echo "   test GUIDs registered" || echo "   ⚠️ test GUIDs not registered"
fi

# The mail witness (B-017): no Outlook in the VM, so a PST of the public corpus
# sources/pst_fixtures.sh pins (EDRM Enron, CC-BY 3.0 US), placed once in the
# Outlook Files of "wac" — never piled up. check-json.py reads the same file
# with pypff (vmtest/tools/pff-venv) and confronts emails.json with it.
PST_WITNESS="$HERE/tools/pst-corpus/zl_south-s_000.pst"
PST_WITNESS_VM='C:\Users\wac\Documents\Outlook Files\wac-witness.pst'
if wants emails && [[ -f "$PST_WITNESS" ]]; then
  # PowerShell, not cmd: the folder's name has a space, which cmd's quoting
  # through the agent does not carry.
  if [[ "$($QGA run -- powershell.exe -NoProfile -Command "New-Item -ItemType Directory -Force 'C:\Users\wac\Documents\Outlook Files' | Out-Null; Test-Path '$PST_WITNESS_VM'" 2>/dev/null | tr -d '\r')" != True ]]; then
    $QGA write "$PST_WITNESS" "$PST_WITNESS_VM" >/dev/null && echo "   + mail witness placed (wac-witness.pst)"
  fi
  echo "pst=$PST_WITNESS_VM|$PST_WITNESS" > "$OUTPUT/reference/emails.txt"
fi

# Witnesses of the small file artefacts, placed before both collections: a
# PowerShell history, a file sent to the recycle bin, a hosts entry, a startup
# script, and the reference counts of setupapi and Defender (see
# place-file-artefacts.ps1). check-json.py finds them in the JSON.
$QGA write "$HERE/guest/place-file-artefacts.ps1" "$VMDIR\\place-file-artefacts.ps1" >/dev/null
$QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\place-file-artefacts.ps1" \
  ${ONLY:+-Only} ${ONLY:+$ONLY} > "$OUTPUT/reference/file-artefacts.txt" 2>/dev/null \
  && echo "   + reference/file-artefacts.txt" || echo "   ⚠️ file artefact witnesses not placed"
# taskkill again once the witnesses are placed: they take minutes (real
# browsing, an RDP session…), and the BAM check expects an execution within
# 300 s of the collection; Windows writes it to the disk within 56 to 82 s,
# hence the wait (and the registry witnesses' with it).
$QGA run --shell "taskkill /f /im WAC.exe >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
if wants_registry_witness; then wait_registry_on_disk; fi

if ! full_cycle; then
  echo "== 3. skipped (--only) == ($(date +%H:%M:%S))"
else
echo "== 3. raw_hive validation (raw extraction + reg load) == ($(date +%H:%M:%S))"
# Tested BOTH ways. A hive copied live is always "dirty":
#   - without --fix, `reg load` MUST refuse it (ERROR_BADDB): that is what proves
#     hive_recover is necessary, and not a luxury;
#   - with --fix, it MUST load.
# A test that fails by construction (which was the case here) ends up being
# ignored, which is worse than no test at all.
# `echo OK & ...` in cmd leaves the space before the `&` in the output: without
# cleaning, every exact comparison becomes a false negative.
clean() { tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

{
  $QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C \\Windows\\System32\\config\\SYSTEM $VMDIR\\SYSTEM_dirty.hiv > raw-dirty.log 2>&1" || true
  WITHOUT=$($QGA run --shell "reg load HKLM\\WAC_TEST $VMDIR\\SYSTEM_dirty.hiv >nul 2>&1 && (echo LOADED & reg unload HKLM\\WAC_TEST >nul) || echo REFUSED" 2>/dev/null | clean || true)
  if [[ "$WITHOUT" == "REFUSED" ]]; then
    echo "REG_LOAD_WITHOUT_PATCH=REFUSED (expected: the raw hive is dirty)"
  else
    echo "REG_LOAD_WITHOUT_PATCH=$WITHOUT (UNEXPECTED: the raw hive was already clean)"
  fi

  $QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C \\Windows\\System32\\config\\SYSTEM $VMDIR\\SYSTEM.hiv --fix > raw.log 2>&1" || true
  WITH=$($QGA run --shell "reg load HKLM\\WAC_TEST $VMDIR\\SYSTEM.hiv >nul 2>&1 && (echo OK & reg unload HKLM\\WAC_TEST >nul) || echo FAILED" 2>/dev/null | clean || true)
  echo "REG_LOAD_WITH_PATCH=$WITH"
  [[ "$WITH" == "OK" ]] || echo "   ❌ the patched hive stays unreadable: a regression of raw_hive or hive_recover"

  # Directory listing: the building block of ExtractDirectoryRaw.
  # The filtering is done on the host: a `findstr` on the guest side, in a pipe
  # passed to cmd /c, returned nothing while the command alone works.
  COUNT=$($QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C \\Windows\\Prefetch x --list 2>&1" 2>/dev/null \
       | grep -a '^Total:' | clean || true)
  echo "LIST_PREFETCH=${COUNT:-(no output)}"

  # The raw reading against Windows' own: the SHA-256 of a file extracted raw
  # must be the one Get-FileHash computes on the file. Chosen to cover the
  # ways a content is read: a small file, large binaries read by batches of
  # contiguous clusters, a WOF-compressed ("Compact OS") binary.
  for f in '\Windows\System32\drivers\etc\hosts' '\Windows\System32\ntoskrnl.exe' \
           '\Windows\System32\shell32.dll' '\Windows\explorer.exe'; do
    $QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C $f $VMDIR\\hashcheck.bin > nul 2>&1" >/dev/null 2>&1 || true
    SAME=$($QGA run -- powershell.exe -NoProfile -Command \
      "if ((Get-FileHash 'C:$f').Hash -eq (Get-FileHash '$VMDIR\\hashcheck.bin').Hash) { 'SAME' } else { 'DIFFERENT' }" 2>/dev/null | clean || true)
    echo "RAW_SHA256 $f=$SAME"
    [[ "$SAME" == "SAME" ]] || echo "   ❌ raw reading of $f differs from Windows' (Get-FileHash)"
  done
  # WOF's fourth algorithm, LZX, which Windows only uses on request: copies
  # compressed by Windows itself (compact /exe:lzx), read raw, must give
  # Get-FileHash's SHA-256 — the check of the LZX decoder on real data.
  $QGA run --shell "mkdir $VMDIR\\lzx 2>nul & copy /y C:\\Windows\\System32\\ntoskrnl.exe $VMDIR\\lzx\\ >nul & copy /y C:\\Windows\\System32\\shell32.dll $VMDIR\\lzx\\ >nul & copy /y C:\\Windows\\System32\\drivers\\etc\\services $VMDIR\\lzx\\services.txt >nul & compact /c /exe:lzx $VMDIR\\lzx\\ntoskrnl.exe $VMDIR\\lzx\\shell32.dll $VMDIR\\lzx\\services.txt >nul" >/dev/null 2>&1 || true
  for f in ntoskrnl.exe shell32.dll services.txt; do
    $QGA run --shell "cd /d $VMDIR && raw_hive_test.exe C \\wactest\\lzx\\$f $VMDIR\\hashcheck.bin > nul 2>&1" >/dev/null 2>&1 || true
    SAME=$($QGA run -- powershell.exe -NoProfile -Command \
      "if ((Get-FileHash '$VMDIR\\lzx\\$f').Hash -eq (Get-FileHash '$VMDIR\\hashcheck.bin').Hash) { 'SAME' } else { 'DIFFERENT' }" 2>/dev/null | clean || true)
    echo "RAW_SHA256_LZX $f=$SAME"
    [[ "$SAME" == "SAME" ]] || echo "   ❌ raw reading of the LZX-compressed $f differs from Windows' (Get-FileHash)"
  done
  $QGA run --shell "del $VMDIR\\hashcheck.bin 2>nul & echo." >/dev/null 2>&1 || true
} | tee "$OUTPUT/raw-validation.txt"
$QGA read "$VMDIR\\raw.log" "$OUTPUT/raw.log" >/dev/null 2>&1 || true
fi

if [[ $RAWONLY -eq 1 ]]; then
  echo "== Done (raw only). Results: $OUTPUT == ($(date +%H:%M:%S))"
  exit 0
fi

echo "== 4. Run of WAC (SYSTEM): collection, then its conversion == ($(date +%H:%M:%S))"
# WAC collects OR converts, never both (B-047): the collection into "out", then
# the conversion of "out" — run.log holds both, one after the other.
# --output must be a simple name (WAC refuses backslashes): created under cwd.
# A collection that stops midway still produces valid JSON files: the absence
# of JSON errors therefore does NOT prove that WAC went to the end.
# qga.py returns the guest command's exit code, which is checked.
CODE=0
# WAC's log is opened in APPEND mode: without a purge it grows from one test to
# the next (636 MiB seen after a series of runs), which makes fetching it
# useless and hides the traces of the current run.
$QGA run --shell "del $VMDIR\\WAC.exe.log 2>nul & echo." >/dev/null 2>&1 || true
# Removed through \\?\: the store holds paths past 260 characters (B-049), which
# rmdir leaves behind otherwise — WAC then refused the next collection
# (working folder not empty). split goes too, rebuilt at step 7: collected here
# (its unsigned scripts), it nested the previous cycle's stores one level deeper
# each cycle — the long-path witness is b049, made on purpose.
$QGA run --shell "cd /d $VMDIR && rmdir /s /q \\\\?\\$VMDIR\\out 2>nul & rmdir /s /q \\\\?\\$VMDIR\\split 2>nul & WAC.exe --collect --output=out $EVENTS_OPTION $BINARY_FLAG --loglevel=2 > run.log 2>&1" || CODE=$?
[[ "$CODE" == "0" ]] && { $QGA run --shell "cd /d $VMDIR && WAC.exe --convert=out $EVENTS_OPTION $BINARY_FLAG --loglevel=2 >> run.log 2>&1" || CODE=$?; }
$QGA read "$VMDIR\\run.log" "$OUTPUT/run.log" >/dev/null || echo "   ⚠️ run.log not fetched"

if [[ -f "$OUTPUT/run.log" ]] && grep -qaiE 'terminate called|Unhandled exception|Exception non gérée' "$OUTPUT/run.log"; then
    echo "   ❌ WAC ENDED ON AN EXCEPTION — incomplete collection:"
    grep -aiE -A2 'terminate called|Unhandled exception|Exception non gérée' "$OUTPUT/run.log" | sed 's/^/      /'
    ABNORMAL_STOP=1
elif [[ "$CODE" != "0" ]]; then
    echo "   ❌ WAC returned code $CODE — collection probably incomplete"
    ABNORMAL_STOP=1
else
    echo "   ✅ WAC went to the end (code $CODE)"
fi

# Fetches the JSON files of a WAC output folder of the VM, the exhibit manifest
# and its seal, and the list of the exhibit store.
#   $1 folder in the VM (under $VMDIR)   $2 folder on the host
fetch_results() {
  local vm="$VMDIR\\$1" host="$2" list="" attempt f
  mkdir -p "$host/exhibits"
  # The listing is retried: right after a long collection the guest agent has
  # once answered with an empty output while the JSON files were there, and the
  # whole run then looked like "no JSON produced".
  for attempt in 1 2 3; do
    list=$($QGA run --shell "dir /b $vm\\*.json 2>nul" || true)
    [[ -n "${list// }" ]] && break
    sleep 5
  done
  if [[ -z "${list// }" ]]; then
    echo "   ⚠️ no JSON produced in $1"
  else
    while read -r f; do
      f="${f%$'\r'}"; [[ -z "$f" ]] && continue
      $QGA read "$vm\\$f" "$host/$f" >/dev/null && echo "   + $f"
    done <<< "$list"
  fi
  # Exhibit manifest + its seal: small, and they are what identifies the exhibits.
  # Without them, check-json.py cannot check the exhibit store (the exhibits
  # themselves weigh hundreds of MiB and stay on the collection medium).
  for f in MANIFEST.json MANIFEST.sha256; do
    $QGA read "$vm\\exhibits\\$f" "$host/exhibits/$f" >/dev/null 2>&1 \
      && echo "   + exhibits/$f" || echo "   ⚠️ exhibits/$f not fetched"
  done
  # List of the files really present in the exhibit store: without it, nothing
  # checks that every exhibit is in the manifest. An exhibit added after the
  # sealing went unnoticed (121 event provider binaries).
  # Written to a file in the VM, then fetched: tens of thousands of lines
  # (--collect --binary) exceed what the guest agent returns as output — the
  # list came back empty, and every exhibit looked missing.
  # Listed by guest/list-tree.ps1 (FindFirstFileW on the \\?\ form): every
  # name as it is, and paths past MAX_PATH (B-049), on every Windows — the
  # script says why neither Get-ChildItem, dir nor robocopy does.
  $QGA write "$HERE/guest/list-tree.ps1" "$VMDIR\\list-tree.ps1" >/dev/null \
    && $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\list-tree.ps1" -Path "$vm\\exhibits" -Output "$VMDIR\\exhibit-list.txt" >/dev/null 2>&1 \
    && $QGA read "$VMDIR\\exhibit-list.txt" "$host/exhibits/LIST.txt" >/dev/null 2>&1 \
    && [[ -s "$host/exhibits/LIST.txt" ]] \
    && echo "   + exhibits/LIST.txt" || echo "   ⚠️ list of the exhibit store not read"
  # The browsers' History databases (with Favicons, the address bar's
  # predictor and the session files, B-048) and the Timeline's
  # ActivitiesCache.db, with their journals: a few hundred KiB to a few MiB, fetched so that
  # check-json.py reads them with Python's own SQLite and confronts
  # web_client.json and activities_cache.json with that independent reading.
  # grep finds nothing when no such database was collected (an --only cycle
  # without browsers nor Timeline): under pipefail that status ended the
  # whole harness before its checks — hence `|| true`.
  if [[ -s "$host/exhibits/LIST.txt" ]]; then
    tr -d '\r' < "$host/exhibits/LIST.txt" | { grep -E '\\User Data\\[^\\]+\\(History|Login Data|Network\\Cookies|Favicons|Network Action Predictor)(-journal|-wal)?$|\\User Data\\[^\\]+\\Sessions\\[^\\]+$|\\WebCache\\WebCacheV01\.dat$|\\Profiles\\[^\\]+\\(places|favicons)\.sqlite(-wal|-journal)?$|\\Profiles\\[^\\]+\\(sessionstore\.jsonlz4|sessionstore-backups\\[^\\]+)$|\\ConnectedDevicesPlatform\\[^\\]+\\ActivitiesCache\.db(-wal|-journal)?$' || true; } | while read -r f; do
      local relative="${f#*\\exhibits\\}"
      mkdir -p "$host/exhibits/$(dirname "${relative//\\//}")"
      $QGA read "$f" "$host/exhibits/${relative//\\//}" >/dev/null 2>&1 && echo "   + exhibits/${relative//\\//}" \
        || echo "   ⚠️ exhibits/${relative//\\//} not fetched"
    done
  fi  # The RDP bitmap caches as WAC read them — their working copy, not the
  # exhibit store (B-040) — and the tiles WAC exported, for check-json.py to
  # confront them with bmc-tools. None of them in an --only cycle without
  # rdp_client: PowerShell then ends in error, and without `|| true` that
  # status ended the whole harness before its checks.
  # The thumbnail of the B-026 witness, exported by WAC: only its own, out of
  # the thousands a cache holds. The working copy of Thunderbird's Inbox
  # (B-017), which check-json.py reads with Python's mailbox module. And the
  # working copies of the Prefetch files, which libscca reads below.
  local thumbnailId
  thumbnailId=$(sed -n 's/^thumbcache=\([0-9a-f]\{16\}\)|.*/\1/p' "$OUTPUT/reference/file-artefacts.txt" 2>/dev/null | tr -d '\r' | head -1)
  # Built apart: within ${thumbnailId:+…}, the "}" of a script block would end the expansion.
  local thumbnailQuery=""
  [[ -n "$thumbnailId" ]] && thumbnailQuery="; Get-ChildItem -LiteralPath '$vm\\thumbcache' -Recurse -Filter '$thumbnailId.*' -ErrorAction SilentlyContinue | Where-Object { -not \$_.PSIsContainer } | ForEach-Object { \$_.FullName }"
  local rdpFiles
  rdpFiles=$($QGA run -- powershell.exe -NoProfile -Command "Get-ChildItem -LiteralPath '$vm\\working\\Users' -Recurse -Force -Filter 'Cache*.bin' -ErrorAction SilentlyContinue | Where-Object { -not \$_.PSIsContainer } | Where-Object { \$_.FullName -like '*Terminal Server Client*' } | ForEach-Object { \$_.FullName }; Get-ChildItem -LiteralPath '$vm\\rdp_cache' -Recurse -Filter '*.bmp' -ErrorAction SilentlyContinue | Where-Object { -not \$_.PSIsContainer } | ForEach-Object { \$_.FullName }$thumbnailQuery; Get-ChildItem -LiteralPath '$vm\\working\\Users' -Recurse -Force -Filter 'Inbox' -ErrorAction SilentlyContinue | Where-Object { -not \$_.PSIsContainer } | Where-Object { \$_.FullName -like '*Thunderbird*' } | ForEach-Object { \$_.FullName }; Get-ChildItem -LiteralPath '$vm\\working\\Windows\\Prefetch' -Force -Filter '*.pf' -ErrorAction SilentlyContinue | ForEach-Object { \$_.FullName }" 2>/dev/null | tr -d '\r' || true)
  while read -r f; do
    [[ -z "$f" ]] && continue
    # The prefix quoted: unquoted, the backslashes of the VM's path are read as escapes.
    local relative="${f#"$vm"\\}"
    mkdir -p "$host/$(dirname "${relative//\\//}")"
    $QGA read "$f" "$host/${relative//\\//}" >/dev/null 2>&1 || echo "   ⚠️ ${relative//\\//} not fetched"
  done <<< "$rdpFiles"
  # libscca's reading of those Prefetch files (lib/prefetch-reference.py),
  # next to the JSON of the same collection: check-json.py confronts them.
  local scca="$HERE/tools/scca-venv/bin/python"
  if [[ -x "$scca" && -d "$host/working/Windows/Prefetch" ]]; then
    "$scca" -I "$HERE/lib/prefetch-reference.py" "$host/working/Windows/Prefetch" "$host/prefetch-libscca.txt" \
      && echo "   + prefetch-libscca.txt" || echo "   ⚠️ Prefetch not read by libscca"
  fi
}

echo "== 5. Fetch of the JSON files == ($(date +%H:%M:%S))"
fetch_results out "$OUTPUT"

# References read by Windows itself, for the cross-checks of check-json.py:
# the MountedDevices values through the live registry API (WAC reads them in
# the raw hive, with its own reader), and the partitions of the disks.
mkdir -p "$OUTPUT/reference"
# The version Windows gives of itself (B-039): its build, and whether it is a
# workstation (ProductType 1) — WAC reads both in the copied SOFTWARE hive.
$QGA run -- powershell.exe -NoProfile -Command \
  '"windows={0}|{1}" -f [Environment]::OSVersion.Version.Build, (Get-CimInstance Win32_OperatingSystem).ProductType' \
  2>/dev/null | tr -d '\r' > "$OUTPUT/reference/windows-version.txt" \
  && echo "   + reference/windows-version.txt" || echo "   ⚠️ Windows version reference not read"
# The shadow copies of C: Windows lists AFTER the collection: Windows deletes
# the oldest copy on its own when their space is full (VolSnap 33; Vista,
# measured: a copy listed before the collection was gone when WAC read the
# catalog). check-json.py expects the copies listed before and after.
if wants shadow_copies; then
$QGA run -- powershell.exe -NoProfile -Command \
  '$v = (Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter -eq "C:" }).DeviceID; Get-WmiObject Win32_ShadowCopy | Where-Object { $_.VolumeName -eq $v } | ForEach-Object { "shadowcopy_after=" + $_.ID }' \
  2>/dev/null | tr -d '\r' > "$OUTPUT/reference/shadow-copies-after.txt" \
  && echo "   + reference/shadow-copies-after.txt" || echo "   ⚠️ shadow copies not listed after the collection"
fi
if wants mounted_devices; then
$QGA run reg.exe query 'HKLM\SYSTEM\MountedDevices' > "$OUTPUT/reference/mounted-devices.txt" 2>/dev/null \
  && echo "   + reference/mounted-devices.txt" || echo "   ⚠️ MountedDevices reference not read"
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-Partition | ForEach-Object { "{0}|{1}|{2}|{3}" -f $_.DriveLetter, $_.Guid, $_.Offset, ($_.AccessPaths -join ";") }' \
  > "$OUTPUT/reference/partitions.txt" 2>/dev/null \
  && echo "   + reference/partitions.txt" || echo "   ⚠️ partitions reference not read"
fi

# WAC's replay of the hives' transaction logs against Windows' own recovery of
# the same files (hive-recovery-reference.ps1): on copies of the collection of
# step 4, loaded by Windows and walked whole — keys, values, and a digest of
# them all. The script works in a folder it removes, and is removed after.
if full_cycle; then
  $QGA write "$HERE/guest/hive-recovery-reference.ps1" "$VMDIR\\hive-recovery-reference.ps1" >/dev/null \
  && $QGA run --timeout 900 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\hive-recovery-reference.ps1" \
       -Collection "$VMDIR\\out" 2>/dev/null | tr -d '\r' > "$OUTPUT/reference/hive-recovery.txt" \
  && [[ -s "$OUTPUT/reference/hive-recovery.txt" ]] \
  && echo "   + reference/hive-recovery.txt" || echo "   ⚠️ hive recovery reference not read"
  $QGA run --shell "del /q $VMDIR\\hive-recovery-reference.ps1 >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
fi

# The number of firewall rules Windows holds, read again right after a
# collection: the one read when the witnesses were placed may have changed by
# then — a component adds a rule while the machine runs (509 at the witnesses,
# 510 at the collection, both right) — so the check accepts each count Windows
# gave around the collections.
record_firewall_count() {
  wants firewall || return 0
  local count
  count=$($QGA run -- powershell.exe -NoProfile -Command "(Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules').ValueCount" 2>/dev/null | tr -d '\r' || true)
  [[ "$count" =~ ^[0-9]+$ ]] && echo "fwcount=$count" >> "$OUTPUT/reference/file-artefacts.txt"
  return 0
}
record_firewall_count

# The TCP listeners as netstat gives them, right after the collection: a
# listening socket outlives it, so WAC's network state must hold the same
# address, port and owner (netstat formats through Winsock, WAC by itself).
if wants network; then
$QGA run -- netstat.exe -ano -p TCP > "$OUTPUT/reference/netstat-tcp.txt" 2>/dev/null \
  && $QGA run -- netstat.exe -ano -p TCPv6 >> "$OUTPUT/reference/netstat-tcp.txt" 2>/dev/null \
  && echo "   + reference/netstat-tcp.txt" || echo "   ⚠️ netstat reference not read"
fi

# USBSTOR dates as Windows gives them (UTC), and the PE header timestamps of
# the executables of System32, for the dates of USBSTOR and of Amcache.
if wants usbstor amcache; then
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like "USBSTOR*" } | ForEach-Object { $i = $_.InstanceId; foreach ($k in "DEVPKEY_Device_InstallDate", "DEVPKEY_Device_LastArrivalDate") { $p = Get-PnpDeviceProperty -InstanceId $i -KeyName $k; if ($p.Data) { "{0}|{1}|{2}" -f $i, $k, $p.Data.ToUniversalTime().ToString("o") } } }' \
  > "$OUTPUT/reference/usbstor.txt" 2>/dev/null \
  && echo "   + reference/usbstor.txt" || echo "   ⚠️ USBSTOR reference not read"
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { try { $f = [IO.File]::OpenRead($_.FullName); $b = New-Object byte[] 1024; [void]$f.Read($b, 0, 1024); $f.Close(); $pe = [BitConverter]::ToInt32($b, 0x3C); if ($pe -gt 0 -and $pe -lt 1016) { "{0}|{1}" -f $_.FullName.ToLower(), [BitConverter]::ToUInt32($b, $pe + 8) } } catch {} }' \
  > "$OUTPUT/reference/pe-timestamps.txt" 2>/dev/null \
  && echo "   + reference/pe-timestamps.txt" || echo "   ⚠️ PE timestamps reference not read"
# SHA-1, size and version of the same executables: Amcache's FileId must hold
# the SHA-1 of the files it inventoried and that did not change since — of
# their first 30 MiB only, as Amcache hashes them (measured on mrt.exe).
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { $f = [IO.File]::OpenRead($_.FullName); $b = New-Object byte[] ([Math]::Min($_.Length, 31457280)); $n = 0; while ($n -lt $b.Length) { $r = $f.Read($b, $n, $b.Length - $n); if ($r -le 0) { break }; $n += $r }; $f.Close(); "{0}|{1}|{2}|{3}" -f $_.FullName.ToLower(), ([BitConverter]::ToString([Security.Cryptography.SHA1]::Create().ComputeHash($b, 0, $n))).Replace("-", "").ToLower(), $_.Length, $_.VersionInfo.FileVersionRaw }' \
  > "$OUTPUT/reference/sha1-system32.txt" 2>/dev/null \
  && echo "   + reference/sha1-system32.txt" || echo "   ⚠️ SHA-1 reference not read"
fi
# The build of each executable of System32 — TimeDateStamp and SizeOfImage,
# the key of Microsoft's symbol server — as read in its header by PowerShell.
if full_cycle; then
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { try { $f = [IO.File]::OpenRead($_.FullName); $b = New-Object byte[] 1024; [void]$f.Read($b, 0, 1024); $f.Close(); $pe = [BitConverter]::ToInt32($b, 0x3C); if ($pe -gt 0 -and $pe -lt 940) { "{0}|{1:X8}|{2:x}" -f $_.FullName.ToLower(), [BitConverter]::ToUInt32($b, $pe + 8), [BitConverter]::ToUInt32($b, $pe + 80) } } catch {} }; exit 0' \
  > "$OUTPUT/reference/pe-build.txt" 2>/dev/null \
  && echo "   + reference/pe-build.txt" || echo "   ⚠️ PE build reference not read"
fi

# The last write of each Prefetch file as Windows gives it, for the dates of
# the file artefacts (WAC reads them in the manifest, from the raw $MFT), and
# when Windows was asked (taken|).
if wants prefetch; then
$QGA run -- powershell.exe -NoProfile -Command \
  '"taken|{0}" -f [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ"); Get-ChildItem C:\Windows\Prefetch\*.pf | ForEach-Object { "{0}|{1}" -f $_.Name, $_.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }' \
  > "$OUTPUT/reference/prefetch-times.txt" 2>/dev/null \
  && echo "   + reference/prefetch-times.txt" || echo "   ⚠️ Prefetch times reference not read"
fi

# Local accounts and groups as Windows names them, for the offline naming of
# the SIDs (WAC reads them in the SAM; Windows through its account API —
# through WMI before Windows 10, which has no Get-LocalUser).
if wants users local_groups; then
$QGA run -- powershell.exe -NoProfile -Command \
  '[Console]::OutputEncoding = [Text.Encoding]::UTF8; if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) { Get-LocalUser | ForEach-Object { "{0}|{1}" -f $_.SID, $_.Name }; Get-LocalGroup | ForEach-Object { "{0}|{1}" -f $_.SID, $_.Name } } else { Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object { "{0}|{1}" -f $_.SID, $_.Name }; Get-CimInstance Win32_Group -Filter "LocalAccount=True" | ForEach-Object { "{0}|{1}" -f $_.SID, $_.Name } }' \
  > "$OUTPUT/reference/accounts.txt" 2>/dev/null \
  && echo "   + reference/accounts.txt" || echo "   ⚠️ accounts reference not read"
fi

# The message Windows itself renders (EvtFormatMessage) for each kind of
# event of the machine, the reference of events.json's messages (B-023). The
# script only reads the logs; its output is fetched, then removed from the VM.
if wants events; then
  $QGA write "$HERE/guest/event-messages-reference.ps1" "$VMDIR\\event-messages-reference.ps1" >/dev/null \
  && $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\event-messages-reference.ps1" -Output "$VMDIR\\event-messages.txt" >/dev/null 2>&1 \
  && $QGA read "$VMDIR\\event-messages.txt" "$OUTPUT/reference/event-messages.txt" >/dev/null 2>&1 \
  && echo "   + reference/event-messages.txt" || echo "   ⚠️ event messages reference not read"
  $QGA run --shell "del /q $VMDIR\\event-messages.txt $VMDIR\\event-messages-reference.ps1 >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
fi

echo "== 6. JSON validity check == ($(date +%H:%M:%S))"
python3 "$HERE/lib/check-json.py" "$OUTPUT" || echo "   ⚠️ some JSON files are invalid (see above)"

if [[ $SPLIT -eq 1 ]]; then
  echo "== 7. Collection (--collect), then conversion (--convert) == ($(date +%H:%M:%S))"
  # The same VM plays both roles; what is checked is what the separation must
  # guarantee:
  #   - the collection converts nothing, and seals its exhibit store;
  #   - the conversion refuses a retouched exhibit, and says why;
  #   - the JSON of the conversion pass the same checks as those of step 4;
  #   - two conversions of one collection give the same JSON (determinism).
  SPLIT_OUT="$OUTPUT/split"
  # Runs WAC in the VM. $1 name of its console log, then its arguments.
  run_wac() {
    local label="$1" code=0; shift
    $QGA run --shell "cd /d $VMDIR && WAC.exe $* > $label.log 2>&1" || code=$?
    $QGA read "$VMDIR\\$label.log" "$OUTPUT/$label.log" >/dev/null 2>&1 || true
    return $code
  }
  json_count() { $QGA run --shell "dir /b $VMDIR\\split\\*.json 2>nul" 2>/dev/null | grep -c '\.json' || true; }

  $QGA run --shell "cd /d $VMDIR && rmdir /s /q \\\\?\\$VMDIR\\split 2>nul & echo." >/dev/null
  if full_cycle; then
  # A copy of a signed Store package with one untouched, one modified and one
  # intruding script: the package verification must tell them apart.
  $QGA write "$HERE/guest/make-fake-package.ps1" "$VMDIR\\make-fake-package.ps1" >/dev/null
  $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\make-fake-package.ps1" \
    > "$OUTPUT/reference/fake-package.txt" 2>/dev/null \
    && echo "   + reference/fake-package.txt" || echo "   ⚠️ copy of a Store package not prepared"
  # A script whose dates are forged back to 2001, as an intruder would
  # ("timestomping"): SetFileTime changes $STANDARD_INFORMATION only, and the
  # manifest must show both sets — 2001, and the real creation in $FILE_NAME.
  $QGA run -- powershell.exe -NoProfile -Command \
    '$d = "C:\wactest\stomped"; New-Item -ItemType Directory -Force $d | Out-Null; $f = "$d\stomped.ps1"; Set-Content $f "# timestomping test"; $t = [datetime]"2001-01-01T00:00:00Z"; (Get-Item $f).CreationTimeUtc = $t; (Get-Item $f).LastWriteTimeUtc = $t; (Get-Item $f).LastAccessTimeUtc = $t; $f' \
    > "$OUTPUT/reference/stomped.txt" 2>/dev/null \
    && echo "   + reference/stomped.txt" || echo "   ⚠️ timestomped file not prepared"

  # A macro document of the user, as an intruder would leave one: no
  # Microsoft catalog can list it, so --collect --binary must collect it.
  $QGA run -- powershell.exe -NoProfile -Command \
    '$f = "C:\Users\wac\Documents\wac-macro-test.docm"; Set-Content $f "PK wac macro document test $(Get-Date -Format o)"; $f' \
    > "$OUTPUT/reference/macro-document.txt" 2>/dev/null \
    && echo "   + reference/macro-document.txt" || echo "   ⚠️ macro document not prepared"
  # A VULNERABLE DRIVER, as an intruder brings one to open the kernel (BYOVD):
  # EVGA's, signed and genuine — its chain holds —, listed by LOLDrivers and
  # Microsoft. Only copied, never loaded. The collection must not clear it.
  # Fetched once from LOLDrivers, checked by its SHA-256; Defender may remove
  # it from the VM, the check then says so.
  VULN_SHA256=33da2ce240b4559cc6e847d56c5fbeaa3d644ec160841920ea0a098dcee28d0e
  VULN_CACHE="$HOME/.cache/wac-test/evga_kernel_driver-x64.sys"
  if [[ ! -f "$VULN_CACHE" ]]; then
    mkdir -p "$(dirname "$VULN_CACHE")"
    curl -sSfL --max-time 60 -o "$VULN_CACHE.part" \
      "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/8dc9504fb5eda1a354971bacffe61ccc.bin" \
      && mv "$VULN_CACHE.part" "$VULN_CACHE" || rm -f "$VULN_CACHE.part"
  fi
  if [[ -f "$VULN_CACHE" ]] && echo "$VULN_SHA256  $VULN_CACHE" | sha256sum -c --status; then
    $QGA run --shell "mkdir C:\\wactest\\vuln 2>nul & echo." >/dev/null 2>&1 || true
    $QGA write "$VULN_CACHE" "C:\\wactest\\vuln\\evga_kernel_driver-x64.sys" >/dev/null \
      && echo 'C:\wactest\vuln\evga_kernel_driver-x64.sys' > "$OUTPUT/reference/vulnerable-driver.txt" \
      && echo "   + reference/vulnerable-driver.txt" || echo "   ⚠️ vulnerable driver not placed"
  else
    echo "   ⚠️ vulnerable driver sample not obtained: its check will be skipped"
  fi

  fi

  # taskkill just before the collection, as in step 2: the BAM check expects
  # its execution within minutes of the collection, and the references above
  # take several. In step 2 the upload and the raw validation leave Windows the
  # time to write it; here the collection follows at once.
  $QGA run --shell "taskkill /f /im WAC.exe >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
  wants_registry_witness && wait_registry_on_disk

  # HARMLESSNESS: witness files the collection is bound to read (--binary
  # collects the macro document and the script) keep their dates and their
  # USN — WAC reads the volume raw, never through the file. Recorded by
  # harmlessness.ps1 before and after; see doc/harmlessness.
  WITNESSES=('C:\Users\wac\Documents\wac-macro-test.docm' 'C:\wactest\stomped\stomped.ps1')
  $QGA write "$HERE/guest/harmlessness.ps1" "$VMDIR\\harmlessness.ps1" >/dev/null
  witness_state() {
    $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\harmlessness.ps1" \
      "${WITNESSES[@]}" 2>/dev/null | tr -d '\r'
  }
  full_cycle && WITNESS_BEFORE=$(witness_state)

  if run_wac collect --collect --output=split $EVENTS_OPTION $BINARY_OPTION --loglevel=2; then
    record_firewall_count
    echo "   ✅ collection went to the end"
  else
    echo "   ❌ collection ended abnormally"; ABNORMAL_STOP=1
  fi

  if full_cycle; then
  WITNESS_AFTER=$(witness_state)
  # The check must be able to fail: the script, read once through Windows,
  # must show a new access date — its own, forged to 2001, is older than the
  # hour below which NTFS does not update it. Where the volume keeps no access
  # date (fsutil behavior disablelastaccess), the control says so.
  $QGA run -- powershell.exe -NoProfile -Command 'Get-Content -LiteralPath C:\wactest\stomped\stomped.ps1 | Out-Null' >/dev/null 2>&1 || true
  WITNESS_CONTROL=$(witness_state | sed -n 2p)
  {
    echo "== before the collection"; echo "$WITNESS_BEFORE"
    echo "== after the collection";  echo "$WITNESS_AFTER"
    echo "== after one read of the script through Windows (control)"; echo "$WITNESS_CONTROL"
    echo "== fsutil behavior query disablelastaccess"
    $QGA run --shell "fsutil behavior query disablelastaccess" 2>/dev/null | tr -d '\r'
  } > "$OUTPUT/harmlessness.txt"
  if [[ -z "$WITNESS_BEFORE" ]] || grep -q '|absent$' <<<"$WITNESS_BEFORE" \
     || [[ $(grep -c . <<<"$WITNESS_BEFORE") -ne ${#WITNESSES[@]} ]]; then
    echo "   ❌ harmlessness: witness files not recorded (see harmlessness.txt)"
  elif [[ "$WITNESS_BEFORE" == "$WITNESS_AFTER" ]]; then
    echo "   ✅ harmlessness: ${#WITNESSES[@]} witness file(s) read by the collection, dates and USN unchanged"
  else
    echo "   ❌ harmlessness: a witness file changed during the collection (see harmlessness.txt)"
  fi
  if [[ "$WITNESS_CONTROL" != "$(sed -n 2p <<<"$WITNESS_AFTER")" ]]; then
    echo "   ✅ harmlessness control: one read through Windows changes the script's access date"
  else
    echo "   ⚠️ harmlessness control: a read through Windows changed nothing (access dates not kept?): the check proves the USN only"
  fi
  fi
  N_JSON=$(json_count)
  [[ "$N_JSON" == "1" ]] && echo "   ✅ collection: investigation.json only, nothing converted" \
                         || echo "   ❌ collection: $N_JSON JSON file(s) written, 1 expected"

  if full_cycle; then
  # Independent reference for the completeness of the collection: the
  # executables of System32 and SysWOW64 as Windows lists them.
  $QGA run -- powershell.exe -NoProfile -Command \
    '[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-ChildItem C:\Windows\System32, C:\Windows\SysWOW64 -Recurse -Force -Include *.exe, *.dll, *.sys -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName }; exit 0' \
    > "$OUTPUT/reference/executables.txt" 2>/dev/null \
    && echo "   + reference/executables.txt" || echo "   ⚠️ executables reference not read"

  # Windows' own verdict on the signatures of System32's executables, for the
  # executables WAC authenticates in memory and does not copy, with the
  # catalog Windows finds for those it does not call Valid
  # (authenticode-reference.ps1, removed after).
  $QGA write "$HERE/guest/authenticode-reference.ps1" "$VMDIR\\authenticode-reference.ps1" >/dev/null \
  && $QGA run --timeout 900 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\authenticode-reference.ps1" \
    > "$OUTPUT/reference/authenticode.txt" 2>/dev/null \
    && echo "   + reference/authenticode.txt" || echo "   ⚠️ authenticode reference not read"
  $QGA run --shell "del /q $VMDIR\\authenticode-reference.ps1 >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true

  fi

  if full_cycle; then
  # The verification script shipped with the documentation, on this
  # collection: seal and every exhibit, the fingerprint-only ones apart.
  $QGA write "$ROOT/sources/scripts/verify-exhibits.ps1" "$VMDIR\\verify-exhibits.ps1" >/dev/null
  code=0
  $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\verify-exhibits.ps1" \
       -Output "$VMDIR\\split" > "$OUTPUT/verify-exhibits.log" 2>&1 || code=$?
  if [[ $code -eq 0 ]]; then
    echo "   ✅ verify-exhibits.ps1: $(grep -a 'verified,' "$OUTPUT/verify-exhibits.log" | tr -d '\r')"
  elif [[ $code -eq 2 ]]; then
    # PowerShell older than 4 (Windows 7): the script says so and stops.
    echo "   ⏭️  verify-exhibits.ps1 not run here: $(tail -1 "$OUTPUT/verify-exhibits.log" | tr -d '\r')"
  else
    echo "   ❌ verify-exhibits.ps1 refuses the collection: $(tail -3 "$OUTPUT/verify-exhibits.log" | tr -d '\r')"
  fi
  fi

  if full_cycle; then
  # Windows' reading of the embedded signatures of third-party binaries, for
  # the signer and the integrity WAC records of those it collects.
  $QGA run -- powershell.exe -NoProfile -Command \
    '[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-ChildItem "C:\Program Files\Qemu-ga", "C:\Program Files\Virtio-Win" -Recurse -Include *.exe, *.dll, *.sys -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $s = Get-AuthenticodeSignature $_.FullName; "{0}|{1}|{2}" -f $_.FullName, $s.Status, $s.SignerCertificate.Subject }; exit 0' \
    > "$OUTPUT/reference/third-party-signatures.txt" 2>/dev/null \
    && echo "   + reference/third-party-signatures.txt" || echo "   ⚠️ third-party signatures reference not read"

  # A retouched snapshot: one byte appended. The conversion must refuse it.
  LIVE="$VMDIR\\split\\exhibits\\live\\system-clock.json"
  $QGA run --shell "copy /y $LIVE $VMDIR\\clock.bak >nul & echo x>> $LIVE" >/dev/null
  if run_wac convert-tampered --convert=split $EVENTS_OPTION $BINARY_FLAG; then
    echo "   ❌ conversion of a retouched collection ACCEPTED"
  elif [[ "$(json_count)" == "2" ]] && grep -qa "no longer match" "$OUTPUT/convert-tampered.log"; then
    echo "   ✅ retouched exhibit refused, before any conversion, with its reason"
  else
    echo "   ❌ retouched exhibit refused, but without conversion.json or its reason"
  fi
  $QGA run --shell "copy /y $VMDIR\\clock.bak $LIVE >nul & del $VMDIR\\clock.bak & del $VMDIR\\split\\conversion.json" >/dev/null

  fi

  # Windows' audit of the reads of the exhibit store around the conversion
  # (B-040): it may read the store to check and copy it, never afterwards.
  $QGA write "$HERE/guest/exhibit-read-audit.ps1" "$VMDIR\\exhibit-read-audit.ps1" >/dev/null
  # A failed start must not end the harness (set -e): said below, and the
  # audit it may have switched on is switched off again.
  AUDIT_SINCE=$($QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\exhibit-read-audit.ps1" -Start "$VMDIR\\split\\exhibits" 2>/dev/null | tr -d '\r' | tail -1 || true)
  [[ "$AUDIT_SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] || AUDIT_SINCE=""
  if run_wac convert --convert=split $EVENTS_OPTION $BINARY_FLAG --loglevel=2; then
    echo "   ✅ conversion went to the end"
  else
    echo "   ❌ conversion ended abnormally"; ABNORMAL_STOP=1
  fi
  # The reads concern the separate collection: the reference goes with its
  # results only, where conversion.json is the one of that conversion — in
  # the main folder, a later run of check-json.py would set them against the
  # main conversion's copy time, and count them all as "after".
  if [[ -n "$AUDIT_SINCE" ]]; then
    mkdir -p "$SPLIT_OUT/reference"
    $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\exhibit-read-audit.ps1" -Stop "$VMDIR\\split\\exhibits" -Since "$AUDIT_SINCE" -Output "$VMDIR\\exhibit-reads.txt" >/dev/null 2>&1 \
      && $QGA read "$VMDIR\\exhibit-reads.txt" "$SPLIT_OUT/reference/exhibit-reads.txt" >/dev/null 2>&1 \
      && echo "   + reference/exhibit-reads.txt" || echo "   ⚠️ reads of the exhibit store not listed"
  else
    echo "   ⚠️ read audit of the exhibit store not set"
    $QGA run --shell "auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:disable >nul" >/dev/null 2>&1 || true
  fi
  $QGA run --shell "del /q $VMDIR\\exhibit-reads.txt $VMDIR\\exhibit-read-audit.ps1 >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
  fetch_results split "$SPLIT_OUT"
  cp -r "$OUTPUT/reference" "$SPLIT_OUT/"
  # The copies Windows lists after THIS collection: it may have deleted the
  # oldest since the first one (VolSnap 33; Windows 7, measured).
  if wants shadow_copies; then
    $QGA run -- powershell.exe -NoProfile -Command \
      '$v = (Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter -eq "C:" }).DeviceID; Get-WmiObject Win32_ShadowCopy | Where-Object { $_.VolumeName -eq $v } | ForEach-Object { "shadowcopy_after=" + $_.ID }' \
      2>/dev/null | tr -d '\r' > "$SPLIT_OUT/reference/shadow-copies-after.txt" || true
  fi
  echo "   -- checks of the converted JSON --"
  python3 "$HERE/lib/check-json.py" "$SPLIT_OUT" || echo "   ⚠️ the converted JSON fail some checks (see above)"

  if full_cycle; then
  if run_wac convert-again --convert=split $EVENTS_OPTION $BINARY_FLAG --loglevel=2; then
    AGAIN="$OUTPUT/split-again"
    fetch_results split "$AGAIN" >/dev/null
    # conversion.json is the log of each conversion: its times differ by nature.
    DIFFERENT=$(cd "$SPLIT_OUT" && for f in *.json; do
                  [[ "$f" == "conversion.json" ]] && continue
                  cmp -s "$f" "$AGAIN/$f" || echo "$f"
                done)
    [[ -z "$DIFFERENT" ]] && echo "   ✅ second conversion: identical JSON (deterministic)" \
                          || echo "   ❌ second conversion differs: $(echo $DIFFERENT)"
  else
    echo "   ❌ second conversion ended abnormally"
  fi
  fi
fi

if [[ -n "$ONLY" ]]; then
  echo "== 8. skipped (--only) == ($(date +%H:%M:%S))"
  $QGA run --shell "del $VMDIR\\wac.yml 2>nul & exit /b 0" >/dev/null 2>&1 || true
else
echo "== 8. Collection driven by wac.yml, without any option == ($(date +%H:%M:%S))"
# The procedure written in wac.yml next to WAC.exe, and WAC.exe run alone: the
# collection must follow the file — nothing converted, no binaries, some artefacts
# switched off — and record it (investigation.json, Tool.Configuration).
CONFIG_OUT="$OUTPUT/configured"
cat > "$OUTPUT/wac.yml" <<YML
# wac.yml of the test cycle
wac_version: $WAC_VERSION
binary: none
output: configured
artefacts:
  events: false
  rdp_server: false
  amcache: false
  registry_backups: false
  prefetch: false
  sessions: false
  network: false
  jump_lists: false
YML
$QGA write "$OUTPUT/wac.yml" "$VMDIR\\wac.yml" >/dev/null
$QGA run --shell "cd /d $VMDIR && rmdir /s /q \\\\?\\$VMDIR\\configured 2>nul & WAC.exe > configured.log 2>&1" \
  && echo "   ✅ collection driven by wac.yml went to the end" || echo "   ❌ collection driven by wac.yml ended abnormally"
$QGA read "$VMDIR\\configured.log" "$OUTPUT/configured.log" >/dev/null 2>&1 || true
$QGA run --shell "del $VMDIR\\wac.yml 2>nul & exit /b 0" >/dev/null 2>&1 || true
fetch_results configured "$CONFIG_OUT" >/dev/null
python3 "$HERE/lib/check-json.py" --configuration "$CONFIG_OUT" || echo "   ⚠️ the configured collection fails its checks (see above)"
fi

if full_cycle || wants hosts; then
echo "== 9. A source every Windows has, removed: expected but missing == ($(date +%H:%M:%S))"
# The hosts file is on every installation, and Windows goes on without it:
# moved aside the time of one collection, it must come out "ExpectedButMissing"
# — not "not collected", not an empty array. Only hosts is asked for, so the
# collection takes a few seconds. The file is put back right after the
# collection, and first of all if an interrupted cycle left it aside.
HOSTS='C:\Windows\System32\drivers\etc\hosts'
restore_hosts() { $QGA run --shell "if exist $VMDIR\\hosts.aside (if not exist $HOSTS move /y $VMDIR\\hosts.aside $HOSTS >nul) & if exist $HOSTS (exit /b 0) else (exit /b 1)" >/dev/null 2>&1; }
restore_hosts || echo "   ❌ hosts file absent before the test, and no copy to put back"
MISSING_OUT="$OUTPUT/missing"
{ echo "# wac.yml of the expected-but-missing test"; echo "wac_version: $WAC_VERSION"; echo "binary: none"
  echo "output: missing"; echo "artefacts:"
  for k in $(sed -n '/^artefacts:/,/^[^ #]/s/^  \([a-z_]*\):.*/\1/p' "$ROOT/sources/wac.yml"); do
    if [[ "$k" == hosts ]]; then echo "  $k: true"; else echo "  $k: false"; fi
  done; } > "$OUTPUT/wac-missing.yml"
$QGA write "$OUTPUT/wac-missing.yml" "$VMDIR\\wac.yml" >/dev/null
CODE=0
$QGA run --shell "cd /d $VMDIR && rmdir /s /q \\\\?\\$VMDIR\\missing 2>nul & move /y $HOSTS $VMDIR\\hosts.aside >nul && WAC.exe > missing.log 2>&1" || CODE=$?
restore_hosts && echo "   ✅ hosts file put back" || echo "   ❌ hosts file NOT put back: $VMDIR\\hosts.aside"
if [[ "$CODE" == "0" ]]; then
  $QGA run --shell "cd /d $VMDIR && WAC.exe --convert=missing >> missing.log 2>&1" || CODE=$?
fi
[[ "$CODE" == "0" ]] && echo "   ✅ collection without hosts, then conversion, went to the end" \
                     || echo "   ❌ collection without hosts, or its conversion, ended abnormally (code $CODE)"
$QGA read "$VMDIR\\missing.log" "$OUTPUT/missing.log" >/dev/null 2>&1 || true
$QGA run --shell "del $VMDIR\\wac.yml 2>nul & exit /b 0" >/dev/null 2>&1 || true
fetch_results missing "$MISSING_OUT" >/dev/null
mkdir -p "$MISSING_OUT/reference" && cp "$OUTPUT/reference/windows-version.txt" "$MISSING_OUT/reference/" 2>/dev/null || true
python3 "$HERE/lib/check-json.py" --expected-missing "$MISSING_OUT" || echo "   ⚠️ the expected-but-missing test fails its checks (see above)"
$QGA run --shell "rmdir /s /q \\\\?\\$VMDIR\\missing 2>nul & del $VMDIR\\missing.log 2>nul & exit /b 0" >/dev/null 2>&1 || true
fi

echo
if [[ "${ABNORMAL_STOP:-0}" == "1" ]]; then
  echo "== ⚠️ ABNORMAL STOP OF WAC: the JSON files above are PARTIAL == ($(date +%H:%M:%S))"
fi
echo "== Results on the host: $OUTPUT == ($(date +%H:%M:%S))"
ls -la "$OUTPUT" | awk 'NR>1{print "   "$NF"  "$5" B"}'
