#!/usr/bin/env bash
# run-wac-test.sh — a fully autonomous WAC test cycle in the Windows VM.
#
# Chains, with no interaction at all: build (optional) -> upload of the binaries
# into the VM -> run of WAC as SYSTEM (admin rights, no UAC) -> fetch of the log
# and of the JSON files onto the host for inspection.
#
# Prerequisite: qemu-guest-agent installed and answering in the VM (`qga.py ping`).
# Usage: ./run-wac-test.sh [--build] [--raw-only]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
QGA="python3 $HERE/qga.py"
VMDIR='C:\wactest'
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT="$HERE/results/$STAMP"
mkdir -p "$OUTPUT"

BUILD=0; RAWONLY=0; SPLIT=1; BINARY_OPTION=--binary
for a in "$@"; do
  [[ "$a" == "--build"    ]] && BUILD=1
  [[ "$a" == "--raw-only" ]] && RAWONLY=1
  [[ "$a" == "--no-split" ]] && SPLIT=0
  # Step 7 with --binary-all: every executable copied, verdict recorded.
  [[ "$a" == "--binary-all" ]] && BINARY_OPTION=--binary-all
done

echo "== 0. Agent =="
$QGA ping

echo "== 0b. USB key =="
# A virtual USB key, attached on every run, so that USBSTOR is populated on any
# test VM — including one recreated from scratch by create-vm.sh — and the USB
# artefacts are checked on every cycle. Attached live only: the VM definition
# is left unchanged, and a VM restart simply gets it attached again here.
DOM="${WAC_VM:-win11-test}"
CONN="qemu:///session"
USB_IMG="${WAC_USB_IMG:-$HOME/vms/wac-usb-test.img}"
mkdir -p "$(dirname "$USB_IMG")"
[[ -f "$USB_IMG" ]] || truncate -s 64M "$USB_IMG"
if ! virsh -c "$CONN" domblklist "$DOM" 2>/dev/null | grep -qF "$USB_IMG"; then
  USB_XML="$(mktemp)"
  cat > "$USB_XML" <<EOF
<disk type='file' device='disk'>
  <driver name='qemu' type='raw'/>
  <source file='$USB_IMG'/>
  <target dev='sdz' bus='usb' removable='on'/>
  <serial>WACUSB0001</serial>
</disk>
EOF
  virsh -c "$CONN" attach-device "$DOM" "$USB_XML" --live >/dev/null && echo "   USB key WACUSB0001 attached"
  rm -f "$USB_XML"
fi
# Windows installs the device asynchronously: wait until it is enumerated.
for attempt in $(seq 1 30); do
  N_USB=$($QGA run -- powershell.exe -NoProfile -Command \
    '(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object InstanceId -like "USBSTOR*WACUSB0001*" | Measure-Object).Count' \
    2>/dev/null | tr -d '\r\n ' || true)
  [[ "${N_USB:-0}" =~ ^[1-9] ]] && { echo "   USB key known to Windows"; break; }
  sleep 2
done

if [[ $BUILD -eq 1 ]]; then
  echo "== 1. Build (Linux cross-compilation) =="
  "$ROOT/build-windows.sh" --test >/dev/null
  echo "   WAC.exe + raw_hive_test.exe rebuilt"
fi

echo "== 2. Upload of the binaries into the VM =="
$QGA run --shell "if not exist $VMDIR mkdir $VMDIR" >/dev/null

# A previous run that was interrupted (Ctrl+C on the host, stuck collection,
# crash) leaves WAC.exe running in the VM. Windows then locks the file and the
# upload fails — and every following test fails until a manual clean-up.
# The leftover binaries are therefore ended before writing, silently when there
# are none.
for exe in WAC.exe raw_hive_test.exe; do
  $QGA run --shell "taskkill /f /im $exe >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
done
# A `reg load` left mounted by an interrupted run locks the extracted hive.
$QGA run --shell "reg unload HKLM\\WAC_TEST >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true

$QGA write "$ROOT/build-windows/WAC.exe"           "$VMDIR\\WAC.exe"
$QGA write "$ROOT/build-windows/raw_hive_test.exe" "$VMDIR\\raw_hive_test.exe"

# GUIDs the reference table does not know, one per source WAC reads them from
# (see register-test-guids.ps1): the names it prints are those check-json.py
# expects in ScheduledTasks.json.
mkdir -p "$OUTPUT/reference"
$QGA write "$HERE/register-test-guids.ps1" "$VMDIR\\register-test-guids.ps1" >/dev/null
$QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\register-test-guids.ps1" \
  > "$OUTPUT/reference/test-guids.txt" 2>/dev/null \
  && echo "   test GUIDs registered" || echo "   ⚠️ test GUIDs not registered"

echo "== 3. raw_hive validation (raw extraction + reg load) =="
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
  $QGA run --shell "del $VMDIR\\hashcheck.bin 2>nul & echo." >/dev/null 2>&1 || true
} | tee "$OUTPUT/raw-validation.txt"
$QGA read "$VMDIR\\raw.log" "$OUTPUT/raw.log" >/dev/null 2>&1 || true

if [[ $RAWONLY -eq 1 ]]; then
  echo "== Done (raw only). Results: $OUTPUT =="
  exit 0
fi

echo "== 4. Run of WAC (SYSTEM) =="
# --output must be a simple name (WAC refuses backslashes): created under cwd.
# A collection that stops midway still produces valid JSON files: the absence
# of JSON errors therefore does NOT prove that WAC went to the end.
# qga.py returns the guest command's exit code, which is checked.
CODE=0
# WAC's log is opened in APPEND mode: without a purge it grows from one test to
# the next (636 MiB seen after a series of runs), which makes fetching it
# useless and hides the traces of the current run.
$QGA run --shell "del $VMDIR\\WAC.exe.log 2>nul & echo." >/dev/null 2>&1 || true
$QGA run --shell "cd /d $VMDIR && rmdir /s /q out 2>nul & WAC.exe --output=out --events --binary --loglevel=2 > run.log 2>&1" || CODE=$?
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
  $QGA run --shell "chcp 65001 >nul & dir /s /b /a-d $vm\\exhibits > $VMDIR\\exhibit-list.txt" >/dev/null 2>&1 \
    && $QGA read "$VMDIR\\exhibit-list.txt" "$host/exhibits/LIST.txt" >/dev/null 2>&1 \
    && [[ -s "$host/exhibits/LIST.txt" ]] \
    && echo "   + exhibits/LIST.txt" || echo "   ⚠️ list of the exhibit store not read"
}

echo "== 5. Fetch of the JSON files =="
fetch_results out "$OUTPUT"

# References read by Windows itself, for the cross-checks of check-json.py:
# the MountedDevices values through the live registry API (WAC reads them in
# the raw hive, with its own reader), and the partitions of the disks.
mkdir -p "$OUTPUT/reference"
$QGA run reg.exe query 'HKLM\SYSTEM\MountedDevices' > "$OUTPUT/reference/mounted-devices.txt" 2>/dev/null \
  && echo "   + reference/mounted-devices.txt" || echo "   ⚠️ MountedDevices reference not read"
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-Partition | ForEach-Object { "{0}|{1}|{2}|{3}" -f $_.DriveLetter, $_.Guid, $_.Offset, ($_.AccessPaths -join ";") }' \
  > "$OUTPUT/reference/partitions.txt" 2>/dev/null \
  && echo "   + reference/partitions.txt" || echo "   ⚠️ partitions reference not read"

# USBSTOR dates as Windows gives them (UTC), and the PE header timestamps of
# the executables of System32, for the dates of USBSTOR and of Amcache.
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object InstanceId -like "USBSTOR*" | ForEach-Object { $i = $_.InstanceId; foreach ($k in "DEVPKEY_Device_InstallDate", "DEVPKEY_Device_LastArrivalDate") { $p = Get-PnpDeviceProperty -InstanceId $i -KeyName $k; if ($p.Data) { "{0}|{1}|{2}" -f $i, $k, $p.Data.ToUniversalTime().ToString("o") } } }' \
  > "$OUTPUT/reference/usbstor.txt" 2>/dev/null \
  && echo "   + reference/usbstor.txt" || echo "   ⚠️ USBSTOR reference not read"
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { try { $f = [IO.File]::OpenRead($_.FullName); $b = New-Object byte[] 1024; [void]$f.Read($b, 0, 1024); $f.Close(); $pe = [BitConverter]::ToInt32($b, 0x3C); if ($pe -gt 0 -and $pe -lt 1016) { "{0}|{1}" -f $_.FullName.ToLower(), [BitConverter]::ToUInt32($b, $pe + 8) } } catch {} }' \
  > "$OUTPUT/reference/pe-timestamps.txt" 2>/dev/null \
  && echo "   + reference/pe-timestamps.txt" || echo "   ⚠️ PE timestamps reference not read"
# The build of each executable of System32 — TimeDateStamp and SizeOfImage,
# the key of Microsoft's symbol server — as read in its header by PowerShell.
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { try { $f = [IO.File]::OpenRead($_.FullName); $b = New-Object byte[] 1024; [void]$f.Read($b, 0, 1024); $f.Close(); $pe = [BitConverter]::ToInt32($b, 0x3C); if ($pe -gt 0 -and $pe -lt 940) { "{0}|{1:X8}|{2:x}" -f $_.FullName.ToLower(), [BitConverter]::ToUInt32($b, $pe + 8), [BitConverter]::ToUInt32($b, $pe + 80) } } catch {} }; exit 0' \
  > "$OUTPUT/reference/pe-build.txt" 2>/dev/null \
  && echo "   + reference/pe-build.txt" || echo "   ⚠️ PE build reference not read"

# The last write of each Prefetch file as Windows gives it, for the dates of
# the file artefacts (WAC reads them in the manifest, from the raw $MFT).
$QGA run -- powershell.exe -NoProfile -Command \
  'Get-ChildItem C:\Windows\Prefetch\*.pf | ForEach-Object { "{0}|{1}" -f $_.Name, $_.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ") }' \
  > "$OUTPUT/reference/prefetch-times.txt" 2>/dev/null \
  && echo "   + reference/prefetch-times.txt" || echo "   ⚠️ Prefetch times reference not read"

# Local accounts and groups as Windows names them, for the offline naming of
# the SIDs (WAC reads them in the SAM; Windows through its account API).
$QGA run -- powershell.exe -NoProfile -Command \
  '[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-LocalUser | ForEach-Object { "{0}|{1}" -f $_.SID, $_.Name }; Get-LocalGroup | ForEach-Object { "{0}|{1}" -f $_.SID, $_.Name }' \
  > "$OUTPUT/reference/accounts.txt" 2>/dev/null \
  && echo "   + reference/accounts.txt" || echo "   ⚠️ accounts reference not read"

echo "== 6. JSON validity check =="
python3 "$HERE/check-json.py" "$OUTPUT" || echo "   ⚠️ some JSON files are invalid (see above)"

if [[ $SPLIT -eq 1 ]]; then
  echo "== 7. Collection (--collect), then conversion (--convert) =="
  # The same VM plays both roles; what is checked is what the separation must
  # guarantee:
  #   - the collection converts nothing, and seals its exhibit store;
  #   - the conversion refuses a retouched exhibit, and says why;
  #   - the JSON of the conversion pass the checks of a full run;
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

  $QGA run --shell "cd /d $VMDIR && rmdir /s /q split 2>nul & echo." >/dev/null
  # A copy of a signed Store package with one untouched, one modified and one
  # intruding script: the package verification must tell them apart.
  $QGA write "$HERE/make-fake-package.ps1" "$VMDIR\\make-fake-package.ps1" >/dev/null
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

  # taskkill just before the collection, as in step 2: the BAM check expects
  # its execution within minutes of the collection, and the references above
  # take several.
  $QGA run --shell "taskkill /f /im WAC.exe >nul 2>&1 & exit /b 0" >/dev/null 2>&1 || true
  if run_wac collect --collect --output=split --events $BINARY_OPTION --loglevel=2; then
    echo "   ✅ collection went to the end"
  else
    echo "   ❌ collection ended abnormally"; ABNORMAL_STOP=1
  fi
  N_JSON=$(json_count)
  [[ "$N_JSON" == "1" ]] && echo "   ✅ collection: investigation.json only, nothing converted" \
                         || echo "   ❌ collection: $N_JSON JSON file(s) written, 1 expected"

  # Independent reference for the completeness of the collection: the
  # executables of System32 and SysWOW64 as Windows lists them.
  $QGA run -- powershell.exe -NoProfile -Command \
    '[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-ChildItem C:\Windows\System32, C:\Windows\SysWOW64 -Recurse -File -Force -Include *.exe, *.dll, *.sys -ErrorAction SilentlyContinue | ForEach-Object FullName; exit 0' \
    > "$OUTPUT/reference/executables.txt" 2>/dev/null \
    && echo "   + reference/executables.txt" || echo "   ⚠️ executables reference not read"

  # Windows' own verdict on the signatures of System32's executables, for the
  # executables WAC authenticates in memory and does not copy.
  $QGA run -- powershell.exe -NoProfile -Command \
    '[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object { $s = Get-AuthenticodeSignature $_.FullName; "{0}|{1}|{2}" -f $_.FullName, $s.Status, $s.SignerCertificate.Subject }' \
    > "$OUTPUT/reference/authenticode.txt" 2>/dev/null \
    && echo "   + reference/authenticode.txt" || echo "   ⚠️ authenticode reference not read"

  # The verification script shipped with the documentation, on this
  # collection: seal and every exhibit, the fingerprint-only ones apart.
  $QGA write "$ROOT/WAC/doc/user/verify-exhibits.ps1" "$VMDIR\\verify-exhibits.ps1" >/dev/null
  if $QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\verify-exhibits.ps1" \
       -Output "$VMDIR\\split" > "$OUTPUT/verify-exhibits.log" 2>&1; then
    echo "   ✅ verify-exhibits.ps1: $(grep -a 'verified,' "$OUTPUT/verify-exhibits.log" | tr -d '\r')"
  else
    echo "   ❌ verify-exhibits.ps1 refuses the collection: $(tail -3 "$OUTPUT/verify-exhibits.log" | tr -d '\r')"
  fi

  # A retouched snapshot: one byte appended. The conversion must refuse it.
  LIVE="$VMDIR\\split\\exhibits\\live\\system-clock.json"
  $QGA run --shell "copy /y $LIVE $VMDIR\\clock.bak >nul & echo x>> $LIVE" >/dev/null
  if run_wac convert-tampered --convert=split --events --binary; then
    echo "   ❌ conversion of a retouched collection ACCEPTED"
  elif [[ "$(json_count)" == "2" ]] && grep -qa "no longer match" "$OUTPUT/convert-tampered.log"; then
    echo "   ✅ retouched exhibit refused, before any conversion, with its reason"
  else
    echo "   ❌ retouched exhibit refused, but without conversion.json or its reason"
  fi
  $QGA run --shell "copy /y $VMDIR\\clock.bak $LIVE >nul & del $VMDIR\\clock.bak & del $VMDIR\\split\\conversion.json" >/dev/null

  if run_wac convert --convert=split --events --binary --loglevel=2; then
    echo "   ✅ conversion went to the end"
  else
    echo "   ❌ conversion ended abnormally"; ABNORMAL_STOP=1
  fi
  fetch_results split "$SPLIT_OUT"
  cp -r "$OUTPUT/reference" "$SPLIT_OUT/"
  echo "   -- checks of the converted JSON --"
  python3 "$HERE/check-json.py" "$SPLIT_OUT" || echo "   ⚠️ the converted JSON fail some checks (see above)"

  if run_wac convert-again --convert=split --events --binary --loglevel=2; then
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

echo
if [[ "${ABNORMAL_STOP:-0}" == "1" ]]; then
  echo "== ⚠️ ABNORMAL STOP OF WAC: the JSON files above are PARTIAL =="
fi
echo "== Results on the host: $OUTPUT =="
ls -la "$OUTPUT" | awk 'NR>1{print "   "$NF"  "$5" B"}'
