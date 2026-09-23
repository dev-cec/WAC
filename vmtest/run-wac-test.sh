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

BUILD=0; RAWONLY=0
for a in "$@"; do
  [[ "$a" == "--build"    ]] && BUILD=1
  [[ "$a" == "--raw-only" ]] && RAWONLY=1
done

echo "== 0. Agent =="
$QGA ping

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

echo "== 5. Fetch of the JSON files =="
# The listing is retried: right after a long collection the guest agent has
# once answered with an empty output while the JSON files were there, and the
# whole run then looked like "no JSON produced".
LIST=""
for attempt in 1 2 3; do
  LIST=$($QGA run --shell "dir /b $VMDIR\\out\\*.json 2>nul" || true)
  [[ -n "${LIST// }" ]] && break
  sleep 5
done
if [[ -z "${LIST// }" ]]; then
  echo "   ⚠️ no JSON produced — see $OUTPUT/run.log"
else
  while read -r f; do
    f="${f%$'\r'}"; [[ -z "$f" ]] && continue
    $QGA read "$VMDIR\\out\\$f" "$OUTPUT/$f" >/dev/null && echo "   + $f"
  done <<< "$LIST"
fi

# Exhibit manifest + its seal: small, and they are what identifies the exhibits.
# Without them, check-json.py cannot check the exhibit store (the exhibits
# themselves weigh hundreds of MiB and stay on the collection medium).
mkdir -p "$OUTPUT/exhibits"
for f in MANIFEST.json MANIFEST.sha256; do
  $QGA read "$VMDIR\\out\\exhibits\\$f" "$OUTPUT/exhibits/$f" >/dev/null 2>&1 \
    && echo "   + exhibits/$f" || echo "   ⚠️ exhibits/$f not fetched"
done
# List of the files really present in the exhibit store: without it, nothing
# checks that every exhibit is in the manifest. An exhibit added after the
# sealing went unnoticed (121 event provider binaries).
$QGA run --shell "chcp 65001 >nul & dir /s /b /a-d $VMDIR\\out\\exhibits" \
  > "$OUTPUT/exhibits/LIST.txt" 2>/dev/null \
  && echo "   + exhibits/LIST.txt" || echo "   ⚠️ list of the exhibit store not read"

echo "== 6. JSON validity check =="
python3 "$HERE/check-json.py" "$OUTPUT" || echo "   ⚠️ some JSON files are invalid (see above)"

echo
if [[ "${ABNORMAL_STOP:-0}" == "1" ]]; then
  echo "== ⚠️ ABNORMAL STOP OF WAC: the JSON files above are PARTIAL =="
fi
echo "== Results on the host: $OUTPUT =="
ls -la "$OUTPUT" | awk 'NR>1{print "   "$NF"  "$5" B"}'
