#!/usr/bin/env bash
# run-footprint.sh — measures what WAC, KAPE and the EZ tools leave on the
# examined machine (backlog B-027), one run per tool, each from the same
# frozen state of the footprint clone (prepare-footprint.sh).
#
# FOR EACH RUN:
#   1. the clone's system disk and its key are fresh qcow2 layers over the
#      base images, its UEFI variables a copy of the base ones: every run
#      starts from the same bytes, and nothing of a run reaches the next;
#   2. the clone boots, and is left SETTLE seconds for Windows' start-up work;
#   3. guest/measure-run.ps1 (on the key) bounds the run by the change
#      journal's USN and the clock, starts the tool as the user "wac" with
#      its highest rights, and exports the journal, Sysmon's events and the
#      other event logs of the window to the key;
#   4. the results are fetched into results/<run>/;
#   5. the clone is shut down cleanly, booted again and its ShimCache
#      (AppCompatCache) read: Windows writes it only at shutdown, out of any
#      bound — a deferred trace of every executable started.
#
# The run "control" starts a command that does nothing: it measures the
# launcher and Windows' own activity, which the analysis (footprint-diff.py)
# subtracts from the others.
#
# Usage: ./run-footprint.sh [run ...]   (default: every run, in order)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DOM=win11-footprint
CONN="qemu:///session"
QGA="python3 $ROOT/vmtest/lib/qga.py --dom $DOM"
VMS="$HOME/vms"
NVRAM="$HOME/.config/libvirt/qemu/nvram"
SETTLE="${SETTLE:-180}"
RESULTS="$HERE/results"

# The runs: a label, and the command line cmd.exe runs in the user's session.
# WAC ends on "press any key": its input is empty (< nul), or it would wait,
# and the bounds of the run with it, until someone answers.
declare -A COMMAND=(
  [control]='ver'
  [wac-collect]='cd /d K:\WAC && WAC.exe --output=collect < nul'
  [kape-targets]='K:\KAPE\KAPE\kape.exe --tsource C: --target !SANS_Triage --tdest K:\out\kape-targets --tflush'
  [kape-modules]='K:\KAPE\KAPE\kape.exe --tsource C: --target !SANS_Triage --tdest K:\out\kape-tdest --tflush --module !EZParser --mdest K:\out\kape-mdest --mflush'
  [ez-live]='K:\ez-live.cmd'
)
ORDER=(control wac-collect kape-targets kape-modules ez-live)
RUNS=("${@:-${ORDER[@]}}")
for run in "${RUNS[@]}"; do [[ -n "${COMMAND[$run]:-}" ]] || { echo "unknown run: $run (runs: ${ORDER[*]})"; exit 2; }; done

[[ -f "$VMS/win11-footprint-base.qcow2" ]] || { echo "no base image: run prepare-footprint.sh first"; exit 1; }

# Stops the clone, at once: its layers are thrown away.
stop_clone() {
  virsh -c "$CONN" domstate "$DOM" | grep -q "shut off" || virsh -c "$CONN" destroy "$DOM" >/dev/null
}

# Waits for the guest agent, then for the given seconds.
wait_agent() {
  for _ in $(seq 1 120); do $QGA ping >/dev/null 2>&1 && break; sleep 5; done
  $QGA ping >/dev/null
  sleep "$1"
}

for run in "${RUNS[@]}"; do
  echo "== $run == ($(date +%H:%M:%S))"
  stop_clone
  rm -f "$VMS/win11-footprint.qcow2" "$VMS/wac-footprint-key.qcow2"
  qemu-img create -q -f qcow2 -b "$VMS/win11-footprint-base.qcow2" -F qcow2 "$VMS/win11-footprint.qcow2"
  qemu-img create -q -f qcow2 -b "$VMS/wac-footprint-key-base.qcow2" -F qcow2 "$VMS/wac-footprint-key.qcow2"
  cp "$NVRAM/win11-footprint_VARS-base.fd" "$NVRAM/win11-footprint_VARS.fd"
  virsh -c "$CONN" start "$DOM" >/dev/null
  wait_agent "$SETTLE"

  # The measuring script, WAC and the EZ script go onto the key, before the
  # bounds: always their current version, and K: is not measured.
  $QGA write "$HERE/guest/measure-run.ps1" 'K:\measure-run.ps1' >/dev/null
  # WAC as last built (bin/), not as the key was frozen with.
  $QGA write "$ROOT/bin/WAC.exe" 'K:\WAC\WAC.exe' >/dev/null
  $QGA write "$ROOT/bin/wac.yml" 'K:\WAC\wac.yml' >/dev/null
  [[ "$run" == ez-live ]] && $QGA write "$HERE/guest/ez-live.cmd" 'K:\ez-live.cmd' >/dev/null
  $QGA run --timeout 14400 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'K:\measure-run.ps1' \
    -Label "$run" -Command "${COMMAND[$run]}" | sed 's/^/   /'

  out="$RESULTS/$run"
  rm -rf "${out:?}"; mkdir -p "$out"
  # One name per line: an event log's name may hold spaces.
  while IFS= read -r f; do
    [[ -n "$f" ]] && $QGA read "K:\\results\\$run\\$f" "$out/$f" >/dev/null
  done < <($QGA run --shell "dir /b K:\\results\\$run" | tr -d '\r')
  echo "   fetched: $(ls "$out" | wc -l) file(s), $(du -sh "$out" | cut -f1)"

  # The deferred trace: the ShimCache, written at shutdown.
  virsh -c "$CONN" shutdown "$DOM" >/dev/null
  for _ in $(seq 1 120); do virsh -c "$CONN" domstate "$DOM" | grep -q "shut off" && break; sleep 5; done
  virsh -c "$CONN" start "$DOM" >/dev/null
  wait_agent 30
  $QGA run -- reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' /v AppCompatCache \
    > "$out/appcompatcache.txt"
  stop_clone
done
rm -f "$VMS/win11-footprint.qcow2" "$VMS/wac-footprint-key.qcow2"
echo "== done == ($(date +%H:%M:%S))"
