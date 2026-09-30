#!/usr/bin/env bash
# ez-compare.sh — WAC against Eric Zimmerman's tool for one artefact (B-015):
# times both in the test VM on the exhibits of the last collection, brings
# their outputs back, and compares them with lib/ez-compare.py.
#
# Precondition: a cycle that collected the artefact (./run-wac-test.sh
# --only=<key>), and the tools installed (./install-tools.sh).
#
# Usage: ./ez-compare.sh <comparison>     e.g. ./ez-compare.sh prefetch (see guest/ez-time.ps1)
# Output: results/ez/<key>-<date>/ (both outputs, timing.txt, compare.txt)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QGA="python3 $HERE/lib/qga.py"
KEY="${1:?usage: $0 <comparison>}"
case "$KEY" in
  mft) MODE=mft ;; events) MODE=evtx ;; prefetch) MODE=prefetch ;;
  recent_documents) MODE=lnk ;; jump_lists) MODE=jumplist ;;
  shellbags|shimcache|amcache) MODE=$KEY ;;
  *) echo "no comparison known for '$KEY'" >&2; exit 2 ;;
esac
OUT="$HERE/results/ez/$KEY-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

$QGA write "$HERE/guest/ez-time.ps1" 'C:\wactest\ez-time.ps1' >/dev/null
$QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File 'C:\wactest\ez-time.ps1' -Comparison "$KEY" | tr -d '\r' | tee "$OUT/timing.txt"
$QGA read "C:\\wactest\\ez\\$KEY.zip" "$OUT/outputs.zip" >/dev/null
(cd "$OUT" && unzip -oq outputs.zip && rm outputs.zip)

python3 "$HERE/lib/ez-compare.py" "$MODE" "$OUT" | tee "$OUT/compare.txt"
