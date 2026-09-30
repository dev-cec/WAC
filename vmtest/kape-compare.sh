#!/usr/bin/env bash
# kape-compare.sh — WAC's collection against KAPE's, on the test VM (B-015):
# both run one right after the other (guest/kape-compare.ps1), timed; their
# file lists are then compared family by family, with the SHA-1 of the files
# both copied (lib/ez-compare.py kape).
#
# WAC runs with the configuration of its kit (bin/wac.yml). With --no-binary,
# its "binary:" key is set to none: KapeTriage copies no executable, and the
# comparison then weighs the same work.
#
# Usage: ./kape-compare.sh [--no-binary] [KAPE target, KapeTriage by default]
# Output: results/kape/<target>-<date>/ (logs, manifest, timing.txt, compare.txt)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QGA="python3 $HERE/lib/qga.py"
NO_BINARY=false
if [[ "${1:-}" == "--no-binary" ]]; then NO_BINARY=true; shift; fi
TARGET="${1:-KapeTriage}"
OUT="$HERE/results/kape/$TARGET$($NO_BINARY && echo -nobinary)-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

if $NO_BINARY; then
  sed 's/^binary: .*/binary: none/' "$HERE/../bin/wac.yml" > "$OUT/wac.yml"
else
  cp "$HERE/../bin/wac.yml" "$OUT/wac.yml"
fi
$QGA write "$HERE/../bin/WAC.exe" 'C:\wactest\WAC.exe' >/dev/null
$QGA write "$OUT/wac.yml" 'C:\wactest\wac.yml' >/dev/null
$QGA write "$HERE/guest/kape-compare.ps1" 'C:\wactest\kape-compare.ps1' >/dev/null
$QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File 'C:\wactest\kape-compare.ps1' -Target "$TARGET" | tr -d '\r' | tee "$OUT/timing.txt"
$QGA run --shell 'del C:\wactest\wac.yml' >/dev/null
$QGA read 'C:\kape\kape-compare.zip' "$OUT/outputs.zip" >/dev/null
python3 -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1] + '/outputs.zip').extractall(sys.argv[1])" "$OUT"
rm "$OUT/outputs.zip"

python3 "$HERE/lib/ez-compare.py" kape "$OUT" | tee "$OUT/compare.txt"
