#!/usr/bin/env bash
# Prints WAC's version, <major>.<minor>.<bugfix>, read where it is written —
# sources/WAC.rc only (FILEVERSION, UTF-8). One reader for the scripts that
# need it: bump-version.sh, build-windows.sh (bin/wac.yml) and the test harness
# (the wac.yml it writes, which must carry the version, see config.cpp).
set -euo pipefail
RC="$(cd "$(dirname "$0")" && pwd)/sources/WAC.rc"
VERSION="$(sed -n 's/^ *FILEVERSION \([0-9]*\),\([0-9]*\),\([0-9]*\),0.*/\1.\2.\3/p' "$RC" | head -1)"
[[ -n "$VERSION" ]] || { echo "FILEVERSION not found in WAC.rc" >&2; exit 1; }
echo "$VERSION"
