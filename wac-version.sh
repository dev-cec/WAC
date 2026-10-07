#!/usr/bin/env bash
# Prints WAC's version, <major>.<minor>.<bugfix>, read where it is written —
# sources/WAC.rc only (FILEVERSION, UTF-16 LE). One reader for the scripts that
# need it: bump-version.sh, build-windows.sh (bin/wac.yml) and the test harness
# (the wac.yml it writes, which must carry the version, see config.cpp).
set -euo pipefail
RC="$(cd "$(dirname "$0")" && pwd)/sources/WAC.rc"
# iconv and sed only: the build already needs iconv (the resource file), and
# MSYS2 has no Python unless asked for one (B-024).
[[ "$(head -c 2 "$RC" | od -An -tx1 | tr -d ' ')" == fffe ]] \
  || { echo "WAC.rc is not UTF-16 LE with its byte order mark" >&2; exit 1; }
VERSION="$(iconv -f UTF-16 -t UTF-8 "$RC" | sed -n 's/^ *FILEVERSION \([0-9]*\),\([0-9]*\),\([0-9]*\),0.*/\1.\2.\3/p' | head -1)"
[[ -n "$VERSION" ]] || { echo "FILEVERSION not found in WAC.rc" >&2; exit 1; }
echo "$VERSION"
