#!/usr/bin/env bash
# Prints WAC's version, <major>.<minor>.<bugfix>, read where it is written —
# sources/WAC.rc only (FILEVERSION, UTF-16 LE). One reader for the scripts that
# need it: bump-version.sh, build-windows.sh (bin/wac.yml) and the test harness
# (the wac.yml it writes, which must carry the version, see config.cpp).
set -euo pipefail
RC="$(cd "$(dirname "$0")" && pwd)/sources/WAC.rc"
python3 - "$RC" <<'PY'
import re, sys
raw = open(sys.argv[1], 'rb').read()
if raw[:2] != b'\xff\xfe':
    sys.exit("WAC.rc is not UTF-16 LE with its byte order mark")
m = re.search(r' FILEVERSION (\d+),(\d+),(\d+),0', raw[2:].decode('utf-16-le'))
if not m:
    sys.exit("FILEVERSION not found in WAC.rc")
print('.'.join(m.groups()))
PY
