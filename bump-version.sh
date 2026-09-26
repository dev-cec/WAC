#!/usr/bin/env bash
# Raises WAC's version, <major>.<minor>.<bugfix>, then rebuilds and stages.
#   ./bump-version.sh --bugfix   fixes only          1.4.0 -> 1.4.1
#   ./bump-version.sh --minor    features added      1.4.1 -> 1.5.0
#   ./bump-version.sh --major    rework of WAC       1.5.0 -> 2.0.0
# The version is written in ONE place, WAC/WAC.rc (FILEVERSION, PRODUCTVERSION
# and their texts): Windows shows it in the executable's properties, and WAC
# reads it there at run time. The usual cycle: commit the sources, run this,
# commit what it staged (WAC.rc and WAC/bin). It commits nothing itself.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RC="$HERE/WAC/WAC.rc"
case "${1:-}" in --major|--minor|--bugfix) ;; *) echo "usage: $0 --major | --minor | --bugfix" >&2; exit 2 ;; esac

python3 - "$RC" "$1" <<'PY'
import re, sys
path, part = sys.argv[1], sys.argv[2]
try:
    raw = open(path, 'rb').read()
    if raw[:2] != b'\xff\xfe':
        sys.exit("WAC.rc is not UTF-16 LE with its byte order mark: not touched")
    text = raw[2:].decode('utf-16-le')
    m = re.search(r' FILEVERSION (\d+),(\d+),(\d+),0\r\n', text)
    if not m:
        sys.exit("FILEVERSION not found in WAC.rc")
    major, minor, bugfix = map(int, m.groups())
    if part == '--major': major, minor, bugfix = major + 1, 0, 0
    elif part == '--minor': minor, bugfix = minor + 1, 0
    else: bugfix += 1
    numbers, dotted = f'{major},{minor},{bugfix},0', f'{major}.{minor}.{bugfix}'
    new, count = re.subn(r'( (?:FILE|PRODUCT)VERSION )\d+,\d+,\d+,0', lambda g: g.group(1) + numbers, text)
    new, texts = re.subn(r'(VALUE "(?:File|Product)Version", ")[^"]*(")', lambda g: g.group(1) + dotted + g.group(2), new)
    if count != 2 or texts != 2:
        sys.exit(f"WAC.rc: {count} version number(s) and {texts} text(s) found, 2 and 2 expected: not touched")
    open(path, 'wb').write(b'\xff\xfe' + new.encode('utf-16-le'))
    print(f"version {dotted}")
except OSError as e:
    sys.exit(f"WAC.rc not updated: {e}")
PY

"$HERE/build-windows.sh"
git -C "$HERE" add "$RC"
echo "Staged: WAC/WAC.rc and WAC/bin. Commit them: git commit -m \"chore : version $(python3 -c "
import re; t=open('$RC','rb').read()[2:].decode('utf-16-le'); print('.'.join(re.search(r' FILEVERSION (\d+),(\d+),(\d+),0', t).groups()))")\""
