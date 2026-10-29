#!/usr/bin/env bash
# Raises WAC's version, <major>.<minor>.<bugfix>, then rebuilds and stages.
#   ./bump-version.sh --bugfix   fixes only          1.4.0 -> 1.4.1
#   ./bump-version.sh --minor    features added      1.4.1 -> 1.5.0
#   ./bump-version.sh --major    rework of WAC       1.5.0 -> 2.0.0
# The version is written in ONE place, sources/WAC.rc (FILEVERSION, PRODUCTVERSION
# and their texts): Windows shows it in the executable's properties, and WAC
# reads it there at run time. The usual cycle: commit the sources, run this,
# commit what it staged (WAC.rc, bin, and the documents that state the
# version). It commits nothing itself.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RC="$HERE/sources/WAC.rc"
case "${1:-}" in --major|--minor|--bugfix) ;; *) echo "usage: $0 --major | --minor | --bugfix" >&2; exit 2 ;; esac

# WAC.rc back as it was if the build fails: left raised, a second run raised it
# again, and a version number was skipped.
BACKUP="$(mktemp)"
cp "$RC" "$BACKUP"
BUILT=0
trap 'if [[ $BUILT == 0 ]]; then cp "$BACKUP" "$RC"; echo "WAC.rc restored: the version is unchanged" >&2; fi; rm -f "$BACKUP"' EXIT

python3 - "$RC" "$1" <<'PY'
import re, sys
path, part = sys.argv[1], sys.argv[2]
try:
    text = open(path, encoding='utf-8', newline='').read()
    m = re.search(r' FILEVERSION (\d+),(\d+),(\d+),0\r?\n', text)
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
    open(path, 'w', encoding='utf-8', newline='').write(new)
    print(f"version {dotted}")
except OSError as e:
    sys.exit(f"WAC.rc not updated: {e}")
PY

"$HERE/build-windows.sh" --test   # the tests too: bin/ holds no test of an older build
BUILT=1
git -C "$HERE" add "$RC"
VERSION=$("$HERE/wac-version.sh")
# The documents that state the version: the README badge, and the information
# page of each manual (PDFs rebuilt when LuaLaTeX is there).
sed -i -E "s#badge/version-[0-9]+\.[0-9]+\.[0-9]+-green#badge/version-$VERSION-green#" "$HERE/README.md"
DOCS=("$HERE"/doc/user/documentation_{FR,EN}.tex "$HERE"/doc/tests/testing_{FR,EN}.tex "$HERE"/doc/validation/validation_{FR,EN}.tex
      "$HERE"/doc/harmlessness/harmlessness_{FR,EN}.tex "$HERE"/doc/comparison/comparison_{FR,EN}.tex)
sed -i -E "s#^(Version du logiciel|Software version) & [0-9]+\.[0-9]+\.[0-9]+ #\1 \& $VERSION #" "${DOCS[@]}"
# The other sentences that name the version: the manuals' scope, the import
# list of the harmlessness file. Not the comparison's test bench: it names the
# version MEASURED, which only a new measurement changes — rewritten here, it
# gave 3.0.0 to the measures of 2.0.0.
sed -i -E "s#(Ce document décrit la version|This document describes version) [0-9]+\.[0-9]+\.[0-9]+#\1 $VERSION#" "$HERE"/doc/user/documentation_{FR,EN}.tex
sed -i -E "s#^(Pour la version|For version) [0-9]+\.[0-9]+\.[0-9]+,#\1 $VERSION,#" "$HERE"/doc/harmlessness/harmlessness_{FR,EN}.tex
# The wac.yml shown in the user manuals carries the version, as --write-config writes it.
sed -i -E "s#^wac_version: [0-9]+\.[0-9]+\.[0-9]+ #wac_version: $VERSION #" "$HERE"/doc/user/documentation_{FR,EN}.tex "$HERE/README.md"
# Rebuilt as the editor builds them (LuaLaTeX), their artefacts removed after.
if command -v lualatex >/dev/null && command -v latexmk >/dev/null; then
  # A failed build would stage PDFs that still state the old version.
  "$HERE/doc/build-docs.sh" "${DOCS[@]}" \
    || { echo "some document did not build: nothing of the documents staged — fix it, then run this again from doc/build-docs.sh" >&2; exit 1; }
fi
git -C "$HERE" add "$HERE/README.md" "${DOCS[@]}" "${DOCS[@]/%.tex/.pdf}"
# The code documentation (doc/html), its version read from WAC.rc too (Doxyfile: $(WAC_VERSION)).
if command -v doxygen >/dev/null; then
  ( cd "$HERE/Doxygen" && WAC_VERSION="$VERSION" doxygen Doxyfile >/dev/null ) \
    || { echo "doxygen failed: doc/html not regenerated (its errors above)" >&2; exit 1; }
  git -C "$HERE" add -A "$HERE/doc/html"
  echo "Code documentation regenerated (doc/html)"
else
  echo "doxygen absent: doc/html not regenerated"
fi
echo "Staged: sources/WAC.rc, bin, README.md, the manuals and doc/html. Commit them: git commit -m \"chore : version $VERSION\""
