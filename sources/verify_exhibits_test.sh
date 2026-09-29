#!/usr/bin/env bash
# verify_exhibits_test.sh — tests the Linux verification scripts of a
# collection, verify-exhibits.sh (English) and verifier-consigne.sh (French),
# on forged collections: both must accept an intact one and refuse every
# alteration, including a manifest that points out of the collection.
# Usage: bash sources/verify_exhibits_test.sh
# Exit code: 0 if every check passes, 1 otherwise.
#
# The two scripts differ only by their messages: every case runs on both and
# checks the exit code and the counters, so that one cannot drift from the
# other unnoticed.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS=("$HERE/doc/user/verify-exhibits.sh" "$HERE/doc/user/verifier-consigne.sh")
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
checks=0; failures=0

# A collection of two stored exhibits (one with a space and a backslash-free
# subfolder), one fingerprint-only binary, one failed item, and its seal.
# $1: folder; $2: optional Python expression that alters the item list
# before the manifest is sealed.
make_collection() {
    local dir="$1" alter="${2:-}"
    mkdir -p "$dir/exhibits/live" "$dir/exhibits/files/Program Files"
    printf 'first exhibit\n' > "$dir/exhibits/live/a.json"
    printf 'second exhibit\n' > "$dir/exhibits/files/Program Files/b.txt"
    python3 - "$dir" "$alter" <<'PYTHON'
import hashlib, json, sys
root, alter = sys.argv[1], sys.argv[2]
def sha(p):
    return hashlib.sha256(open(root + "/" + p, "rb").read()).hexdigest().upper()
items = [
    {"ExhibitPath": "exhibits\\live\\a.json", "Result": "OK", "SHA256": sha("exhibits/live/a.json")},
    {"ExhibitPath": "exhibits\\files\\Program Files\\b.txt", "Result": "OK",
     "SHA256": sha("exhibits/files/Program Files/b.txt")},
    {"SourcePath": "C:\\Windows\\explorer.exe", "ContentStored": False, "Result": "OK"},
    {"SourcePath": "C:\\absent", "Result": "0x80070002"},
]
if alter:
    exec(alter)
text = json.dumps({"Tool": "WAC", "Items": items}, indent=1).replace("\n", "\r\n")
open(root + "/exhibits/MANIFEST.json", "w", encoding="utf-8-sig", newline="").write(text)
digest = hashlib.sha256(open(root + "/exhibits/MANIFEST.json", "rb").read()).hexdigest().upper()
open(root + "/exhibits/MANIFEST.sha256", "w").write(digest + "  MANIFEST.json\r\n")
PYTHON
}

# $1: case name; $2: folder; $3: expected exit code; $4: expected number of
# verified exhibits; $5: expected number of mismatches ("" for a refused seal).
expect() {
    local name="$1" dir="$2" code="$3" ok="$4" ko="$5" script out got
    for script in "${SCRIPTS[@]}"; do
        checks=$((checks + 1))
        out="$(bash "$script" "$dir" 2>&1)"; got=$?
        local verdict=""
        [ "$got" -eq "$code" ] || verdict="exit code $got, expected $code"
        if [ -n "$ko" ] && [ -z "$verdict" ]; then
            printf '%s\n' "$out" | grep -Eq "^$ok [a-z(). ]+, $ko [a-z(). ]+$" \
                || verdict="counters: expected $ok verified, $ko mismatch(es)"
        fi
        if [ -n "$verdict" ]; then
            failures=$((failures + 1))
            echo "FAIL $name ($(basename "$script")): $verdict"
            printf '%s\n' "$out" | sed 's/^/    /'
        fi
    done
}

make_collection "$WORK/intact"
expect "intact collection accepted" "$WORK/intact" 0 2 0
out="$(bash "${SCRIPTS[0]}" "$WORK/intact")"
checks=$((checks + 1))
printf '%s\n' "$out" | grep -q '^1 binarie(s) authenticated' \
    || { failures=$((failures + 1)); echo "FAIL fingerprint-only binary not counted: $out"; }

make_collection "$WORK/lowercase" 'items[0]["SHA256"] = items[0]["SHA256"].lower()'
expect "fingerprint in lower case accepted" "$WORK/lowercase" 0 2 0

make_collection "$WORK/altered"
printf 'retouched\n' >> "$WORK/altered/exhibits/live/a.json"
expect "altered exhibit refused" "$WORK/altered" 1 1 1

make_collection "$WORK/missing"
rm "$WORK/missing/exhibits/files/Program Files/b.txt"
expect "missing exhibit refused" "$WORK/missing" 1 1 1

make_collection "$WORK/seal"
sed -i 's/first/First/' "$WORK/seal/exhibits/live/a.json"
printf ' ' >> "$WORK/seal/exhibits/MANIFEST.json"
expect "modified manifest refused by the seal" "$WORK/seal" 1 "" ""

make_collection "$WORK/nosha" 'del items[1]["SHA256"]'
expect "stored exhibit without a fingerprint refused" "$WORK/nosha" 1 1 1

# A manifest that names a file of the investigation machine: never accepted,
# whatever its fingerprint.
mkdir -p "$WORK/outside"; printf 'machine file\n' > "$WORK/outside/secret"
make_collection "$WORK/dotdot" 'import hashlib; items.append({"ExhibitPath": "exhibits\\..\\..\\outside\\secret", "Result": "OK", "SHA256": hashlib.sha256(b"machine file\n").hexdigest()})'
expect "path out of the collection by .. refused" "$WORK/dotdot" 1 2 1

make_collection "$WORK/absolute" 'import hashlib; items.append({"ExhibitPath": "'"$WORK"'/outside/secret", "Result": "OK", "SHA256": hashlib.sha256(b"machine file\n").hexdigest()})'
expect "absolute path refused" "$WORK/absolute" 1 2 1

make_collection "$WORK/link" 'import hashlib; items.append({"ExhibitPath": "exhibits\\link", "Result": "OK", "SHA256": hashlib.sha256(b"machine file\n").hexdigest()})'
ln -s "$WORK/outside/secret" "$WORK/link/exhibits/link"
expect "symbolic link out of the collection refused" "$WORK/link" 1 2 1

make_collection "$WORK/broken"
printf '{"Items": [' > "$WORK/broken/exhibits/MANIFEST.json"
sha256sum "$WORK/broken/exhibits/MANIFEST.json" | sed 's| .*|  MANIFEST.json|' > "$WORK/broken/exhibits/MANIFEST.sha256"
expect "sealed but unreadable manifest refused" "$WORK/broken" 1 0 1

expect "absent collection refused" "$WORK/none" 1 "" ""

if [ "$failures" -eq 0 ]; then
    echo "all passed: $checks check(s), 0 failure(s)"
else
    echo "$failures failure(s) out of $checks check(s)"; exit 1
fi
