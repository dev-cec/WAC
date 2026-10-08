#!/usr/bin/env bash
# verify-exhibits.sh — checks the seal and every exhibit of a WAC collection,
# from a Linux investigation machine: the collection is examined away from the
# Windows machine it comes from, which it cannot infect there.
# Usage: bash verify-exhibits.sh /media/usb/output
# Exit code: 0 if everything matches, 1 otherwise.
# Needs: bash, coreutils (sha256sum, realpath), python3 (reads the JSON only).
#
# The fingerprints are computed by sha256sum, not by WAC: a verification that
# does not rely on the tool that produced the collection.
#
# The manifest comes from the examined machine, so it is treated as hostile:
# an exhibit path that leaves the collection (.., absolute path, symbolic
# link) is refused and counted as a mismatch, never read.

set -u
output="${1:-./output}"
manifest="$output/exhibits/MANIFEST.json"
seal="$output/exhibits/MANIFEST.sha256"

for tool in sha256sum realpath python3; do
    command -v "$tool" >/dev/null || { echo "MISSING TOOL: $tool"; exit 1; }
done
[ -f "$manifest" ] && [ -f "$seal" ] || { echo "NO MANIFEST: $manifest or $seal absent"; exit 1; }
root="$(realpath -e -- "$output")" || exit 1

# 1. The seal: the manifest's fingerprint must be the one recorded beside it.
recorded="$(head -c 64 -- "$seal" | tr 'a-f' 'A-F')"
actual="$(sha256sum -- "$manifest" | head -c 64 | tr 'a-f' 'A-F')"
if [ "$recorded" != "$actual" ]; then echo "SEAL MISMATCH: the manifest was modified"; exit 1; fi
echo "Seal verified ($actual)"

# 2. Every exhibit: its SHA-256 must be the one in the manifest.
# python3 lists the exhibits kept with their content, as NUL-separated
# "S, SHA-256, path" records, and one "F" record per authenticated binary that
# was not copied (--collect --binary): no file to verify. NUL cannot occur in
# a path, whatever the manifest holds.
list_exhibits() {
    python3 - "$manifest" <<'PYTHON'
import json, sys
with open(sys.argv[1], encoding="utf-8-sig") as f:
    items = json.load(f).get("Items") or []
out = sys.stdout.buffer
for item in items:
    if not isinstance(item, dict) or item.get("Result") != "OK":
        continue
    if item.get("ContentStored") is False:
        out.write(b"F\0")
        continue
    sha = str(item.get("SHA256") or "").replace("\0", "")
    path = str(item.get("ExhibitPath") or "").replace("\0", "")
    out.write(b"S\0" + sha.encode() + b"\0" + path.encode("utf-8", "surrogateescape") + b"\0")
PYTHON
}

ok=0; ko=0; fingerprint_only=0
while IFS= read -r -d '' kind; do
    if [ "$kind" = F ]; then fingerprint_only=$((fingerprint_only + 1)); continue; fi
    IFS= read -r -d '' expected || break
    IFS= read -r -d '' exhibit || break
    # The manifest writes Windows paths, relative to the output folder.
    relative="${exhibit//\\//}"
    file="$(realpath -e -- "$root/$relative" 2>/dev/null)" || file=""
    case "$relative" in
        ""|/*) file="" ;;
    esac
    case "$file" in
        "$root"/*) ;;
        *) ko=$((ko + 1)); echo "MISMATCH: $exhibit"; continue ;;
    esac
    hash="$(sha256sum -- "$file" | head -c 64 | tr 'a-f' 'A-F')"
    if [ -n "$expected" ] && [ "$hash" = "$(printf '%s' "$expected" | tr 'a-f' 'A-F')" ]; then
        ok=$((ok + 1))
    else
        ko=$((ko + 1)); echo "MISMATCH: $exhibit"
    fi
done < <(list_exhibits || printf 'S\0\0unreadable manifest\0')

echo "$ok exhibit(s) verified, $ko mismatch(es)"
echo "$fingerprint_only binarie(s) authenticated and fingerprinted only (no copy to verify)"
[ "$ko" -eq 0 ] || exit 1
