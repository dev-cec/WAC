#!/usr/bin/env bash
# verify-exhibits.sh — checks the seal and every exhibit of a WAC collection,
# from a Linux investigation machine: the collection is examined away from the
# Windows machine it comes from, which it cannot infect there.
# Usage: bash verify-exhibits.sh [--language=en|fr] [--seal=<SHA-256>] /media/usb/output
#   --seal      the seal WAC printed at the collection, as written down in the
#               report: compared with MANIFEST.sha256 (see below)
#   --language  the messages' language; verifier-consigne.sh is this script
#               in French
# Exit code: 0 if everything matches, 1 otherwise.
# Needs: bash, coreutils (sha256sum, realpath), python3 (reads the JSON only).
#
# The fingerprints are computed by sha256sum, not by WAC: a verification that
# does not rely on the tool that produced the collection.
#
# The seal beside the manifest proves only that the manifest is unchanged
# since it was sealed: whoever rewrites the manifest can rewrite its seal.
# Against that, the value written down at the collection (--seal).
#
# The manifest comes from the examined machine, so it is treated as hostile:
# an exhibit path that leaves the collection (.., absolute path, symbolic
# link) is refused and counted as a mismatch, never read; a manifest without
# its list of exhibits is refused, never taken for an empty collection.

set -u
language=en; expected_seal=""; output="./output"
for argument in "$@"; do
    case "$argument" in
        --language=*) language="${argument#--language=}" ;;
        --seal=*) expected_seal="$(printf '%s' "${argument#--seal=}" | tr 'a-f' 'A-F')" ;;
        *) output="$argument" ;;
    esac
done

# The messages, in the language asked for. $1: the message's key; the rest
# goes into its text.
say() {
    local key="$1"; shift
    if [ "$language" = fr ]; then
        case "$key" in
            tool) echo "OUTIL ABSENT : $1" ;;
            absent) echo "MANIFESTE ABSENT : $1 ou $2" ;;
            seal) echo "SCEAU NON CONFORME : manifeste modifie" ;;
            noted) echo "SCEAU NON CONFORME : $1 au lieu de $2, releve a la collecte" ;;
            sealed) echo "Sceau conforme ($1)" ;;
            unnoted) echo "Sceau compare a MANIFEST.sha256 seul : donner --seal=<valeur relevee a la collecte> pour l'opposer a une reecriture" ;;
            unreadable) echo "MANIFESTE ILLISIBLE : $1" ;;
            mismatch) echo "DIFFERENTE : $1" ;;
            total) echo "$1 piece(s) conforme(s), $2 differente(s)" ;;
            binaries) echo "$1 binaire(s) authentifie(s), empreinte seule (pas de copie a verifier)" ;;
        esac
    else
        case "$key" in
            tool) echo "MISSING TOOL: $1" ;;
            absent) echo "NO MANIFEST: $1 or $2 absent" ;;
            seal) echo "SEAL MISMATCH: the manifest was modified" ;;
            noted) echo "SEAL MISMATCH: $1 instead of $2, written down at the collection" ;;
            sealed) echo "Seal verified ($1)" ;;
            unnoted) echo "Seal checked against MANIFEST.sha256 only: give --seal=<value written down at the collection> to hold it against a rewrite" ;;
            unreadable) echo "UNREADABLE MANIFEST: $1" ;;
            mismatch) echo "MISMATCH: $1" ;;
            total) echo "$1 exhibit(s) verified, $2 mismatch(es)" ;;
            binaries) echo "$1 binary(ies) authenticated and fingerprinted only (no copy to verify)" ;;
        esac
    fi
}

manifest="$output/exhibits/MANIFEST.json"
seal="$output/exhibits/MANIFEST.sha256"
for tool in sha256sum realpath python3; do
    command -v "$tool" >/dev/null || { say tool "$tool"; exit 1; }
done
[ -f "$manifest" ] && [ -f "$seal" ] || { say absent "$manifest" "$seal"; exit 1; }
root="$(realpath -e -- "$output")" || exit 1

# 1. The seal: the manifest's fingerprint must be the one recorded beside it,
# and the one written down at the collection when it is given.
recorded="$(head -c 64 -- "$seal" | tr 'a-f' 'A-F')"
actual="$(sha256sum -- "$manifest" | head -c 64 | tr 'a-f' 'A-F')"
if [ "$recorded" != "$actual" ]; then say seal; exit 1; fi
if [ -n "$expected_seal" ] && [ "$expected_seal" != "$actual" ]; then say noted "$actual" "$expected_seal"; exit 1; fi
say sealed "$actual"
[ -n "$expected_seal" ] || say unnoted

# 2. Every exhibit: its SHA-256 must be the one in the manifest.
# python3 lists the exhibits kept with their content, as NUL-separated
# "S, SHA-256, path" records, and one "F" record per authenticated binary that
# was not copied (--collect --binary): no file to verify. NUL cannot occur in
# a path, whatever the manifest holds. A manifest that is no JSON, or whose
# Items is no list, ends with exit code 3: refused.
list_exhibits() {
    python3 - "$manifest" <<'PYTHON'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8-sig") as f:
        items = json.load(f).get("Items")
except (OSError, ValueError, AttributeError):
    sys.exit(3)
if not isinstance(items, list):
    sys.exit(3)
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
    if [ "$kind" = X ]; then ko=$((ko + 1)); say unreadable "$manifest"; continue; fi
    # The manifest writes Windows paths, relative to the output folder.
    relative="${exhibit//\\//}"
    file="$(realpath -e -- "$root/$relative" 2>/dev/null)" || file=""
    case "$relative" in
        ""|/*) file="" ;;
    esac
    case "$file" in
        "$root"/*) ;;
        *) ko=$((ko + 1)); say mismatch "$exhibit"; continue ;;
    esac
    hash="$(sha256sum -- "$file" | head -c 64 | tr 'a-f' 'A-F')"
    if [ -n "$expected" ] && [ "$hash" = "$(printf '%s' "$expected" | tr 'a-f' 'A-F')" ]; then
        ok=$((ok + 1))
    else
        ko=$((ko + 1)); say mismatch "$exhibit"
    fi
done < <(list_exhibits || printf 'X\0\0\0')

say total "$ok" "$ko"
say binaries "$fingerprint_only"
[ "$ko" -eq 0 ] || exit 1
