#!/usr/bin/env bash
# mft_fixtures.sh — the test data of mft_test: a real $MFT, and what ntfsinfo
# (ntfs-3g, an independent NTFS implementation) reads in each of its records.
#
# An NTFS volume is formatted by mkntfs in a file, files are added with ntfscp
# (no mount, no privilege), its $MFT is dumped with ntfscat, then each record
# is described by ntfsinfo, one line per record in use:
#   entry|sequence|inUse|directory|parent|name|size|si×4|fn×4|streams
# (the four dates in the order created, modified, record changed, accessed)
# with the dates in seconds since 1970 (ntfsinfo prints them to the second),
# the size "-" for a directory or a record without unnamed $DATA, the name the
# long one (Win32, Win32 & DOS, then POSIX; DOS as a last resort) — the
# preference of MftEntry::parse, the streams the named $DATA ("$SDS,$SDH").
#
# Usage: mft_fixtures.sh <folder>   → <folder>/mft.bin, <folder>/mft-reference.txt
set -euo pipefail
OUT="${1:?usage: mft_fixtures.sh <folder>}"
mkdir -p "$OUT"
IMG="$OUT/volume.img"
rm -f "$IMG"
truncate -s 64M "$IMG"
mkntfs -F -Q -q "$IMG" 2>/dev/null
# Files of several sizes: resident (a few bytes), non-resident, a non-ASCII name.
for i in 1 2 3; do
  head -c $((i * 3000)) /dev/urandom > "$OUT/content"
  ntfscp -q "$IMG" "$OUT/content" "file$i.bin"
done
printf 'small' > "$OUT/content"
ntfscp -q "$IMG" "$OUT/content" "résumé.txt"
rm -f "$OUT/content"
# Distinct dates in each file record: mkntfs and ntfscp write the same instant
# eight times, which would let a decoder that reads the wrong date through.
# Written in the image itself (first stride of the record, fixups untouched),
# so that ntfsinfo reads them as the reference.
python3 - "$IMG" <<'PY'
import struct, sys
with open(sys.argv[1], "r+b") as f:
    boot = f.read(512)
    cluster = struct.unpack_from("<H", boot, 0x0B)[0] * boot[0x0D]
    start = struct.unpack_from("<Q", boot, 0x30)[0] * cluster
    for entry in range(64, 68):
        f.seek(start + entry * 1024)
        record = bytearray(f.read(1024))
        if record[:4] != b"FILE":
            continue
        p = struct.unpack_from("<H", record, 0x14)[0]
        while p + 16 < 510:
            kind, length = struct.unpack_from("<II", record, p)
            if kind == 0xFFFFFFFF or length < 16:
                break
            value = p + struct.unpack_from("<H", record, p + 0x14)[0]
            first = {0x10: value, 0x30: value + 8}.get(kind)
            if first is not None and first + 32 <= 510:
                for k in range(4):   # 2021-01-01 + entry hours + k days (+ 7 days for $FILE_NAME)
                    ticks = (132539328000000000 + entry * 36000000000 + k * 864000000000
                             + (6048000000000 if kind == 0x30 else 0))
                    struct.pack_into("<Q", record, first + 8 * k, ticks)
            p += length
        f.seek(start + entry * 1024)
        f.write(record)
PY
# ntfscat gives the records with their fixups APPLIED, not as they lie on the
# disk: the $MFT is read raw from the image (boot sector: bytes per sector at
# 0x0B, sectors per cluster at 0x0D, first cluster of the $MFT at 0x30 —
# contiguous on a fresh volume), and checked against ntfscat once fixed up.
ntfscat "$IMG" '$MFT' > "$OUT/mft-fixed.bin"
python3 - "$IMG" "$OUT/mft-fixed.bin" "$OUT/mft.bin" <<'PY'
import struct, sys
image, fixed, out = sys.argv[1:4]
with open(image, "rb") as f:
    boot = f.read(512)
    sector, perCluster = struct.unpack_from("<H", boot, 0x0B)[0], boot[0x0D]
    mftCluster = struct.unpack_from("<Q", boot, 0x30)[0]
    reference = open(fixed, "rb").read()
    f.seek(mftCluster * sector * perCluster)
    raw = f.read(len(reference))
for at in range(0, len(raw), 1024):
    record = bytearray(raw[at:at + 1024])
    if record[:4] == b"FILE":
        offset, count = struct.unpack_from("<HH", record, 4)
        for i in range(1, count):
            assert record[i * 512 - 2:i * 512] == record[offset:offset + 2], "torn record in the image"
            record[i * 512 - 2:i * 512] = record[offset + 2 * i:offset + 2 * i + 2]
    assert bytes(record) == reference[at:at + 1024] or record[:4] != b"FILE", f"record {at // 1024}: raw and ntfscat differ"
open(out, "wb").write(raw)
PY
rm -f "$OUT/mft-fixed.bin"
RECORDS=$(( $(stat -c %s "$OUT/mft.bin") / 1024 ))

python3 - "$IMG" "$RECORDS" > "$OUT/mft-reference.txt" <<'PY'
import calendar, re, subprocess, sys, time
img, records = sys.argv[1], int(sys.argv[2])
PREFERENCE = {"Win32": 0, "Win32 & DOS": 0, "POSIX": 1, "DOS": 2}
DATES = ["File Creation Time", "File Altered Time", "MFT Changed Time", "Last Accessed Time"]
def epoch(text):
    return calendar.timegm(time.strptime(text.strip(), "%a %b %d %H:%M:%S %Y UTC"))
for entry in range(records):
    run = subprocess.run(["ntfsinfo", "-i", str(entry), img], capture_output=True, text=True)
    if run.returncode != 0 or "Dumping Inode" not in run.stdout:
        continue
    seq = flags = None
    section, names, size, si, streams, attributeName = None, [], None, [None] * 4, [], None
    current = {}
    for line in run.stdout.splitlines():
        m = re.match(r"\s*([^:]+):\s*(.*)$", line)
        if line.startswith("Dumping attribute"):
            if section == "$FILE_NAME" and current:
                names.append(current)
            section = re.search(r"\$\w+", line).group(0)
            current, attributeName = {}, None
            continue
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        if key == "MFT Record Seq. Numb.":
            seq = int(value.split()[0])
        elif key == "MFT Record Flags":
            flags = value
        elif section == "$STANDARD_INFORMATION" and key in DATES:
            si[DATES.index(key)] = epoch(value)
        elif section == "$FILE_NAME":
            if key == "Parent directory": current["parent"] = int(value.split()[0])
            elif key in DATES: current.setdefault("dates", [None] * 4)[DATES.index(key)] = epoch(value)
            elif key == "Namespace": current["space"] = value
            elif key == "Filename": current["name"] = value[1:-1]
        elif section == "$DATA" and key == "Attribute name":
            attributeName = value[1:-1]
            streams.append(attributeName)
        elif section == "$DATA" and key == "Data size" and attributeName is None:
            size = int(value.split()[0])
    if section == "$FILE_NAME" and current:
        names.append(current)
    if not names or flags is None or "IN_USE" not in flags:
        continue
    best = min(names, key=lambda n: PREFERENCE.get(n.get("space"), 3))
    directory = "DIRECTORY" in flags
    print("|".join(str(x) for x in (entry, seq, 1, int(directory), best["parent"], best["name"],
                                     "-" if directory or size is None else size, *si, *best["dates"],
                                     ",".join(streams))))
PY
echo "$(wc -l < "$OUT/mft-reference.txt") record(s) described in $OUT/mft-reference.txt"
