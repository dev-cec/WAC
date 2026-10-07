#!/usr/bin/env bash
# raw_volume_test.sh — WAC's raw NTFS reader on a real NTFS volume, under Wine:
# a file read through the directory index must be the file the index names.
#
# The volume is the one mft_fixtures.sh formats with mkntfs (ntfs-3g). Wine
# serves it as drive T: — the dosdevices link "t::" is what "\\.\T:" opens —
# in a Wine prefix of its own, removed at the end. raw_hive_test.exe reads it
# exactly as WAC reads a disk.
#
#   1. file1.bin extracted: its bytes are those ntfscat (ntfs-3g, another
#      implementation of NTFS) reads.
#   2. file1.bin's record given another sequence number, its index entry left
#      as it was — what the running system does when it deletes a file and
#      gives its record to another between the listing of the directory and
#      the read. The extraction must be refused and leave no file: before
#      B-043 the record was read anyway, and another file's content sealed
#      under the first one's name (an SRU*.log holding a hive's "hbin"
#      blocks, measured in the test VM).
#
# Usage: raw_volume_test.sh <folder of mft_fixtures.sh> <raw_hive_test.exe>
set -euo pipefail
FIXTURES="${1:?usage: raw_volume_test.sh <fixtures folder> <raw_hive_test.exe>}"
EXE="${2:?usage: raw_volume_test.sh <fixtures folder> <raw_hive_test.exe>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export WINEPREFIX="$WORK/prefix" WINEDEBUG=-all
wineboot -i >/dev/null 2>&1
cp "$FIXTURES/volume.img" "$WORK/volume.img"
ln -s "$WORK/volume.img" "$WINEPREFIX/dosdevices/t::"

checks=0; failures=0
check() {   # check <status, 0 when right> <what>
  checks=$((checks + 1))
  if [[ "$1" != 0 ]]; then failures=$((failures + 1)); echo "  FAILED  $2"; fi
}

# 1. A sound read, against ntfscat.
ntfscat "$WORK/volume.img" /file1.bin > "$WORK/expected.bin"
wine "$EXE" T '\file1.bin' "Z:$WORK/read.bin" >/dev/null 2>&1 || true
cmp -s "$WORK/expected.bin" "$WORK/read.bin" && status=0 || status=1
check $status "file1.bin: not the bytes ntfscat reads"

# 2. The record reused since the index was written: a new sequence number.
entry="$(ntfsinfo -F /file1.bin "$WORK/volume.img" 2>/dev/null | sed -n 's/^Dumping Inode \([0-9]*\).*/\1/p')"
python3 -I - "$WORK/volume.img" "$entry" <<'PY'
import struct, sys
path, entry = sys.argv[1], int(sys.argv[2])
with open(path, "r+b") as f:
    boot = f.read(512)
    cluster = struct.unpack_from("<H", boot, 0x0B)[0] * boot[0x0D]
    size = struct.unpack_from("<b", boot, 0x40)[0]
    record = (1 << -size) if size < 0 else size * cluster
    at = struct.unpack_from("<Q", boot, 0x30)[0] * cluster + entry * record
    f.seek(at)
    header = f.read(0x12)
    assert header[:4] == b"FILE", "no FILE record at the entry ntfsinfo gives"
    # Offset 0x10, inside the first stride but not its last two bytes: the
    # fixups stay valid.
    f.seek(at + 0x10)
    f.write(struct.pack("<H", struct.unpack_from("<H", header, 0x10)[0] + 1))
PY
rm -f "$WORK/read.bin"
if wine "$EXE" T '\file1.bin' "Z:$WORK/read.bin" >/dev/null 2>&1; then status=1; else status=0; fi
check $status "record reused: extraction not refused"
[[ ! -e "$WORK/read.bin" ]] && status=0 || status=1
check $status "record reused: a copy was left"

echo "$checks check(s), $failures failure(s)"
[[ $failures == 0 ]]
