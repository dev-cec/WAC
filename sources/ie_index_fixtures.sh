#!/usr/bin/env bash
# ie_index_fixtures.sh — the test data of ie_index_dat_test: four real
# index.dat files (MSIE Cache File 5.2) from the public test data of the plaso
# project (Apache 2.0), and what pymsiecf — libmsiecf's own reader, written
# independently of WAC — reads in each of their records.
#
# The files are not versioned in WAC: they are downloaded, pinned by their
# SHA-256, refused if they differ. One reference line per record:
#   file|offset|kind|recovered|location|filename|directory|primary|secondary|expiry|checked|hits|datasize
# (kind URL, REDR or LEAK; directory -1 for none; times as integers).
#
# Needs: curl, and a Python with pymsiecf (pip install libmsiecf-python),
# given by $PYTHON (python3 by default).
# Usage: ie_index_fixtures.sh <folder>   → <folder>/*.dat, <folder>/ie-index-reference.txt
set -euo pipefail
OUT="${1:?usage: ie_index_fixtures.sh <folder>}"
PYTHON="${PYTHON:-python3}"
BASE=https://raw.githubusercontent.com/log2timeline/plaso/main/test_data
mkdir -p "$OUT"
while read -r name path digest; do
  curl -s -f -L -o "$OUT/$name" "$BASE/$path"
  echo "$digest  $OUT/$name" | sha256sum -c --quiet - || { echo "$name: SHA-256 differs, refused" >&2; exit 1; }
done <<'LIST'
history.dat msiecf/History.IE5/index.dat d54847adc8be889cb687bd7c60af50153d310eb3fc32a79d20c93eecb655bfc1
content.dat msiecf/Content.IE5/index.dat d6f7d3c4cd1b05b637dca8d41fcb652cc3809a0650181e447bf609bbc81d7db9
mshist.dat MSHist012013031020130311-index.dat e2a4034e50beb669dbd9dddfecfde756e106c32629eefa8330e3cde7af6fceef
nfury.dat msiecf/nfury_index.dat 0cb5e8fc5662aac8591fc34c3adf20305a7f272764069eb6b0ef8d11322c2e94
LIST
"$PYTHON" - "$OUT" > "$OUT/ie-index-reference.txt" <<'PY'
import os, sys, pymsiecf
folder = sys.argv[1]
for name in ("history.dat", "content.dat", "mshist.dat", "nfury.dat"):
    f = pymsiecf.file()
    f.open(os.path.join(folder, name))
    items = [(f.get_item(i), 0) for i in range(f.number_of_items)]
    items += [(f.get_recovered_item(i), 1) for i in range(f.number_of_recovered_items)]
    for item, recovered in items:
        kind = {"url": "URL", "redirected": "REDR", "leak": "LEAK"}[type(item).__name__]
        location = getattr(item, "location", None) or ""
        filename = getattr(item, "filename", None) or ""
        directory = getattr(item, "cache_directory_index", -1)
        directory = -1 if directory is None or directory < 0 else directory
        if kind == "URL":
            times = (item.get_primary_time_as_integer(), item.get_secondary_time_as_integer(),
                     item.get_expiration_time_as_integer(), item.get_last_checked_time_as_integer(), item.number_of_hits,
                     len(item.data or b""))
        else:
            times = (0, 0, 0, 0, 0, 0)
        print("|".join(str(v) for v in (name, item.offset, kind, recovered, location, filename, directory) + times))
    f.close()
PY
echo "$(wc -l < "$OUT/ie-index-reference.txt") records -> $OUT/ie-index-reference.txt"
