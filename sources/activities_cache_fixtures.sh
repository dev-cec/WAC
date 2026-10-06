#!/usr/bin/env bash
# activities_cache_fixtures.sh — the test data of activities_cache_test: a
# real Windows 10 Timeline database (ActivitiesCache.db, 112 activities of
# every kind: applications, pages, focus time) from the public test data of
# the plaso project (Apache 2.0), and what Python's own SQLite reads in it.
#
# The file is not versioned in WAC: it is downloaded, pinned by its SHA-256,
# refused if it differs. The reference is one JSON object per row of
# Activity and ActivityOperation, each column converted by the rules of
# activities_cache.h written again here, independently of WAC: Unix times as
# "<column>Utc" in ISO 8601, GUIDs from their .NET byte order (uuid bytes_le),
# JSON payloads parsed, other blobs as text or hexadecimal; NULL, zero dates,
# zero GUIDs and empty texts left out.
#
# Needs: curl, python3.
# Usage: activities_cache_fixtures.sh <folder>
#        → <folder>/ActivitiesCache.db, <folder>/activities-reference.jsonl
set -euo pipefail
OUT="${1:?usage: activities_cache_fixtures.sh <folder>}"
BASE=https://raw.githubusercontent.com/log2timeline/plaso/main/test_data
mkdir -p "$OUT"
curl -s -f -L -o "$OUT/ActivitiesCache.db" "$BASE/windows/ActivitiesCache.db"
echo "95811eebd1ea3ec0244bda5c5200266861cfcf405eed687dce96af8589836888  $OUT/ActivitiesCache.db" \
  | sha256sum -c --quiet - || { echo "ActivitiesCache.db: SHA-256 differs, refused" >&2; exit 1; }
python3 - "$OUT" > "$OUT/activities-reference.jsonl" <<'PY'
import datetime, json, os, sqlite3, sys, uuid
db = sqlite3.connect("file:" + os.path.join(sys.argv[1], "ActivitiesCache.db") + "?mode=ro", uri=True)

def blob(value):
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex().upper()
    try:
        return json.loads(text)
    except ValueError:
        printable = text and all(c in "\t\r\n" or ord(c) >= 0x20 for c in text)
        return text if printable else value.hex().upper()

for table in ("Activity", "ActivityOperation"):
    types = {r[1]: r[2].upper() for r in db.execute(f"PRAGMA table_info({table})")}
    cursor = db.execute(f"SELECT * FROM {table}")
    names = [d[0] for d in cursor.description]
    for row in cursor:
        record = {"Table": table}
        for name, value in zip(names, row):
            kind = types[name]
            if value is None:
                continue
            if kind == "DATETIME":
                if value > 0:
                    instant = datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
                    record[name + "Utc"] = instant.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
            elif kind == "GUID" and isinstance(value, bytes) and len(value) == 16:
                if any(value):
                    record[name] = "{" + str(uuid.UUID(bytes_le=value)).upper() + "}"
            elif "INT" in kind:
                record[name] = value
            elif kind == "BLOB" or isinstance(value, bytes):
                record[name] = blob(value)
            elif value != "":
                record[name] = value
        print(json.dumps(record, ensure_ascii=False))
PY
echo "$(wc -l < "$OUT/activities-reference.jsonl") reference record(s) in $OUT"
