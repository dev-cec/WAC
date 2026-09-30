#!/usr/bin/env python3
"""ese-compare.py — WAC's ESE reader against an independent one.

Compares, value by value, what `ese_test.exe <database>` dumps (one line per
record: table, tab, JSON object) with what dissect.esedb (Fox-IT, written
independently of WAC) reads in the same file. Values are brought to WAC's
forms: integers, reals in text (%.9g / %.17g), GUIDs in braces, binary in
upper-case hexadecimal, OLE dates in ISO 8601 UTC (to the second: WAC rounds
as VariantTimeToSystemTime does).

WHY. A reader one byte off gives valid, wrong values; only a second reader of
the same bytes shows it.

Usage: ese-compare.py <database> <ese_test dump>
       (dissect.esedb installed: pip install dissect.esedb)
"""
import datetime
import json
import struct
import sys

from dissect.esedb import EseDB

OLE_EPOCH = datetime.datetime(1899, 12, 30)


def wac_form(column, value):
    """A value read by dissect, in the form WAC gives it."""
    if value is None:
        return None
    if isinstance(value, list):
        return [wac_form(column, v) for v in value]
    kind = column.type.name
    if kind == "DateTime":
        days = struct.unpack("<d", struct.pack("<q", value))[0]
        moment = OLE_EPOCH + datetime.timedelta(days=days)
        return moment.replace(microsecond=0) + datetime.timedelta(seconds=round(moment.microsecond / 1e6))
    if kind == "IEEESingle":
        return "%.9g" % value
    if kind == "IEEEDouble":
        return "%.17g" % value
    if kind == "GUID":
        return "{" + str(value).upper().strip("{}") + "}"
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex().upper()
    return value


def same(column, mine, theirs):
    if column.type.name == "DateTime" and isinstance(mine, str) and isinstance(theirs, datetime.datetime):
        return datetime.datetime.strptime(mine[:19], "%Y-%m-%dT%H:%M:%S") == theirs.replace(tzinfo=None)
    return mine == theirs


def main():
    path, dump = sys.argv[1], sys.argv[2]
    mine = {}
    with open(dump, encoding="utf-8") as f:
        for line in f:
            table, _, record = line.rstrip("\n").partition("\t")
            mine.setdefault(table, []).append(json.loads(record))
    db = EseDB(open(path, "rb"))
    compared = differences = 0
    for table in db.tables():
        columns = {c.name: c for c in table.columns}
        theirs = []
        for record in table.records():
            values = {}
            for name, column in columns.items():
                try:
                    value = wac_form(column, record.get(name))
                except Exception:
                    value = None
                if value not in (None, "", []):
                    values[name] = value
            if values:
                theirs.append(values)
        ours = mine.get(table.name, [])
        if len(ours) != len(theirs):
            print(f"  ❌ {table.name}: {len(ours)} record(s) read by WAC, {len(theirs)} by dissect.esedb")
            differences += 1
            continue
        for index, (a, b) in enumerate(zip(ours, theirs)):
            for name in set(a) | set(b):
                compared += 1
                if not same(columns[name], a.get(name), b.get(name)):
                    differences += 1
                    if differences <= 10:
                        print(f"  ❌ {table.name}[{index}].{name}: WAC {a.get(name)!r}, dissect {b.get(name)!r}")
    print(f"{'✅' if not differences else '❌'} {compared} value(s) compared, {differences} difference(s)")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
