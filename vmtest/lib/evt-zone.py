"""evt-zone.py — the zone in force a classic System log (.evt, Windows XP and
Server 2003) says, read here independently of WAC (backlog B-077): its
EventLog 6005 (the log service started, at each boot), 6006 (stopped, at each
shutdown) and 6013 (uptime), whose last string is "<standard offset> <standard
name>" ("-60 Romance Standard Time": measured on Server 2003, 2026-11-10).

The file WAC collected (its working copy, read on the key) is walked from the
end-of-file record (0x28 bytes, 0x11111111 … 0x44444444), which holds the
true offset of the oldest record and the next record number: on a log taken
raw while the service runs, the header's are not always written. A record
that reaches the end of the file goes on right after the 0x30-byte header.

Usage: python3 evt-zone.py <SysEvent.evt>
Prints one line per such event, oldest first: record|writtenUtc|eventId|lastString
"""
import datetime
import struct
import sys

HEADER = 0x30
EOF_MARKS = struct.pack("<IIII", 0x11111111, 0x22222222, 0x33333333, 0x44444444)
ZONE_EVENTS = (6005, 6006, 6013)


def wrapped(data, offset, size):
    """size bytes from offset, past the file's end going on after the header."""
    out = b""
    while len(out) < size:
        if offset >= len(data):
            offset = HEADER
        take = min(size - len(out), len(data) - offset)
        out += data[offset:offset + take]
        offset += take
    return out, offset


def utf16z(record, at):
    """A null-terminated UTF-16 string of the record, and the offset after it."""
    end = at
    while end + 1 < len(record) and record[end:end + 2] != b"\0\0":
        end += 2
    return record[at:end].decode("utf-16le", "replace"), end + 2


def main():
    data = open(sys.argv[1], "rb").read()
    eof = data.find(EOF_MARKS, HEADER)
    if eof < 4:
        sys.exit("no end-of-file record")
    begin, _end, current, oldest = struct.unpack_from("<IIII", data, eof + 16)
    offset, number = begin, oldest
    while number < current:
        head, _ = wrapped(data, offset, 8)
        length, signature = struct.unpack("<I4s", head)
        if signature != b"LfLe" or length < 0x38 or length > len(data):
            break
        record, offset = wrapped(data, offset, length)
        (record_number, _generated, written, event_id, _type, strings, _category, _flags,
         _closing, string_offset) = struct.unpack_from("<IIIIHHHHII", record, 8)
        number = record_number + 1
        source, _ = utf16z(record, 0x38)
        if source != "EventLog" or event_id & 0xFFFF not in ZONE_EVENTS or not strings:
            continue
        at, last = string_offset, ""
        for _ in range(strings):
            if at >= len(record):
                break
            last, at = utf16z(record, at)
        instant = datetime.datetime.fromtimestamp(written, datetime.timezone.utc)
        print(f"{record_number}|{instant:%Y-%m-%dT%H:%M:%S}.0000000Z|{event_id & 0xFFFF}|{last}")


if __name__ == "__main__":
    main()
