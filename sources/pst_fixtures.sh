#!/usr/bin/env bash
# pst_fixtures.sh — the test data of pst_test: real PST and OST files, and
# what pypff — libpff's own reader, written independently of WAC — reads in
# each of their messages.
#   - java-libpst's test files (Apache 2.0): two Unicode PSTs and an OST of
#     Outlook 2013 (version 36: 4 KiB pages, compressed blocks);
#   - a PST of the EDRM Enron v2 corpus as published by intellekthq on
#     Hugging Face (CC-BY 3.0 US; privacy-sensitive items removed, free space
#     overwritten): 246 messages, 65 attachments, and 4 items pypff itself
#     cannot read, where WAC's robustness is tried.
# The files are not versioned in WAC: they are downloaded, pinned by their
# SHA-256, refused if they differ. One reference line per item pypff reads:
#   file|identifier|subject|sender|delivery|submit|attachments|body
# the times as FILETIME integers (0 for none), the attachments as
# "name:size:sha256" joined by ";", the body as the SHA-256 of its plain text
# (empty for none); an attachment that is an embedded object, the bytes of its
# subnode as pypff reads them. An item pypff cannot read gives
# "file|-|unreadable".
#
# Needs: curl, and a Python with pypff (pip install libpff-python), given by
# $PYTHON (python3 by default).
# Usage: pst_fixtures.sh <folder>   → <folder>/*.pst|*.ost, <folder>/pst-reference.txt
set -euo pipefail
OUT="${1:?usage: pst_fixtures.sh <folder>}"
PYTHON="${PYTHON:-python3}"
LIBPST=https://raw.githubusercontent.com/rjohnsondev/java-libpst/develop/src/test/resources
ENRON=https://huggingface.co/datasets/intellekthq/enron-ferc-pst/resolve/main/data
mkdir -p "$OUT"
while read -r name url digest; do
  [[ -f "$OUT/$name" ]] || curl -s -f -L -o "$OUT/$name" "$url"
  echo "$digest  $OUT/$name" | sha256sum -c --quiet - || { echo "$name: SHA-256 differs, refused" >&2; exit 1; }
done <<LIST
dist-list.pst $LIBPST/dist-list.pst c86841da106036b5abe5a2141dc7644cbb2bf8b504873515eb35a2efeb8c28ac
passworded.pst $LIBPST/passworded.pst e1085e210bc823fcfbdd1220da08b51423f3c39301c563a99dde71895f2af217
example-2013.ost $LIBPST/example-2013.ost b18ff390d0c22273029ee580ab6025976af69a4f84e276d1b1c01a988650853d
zl_south-s_000.pst $ENRON/zl_south-s_000.pst 852f2090a3a44df3294baab6d6a432cbeecf6bfa2c92944e8c89ffcca14104ab
LIST
"$PYTHON" - "$OUT" > "$OUT/pst-reference.txt" <<'PY'
import hashlib, os, sys, pypff
folder = sys.argv[1]

def clean(text):
    return (text or "").replace("|", " ").replace("\n", " ").replace("\r", " ")

def recorded(item, identifier):
    """A string property as pypff reads it in the item's first record set: for
    the items it does not type as messages (a free/busy item has no subject
    attribute, though the file holds one)."""
    if item.number_of_record_sets:
        rs = item.get_record_set(0)
        for i in range(rs.number_of_entries):
            e = rs.get_entry(i)
            if e.entry_type == identifier and e.value_type in (0x1E, 0x1F):
                return e.data_as_string
    return ""

def walk(name, f):
    for i in range(f.number_of_sub_messages):
        try:
            m = f.get_sub_message(i)
            attachments = []
            for k in range(getattr(m, "number_of_attachments", 0) or 0):
                a = m.get_attachment(k)
                data = a.read_buffer(a.size) if a.size else b""
                attachments.append(f"{clean(a.long_filename)}:{a.size}:{hashlib.sha256(data).hexdigest()}")
            body = getattr(m, "plain_text_body", None)
            subject = m.subject if hasattr(m, "subject") else recorded(m, 0x0037)
            sender = m.sender_name if hasattr(m, "sender_name") else recorded(m, 0x0C1A)
            print("|".join([name, str(m.identifier), clean(subject), clean(sender),
                            str(m.get_delivery_time_as_integer() or 0) if hasattr(m, "get_delivery_time_as_integer") else "0",
                            str(m.get_client_submit_time_as_integer() or 0) if hasattr(m, "get_client_submit_time_as_integer") else "0",
                            ";".join(attachments), hashlib.sha256(body).hexdigest() if body else ""]))
        except OSError:
            print(f"{name}|-|unreadable")
    for i in range(f.number_of_sub_folders):
        walk(name, f.get_sub_folder(i))

for name in ("dist-list.pst", "passworded.pst", "example-2013.ost", "zl_south-s_000.pst"):
    p = pypff.file()
    p.open(os.path.join(folder, name))
    walk(name, p.get_root_folder())
    p.close()
PY
echo "$(wc -l < "$OUT/pst-reference.txt") items -> $OUT/pst-reference.txt"
