#!/usr/bin/env python3
"""fat-compare.py — WAC's FAT and exFAT reader against an independent one.

Compares the present entries `fat_test.exe <image>` lists (path, size, folder)
with those dissect.fat (Fox-IT, written independently of WAC) reads in the
same image. dissect.fat does not show deleted entries: those are checked
against what the harness deleted (place-file-artefacts.ps1).

WHY. A reader one byte off gives valid, wrong names and sizes; only a second
reader of the same bytes shows it.

Usage: fat-compare.py <image> <fat_test listing of that image>
       (dissect.fat installed: pip install dissect.fat)
"""
import sys

from dissect.fat import exfat, fat


def dissect_entries(path):
    """{path: (size, is_directory)} of the present entries, as dissect.fat reads them."""
    out = {}
    with open(path, "rb") as fh:
        if fh.read(11)[3:11] == b"EXFAT   ":
            fh.seek(0)
            volume = exfat.ExFAT(fh)

            def walk(entries, prefix):
                for name, (entry, children) in entries.items():
                    if name == "/":
                        walk(children or {}, prefix)
                        continue
                    name = name.rstrip("/")
                    out[prefix + "\\" + name] = (0 if children is not None else entry.stream.data_length, children is not None)
                    if children is not None:
                        walk(children, prefix + "\\" + name)
            walk(volume.files, "")
        else:
            fh.seek(0)
            volume = fat.FATFS(fh)

            def walk(directory, prefix):
                for entry in directory.iterdir():
                    if entry.name in (".", ".."):
                        continue
                    is_dir = entry.is_directory()
                    out[prefix + "\\" + entry.name] = (0 if is_dir else entry.size, is_dir)
                    if is_dir:
                        walk(entry, prefix + "\\" + entry.name)
            walk(volume.root, "")
    return out


def main():
    image, listing = sys.argv[1], sys.argv[2]
    mine = {}
    with open(listing, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or "|" not in line:
                continue
            path, size, deleted, directory = line.rstrip("\n").split("|")[:4]
            if deleted == "0":
                mine[path] = (0 if directory == "1" else int(size), directory == "1")
    theirs = dissect_entries(image)
    # A volume label is an entry for dissect.fat, a label for WAC.
    theirs = {p: v for p, v in theirs.items() if not (p.count("\\") == 1 and v == (0, False) and p[1:].isupper() and p not in mine)}
    wrong = sorted(set(mine.items()) ^ set(theirs.items()))
    for w in wrong[:10]:
        print(f"  ❌ {w[0]}: WAC {mine.get(w[0])}, dissect {theirs.get(w[0])}")
    print(f"{'✅' if not wrong else '❌'} {len(theirs)} present entries compared, {len(wrong)} difference(s)")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
