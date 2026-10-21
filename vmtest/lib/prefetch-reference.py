#!/usr/bin/env python3
"""prefetch-reference.py — what libscca reads in Prefetch files: the
independent reading check-json.py confronts prefetchs.json with.

libscca (pyscca, written by Joachim Metz, independently of WAC) decodes the
versions 17 to 31, compressed ones too. Run with the interpreter of
vmtest/tools/scca-venv (pip install libscca-python), not versioned.

Usage: prefetch-reference.py <folder of .pf files> <output file>

One line per file it reads:
  name|version|hash|run count|last runs (FILETIME, comma-separated)|volume serials|file names
A file libscca cannot read gives "name|error|<message>".
"""
import os
import sys

import pyscca


def describe(path):
    """The line of one Prefetch file, as libscca reads it."""
    prefetch = pyscca.open(path)
    try:
        runs = []
        # Version 23 keeps one run time, 26 and later eight; libscca says how
        # many it reads by refusing the next one.
        for i in range(8):
            try:
                value = prefetch.get_last_run_time_as_integer(i)
            except (IOError, OSError, IndexError):
                break
            if value:
                runs.append(str(value))
        serials = [f"{prefetch.get_volume_information(i).serial_number:08X}" for i in range(prefetch.number_of_volumes)]
        # The names libscca reads, the empty ones aside: a file name section
        # padded with zeros (a Prefetch Windows was rewriting while it was
        # copied, measured on Vista: 642 names, 2164 strings) is split by
        # libscca into as many empty strings, which are no file.
        names = sum(1 for i in range(prefetch.number_of_filenames) if prefetch.get_filename(i))
        return "|".join([os.path.basename(path), str(prefetch.format_version), f"{prefetch.prefetch_hash:08X}",
                         str(prefetch.run_count), ",".join(runs), ",".join(serials), str(names)])
    finally:
        prefetch.close()


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    folder, output = sys.argv[1], sys.argv[2]
    lines = []
    for name in sorted(os.listdir(folder)):
        if not name.lower().endswith(".pf"):
            continue
        try:
            lines.append(describe(os.path.join(folder, name)))
        except (IOError, OSError) as error:
            lines.append(f"{name}|error|{error}")
    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


if __name__ == "__main__":
    main()
