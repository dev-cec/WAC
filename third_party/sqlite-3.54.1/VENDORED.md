# SQLite 3.54.1 — copied into WAC

- Origin: https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip
- SHA3-256 of `sqlite3.c` in it: `e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81`
  (the value sqlite.org publishes in its release history, checked on 2026-11-04).
  SHA-256 of the archive: `0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9`.
- Licence: public domain (stated in the header of `sqlite3.c`).
- Files kept, UNMODIFIED: `sqlite3.c` and `sqlite3.h`, the amalgamation. The
  command-line shell (`shell.c`) and the extension header are left out.

## Why a dependency

The browsers keep their history, downloads and searches in SQLite
databases (Chromium's `History`, Firefox's `places.sqlite`), so do the
Windows timeline (`ActivitiesCache.db`) and many web applications. Reading
the format by hand — B-tree pages, overflow chains, the WAL and the
rollback journal — would be a second, unproven implementation of a format
whose reference implementation is small, public domain, and the most
tested library there is. Decision of 2026-09-30 (backlog B-010, B-016).

## How WAC uses it

Never on the examined machine, never on an exhibit: a database is opened on
a private copy, made in the working directory with its `-wal` or `-journal`,
so that SQLite replays them as Windows' applications would — as WAC replays
the hives' logs. See `sqlite_reader.h`.

## Build

Compiled into WAC.exe by `build-windows.sh`, as C, with the options listed
there (thread-safety off — one reader at a time —, extension loading and
deprecated interfaces left out). To update: replace both files from a new
amalgamation, record its SHA3-256 here, rebuild, rerun `file_artefacts_test`.

## Why this version

3.53.4 is affected by CVE-2026-119371, 119375, 119376 and 119591, which a forged
database or its WAL can reach (stack exhaustion through a view, uninitialised
page-cache memory read through an undersized WAL). The FTS, R-Tree and session
CVEs of the same list concern extensions not compiled here. CVE-2026-119586 is
the command-line shell's, which is left out. `sqlite_reader.cpp` also keeps views
and triggers from running on an examined database.
