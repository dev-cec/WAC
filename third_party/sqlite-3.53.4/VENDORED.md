# SQLite 3.53.4 — copied into WAC

- Origin: https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip
- SHA3-256 of that archive: `628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e`
  (the value sqlite.org publishes on its download page, checked on 2026-10-01).
  Its SHA-256: `1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d`.
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
