# Building WAC (Linux and Windows, MinGW-w64)

*Version française : [BUILD_FR.md](BUILD_FR.md)*

One procedure, `build-windows.sh`, the same on Linux and on Windows: it
produces `WAC.exe` (PE32+ x64), a **standalone** executable — the C++ runtime
is linked statically, and the program depends only on **Windows system DLLs**
(present on every target). The MSVC / Visual Studio build has been removed:
two toolchains meant two programs to verify, and the Visual Studio project,
which did not discover the sources, had already broken several commits
unnoticed.

## Requirements (once)

**Linux** (cross-compilation, no Windows machine needed):
```bash
sudo apt-get install -y g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools
```

**Windows** — optional: the `WAC.exe` published in `bin/` is the Linux
build's, and that is the one to download. To build on Windows anyway, two
installations:

1. **Git for Windows** (https://git-scm.com), needed anyway to clone the
   repository: it also brings the bash and the Unix tools (`sed`, `grep`,
   `tar`, `sha256sum`…) `build-windows.sh` needs. The repository keeps its
   `.sh` scripts with LF line endings (`.gitattributes`), even with Git for
   Windows' default setting (`core.autocrlf=true`).
2. **The MinGW-Builds compiler** (niXman's project):
   `x86_64-13.2.0-release-win32-seh-msvcrt-rt_v11-rev1.7z`
   (https://github.com/niXman/mingw-builds-binaries/releases, release
   `13.2.0-rt_v11-rev1`), unpacked with 7-Zip into `C:\mingw-win32` — or
   elsewhere, naming the folder in the `WAC_MINGW` variable. It is exactly
   Debian's toolchain: GCC 13.2.0, MinGW-w64 v11, **win32** threads,
   **msvcrt** runtime. No checksum is published; the one recorded for WAC is
   `15b914f38f2f2e2d6f7b9b8425ff22b7e406878b01920190b09ce0dd8259c6aa`.

Then, at the root of the repository, from `cmd`, PowerShell or a
double-click:
```
build-windows.cmd            :: or build-windows.cmd --test
```
`build-windows.cmd` only puts MinGW-Builds' compiler first in the path and
runs `build-windows.sh` in Git's bash: the build procedure stays one.

**Why this compiler and not another** — MSYS2's, for instance. The latter's
*thread model* is "posix": it links winpthreads
into `WAC.exe`, and with it **38 imports** WAC never calls but its import
table shows — `SetSystemTime`, `SetThreadContext`, `SuspendThread`,
`TerminateProcess`, `OpenProcess`, `SetProcessAffinityMask`… An analysis or
defence tool sees them: a wider footprint than the harmlessness file
describes, and names that draw attention on the examined machine. With
"win32" threads (Windows' own threads) those imports are gone: measured on
Windows, the same six DLLs as the Linux build, and eight msvcrt input/output
functions of difference (`_exit` on one side, `fgetpos`, `fsetpos`, `getwc`,
`putc`, `putwc`, `ungetwc`, `_filelengthi64` on the other). "win32" is the
thread model's name, not an architecture: the program is x86_64 either way.
The **msvcrt** runtime matters too: UCRT64 would change the imported DLLs
(`api-ms-win-crt-*`). `build-windows.sh` refuses any compiler whose thread
model is not "win32".

## Building
From the root of the repository, on Linux (on Windows: `build-windows.cmd`,
same options):
```bash
./build-windows.sh            # incremental
./build-windows.sh --clean    # from scratch
./build-windows.sh --test     # also builds raw_hive_test.exe and the harnesses of build-windows/tests/
# -> build-windows/WAC.exe
```

The script picks the toolchain by the system — the compiler prefixed
`x86_64-w64-mingw32-` on Linux, the `g++` of the path on Windows — and checks
that it does produce 64-bit Windows programs (`-dumpmachine`) with "win32"
threads (`-v`). Never by fallback: on Linux, an unprefixed `g++` would produce
a Linux program.

The build is reproducible for a given GCC version: the same sources give the
same `WAC.exe`, byte for byte. Two different GCC versions, or two builds of
the same one (Debian's and MinGW-Builds'), may give two different
executables, both correct:
`bin/SHA256SUMS`, produced by the delivered build, is the reference.

## What the script does
1. Compiles the resource (version, icon, reference `wac.yml`): `WAC.rc`, in
   UTF-8, given to `windres` as code page 65001, its line ends and the icon's
   path normalised.
2. Compiles every translation unit found in `sources/` (except `*_test.cpp`)
   with a **force-included compatibility header**.
3. Compiles libyaml (reading of `wac.yml`) and SQLite (the browsers' databases), see below, as C.
4. Links statically (`-static -static-libgcc -static-libstdc++`) against the
   system import libraries, **without a timestamp** (`--no-insert-timestamp`).
5. Checks the guards: static runtime, no network library nor domain name
   resolution function imported (refused otherwise).
6. Copies `WAC.exe`, `raw_hive_test.exe`, `wac.yml`, the scripts that verify a
   collection and `SHA256SUMS` to `bin`, and stages them (no commit).

## Version and release
Format `<major>.<minor>.<bugfix>`, written in `sources/WAC.rc` only
(executable's properties; WAC reads it back at run time). To release: commit
the sources, run `./bump-version.sh --bugfix|--minor|--major` (increments,
rebuilds, stages `WAC.rc` and `bin`, regenerates the code documentation
`doc/html` with the same version), commit.

## Adding a version of Windows, or an artefact format

What WAC knows of the versions of Windows lies in **one table**, `sources/artefact_catalogue.cpp`: for each key of `wac.yml`, the first build where the artefact exists, the one where it went away, its successive forms (location, format, converted or not) and since when its source is always there. No other file names a version.

- **A new version of Windows**: add its line to `windowsReleases()` (first and last known builds); if it moves or changes an artefact, add a form to that artefact; if it withdraws one, set `untilBuild`. Until then, the version is treated as the last one known and flagged as such in the investigation log.
- **A new format**: add the form with its signature (`signatures`: the internal version or magic number the piece carries) and `decoded` false until the decoder exists — the piece is then collected raw and its JSON says "unsupported format". The collector compares no version number itself: it asks `pieceFormat(key, signature)` before decoding. Write the decoder, then set `decoded` to true.
- **A source that is always there** (`expectedSinceBuild`): to be set only for a file or a key that every installation has AND that can be removed without stopping Windows. Its absence from a collection then becomes the status "expected but missing". Never for what exists only after an event, for a state of the running system or for a metadata file of the volume; server editions are still to be measured.
- **A new artefact**: its key in `wac.yml`, its switch in `artefactSwitches()` (`config.cpp`) and its line in the table — the test refuses a key missing on either side.

Then, from `sources/`:

```
g++ -std=c++17 -g -fsanitize=address,undefined -I. artefact_catalogue.cpp artefact_catalogue_test.cpp -o /tmp/act
/tmp/act wac.yml                                # the table is consistent, and wac.yml follows it
/tmp/act wac.yml --dump > /tmp/artefacts.tsv
../doc/artefact-table.py /tmp/artefacts.tsv     # the manuals' table, FR and EN
../doc/build-docs.sh ../doc/user/documentation_FR.tex ../doc/user/documentation_EN.tex
```

`artefact-table.py` stops if a text of the table has no French translation: add it to its dictionary.

## Compatibility pieces (`third_party/` folder)
| Item | Role |
|---|---|
| `compat-include/wac_mingw_compat.h` | Force-included: `<filesystem>`, and the constants the MinGW headers lack and WAC uses. |
| `libyaml-0.2.5/` | Reading of `wac.yml`: the 4 parser files of libyaml 0.2.5, unmodified (origin and fingerprint in `VENDORED.md`). |
| `sqlite-3.53.4/` | Reading of the browsers' databases: the SQLite 3.53.4 amalgamation, unmodified (origin, SHA3-256 and options in `VENDORED.md`); its one warning exclusion, `-Wno-unused-parameter`, is documented in `build-windows.sh`. |

## Verified standalone
`WAC.exe` imports only: `ADVAPI32, KERNEL32, msvcrt, Secur32, WTSAPI32` — what
querying the running system requires. **No MinGW DLL** (static runtime); no
`offreg.dll` (the hives are read by `sources/offline_registry.cpp`); no `ole32`,
`oleaut32`, `propsys` or `shell32` (GUIDs, SIDs, OLE dates, property names and
the command line are handled by WAC itself, checked against Windows by
`system_conversions_test`). The full list of imported functions, and what it
proves, is in the harmlessness file. Check with:
```bash
x86_64-w64-mingw32-objdump -p build-windows/WAC.exe | grep "DLL Name"   # on Windows (Git Bash, MinGW-Builds first in the path): objdump
```
