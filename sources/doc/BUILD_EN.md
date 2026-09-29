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

**Windows**: install MSYS2 (https://www.msys2.org), open the **MSYS2 MINGW64**
shell (not UCRT64: its runtime would change `WAC.exe`'s imports), then:
```bash
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-binutils libiconv git
```

## Building
From the root of the repository, in the Linux or MSYS2 MINGW64 shell:
```bash
./build-windows.sh            # incremental
./build-windows.sh --clean    # from scratch
./build-windows.sh --test     # also builds raw_hive_test.exe and the harnesses of build-windows/tests/
# -> build-windows/WAC.exe
```

The script picks the toolchain by the system — the compiler prefixed
`x86_64-w64-mingw32-` on Linux, MSYS2's on Windows — and checks that it does
produce 64-bit Windows programs (`-dumpmachine`). Never by fallback: on Linux,
an unprefixed `g++` would produce a Linux program.

The build is reproducible for a given GCC version: the same sources give the
same `WAC.exe`, byte for byte. Two different GCC versions (the Linux
distribution's and MSYS2's) may give two different executables, both correct:
`bin/SHA256SUMS`, produced by the delivered build, is the reference.

## What the script does
1. Converts `WAC.rc` (UTF-16) to UTF-8 for `windres`, normalises its paths
   (icon) and compiles the resource (version, icon, reference `wac.yml`).
2. Compiles every translation unit found in `sources/` (except `*_test.cpp`)
   with a **force-included compatibility header**.
3. Compiles libyaml (reading of `wac.yml`, see below) as C.
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
`sources/doc/html` with the same version), commit.

## Compatibility pieces (`third_party/` folder)
| Item | Role |
|---|---|
| `compat-include/wac_mingw_compat.h` | Force-included: `<filesystem>`, and the constants the MinGW headers lack and WAC uses. |
| `libyaml-0.2.5/` | Reading of `wac.yml`: the 4 parser files of libyaml 0.2.5, unmodified (origin and fingerprint in `VENDORED.md`). WAC's only third-party library. |

## Verified standalone
`WAC.exe` imports only: `ADVAPI32, KERNEL32, msvcrt, Secur32, WTSAPI32` — what
querying the running system requires. **No MinGW DLL** (static runtime); no
`offreg.dll` (the hives are read by `sources/offline_registry.cpp`); no `ole32`,
`oleaut32`, `propsys` or `shell32` (GUIDs, SIDs, OLE dates, property names and
the command line are handled by WAC itself, checked against Windows by
`system_conversions_test`). The full list of imported functions, and what it
proves, is in the harmlessness file. Check with:
```bash
x86_64-w64-mingw32-objdump -p build-windows/WAC.exe | grep "DLL Name"   # in MSYS2: objdump
```
