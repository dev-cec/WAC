# Building WAC from Linux (MinGW-w64 cross-compilation)

*Version française : [BUILD-LINUX_FR.md](BUILD-LINUX_FR.md)*

Produces `WAC.exe` (PE32+ x64) from Linux, **without a Windows machine**, as a
**standalone** executable: the C++ runtime is linked statically, and the program
depends only on **Windows system DLLs** (present on every target). The original
MSVC / Visual Studio build (`WAC.sln`) remains usable side by side.

## Requirements (once)
```bash
sudo apt-get install -y g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools
```

## Building
```bash
./build-windows.sh            # incremental
./build-windows.sh --clean    # from scratch
./build-windows.sh --test     # also builds raw_hive_test.exe (test tool)
# -> build-windows/WAC.exe
```

## What the script does
1. Generates the import library `third_party/offreg/liboffreg.a` (Offline
   Registry API, missing from MinGW) from `offreg.def`.
2. Converts `WAC.rc` (Visual Studio UTF-16) to UTF-8 for `windres`, normalises
   its paths (icon) and compiles the resource (version + icon).
3. Compiles every translation unit found in `WAC/` (except `*_test.cpp`) with a
   **force-included compatibility header**.
4. Links statically (`-static -static-libgcc -static-libstdc++`) against the
   system import libraries.

## Compatibility pieces (`third_party/` folder)
| Item | Role |
|---|---|
| `offreg/offreg.h` + `offreg.def` + `liboffreg.a` | Shim for the Offline Registry API (`offreg.dll`), missing from MinGW. x64 has a single calling convention. |
| `compat-include/wac_mingw_compat.h` | Force-included: `math.h` / `<filesystem>`, and constants MinGW lacks. |
| `compat-include/{Sddl,ShellAPI}.h` | Case aliases (MSVC is case-insensitive about include names, MinGW on Linux is not). |

## Keeping the Visual Studio project in step
Sources are discovered automatically by `build-windows.sh`, but **not** by the
Visual Studio project: every new `.cpp` / `.h` must also be added to
`WAC/WAC.vcxproj` and `WAC/WAC.vcxproj.filters`. Forgetting it once broke the
MSVC build for several commits, unnoticed because only the Linux build was
tested.

## Verified standalone
`WAC.exe` imports only: `ADVAPI32, KERNEL32, msvcrt, offreg, ole32, OLEAUT32,
PROPSYS, Secur32, WTSAPI32` — **no MinGW DLL** (static runtime). Check with:
```bash
x86_64-w64-mingw32-objdump -p build-windows/WAC.exe | grep "DLL Name"
```
