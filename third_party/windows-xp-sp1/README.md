# Exports of Windows XP SP1 — the reference WAC32.exe is checked against

`exports.txt` lists every function six system DLLs of **Windows XP
Professional SP1** (x86, 5.1.2600.1106, `xpsp1.020828-1920`) export by name:
`advapi32.dll`, `kernel32.dll`, `msvcrt.dll`, `psapi.dll`, `secur32.dll` and
`wtsapi32.dll` — the only ones WAC32.exe imports. `psapi.dll` (the module list
of each process) was read from the system folder of the XP SP1 test machine,
its version resource giving the same build. One `dll function` per line.

**Why.** A program does not load on a Windows that lacks one function it
imports. `build-windows.sh` confronts the import table of WAC32.exe with this
list at every build: an import absent from it — a function, or a DLL — fails
the build, instead of being found on the examined machine.

**Origin.** Names only, no code: read from the DLLs of the installation medium
(`I386\*.DL_`, expanded with `cabextract`) by

    i686-w64-mingw32-objdump -p <dll>      # table [Ordinal/Name Pointer]

To add a DLL, or to check against another version of Windows, list its exports
the same way.
