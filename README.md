# WAC (Windows Artefact Collector) 🛠️  
![version](https://img.shields.io/badge/Architecture-64bit-red)  
![CPP](https://img.shields.io/badge/C%2B%2B-VS2022_%7C_MinGW--w64-blue)

## :thumbsup: PROVIDER
This tool is developed by the Aerospace Cyber ​​Defense Center of Excellence of the Air and Space School in Salon-de-Provence on air base 701.

## 🔎 OVERVIEW

WAC collects forensic artefacts and event logs from a Windows machine and exports
them as **JSON**, ready to feed a monitoring or analysis pipeline.

Its guiding principle is **minimal footprint on the machine under examination**:
what WAC leaves behind should be as close to nothing as the task allows, and
whatever it cannot avoid must be written down.

## 🧭 HOW IT WORKS

**The volume is read raw, in read-only.** WAC opens `\\.\X:`, walks the `$MFT`
itself and copies the registry hives onto the collection medium. It does **not**
create a Volume Shadow Copy, and it does **not** use COM or WMI — all of which
left entries in the event logs of the examined machine.

**Artefacts are then parsed from those copies**, never from the live system.

**Nothing is assumed to be on `C:`.** The system drive is detected at run time,
and — this matters on machines with a system SSD and a separate data disk —
**user profiles may live on a different volume than Windows**. WAC groups the
files to extract by volume and reads each one in turn, so a profile under
`D:\Users\…` is collected like any other. The JSON always reports the original
path, with its real drive letter.

Detecting the drive costs nothing: the path comes from `GetSystemDirectoryW`,
already in the process's memory — no disk access, no log entry. Scanning each
volume's `$MFT` to find `\Windows` would be *more* intrusive, since it would
mean opening a handle on every volume, and that is the auditable part.

Only three readings remain live, because their subject *is* the instant of
collection and no file can hold it: **running processes**, **open sessions**, and
the current time. Everything else — event logs included — is read from a copy.

Two one-off registry reads also stay live, because they are a *prerequisite* of
reading offline: which volume letter to extract, and where the per-user hives
live.

## 📄 WHAT IS COLLECTED

System and account information, scheduled tasks, services **and drivers**,
running processes, open sessions, and optionally the event logs — plus the usual
registry and file artefacts: UserAssist, MUICache, BAM, USB devices, Shellbags,
MRU, Run keys, Shimcache, Amcache, jumplists, Prefetch and recent documents.

One file per artefact, plus `investigation.json` (see below). The output schema
is documented by the code itself: every field carries a doc comment explaining
what it is and, where it matters, why it is trustworthy.

## ▶️ USAGE

To minimize disk traces, this standalone tool should be run **as administrator** from a USB stick using the command:

```
usage: wac [--dump] [--events] [--md5] [--output=output] [--loglevel=2] [--debug]
        --help or /? : show this help
        --dump : add hexa value in json files for shellbags and LNK files
        --events : extract and parse the .evtx event logs (adds ~117 MB to the collection)
        --md5 : activate hash md5 computing for files referenced in artefacts
        --output=[directory name] : directory name to store output files starting from current directory. By default the directory is 'output'
        --loglevel=[0] : define level of details in logfile and activate logging in wac.log
        --debug : show the raw NTFS reader trace on stderr (path resolution,
                  index blocks, data runs). Separate from --loglevel, which logs
                  the COLLECTION rather than the low-level volume reading.

         loglevel = 0 => no logging
         loglevel = 1 => activate logging for each artefact type treated
         loglevel = 2 => activate logging for each artefact treated
         loglevel = 3 => activate logging for each subfunction called (used for debug only)
```

All options are optional and **disabled by default**.

**Default output files are saved in :**
- The `output` directory for standard results
- The `log` file for logs when using `--loglevel`

## 🛡️ FOOTPRINT ON THE EXAMINED MACHINE

This is the section to read before running WAC on a case. It lists **what WAC
does to the machine**, operation by operation — including what it cannot avoid.

### Gone: what WAC no longer does

| Removed | Traces it used to leave |
|---|---|
| **Volume Shadow Copy** | shadow creation/deletion in `Microsoft-Windows-VolumeSnapshot-Driver/Operational`; VSS service events (8224…) in `Application`; ESENT writer events; a mount point created and removed under `C:\Windows\Temp` |
| **COM / WMI** | `WinMgmt` service solicited, logged in `Microsoft-Windows-WMI-Activity/Operational`; possible Amcache entries |
| **Task Scheduler via COM** | `Schedule` service solicited, entries in `Microsoft-Windows-TaskScheduler/Operational`, one COM call per task (×217 on a normal machine) |
| **`winbrand.dll` loaded** | a module loaded into the collecting process just to obtain the OS display name |
| **`OpenProcess(PROCESS_ALL_ACCESS)` ×N** | one full-access handle per process — the loudest possible pattern, and the one endpoint protections watch |
| **`OpenService` ×N** | one handle per service on the Service Control Manager |
| **EventLog API (`wevtapi`)** | the `EventLog` service solicited for every channel — a service that can write its own entries *while being read*. The `.evtx` files are now extracted raw and parsed in-process; `wevtapi.dll` is no longer even linked |

### Remaining: what WAC still does, and what it costs

| Operation | Footprint |
|---|---|
| **Raw volume read** (`\\.\X:`, `GENERIC_READ`) | one handle **per volume actually holding artefacts** — usually one. **No file is opened**, so no last-access timestamp is touched and no directory is walked by the OS. If *object access auditing* is enabled, opening a volume can be logged (Security 4656/4663) |
| **Writing the collection** | on the **collection medium only** (the USB stick). Nothing is written to the examined disk |
| **Hive repair** | 8 bytes of the base block, **on the copy**. The original is never opened for writing; its fingerprint is recorded before the patch |
| **Service state** (1 × `EnumServicesStatusExW`) | one read-only query to the SCM over `\\.\pipe\ntsvcs`. No handle per service, no state change, so no `System` 7036 event |
| **Processes** (`CreateToolhelp32Snapshot`) | a kernel snapshot; no process handle is opened |
| **Process owners** (1 × `WTSEnumerateProcessesEx`) | solicits the Terminal Services service, once |
| **Sessions** (`LsaEnumerateLogonSessions`) | solicits LSASS; reads only |
| **Profile list** (1 registry key) | a local read of `HKLM\SOFTWARE\…\ProfileList`. No RPC |
| **Event logs** (`--events`) | reads `\Windows\System32\winevt\Logs\*.evtx` through the same raw volume handle as every other artefact — **no service is solicited**, and the parsing happens on the copy. The only cost left is the size: ~117 MB written to the collection medium |
| **MD5 hashing** (`--md5`) | opens each referenced file for reading. Windows disables last-access updates by default (`NtfsDisableLastAccessUpdate`), but on a system where they are enabled, **this does update them** |

### Unavoidable: the trace of running anything at all

No collection tool can escape these. They are listed so that an analyst
recognises WAC's own footprint instead of mistaking it for the suspect's
activity:

- **running `WAC.exe` is itself an execution**: it produces a Prefetch file for
  `WAC.exe`, an Amcache entry, and — if process-creation auditing is on — a
  Security 4688 event. Expect to find WAC in the very artefacts it collects;
- **plugging the USB stick** registers the device in `USBSTOR`,
  `MountedDevices` and the related logs;
- **logging on to run it** creates a logon session and its journal entries;
- reading 117 MB of event logs and several gigabytes of volume **evicts the
  file-system cache**, which alters the machine's performance state (not its
  disk contents).

`investigation.json` records each operation with the footprint it is expected to
leave, so this list can be checked against what actually happened during a given
collection.

### Data integrity rules

**Timestamps are emitted twice**, as `X` and `XUtc`. The local one carries the
**suspect's** UTC offset — not the examiner's — read from the `SYSTEM` hive. The
suffix always tells the truth about the value, which is why two separate
functions produce them rather than one function with a flag. A mismatch between
the suspect's time zone and the collecting host's is flagged in
`investigation.json`: it means either an image analysed elsewhere, or a clock
changed since the collection.

**A value that has no source is not emitted at all.** An empty key would read as
a failed read and could not be told apart from "the hive does not hold this
value". What could not be read is recorded in `investigation.json` instead.

**An object that cannot be decoded still yields its bytes.** An unknown shell
item, an unrecognised extension block, a value type not yet supported: the raw
hexadecimal is attached, so an analyst can decode later what WAC could not. The
alternative — dropping it silently — would make "we cannot read this" look like
"there was nothing there".

**Paths and values are stored raw.** Escaping happens once, at serialisation, so
what you read in the JSON is what was on the disk.

## 🧪 SAMPLE OUTPUT

Example of extracted system information:

```json
{
  "ComputerName": "N5-00-00022-P02",
  "DomainName": "ecole-air.fr",
  "OsArchitecture": "x64(AMD ou Intel)",
  "OsName": "Windows 11 Pro",
  "ProductNameRaw": "Windows 10 Pro",
  "Version": "10.0.26200.9457",
  "DisplayVersion": "25H2",
  "InstallDate": "2026-09-12T13:30:15+02:00",
  "InstallDateUtc": "2026-09-12T11:30:15Z",
  "LastBootUpTime": "2026-09-14T21:59:56+02:00",
  "LastBootUpTimeUtc": "2026-09-14T19:59:56Z",
  "BootTimeSource": "calculé depuis GetTickCount64 ; exclut les périodes de veille et d'hibernation, donc borne supérieure du démarrage réel",
  "CurrentTimeZoneId": "Romance Standard Time",
  "CurrentBias": -120,
  "DaylightInEffect": true,
  "TimeZoneSource": "ruche SYSTEM de la machine examinée"
}
```

Three details in this output are deliberate, and illustrate the rules above:

- **`ProductNameRaw` appears only when it differs from `OsName`.** Windows 11
  still reports "Windows 10" in `ProductName`; the build number is the only
  reliable discriminant. The raw value is kept so the correction stays verifiable.
- **`BootTimeSource` states a reservation.** The boot time is derived from
  `GetTickCount64`, which excludes sleep and hibernation: it bounds the observed
  activity, it does not prove the boot instant. Without that note, the value would
  read as a certainty.
- **`TimeZoneSource` says which clock was used.** Otherwise an unexpected offset
  would be indistinguishable from a read error.

## 🚀 PERFORMANCE

A collection takes about **2 minutes** with the default options, up to roughly
**20 minutes** with `--events`, and longer still with `--md5`. The figure depends
heavily on the hardware: USB 2 or USB 3, processor, memory, disk.

**`--md5` can take a long time if the disk holds large files — videos, for
instance.**

WAC no longer uses the Win32 API to read the event logs: Windows 11 makes that
API dramatically slower. Everything *except* the event logs took a handful of
seconds; the logs alone accounted for the minutes.

Event logs are now read from the `.evtx` files, and that removes the two costs
the API imposed:

- **the wait** — a query per channel, each round-tripping through a service, is
  replaced by a sequential read of the files plus in-process parsing;
- **the memory** — the API path built every record in memory before writing
  anything. Records are now written **as they are parsed**, so the memory used no
  longer depends on how big the logs are. Measured below: 1 281 MB against
  26 MB.

### Measured

**Time.** The last collection driven through the EventLog API, on the Windows 11
test VM, is recorded in its own `investigation.json`: the events step took
**581 s for 102 627 events** out of 596 s for the whole collection — 97 % of the
run, for a single artefact among the twenty-odd others. The offline parser, on 20 real logs
(57 MB, 96 076 records, cross-compiled build under `wine` on Linux), takes
**4.7 s**. The two do not run on the same machine and the second excludes the raw
extraction, so read this as an order of magnitude, not a ratio: seconds instead
of minutes, because nothing round-trips through a service any more.

**Memory.** This one *is* measured on identical data, which makes it a real
comparison: the same records, the same build, the same host — only the writing
strategy differs. `evtx_test --collecte` streams; `evtx_test --collecte-memoire`
reproduces the old strategy (every record built in memory, then serialised in one
block).

| Write strategy | Peak working set | Wall clock |
|---|---|---|
| in memory, then serialised (as the API path did) | **1 281 MB** | 5.7 s |
| streamed, one record at a time (now) | **26 MB** | 4.7 s |

A factor of **49**, and the two files come out **byte for byte identical**. The
point is not the ratio but the shape: the streamed figure does not grow with the
size of the logs, so it cannot reach the level where Windows starts paging — and
paging writes to `pagefile.sys`, on the disk one is trying not to modify.

The **~20 minutes** quoted above is the measured figure for the *old* API path;
the offline path has not yet been timed end to end on physical hardware.

What replaces them is the extraction itself: the `.evtx` files must be copied to
the collection medium first (~117 MB on an ordinary installation), and on a USB
stick that copy is the dominant cost. This is why `--events` remains **opt-in**:
without it, the logs are neither extracted nor parsed.

**Correctness, not just speed.** The parser was validated against 20 real logs,
record by record, using `python-evtx` as an independent implementation. Two
results are worth stating:

- on every log, WAC reads **at least** every record the reference reads — it
  never misses one;
- reading from the file also **fixed a wrong value the API produced**. The API
  path asked only for `Event/EventData/Data`; on an event that stores its data
  in `UserData` instead, that request fills nothing, and the value was read
  anyway — so the event inherited another event's data. On a real collection,
  *log cleared* (1102) — one of the most significant events of an intrusion —
  carried a path belonging to a different record. Valid JSON, right key, wrong
  value;
- on several logs it reads **considerably more**, because it does not trust the
  file header. A log closed abruptly — the normal state of a machine seized
  while running — under-reports its own chunk count: on one sample the header
  announced 3 chunks and 326 records where the file actually held 1 881
  continuous records spanning eight months. A single damaged chunk no longer
  ends the file either.

## 🧰 BUILD REQUIREMENTS

### Visual Studio 2022 (Windows)
- Requires **Windows SDK 10** and **Windows WDK 10**
- 📥 Download: [Microsoft WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- **Include path** and **lib path** of **project properties directories** must be updated with WDK correct path dependent of WDK installed version. Actually, the configured WDK version is 10.0.26100.0.

### Cross-compiling from Linux (MinGW-w64)
```bash
./build-windows.sh          # produces build-windows/WAC.exe, self-contained
./build-windows.sh --test   # also builds raw_hive_test.exe (raw NTFS reader)
```
The C++ runtime is linked statically: the executable depends only on Windows
system DLLs — which matters for a tool run from a USB stick on a machine one must
not install anything on. `offreg.dll` (offline registry API) ships with the tool;
its import library is generated at build time from the bundled `.def`.

`-Wall -Wextra` is enabled. The warnings that remain are deliberate: they mark
format fields that are decoded but not yet emitted, and serve as the to-do list
for format completeness.

## 🧪 AUTOMATED TESTING

`vmtest/` drives a Windows 11 VM through the **qemu-guest-agent**, with no
interaction at all: build on Linux → run as `NT AUTHORITY\SYSTEM` in the VM →
JSON pulled back to the host and checked.

What it validates: compilation, **termination**, JSON validity, and Windows path
consistency. What it does **not** validate: whether the values are *right*. A
wrong field under a correct key, a misread date or a parsing shift all produce
perfectly valid JSON.

That is what the **cross-checks** in `check-json.py` are for — comparing a value
*computed by WAC* against an *independent* value from the same collection. They
are what caught real errors in valid JSON: Prefetch path hashes against their own
file names, `X`/`XUtc` pairs holding the same wall-clock time, sessions starting
before boot, impossible service states, `$MFT` references pointing at reserved
entries. See `vmtest/README.md`.

### Testing the EVTX parser outside Windows

A VM only ever produces its own logs: one Windows version, all of them clean.
The BinXML decoder needs the opposite — old logs, forwarded logs, logs closed
abruptly, logs with a damaged chunk. `WAC/evtx_test.cpp` exists for that. It is
excluded from the build by the `_test.cpp` pattern and runs under `wine`, so a
journal can be replayed on the development machine:

```bash
# build the harness (cross-compiled, runs under wine)
cd WAC
x86_64-w64-mingw32-g++ -std=c++17 -O2 -municode -static -static-libgcc   -static-libstdc++ -DUNICODE -D_UNICODE -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00   -include ../third_party/compat-include/wac_mingw_compat.h   -I../third_party/offreg -I../third_party/compat-include   evtx.cpp evtx_test.cpp events.cpp xml_light.cpp tools.cpp quickdigest5.cpp   -o /tmp/evtx_test.exe -L../third_party/offreg -loffreg -lole32 -loleaut32   -luuid -lshlwapi -ladvapi32 -lshell32 -lversion -lwtsapi32 -lsecur32   -lpropsys -lntdll

# wine needs an offreg.dll in the working directory: tools.cpp imports it, and
# the harness never calls it. A stub built from the bundled .def is enough:
#   { echo '#include <windows.h>';
#     tail -n +3 ../third_party/offreg/offreg.def | sed '/^$/d' | while read -r f; do
#       echo "extern \"C\" __declspec(dllexport) DWORD $f(void){return 1;}"; done
#   } > /tmp/offreg_stub.cpp
#   x86_64-w64-mingw32-g++ -shared -o offreg.dll /tmp/offreg_stub.cpp

wine /tmp/evtx_test.exe "Z:/path/to/Security.evtx"          # summary per log
wine /tmp/evtx_test.exe "Z:/path/to/Security.evtx" 3        # + XML of 3 records
wine /tmp/evtx_test.exe "Z:/path/to/Security.evtx" --dump   # one record per line
```

`--dump` prints `record id<TAB>xml` in UTF-8, which is what makes an automated
comparison against another implementation possible — `python-evtx`, for example.
That comparison is what showed a chunk with a bad signature was ending the read
of the whole file: 14 records out of 270.

**Timing and memory** are measured with the third mode, which runs the *complete*
chain — raw file → BinXML → `xml_light` → `Event` → streamed JSON — on a
directory laid out like an extraction:

```bash
mkdir -p /tmp/tree/Windows/System32/winevt/Logs /tmp/out
cp *.evtx /tmp/tree/Windows/System32/winevt/Logs/
/usr/bin/time -v wine /tmp/evtx_test.exe --collecte "Z:/tmp/tree" "Z:/tmp/out"
```

It reports the number of logs, records and discarded records, and writes
`/tmp/out/events.json`. `time -v` gives the wall clock and the peak working set
— the figure that matters, since it is what used to cause paging. Reference run:
20 logs, 57 MB, 96 076 records, **4.7 s**, **26 MB peak**, 0 discarded.

`--collecte-memoire` runs the same chain but keeps every record in memory and
serialises in one block, the way the API path did. It exists to make the memory
claim checkable rather than asserted: same records, same build, same host, only
the write strategy differs. It should produce a **byte-for-byte identical**
`events.json` — which is also how `EcrivainJsonTableau` is verified against
`writeJsonFile`:

```bash
/usr/bin/time -v wine /tmp/evtx_test.exe --collecte-memoire "Z:/tmp/tree" "Z:/tmp/out2"
cmp /tmp/out/events.json /tmp/out2/events.json   # must be silent
```

## 📚 DOCUMENTATION

- **API documentation**: HTML, generated with Doxygen from the source comments
  (`Doxygen/Doxyfile`, output in `WAC/doc/html`). Regenerate with
  `cd Doxygen && doxygen Doxyfile`.
- `docs/BUILD-LINUX.md` — cross-compilation details.

The design rationale lives **in the code**, next to what it explains: each
non-obvious choice carries a comment saying why it is that way and what breaks
otherwise. Several of them record a defect that was actually hit — a hash
formatted without padding, a length compared against a hard-coded value, a
pointer read after being freed — because the cause is the part worth keeping.
