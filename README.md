# WAC (Windows Artefact Collector) 🛠️  
![version](https://img.shields.io/badge/Architecture-64bit-red)  
![CPP](https://img.shields.io/badge/C%2B%2B-VS2022_%7C_MinGW--w64-blue)

## :thumbsup: PROVIDER
This tool is developed by the Aerospace Cyber ​​Defense Center of Excellence of the Air and Space School in Salon-de-Provence on air base 701.

## 🔎 OVERVIEW

WAC collects forensic artefacts and event logs from a Windows machine and exports
them as **JSON** 🧾, ready to feed a monitoring or analysis pipeline.

Its guiding principle is **minimal footprint on the machine under examination**:
what WAC leaves behind should be as close to nothing as the task allows, and
whatever it cannot avoid must be written down.

## 🧭 HOW IT WORKS

**The volume is read raw, in read-only.** WAC opens `\\.\C:`, walks the `$MFT`
itself and copies the registry hives onto the collection medium. It does **not**
create a Volume Shadow Copy, and it does **not** use COM or WMI — all of which
left entries in the event logs of the examined machine.

**Artefacts are then parsed from those copies**, never from the live system. The
system drive letter is detected at run time, so Windows and the user profiles
need not be on `C:`.

Only three readings remain live, because their subject *is* the instant of
collection and no file can hold it: **running processes**, **open sessions**, and
the current time. Event logs are still read through the API — the last remaining
candidate for offline collection.

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

To minimize disk traces, this standalone tool should be run **as administrator**
🔐 from a USB stick using the command:

```
usage: wac [--dump] [--events] [--md5] [--output=output] [--loglevel=2] [--debug]
        --help or /? : show this help
        --dump : add hexa value in json files for shellbags and LNK files
        --events : converts events to json (long time)
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
- 📁 The `output` directory for standard results
- ⚠️ The `log` file for logs when using `--loglevel`

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

### Remaining: what WAC still does, and what it costs

| Operation | Footprint |
|---|---|
| **Raw volume read** (`\\.\C:`, `GENERIC_READ`) | one volume handle. **No file is opened**, so no last-access timestamp is touched and no directory is walked by the OS. If *object access auditing* is enabled, opening the volume can be logged (Security 4656/4663) |
| **Writing the collection** | on the **collection medium only** (the USB stick). Nothing is written to the examined disk |
| **Hive repair** | 8 bytes of the base block, **on the copy**. The original is never opened for writing; its fingerprint is recorded before the patch |
| **Service state** (1 × `EnumServicesStatusExW`) | one read-only query to the SCM over `\\.\pipe\ntsvcs`. No handle per service, no state change, so no `System` 7036 event |
| **Processes** (`CreateToolhelp32Snapshot`) | a kernel snapshot; no process handle is opened |
| **Process owners** (1 × `WTSEnumerateProcessesEx`) | solicits the Terminal Services service, once |
| **Sessions** (`LsaEnumerateLogonSessions`) | solicits LSASS; reads only |
| **Profile list** (1 registry key) | a local read of `HKLM\SOFTWARE\…\ProfileList`. No RPC |
| **Event logs** (`--events`) | **the heaviest remaining trace**: solicits the `EventLog` service, which can write its own entries *while being read*. This is the last collector still using an API instead of reading the `.evtx` files |
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

|                              **Architecture**                              | **Without events** | **With Events** |
|:--------------------------------------------------------------------------:|:------------------:|:---------------:|
| - Intel Core i7-8750 2.20 GHz<br>- 16 Go RAM<br>- Windows 11 home Edition <br>- Installed since 162 days |         ⌛5s        |   ⌛19 min 37s   |
| - Intel Core i7-8665U 2.11 GHz<br>- 16 Go RAM<br>- Windows 10 Pro 22H2<br>- Installed since 1323 days  |         ⌛9s        |   ⌛1 min 42s   |

**The option --md5 may be pretty long if you have big files on your hard drive, for exemple videos.**

The gap between the two "with events" figures is not a hardware one: it is
Windows 11 that makes the EventLog API dramatically slower. Everything *except*
the event logs takes a handful of seconds — the events alone account for the
rest, and for a peak of several hundred megabytes of memory, since every record
is built in memory before being written. Reading the `.evtx` files directly,
which are just files on the volume, would remove both.

## 🧰 BUILD REQUIREMENTS

### Visual Studio 2022 (Windows)
- Requires **Windows SDK 10** and **Windows WDK 10**
- 📥 Download: [Microsoft WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- **Include path** and **lib path** of **project properties directories** must be updated with WKD correct path dependent of WDK installed version. Actually, the configured WDK version is 10.0.26100.0.

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

## 📚 DOCUMENTATION

- API documentation: **HTML**, generated with Doxygen (`Doxygen/Doxyfile`).
- `docs/MIGRATION-VSS-vers-lecture-brute.md` — the engineering log of the move to
  raw, offline collection: every design decision, and the cause of every defect
  found along the way. Written to be read by whoever maintains this next.
- `docs/BUILD-LINUX.md` — cross-compilation details.
