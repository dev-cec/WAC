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

**NTFS compression is handled.** Windows 11 turns compression on for
`\Windows\System32\winevt\Logs`, so the event logs are stored compressed
(measured: `System.evtx`, 1 118 208 bytes held in 589 824 on disk). A raw reader
that ignores this returns *nothing* for those files — on a Windows 11 VM, 400 of
404 logs failed before this was implemented, which made the offline reading of
event logs useless on the most common operating system. Compression is a
directory attribute that a user or a policy can set anywhere, so any artefact can
be affected.

**Preallocated files are read the way NTFS presents them.** A file can be grown
without its new clusters being written: NTFS allocates them without erasing
them, and returns **zeros** for everything past the *valid data length*. The
disk itself still holds whatever the previous owner of those clusters left
there. The event logs are preallocated to their maximum size, so ignoring that
length copied **x64 machine code of a vanished DLL** into
`CodeIntegrity%4Operational.evtx` in place of empty chunks (135 168 valid bytes
out of 1 052 672), and made 19 logs out of 404 — `System.evtx` among them —
fail to extract. Beyond the valid length, WAC now writes zeros without reading
the clusters, and the manifest records `ValidDataBytes` for every such file.
The fingerprint of the exhibit is thus the one any ordinary acquisition gives.

**Validated end to end on the logs themselves.** Each EVTX chunk carries two
CRC32 (header, records): an independent check that no decompression, no valid
length and no fragmented attribute was mishandled. On the test VM, the 1 505
chunks of the 404 extracted logs all verify. That check caught a rule of
mine that decoded without any error and returned wrong data: a last compression
unit held in one cluster *is* compressed, even though it saves nothing.

**The volume is read raw, in read-only.** WAC opens `\\.\X:`, walks the `$MFT`
itself and copies the registry hives onto the collection medium. It does **not**
create a Volume Shadow Copy, and it does **not** use COM or WMI — all of which
left entries in the event logs of the examined machine.

**Artefacts are then parsed from those copies**, never from the live system. The
hives' transaction logs are extracted too and **replayed onto the copy**, so what
is parsed is the machine's actual state and not the last state Windows happened
to flush to disk.

**The copies are kept twice, and that is a procedure rather than a convenience.**
A digital exhibit is never examined on itself: one takes a copy, seals it, and
works on a *second* copy. If the analysis damages something — a tool that writes,
a hive replayed, a mistaken command — the sealed copy is still there and the
operation can be redone. Hence two directories on the collection medium:

```
<output>/
  consigne/          raw copies, exactly as read from the volume.
    MANIFESTE.json   what identifies each exhibit and the collection
    MANIFESTE.sha256 the manifest's own fingerprint — its seal
    Windows/…        the pieces, under their original paths
  travail/           working copies. Hives are replayed HERE. Every collector
    Windows/…        reads from here and knows nothing of the split.
  *.json             the artefacts
```

`consigne/` is never reopened for writing after extraction. The split applies to
**every** extracted file, including those WAC does not modify — Prefetch,
jumplists, `.lnk`, event logs. Duplicating only what one modifies would make the
procedure depend on what the tool *believes* it does, which is precisely what an
outside party needs to be able to check. The cost is disk space on the collection
medium: roughly twice the extracted volume.

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

**WAC no longer opens any key of the examined machine's registry.** The last
one was the profile list (`ProfileList`), needed to know where the per-user
hives live — hence before any hive was available offline. It is now read in the
extracted `SOFTWARE` hive, which makes hive extraction a two-pass affair:

1. raw extraction of the machine hives (`SYSTEM`, `SOFTWARE`, `SAM`, `Amcache`);
2. `SOFTWARE` opened **on the working copy**, profile list read there;
3. raw extraction of each profile's `ntuser.dat` and `usrClass.dat`;
4. raw extraction of the file artefacts (Prefetch, jumplists, `.lnk`).

The cost is a second read of the volume's `$MFT`. The environment variables of
`ProfileImagePath` (`%systemroot%`…) are expanded from the detected system
drive, not from WAC's own environment: the value belongs to the examined
installation.

## 📄 WHAT IS COLLECTED

System and account information, scheduled tasks, services **and drivers**,
running processes, open sessions, and optionally the event logs — plus the usual
registry and file artefacts: UserAssist, MUICache, BAM, USB devices, Shellbags,
MRU, Run keys, Shimcache, Amcache, jumplists, Prefetch and recent documents.

With `--binary`, every file those artefacts point to — a process's executable, a
service's binary and DLL, a scheduled task's command, the files a program loaded
(Prefetch), Shimcache and Amcache entries, a shortcut's or jump list's target — is
fingerprinted, and executables, libraries, drivers, scripts and **Office
documents able to carry macros** (`.doc`, `.docm`, `.xls`, `.xlsm`, `.xlsb`,
`.ppt`, `.pptm`, templates and add-ins, Publisher, Visio, Access) are
**collected**. `.docx`/`.xlsx`/`.pptx` cannot hold VBA and are only hashed. A fingerprint
lets a public database be queried without sending it anything, but it says
nothing about a binary nobody knows — the one that matters to the investigation —
and a binary left behind may be gone by the time a detection comes in. Documents
and data files are only hashed: they are not payloads, and copying them would
turn the collection into a copy of the user's files.

One file per artefact, plus `investigation.json` (see below). The output schema
is documented by the code itself: every field carries a doc comment explaining
what it is and, where it matters, why it is trustworthy.

## ▶️ USAGE

To minimize disk traces, this standalone tool should be run **as administrator** from a USB stick using the command:

```
usage: wac [--dump] [--events] [--binary] [--output=output] [--loglevel=2] [--debug]
        --help or /? : show this help
        --dump : add hexa value in json files for shellbags and LNK files
        --events : extract and parse the .evtx event logs (adds ~117 MB to the collection)
        --binary : fingerprint (MD5, SHA-1, SHA-256) every file referenced in
                   artefacts, read raw; executables, libraries, drivers and
                   scripts are also collected into the exhibit store
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
| **Writing the collection** | on the **collection medium only** (the USB stick). Nothing is written to the examined disk. Each extracted file is written **twice** — once to `consigne/`, once to `travail/` — because the exhibit and the working copy are separate by procedure |
| **Transaction-log replay** | the `.LOG1/.LOG2` are applied **to the copy**, giving the machine's real state rather than its last flushed one. The original content of every replaced page goes into an undo journal, so the raw copy stays reconstructible to the byte. Measured on a real machine: 452 KB for `SYSTEM`, 1 172 KB for `SOFTWARE`, 600 KB for one `ntuser.dat` |
| **Hive repair** | 8 bytes of the base block, **on the copy** — now only a fallback, since a replayed hive is clean by construction. The original is never opened for writing; its fingerprint is recorded first |
| **Service state** (1 × `EnumServicesStatusExW`) | one read-only query to the SCM over `\\.\pipe\ntsvcs`. No handle per service, no state change, so no `System` 7036 event |
| **Processes** (`CreateToolhelp32Snapshot`) | a kernel snapshot; no process handle is opened |
| **Process owners** (1 × `WTSEnumerateProcessesEx`) | solicits the Terminal Services service, once |
| **Sessions** (`LsaEnumerateLogonSessions`) | solicits LSASS; reads only |
| **Event logs** (`--events`) | reads `\Windows\System32\winevt\Logs\*.evtx` through the same raw volume handle as every other artefact — **no service is solicited**, and the parsing happens on the copy. The only cost left is the size: ~117 MB written to the collection medium |
| **Event message resolution** (`--events`) | reads the resource file of each provider that actually produced an event, through the same raw volume handle. These are operating-system binaries, not exhibits, but they go into the exhibit store with their fingerprints like everything else — which records *which build's* wording was used. ~121 MB on an ordinary installation |
| **Referenced files** (`--binary`) | read through the same raw volume handle, kept open for the whole phase — **no file is opened**, so no last-access timestamp is touched. The fingerprints used to come from opening each file through the API, which did update that timestamp where Windows maintains it — on the very document a shortcut proves was opened. A volume that is not NTFS (a CD-ROM, a FAT stick) cannot be read raw: its files are reported as unread, never opened another way |

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

**Every exhibit is identified by three fingerprints.** MD5, SHA-1 and SHA-256,
all three computed *while the bytes are being written* — so they bear on what was
read from the volume, not on a later re-read of the copy. Three and not one
because MD5 collisions have been producible at will since 2008 and SHA-1 since
2017: a single fingerprint no longer settles an identity dispute, three of them
do. They are recorded in `consigne/MANIFESTE.json`, together with, for each
piece: its source path with drive letter, its size as extracted *and* as declared
by the `$DATA` attribute (a divergence means a truncated extraction, which a
fingerprint alone would not reveal — it would simply be the fingerprint of the
truncated file), its `$MFT` entry number (which identifies the file on the volume
independently of its name), the four NTFS timestamps of the **source** file, the
moment of its extraction in UTC and in the suspect's local time, the collection
method, and the outcome — **failures included**, since a piece missing from the
manifest would read as a piece never looked for.

The manifest is sealed by `consigne/MANIFESTE.sha256`, which carries its
fingerprint. A manifest cannot hash itself, and without that second file any
retouching of it would be undetectable — while the manifest is precisely what
attests to the exhibits.

**Everything WAC writes onto a copy can be undone.** Two operations modify an
extracted hive: the 8-byte base-block patch, fully described in
`investigation.json`, and the transaction-log replay, which first writes
`<hive>.undo` holding the original bytes of every page it is about to replace
(base block included). Verified on three real hives: restoring the undo journal
reproduces the raw copy byte for byte. The `.LOG1/.LOG2` files are kept as well,
so a third party can redo the replay independently.

**Replay follows the file, not the sequence numbers.** A transaction log is
reused in place, so entries from an earlier generation survive *after* the end of
the current chain. Sorting entries by sequence number brings a stale one to the
front and applies pages **older** than the hive — measured on a real collection:
BAM timestamps, which are execution evidence, moved fifteen minutes backwards.
WAC therefore walks each log in file order and stops at the first break in the
chain, and every entry is checked against both of its Marvin32 checksums before
being applied (verified on 60 entries from 11 logs).

**Every event says which file it came from.** A single channel can be carried by
several files — the live log and its archives, whose record numbers legitimately
overlap, and, as measured on a real machine, a log that holds events declaring
*another* channel. Without that provenance, two events with the same channel and
the same record number are indistinguishable, and there is no way to tell a
legitimate duplicate from a reading defect. `EvtSourceLog` carries the log file
name, and the test harness checks uniqueness **per file** rather than per channel
— the invariant that actually holds.

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
  "LastBootUpTime": "2026-09-14T21:59:56.5000000+02:00",
  "LastBootUpTimeUtc": "2026-09-14T19:59:56.5000000Z",
  "BootTimeSource": "noyau (SystemTimeOfDayInformation : BootTime - BootTimeBias), heure affichée par l'horloge au démarrage",
  "ClockAdjustedSinceBootMs": 4365,
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
- **`BootTimeSource` says where the boot time comes from.** It is read from the
  kernel (`BootTime − BootTimeBias`): what the clock showed at boot, on the same
  reference as the event logs and logon sessions — checked against the
  Kernel-General 12 event to the millisecond. The former estimate (now minus
  `GetTickCount64`) ignored clock corrections and landed 3.5 s late on a resumed
  VM. `ClockAdjustedSinceBootMs` is the total of those corrections: a few seconds
  is routine resynchronisation, a large value means a clock changed since boot.
- **`TimeZoneSource` says which clock was used.** Otherwise an unexpected offset
  would be indistinguishable from a read error.

## 🚀 PERFORMANCE

A collection takes about **2 minutes** with the default options, up to roughly
**20 minutes** with `--events`, and longer still with `--binary`. The figure
depends heavily on the hardware: USB 2 or USB 3, processor, memory, disk.

**`--binary` was dominated by the size of what it collects** — before
authentic Microsoft binaries were left in place (see below: 99 files, 336 MB,
since). Measured on the Windows 11 test VM without that check: 6 432 files
referenced by the artefacts, 4 874 read, 2 131 executables, libraries, drivers
and scripts collected — **3.3 GB**, written
twice (exhibit store and working copy), so about 6.5 GB on the collection
medium; the whole collection went from 70 s to about 310 s on a VM backed by
NVMe. On a USB stick, writing is the cost. The volume is very concentrated: a
handful of files above 100 MB (`msedge.dll`, 332 MB, `mrt.exe`,
`OneDriveSetup.exe`) weigh over a gigabyte.

**Authentic Microsoft binaries are hashed, not collected.** Most referenced
binaries are Windows components, identical on every machine of the same build.
Their origin is provable on the machine itself, with no list to carry: Windows'
own **catalogs** (`System32\CatRoot`, signed by Microsoft, listing the
fingerprint of every system file) and the **embedded signature** of individually
signed binaries (Edge, OneDrive, Office). A file whose Authenticode digest is in
a validly Microsoft-signed catalog, or whose embedded signature is a valid
Microsoft one, is fingerprinted and left in place; everything else is collected
— including a System32 binary replaced by an attacker, whose digest no longer
matches. **No trace**: `WinVerifyTrust` and `CryptCATAdmin` would solicit the
CryptSvc service, read the certificate stores in the live registry and check
revocation over the network (writing to `CryptnetUrlCache`). WAC reads catalogs
and binaries raw and verifies everything in memory — ASN.1, X.509, PKCS#7, RSA,
SHA-1/256/384 — up to Microsoft roots **embedded in the executable**, never the
machine's store. Signers are restricted to Microsoft's own code: certificates
chaining to a Microsoft root but used for **third-party** code — *Hardware
Compatibility Publisher* (WHQL drivers), *Early Launch Anti-malware Publisher* —
are not accepted, since vulnerable signed drivers are a classic attack path.
The catalogs that justified a decision go into the exhibit store, so a third
party can re-check it. Confronted with `Get-AuthenticodeSignature` on 2 233
binaries: 2 126 authenticated by both, **no file accepted by WAC and rejected by
Windows**. Scripts are covered too: a catalog lists a script by the SHA-256 of
its raw bytes (established on 473 PowerShell and WSH scripts of Windows 11), and
a PowerShell script's embedded signature block (`# SIG # Begin signature block`,
or its XML form) signs the UTF-16LE text that precedes it — verified on every
signed script of the test VM, and a one-word change makes it rejected. A WSH
script (`.vbs`, `.js`, `.wsf`) signed only inline is still collected: its
signed digest covers a normalised form of the text that could not be
established with certainty. On the test VM, collected binaries went from 2 131
(3.3 GB) to 92 (335 MB), in the same time; the scripts still collected are the
unsigned ones.

**Identical content is stored once.** A file's SHA-256 is only known once it
has been read, so it is first written to a staging directory next to the
exhibit store, then *renamed* into it if new, or dropped if that content is
already there under another path. The exhibit store thus only ever receives
final pieces. The other paths stay exhibits in their own right — their own
path, `$MFT` entry and timestamps — declared `SharedExhibit` in the manifest,
pointing to the stored copy. On the test VM: 90 duplicates, 528 MB not written
twice (Edge and WebView2 ship the same `msedge.dll`). Each file is read
once however many artefacts cite it, and hashing a file costs no more trace than
collecting it — only space. When space runs short (under 1 GB left, counting the
working copies still owed), files are hashed without being copied, and the
investigation log says how many.

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
- the **plain-language message** is back. It is not in the log at all: the log
  holds an event id and its data, while the sentence lives in the provider's
  resource file. WAC now reconstructs it offline, following the same chain the
  API followed — provider GUID → its resource file, named in the `SOFTWARE`
  hive → the `WEVT_TEMPLATE` resource, which maps an *event* id to a *message*
  id → the `MESSAGETABLE` resource, which on a localized system lives in the
  satellite `<language>\<name>.mui` → substitution of the event's own values
  into the `%1 %2 …` marks. Resource files are extracted **on demand**, once per
  provider that actually produced an event: extracting all of the ~930 declared
  publishers would cost hundreds of megabytes for providers that were silent.
  **This required reading WOF — and it is read raw, with no fallback.** Windows
  10 and 11 store their system binaries compressed by "Compact OS": the file's
  `$DATA` attribute is **sparse** and the payload lives in a named stream
  `WofCompressedData`. Seen through the API such a file looks perfectly
  ordinary — normal attributes, one stream, full size — because the system's
  filter reassembles it on the fly. Seen on disk it is something else, and the
  `$MFT` attribute listing says so plainly:

  ```
  0x80 (unnamed)          1 372 160 bytes  SPARSE     <- empty $DATA
  0x80 WofCompressedData    667 578 bytes             <- the real content
  0xC0 reparse point           0x80000017  algorithm 2
  ```

  A raw reader that ignores this returns a correctly-sized file of **all zeros**;
  on the test VM all 121 provider binaries came back that way. `xpress.h/cpp`
  implements the XPRESS-Huffman decompressor the three XPRESS variants share,
  and `raw_hive` walks the chunk table of the named stream. **Detection looks at
  the whole file, not just its base `$MFT` record**: when a file has too many
  attributes to fit in one record, NTFS spreads them over several and leaves only
  an `$ATTRIBUTE_LIST` behind — a file in that shape has neither its reparse
  point nor its named stream in the base record, and 56 provider binaries were
  missed that way until the traversal was added. Nothing is opened on the
  examined machine. The fourth WOF variant, LZX, is a distinct and far more
  complex format: it is **not** implemented, and such a file is reported as
  unsupported rather than returned wrong;
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

`-Wall -Wextra` is enabled and the build is now **warning-free**. Those warnings
used to serve as the to-do list for format completeness — each one marked a field
the parsers decoded and then dropped. Clearing them turned up real defects rather
than cosmetic ones:

- a `.lnk` **volume label** read from the wrong offset and as ANSI when the
  format said Unicode, so it came out truncated at its first character;
- per-loaded-file **`$MFT` references** in Prefetch, never parsed at all — they
  identify a file on the volume independently of its name, so a renamed or
  deleted executable can still be found. 9 117 references on the test machine,
  all passing the plausibility check. **Known limitation**: they come out on 155
  of 279 Prefetch files; on the other 124 the metrics block is not read and the
  reason is not yet established. The format version is now emitted for each
  Prefetch, which is what a diagnosis needs;
- four **announced string lengths** that were read but never used to bound the
  read itself, leaving the parsers to run to the next zero byte, wherever that
  fell;
- three **counts taken from the file on trust** (volumes, `$MFT` references,
  file metrics), now bounded by the size the file itself declares for the block.

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
entries. See `vmtest/README.md` (French: `vmtest/README.fr.md`).

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

### Two more test harnesses, for two silent failure modes

Both are excluded from the build by the `_test.cpp` pattern and compile natively
on Linux — no Windows needed.

`sha_test.cpp` confronts the fingerprint code with published test vectors. A
wrong fingerprint is the worst kind of silent defect: it produces a
flawless-looking exhibit store that identifies nothing. Two families of cases:
the four FIPS 180-4 vectors validate the algorithms, and the lengths 55 to 128
validate the **padding**, the one place an otherwise correct implementation goes
wrong (at 56 bytes the length no longer fits in the block and must move to the
next one).

```bash
cd WAC && g++ -std=c++17 -I. sha.cpp sha_test.cpp -o /tmp/sha_test && /tmp/sha_test
```

`lznt1_test.cpp` checks the NTFS decompressor against **Microsoft's own
compressor**: `RtlCompressBuffer` from `ntdll` compresses a known file one
compression unit at a time, and the test decompresses each unit here and compares
byte for byte. A wrong decompressor usually decodes without any error and returns
wrong data, which is why the comparison is exhaustive rather than a size check.
Result on a 1 118 208-byte log: 16 compressed units out of 16 conform, 1 048 576
bytes identical.

`wevt_test.cpp` checks the five-link chain that turns an event into a sentence,
against a **real provider's** files — its DLL and its localized satellite. Each
link fails silently: the field simply disappears and the collection stays valid,
so nothing points at the broken link. Two defects were caught exactly that way
while writing it: a provider's block descriptors are **eight** bytes and not
four (read by four, no block is ever found — 0 events described for a provider
that describes 202), and an event descriptor is **48** bytes and not 44 (with a
44-byte stride, only one record in twelve is coherent, with no error at all).
The stride is therefore *derived* from the block size the resource declares, so
a mismatch is caught rather than silently mis-read. The test also checks the
mark substitution, including that a mark with no data **stays visible** —
erasing it would suggest a complete sentence.

```bash
cd WAC && g++ -std=c++17 -I. pe_resource.cpp wevt.cpp wevt_test.cpp -o /tmp/wevt_test
/tmp/wevt_test gpsvc.dll fr-FR/gpsvc.dll.mui "{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}" 1002 4001
```

`xpress_test.cpp` checks the WOF decompressor against **Microsoft's own
compressor**, the same way `lznt1_test` does: `RtlCompressBuffer` compresses a
known file chunk by chunk in the VM, and the test decompresses each chunk here
and compares byte for byte. Result on a 1 118 208-byte log: 137 compressed
chunks out of 137 conform. Getting there took two corrections that no
compilation catches — the bit stream is read as **little-endian 16-bit words
whose bits are consumed most-significant first**, and the bit buffer must be
topped up to 16 bits **after every symbol**, literals included, because that
refill advances the same byte cursor the extended match lengths are read from.
With the refill only after matches, 16 chunks out of 137 decoded correctly and
the rest came out wrong with no error at all.

`consigne_test.cpp` checks the exhibit-store procedure, and specifically the one
thing that must never happen and is silent when it does: **the sealed copy being
modified**. It runs the production chain — same fingerprints, same manifest, same
verified copy, same replay — on hive files given as arguments, then verifies that
`consigne/` is byte-identical afterwards while `travail/` has changed, that the
seal carries the manifest's real fingerprint, and that the manifest was not
copied into the working directory.

```bash
wine /tmp/consigne_test.exe "Z:/tmp/out" "Z:/path/to/SYSTEM" "Z:/path/to/ntuser.dat"
```

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

- **User manual**, in English and French, maintained together:
  `WAC/doc/user/documentation_EN.pdf` and `WAC/doc/user/documentation_FR.pdf`,
  built from the `.tex` files beside them with `latexmk -xelatex` (fonts: Noto
  Sans, DejaVu Sans Mono). They cover preparing a collection, the options,
  reading the output, verifying the exhibit store and the traces left on the
  examined machine. `verify-exhibits.ps1` (English) and `verifier-consigne.ps1`
  (French) check the seal and every exhibit of a collection. The English cover
  page, `WAC/doc/cover page.png`, is generated from the French one by
  `WAC/doc/translate-cover.py`, which repaints its text in the same fonts and
  layout.
- `WAC/doc/BUILD-LINUX.md` (French: `BUILD-LINUX.fr.md`) — cross-compilation details.

The design rationale lives **in the code**, next to what it explains: each
non-obvious choice carries a comment saying why it is that way and what breaks
otherwise. Several of them record a defect that was actually hit — a hash
formatted without padding, a length compared against a hard-coded value, a
pointer read after being freed — because the cause is the part worth keeping.
