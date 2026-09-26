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
  exhibits/          raw copies, exactly as read from the volume.
    MANIFEST.json   what identifies each exhibit and the collection
    MANIFEST.sha256 the manifest's own fingerprint — its seal
    Windows/…        the pieces, under their original paths
  working/           working copies. Hives are replayed HERE. Every collector
    Windows/…        reads from here and knows nothing of the split.
  *.json             the artefacts
```

`exhibits/` is never reopened for writing after extraction. The split applies to
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
usage: wac [--config=file | --write-config] [--collect | --full | --convert=folder] [--dump] [--events] [--binary | --binary-all] [--threads=N] [--output=output] [--loglevel=2] [--debug]
       wac --update-trust[=folder]
        --help or /? : show this help
        --update-trust[=folder] : on the ANALYSIS WORKSTATION, BEFORE the
                    collection, and alone: downloads Microsoft's trusted roots
                    and disallowed certificates, checks their signatures, and
                    writes the trust set into folder (by default `trust`, next
                    to WAC.exe), to be carried on the key (see below)
        --collect : collection only, on the examined machine: live snapshots and
                    raw extraction into the sealed exhibit store; nothing is
                    converted. With --events, the resource files of every event
                    provider; with --binary, every executable of every fixed
                    NTFS volume is read and verified in memory, and only those
                    not authenticated (catalog, embedded signature, Store
                    package) are copied (~0.7 GB on a plain Windows 11)
        --convert=folder : conversion only, on an analysis workstation, of the
                    collection made with --collect in that folder: seal and
                    every fingerprint checked first, JSON written next to the
                    exhibit store, conversion.json as its log
        --dump : add hexa value in json files for shellbags and LNK files
        --events : extract and parse the .evtx event logs (adds ~117 MB to the collection)
        --binary : in a full run, fingerprint every file CITED by an artefact,
                   read raw; the cited executables, libraries, drivers and
                   scripts not authenticated as Microsoft are also collected.
                   With --collect, every executable of every fixed NTFS volume
                   instead, cited or not (see --collect)
        --binary-all : like --binary, but every executable is collected,
                   authenticated or not; the signature is still checked and
                   its verdict recorded in the manifest
        --threads=N : threads analysing the executables of --collect --binary
                   (PE, Authenticode, catalogs, fingerprints); by default the
                   processor's threads minus one, the reading keeping its own.
                   The result does not depend on it: the manifest is the same
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

### The configuration file, `wac.yml`

Rather than typing the options at every collection, write the procedure once
in `wac.yml`, next to `WAC.exe`: WAC applies it first, and an option given on
the command line overrides it. `WAC.exe --write-config` writes the reference
file, commented — the recommended procedure: collection only, unverified
binaries collected, event logs included.

```yaml
convert: false          # true: collect and convert here; false: collect only (--convert elsewhere)
binary: unverified      # none | unverified | all
threads: 0              # analysis threads for the binaries, 0: automatic
output: output
log_level: 0
dump: false
artefacts:              # one switch per artefact; all the hives are `registry`
  registry: true
  events: true
  scheduled_tasks: true
  services: true
  processes: true
  sessions: true
  prefetch: true
  jump_lists: true
  recent_documents: true
```

- **Strict**: an unknown key, a value outside the ones allowed (`true`/`false`
  only, not `yes`), a duplicate key, a list: the collection is refused before
  it starts, with the line at fault. A key left out keeps its default.
- **Recorded**: the file's path, SHA-256 and content go into
  `investigation.json` (`Tool.Configuration`) — the procedure applied is part
  of the evidence.
- An artefact switched off is not read at all, and its JSON file says so
  (`CollectionStatus: NotRequested`, with the key): never mistaken for a
  failure or for an absence of traces.
- `--config=<file>` reads another file; `--full` collects and converts here
  although the file says `convert: false`.
- Without `wac.yml`, WAC behaves as before: full run, options as given.
- The YAML is read by libyaml 0.2.5, the reference implementation, compiled
  into `WAC.exe` (`third_party/libyaml-0.2.5`, see its `VENDORED.md`).

**Default output files are saved in :**
- The `output` directory for standard results
- The `log` file for logs when using `--loglevel`

### The trust set (`--update-trust`)

Checking a third-party signature means tying it to a root that is trusted,
and to none that is distrusted. Taken from the examined machine, those roots
would be the attacker's to choose: a root added by the attacker validates the attacker's binaries.
`--update-trust` therefore takes them from Microsoft, on the analysis
workstation, before leaving for the collection:

| File | Content |
|---|---|
| `authroot.stl` | the roots of Microsoft's root program, the uses each is trusted for, its distrust date |
| `disallowedcert.stl` | the keys and certificates Microsoft distrusts |
| `roots\<SHA-1>.crt` | every root `authroot.stl` names (562 on 2026-08-25) |
| `roots.pem` | those trusted for code signing and not distrusted, for `osslsigncode` or `openssl` on Linux |
| `vulnerable-drivers.json` | the fingerprints (file and Authenticode) of vulnerable or malicious drivers, from Microsoft's blocklist (1,086) and LOLDrivers (8,151), and the 217 signers Microsoft's blocklist denies, with what narrows each down: the signer's certificate name, the WHQL manufacturer, the files |
| `crl\` , `revocation.json` | the revocation lists (CRL) of every authority capable of code signing that the Common CA Database lists (387 in 2026), those of Microsoft's own code signing authorities (not in the CCADB: WHQL drivers, Store, Windows Phone…), and those earlier collections found missing (`wanted-crls.txt`); and the 2,935 authorities the CCADB says revoked |
| `sources\` | the unsigned lists as downloaded: `VulnerableDriverBlockList.zip`, `loldrivers.json`, `ccadb.csv` |
| `trust-manifest.json` | date, sources, counts, SHA-256 of every file; written last, so that an interrupted set is seen as absent |

The set can be carried without being trusted: both trust lists are signed by
Microsoft's trust list publisher, checked up to a Microsoft root embedded in
WAC, and every root must have the SHA-1 the signed list names — an altered set
is refused. Each CRL is signed by its authority, a signature checked where it
is used. The driver lists and the CCADB report are not signed: their
authenticity is that of HTTPS, and the manifest says so; a list that cannot be
obtained is recorded as missing. It is the only mode that uses the network, through WinHTTP loaded
at run time; the build refuses a `WAC.exe` that imports a network library.
At the collection (`--binary`), the set is checked again as a whole — an
altered set is refused and treated as absent, as the investigation log says —
and the chain of every intact third-party signature is verified against it:
tied to a root Microsoft trusts for code signing, no certificate disallowed,
no authority revoked, every certificate valid at the signing time given by a
verified time stamp (RFC 3161 or counter-signature) — at the collection's
time without one —, and none revoked according to its issuer's signed CRL:
revoked for a compromise or without a reason, refused; for another reason,
refused unless stamped before. No signed CRL for a certificate: its
revocation is not verifiable, and the binary cannot be cleared. The CRL
addresses a collection lacked are written to `trust\wanted-crls.txt` on the
key, and the next `--update-trust` fetches them. The manifest records it all
(`EmbeddedChainTrusted`, `EmbeddedChainRoot`, `EmbeddedChainReason`,
`EmbeddedTimeStampUtc`, `EmbeddedTimeStampAuthority`,
`EmbeddedRevocationListsUtc`). A binary whose chain holds is still not
cleared when it is a vulnerable or malicious driver: its fingerprint
(Authenticode — equal to LOLDrivers' Authentihash, measured — or of the file)
in Microsoft's blocklist or LOLDrivers, or a signer Microsoft denies, with
every narrowing it gives (signer, WHQL manufacturer, original file name read
in the version resource — not the name on disk, which an attacker changes —,
version bounds). A list of drivers missing from the set: no driver can be
cleared. Under `--binary`, a cleared third-party binary is fingerprinted, not
copied, like a Microsoft one; without a usable trust set, every third-party
binary is collected, as the investigation log says.

On a Linux workstation it runs under wine. About 70 seconds for 64 MB; the
562 roots are
identical, byte for byte, to those of Windows' `certutil -generateSSTFromWU`.

## 🔀 COLLECT HERE, CONVERT ELSEWHERE

The same two sections as chapter 5 of the user documentation.

### Why separate collection and conversion

A WAC run does two different things:

1. **The collection** — observing what only a running system shows (processes,
   sessions, service states, clock), reading the disk raw, and copying the
   evidence into a sealed exhibit store. This part **needs** the examined
   machine.
2. **The conversion** — parsing thousands of copied files (hives, event logs,
   Prefetch, shortcuts…) into JSON. This part only needs the sealed exhibit
   store, **not** the machine.

Running the conversion on the examined machine adds work there that nothing
requires:

- minutes of processing in WAC's memory, which Windows may page out to
  `pagefile.sys` — on the very disk under examination;
- a process that stays longer on the machine, seen and logged by its security
  software;
- if WAC crashes, a Windows Error Reporting file written on the machine.

The conversion never reads the machine's own files or registry — only the
copies on the collection medium — but it still runs there.

Good forensic practice says to avoid exactly that:

- **ISO/IEC 27037** covers the identification, collection and preservation of
  digital evidence, **ISO/IEC 27042** its analysis: two distinct stages;
- **ACPO principle 1**: no action should change data on the examined machine —
  every operation run there must be necessary;
- **ACPO principle 3**: an independent third party must be able to repeat the
  process and reach the same result.

Separating the two stages brings three things:

- **fewer traces** on the examined machine: only the collection runs there;
- **evidence checked before any analysis**: `--convert` verifies the seal and
  the SHA-256 of every exhibit first, and refuses a retouched collection;
- **a reproducible analysis**: two conversions of one collection give
  byte-identical JSON files, and the analysis can be redone later — with a
  corrected WAC, or by a third party — without going back to the machine.

### Which mode to choose

**By default: `--collect` on the examined machine, then `--convert` on an
analysis workstation.**

```
E:\> WAC.exe --collect --events --binary --output=accounting-pc-01     (examined machine, as administrator)
D:\> WAC.exe --convert=E:\accounting-pc-01 --events --binary           (analysis workstation)
```

| | Full run (\<default\>) | `--collect` | `--convert=folder` |
|---|---|---|---|
| Runs on | the examined machine | the examined machine | an analysis workstation |
| Does | collection **and** conversion, in one run | collection only: live snapshots, raw extraction, sealed exhibit store — **nothing converted** | checks the seal and every fingerprint, then converts; the exhibit store is only read |
| `--binary` examines | only the files **cited by the artefacts**; a binary no artefact cites is not examined | **every executable of every fixed NTFS volume**, cited or not | what the collection took |
| `--binary` collects | the cited executables **not authenticated**, with their fingerprints; the authenticated ones are fingerprinted, not copied | the executables **not authenticated**, with their fingerprints; the authenticated ones are fingerprinted, not copied | — |
| `--binary-all` collects | **every** cited executable, authenticated or not, with its signature verdict | **every** executable, authenticated or not, with its signature verdict | — |
| Traces on the examined machine | the collection's **and the conversion's** (processing, memory, a longer process, a crash report if it crashes) | the collection's only | **none**: the machine is not involved |
| Duration on the test VM (`--events --binary`) | 4 min 33 s | 16 min 39 s — the extra time is *reading* the whole volume, which writes nothing to it | 43 s |
| Reproducible | partly: its exhibit store is sealed, but holds neither the authenticated binaries it cited nor any record of them, and converting it again is not a tested path | yes, through `--convert` | yes: two conversions give identical JSON files |

**Use the full run only in specific cases, and say so in the report:**

- the results are needed on the spot and no analysis workstation is at hand;
- the machine must be released within minutes, and the 16 minutes of a
  `--collect --binary` cannot be afforded.

**`--binary` or `--binary-all`.** Both read every executable raw and verify
its signature in memory; they differ in what they **copy**. An executable is
*authenticated* when a Microsoft catalog lists it, when it carries a valid
Microsoft signature, or when it belongs to a Store package whose signature and
block map it matches. A third-party executable is *cleared* the same way when
a trust set is on the key (`--update-trust`) and its signature holds against
it: chain to a root Microsoft trusts for code signing, valid at the signing
time, not revoked, not a vulnerable driver. Every other one — unsigned,
modified, unknown, or third-party without a usable trust set — is *not
authenticated*. The table describes a `--collect`;
a full run applies the same rules to the executables the artefacts cite, the
fingerprints of the authenticated ones going into the artefact JSON files
instead of the manifest.

| | `--binary` (the usual choice) | `--binary-all` |
|---|---|---|
| Signature checked | yes, in memory | yes, in memory |
| Authenticated or cleared executable | **not copied**: its Authenticode digest, its verdict and its build (`SymbolServerKey`) are recorded in the manifest — a Microsoft binary can be fetched again, identical, from Microsoft's symbol server | **copied**, with its three fingerprints and its verdict (`SignatureVerified`, `Signature`) |
| Not authenticated | **copied**, with MD5, SHA-1, SHA-256 (and the Authenticode digest of a PE) and the reason (`SignatureReason`) | **copied**, the same way |
| Exhibit store, test VM (`--collect --events`) | 1.8 GB | 20.0 GB |
| Collection time, test VM | 16 min 39 s | 21 min 45 s |
| When | always, unless the case says otherwise | the content of every executable must itself be in the exhibit store |

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
| **Writing the collection** | on the **collection medium only** (the USB stick). Nothing is written to the examined disk. Each extracted file is written **twice** — once to `exhibits/`, once to `working/` — because the exhibit and the working copy are separate by procedure |
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
do. They are recorded in `exhibits/MANIFEST.json`, together with, for each
piece: its source path with drive letter, its size as extracted *and* as declared
by the `$DATA` attribute (a divergence means a truncated extraction, which a
fingerprint alone would not reveal — it would simply be the fingerprint of the
truncated file), its `$MFT` entry number (which identifies the file on the volume
independently of its name), the four NTFS timestamps of the **source** file, the
moment of its extraction in UTC and in the suspect's local time, the collection
method, and the outcome — **failures included**, since a piece missing from the
manifest would read as a piece never looked for.

The manifest is sealed by `exhibits/MANIFEST.sha256`, which carries its
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

Measured on the Windows 11 test VM (NVMe-backed, 25 September 2026, version
1.3.1), each run checked by the harness with no failure:

| Run | Duration | Exhibit store | What it holds |
|---|---|---|---|
| full, `--events --binary` | **4 min 33 s** | 0.74 GB, 1 640 exhibits | 24 JSON files; 170 344 events from 404 logs; 6 698 cited files, 2 146 authenticated and not collected, 75 collected (250 MB) |
| `--collect --events --binary` | **16 min 39 s** | 1.81 GB, 6 060 files | 43 513 executables of the volume read and verified, 27 958 authenticated (not copied), 12 700 Windows differential files, 2 508 collected (676 MB); resources of all 934 event providers (649 MB) |
| `--convert` of that collection | **43 s** | read only | seal and 6 461 fingerprints checked first; identical JSON on a second run |
| `--collect --events --binary-all` | **21 min 45 s** | 20.0 GB | 58 509 executables copied, each with its signature verdict (previous cycle) |

**Where the time goes** in a `--collect --binary`, as WAC's log records it per
phase: reading and verifying the 43 513 executables takes **10 min 46 s** — of which
loading the 13 817 signature catalogs 32 s, Store packages 8 s — and copying the
unauthenticated ones **29 s**; hives, event logs, provider resources and sealing
take the rest. The cost is reading and hashing the whole volume, not writing:
the raw reader fetches contiguous clusters by batches of 1 MiB, and an
authenticated binary gets its Authenticode digest only, its MD5, SHA-1 and
SHA-256 being computed solely for what is collected. The duration depends
heavily on the hardware: USB 2 or USB 3, processor, disk.

**Authentic Microsoft binaries are hashed, not collected.** Most referenced
binaries are Windows components, identical on every machine of the same build.
Their origin is provable on the machine itself, with no list to carry: Windows'
own **catalogs** (`System32\CatRoot`, `WinSxS\Catalogs` and
`servicing\Packages`, over 13 000 on Windows 11, signed by Microsoft, listing
the fingerprint of every system file) and the **embedded signature** of individually
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
established with certainty. On the test VM, a full run's cited binaries went
from 2 131 collected (3.3 GB) before this check to 75 (250 MB) now; the scripts
still collected are the unsigned ones. Store applications, signed per package
rather than per file, are verified through the package signature and its block
map, 64 KiB block by block.

**Identical content is stored once.** A file's SHA-256 is only known once it
has been read, so it is first written to a staging directory next to the
exhibit store, then *renamed* into it if new, or dropped if that content is
already there under another path. The exhibit store thus only ever receives
final pieces. The other paths stay exhibits in their own right — their own
path, `$MFT` entry and timestamps — declared `SharedExhibit` in the manifest,
pointing to the stored copy. Measured when every cited binary was still
collected: 90 duplicates, 528 MB not written twice (Edge and WebView2 ship the
same `msedge.dll`). Each file is read
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
strategy differs. `evtx_test --collect` streams; `evtx_test --collect-memory`
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

End to end, the offline path now takes **4 min 33 s** for a full run with `--events`
and `--binary` on the test VM (170 344 events from 404 logs), against about
20 minutes for the old API path; it has not yet been timed on physical
hardware.

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
  A `--collect` run does take them all (934 providers, 649 MB): which ones the
  logs cite is only known at conversion, on another machine.
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
  examined machine. The fourth WOF variant, **LZX** on 32 KiB chunks — which
  Windows only uses on request (`compact /exe:lzx`, disk "compacting" tools) —
  is a distinct and far more complex format, read too: `lzx.h/cpp`, written
  from Microsoft's own specification of the format, is checked against files
  compressed by Windows itself (identical SHA-256, 646 chunks out of 646) and
  against 235 707 truncated or damaged inputs under AddressSanitizer;
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
./build-windows.sh --test   # also builds raw_hive_test.exe, and the harnesses in tests/
```
The C++ runtime is linked statically: the executable depends only on Windows
system DLLs — which matters for a tool run from a USB stick on a machine one must
not install anything on. The registry hives are read by WAC's own reader
(`WAC/offline_registry.cpp`), linked into the executable: Microsoft's
`offreg.dll` is no longer used — a DLL that recent Windows versions ship in
`System32`, so WAC used to read the evidence through a library of the examined
machine. The reader keeps offreg's functions and contract; `offline_registry_test`
confronts it with Microsoft's DLL on whole hives (below).

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
entries. See `vmtest/README.md` (French: `vmtest/README_FR.md`), and the
validation report (`WAC/doc/validation/`) for the whole list with its results.

### Testing the EVTX parser outside Windows

A VM only ever produces its own logs: one Windows version, all of them clean.
The BinXML decoder needs the opposite — old logs, forwarded logs, logs closed
abruptly, logs with a damaged chunk. `WAC/evtx_test.cpp` exists for that. It is
excluded from the build by the `_test.cpp` pattern and runs under `wine`, so a
journal can be replayed on the development machine:

```bash
# built by ./build-windows.sh --test, runs under wine
cd build-windows/tests
wine evtx_test.exe "Z:/path/to/Security.evtx"          # summary per log
wine evtx_test.exe "Z:/path/to/Security.evtx" 3        # + XML of 3 records
wine evtx_test.exe "Z:/path/to/Security.evtx" --dump   # one record per line
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

`ntfs_fixup_test.cpp` checks the fixups of NTFS multi-sector records (`$MFT`
records, index blocks). NTFS ends every 512-byte stride of such a record with an
update sequence number; WAC used to restore the real bytes without comparing
that number, so a record torn by an interrupted write came out as plausible
data, a mix of two versions. The number is now checked first — the stride is
always 512 bytes, whatever the sector size the volume declares, as in Linux's
`ntfs3` — and a torn record or index block is refused and logged. The harness
builds sound, torn and malformed records whose outcome is known, then compares
WAC's verdict with an independent check on 20,000 random records against a
guard page: 44,610 checks, no failure; it fails on the former behaviour. On the
test VM's real volume, no record is refused (`raw.log`: no "torn record").

`consigne_test.cpp` checks the exhibit-store procedure, and specifically the one
thing that must never happen and is silent when it does: **the sealed copy being
modified**. It runs the production chain — same fingerprints, same manifest, same
verified copy, same replay — on hive files given as arguments, then verifies that
`exhibits/` is byte-identical afterwards while `working/` has changed, that the
seal carries the manifest's real fingerprint, and that the manifest was not
copied into the working directory.

```bash
wine build-windows/tests/consigne_test.exe "Z:/tmp/out" "Z:/path/to/SYSTEM" "Z:/path/to/ntuser.dat"
```

`lnk_test.cpp` checks that the shortcut parser **never reads outside its
buffer**. Every length in a `.lnk` — ID list, shell items, extension blocks,
strings — comes from the file itself, and an over-read does not crash on its
own: it publishes whatever lies past the buffer, in a perfectly valid JSON. The
test makes it crash: each input is placed so that it ends exactly at a page
boundary, the next page being mapped `PAGE_NOACCESS`. Each shortcut given is
parsed whole, then in every one of its truncations, then with 2,000 random
corruptions (fixed seed). Its first runs caught a shell item read at fixed
offsets past its declared size (network item, `+0x54`), and an endless loop in
`replaceAll()` when the string looked for is empty; the shortcuts of a real
machine then caught two more, in the property store values (`readScalar`,
`SPSValue`). Result on 220 shortcuts of a real machine and eight of the test VM:
over 570,000 inputs, no read outside the buffer.

`--test` puts these harnesses in `build-windows/tests/`, apart from `WAC.exe`:
they are never to be copied onto a collection key.

```bash
./build-windows.sh --test
cd build-windows/tests && wine lnk_test.exe a.lnk b.lnk ...
```

Both tests place each input against the guard page twice: once ending at it,
once starting right after it (`guard_page.h`). The second layout catches reads
*before* the input — a negative offset computed from the data, which the first
one lets through because the bytes before the input are mapped.

`parsers_test.cpp` does the same for the **automatic and custom jump lists**
and the **Prefetch** files, whose parsers follow chains and offsets the file
declares: OLE sector chains and allocation tables, the DestList, the scan for
shortcut headers, the SCCA blocks. A watchdog also fails the test if one parse
does not end within 60 s — a cyclic sector chain on a forged file is a defect
too — and a fault handler names the input and the faulting instruction. A
compressed Prefetch is decompressed first (ntdll), so that the test aims at
WAC's SCCA parser; run it on Windows for that reason. What its first runs
caught on the files of a real machine:

- a Prefetch read 20 bytes past its end when truncated: the minimum size
  stopped at the run times (192 bytes), the run count is read at 212;
- the Prefetch file names read up to the first zero met, past their block;
- in the OLE reader, reviewed at the same time: the header read before its
  size was checked, sector offsets computed in `int` (a negative one passed
  the bound check), 4096-byte sectors read 3584 bytes too early, and the MSAT
  beyond the header copied without bounds, stopped after one byte, then read
  one id in four;
- a custom jump list of 25 or 26 bytes made an unsigned difference wrap around
  and the scan run far past the buffer.

Result on the files of a real machine, each input on both sides of the guard
page: 48 automatic jump lists (175,585 inputs), 23 custom ones (79,036) and
307 Prefetch (1,246,491), and four registry hives (`hive`, 16,207): no read outside the buffer, every parse ended.

`offline_registry_test.cpp` confronts **WAC's own hive reader** with
Microsoft's `offreg.dll`, loaded dynamically from the path given: both walk
every key of the hives given, and every name, date, class, count, maximum,
value type and value byte is compared, as well as the contract's edge cases
(buffer too small, size probe, default value, missing key or value). Its first
run showed that offreg returns the SUBKEY maxima the key records (possibly
stale) but MEASURES the value maxima, and counts the terminator in the size it
asks for. Result: the eight hives of the test VM (322,589 keys, 588,640
values) and ten of a real machine (951,063 keys, 1,867,499 values), identical.
The one intended difference: a hive whose logs were not replayed is refused,
where recent versions of offreg read it as is — stale keys without an error.

```bash
offline_registry_test.exe C:\Windows\System32\offreg.dll SYSTEM SOFTWARE ntuser.dat ...
```

`system_conversions_test.cpp` confronts the conversions WAC now does itself
with the Windows functions it no longer imports: GUIDs (`StringFromGUID2`),
SIDs in both directions (`ConvertSidToStringSidW`, `ConvertStringSidToSidW`),
OLE dates (`VariantTimeToSystemTime`) and property names
(`PSGetNameFromPropertyKey`, against the table generated from the Windows
property schema by `vmtest/property-schema.cpp`). WAC.exe thus imports only
what querying the running system requires: `ADVAPI32, KERNEL32, msvcrt,
Secur32, WTSAPI32`. Getting the dates right took the test: Windows adds half a
second TO THE DATE, then truncates — a rounding of the seconds of the day,
whatever the order of the operations, disagreed on the half-second cases. It
also showed that Windows writes an identifier authority of 2^32 or more in
hexadecimal without padding. The same program checks the date conversions
whose result was once ignored: every FAT date against `DosDateTimeToFileTime`
(an impossible one — month 13, hour 25 — gave whatever the stack held, it now
gives a null date, not emitted), and the suspect's offset in both directions
(local to UTC used `LocalFileTimeToFileTime`, hence the offset of the machine
running WAC). It also checks daylight saving time: WAC applies to each date the offset in
force AT THAT DATE, from the suspect's rules year by year (`time_zone.cpp`),
where it used to apply the collection day's offset to every date — a winter
date collected in summer came out one hour off and labelled `+02:00`. The
offsets are compared with `SystemTimeToTzSpecificLocalTimeEx` and
`TzSpecificLocalTimeToSystemTimeEx` on every time zone of Windows, at every
transition from 1980 to 2035; and `check-json.py` confronts the offset of every
local date of a real collection with the tz database, an independent source —
which caught the daylight saving dates of the SYSTEM hive read in the wrong
layout (`TIME_FIELDS`, the weekday last, not `SYSTEMTIME`). Result: 9,661,562
comparisons, identical. Two
intended differences: WAC refuses a SID text Windows would truncate (a
sub-authority of 2^32 or more, a 16th sub-authority), and a NaN date, for which
Windows returns a meaningless time. Run it on Windows (the test VM).

```bash
./build-windows.sh --test
parsers_test.exe jumplist-auto   file.automaticDestinations-ms ...
parsers_test.exe jumplist-custom file.customDestinations-ms ...
parsers_test.exe prefetch        CMD.EXE-0BD30981.pf ...
```

**Timing and memory** are measured with the third mode, which runs the *complete*
chain — raw file → BinXML → `xml_light` → `Event` → streamed JSON — on a
directory laid out like an extraction:

```bash
mkdir -p /tmp/tree/Windows/System32/winevt/Logs /tmp/out
cp *.evtx /tmp/tree/Windows/System32/winevt/Logs/
/usr/bin/time -v wine build-windows/tests/evtx_test.exe --collect "Z:/tmp/tree" "Z:/tmp/out"
```

It reports the number of logs, records and discarded records, and writes
`/tmp/out/events.json`. `time -v` gives the wall clock and the peak working set
— the figure that matters, since it is what used to cause paging. Reference run:
20 logs, 57 MB, 96 076 records, **4.7 s**, **26 MB peak**, 0 discarded.

`--collect-memory` runs the same chain but keeps every record in memory and
serialises in one block, the way the API path did. It exists to make the memory
claim checkable rather than asserted: same records, same build, same host, only
the write strategy differs. It should produce a **byte-for-byte identical**
`events.json` — which is also how `EcrivainJsonTableau` is verified against
`writeJsonFile`:

```bash
/usr/bin/time -v wine build-windows/tests/evtx_test.exe --collect-memory "Z:/tmp/tree" "Z:/tmp/out2"
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
  page, `WAC/doc/cover_EN.png`, is generated from the French one by
  `WAC/doc/translate-cover.py`, which repaints its text in the same fonts and
  layout.
- **Testing guide**, in English and French: `WAC/doc/tests/testing_EN.pdf` and
  `WAC/doc/tests/testing_FR.pdf`. How to run each test by hand — the VM cycle
  and its cross-checks, the format harnesses, the robustness harnesses — what
  each one proves and does not prove, and how to read a failure. Its covers are
  derived from the manual's by `WAC/doc/retitle-cover.py`, which changes only
  the title. Every document shares one layout, `WAC/doc/wac-style.tex`.
- **Validation report**, in English and French:
  `WAC/doc/validation/validation_EN.pdf` and `validation_FR.pdf`. What
  establishes WAC's quality: the checks WAC runs itself during every
  collection, the thirteen test programs and their judges, the VM cycle and the
  cross-checks of `check-json.py`, the cross-checks on a real collection — with
  the reference result of each, the defects each one caught, and the limits of
  what they guarantee. Same template, cover retitled by `retitle-cover.py`.
- `WAC/doc/BUILD-LINUX_EN.md` (French: `BUILD-LINUX_FR.md`) — cross-compilation details.

The design rationale lives **in the code**, next to what it explains: each
non-obvious choice carries a comment saying why it is that way and what breaks
otherwise. Several of them record a defect that was actually hit — a hash
formatted without padding, a length compared against a hard-coded value, a
pointer read after being freed — because the cause is the part worth keeping.
