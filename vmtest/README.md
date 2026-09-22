# Windows 11 test VM — driving WAC unattended

*Version française : [README.fr.md](README.fr.md)*

Tests WAC on a real Windows 11 (real NTFS) **with no interaction at all**: build
on Linux → run in the VM as SYSTEM → JSON brought back to the host.

Everything goes through the **qemu-guest-agent** (virtio-serial channel): no
network, no file share, no clicking in the VM (commands run as SYSTEM:
administrator rights, no UAC).

## Files
| File | Role |
|---|---|
| `create-vm.sh` | Creates the VM from scratch, unattended: autounattend + UEFI Secure Boot + TPM 2.0 + guest-agent channel, boot unblocked by key injection, then waits for the agent to answer. |
| `autounattend.xml` | Silent Windows install (French, Win11 Pro, local admin account `wac`/`wac`, OOBE skipped, autologon) **and automatic guest-agent install** at first logon from the virtio-win CD. |
| `qga.py` | Guest-agent helper: `ping`, `run` (execute), `read`/`write` (exchange files). |
| `run-wac-test.sh` | Full test cycle: build → send the binaries → `raw_hive` validation (raw extraction + `reg load`) → run WAC → bring the log and the JSON back into `results/<timestamp>/`. |
| `check-json.py` | Checks the outputs: JSON validity, Windows paths, and **cross-checks** (see below). Also usable alone: `python3 check-json.py results/<timestamp>`. |

## What the harness validates — and what it does not

It validates **compilation**, WAC's **termination** (exit code, no
`terminate called` / `Unhandled exception`), the **JSON validity** of every
output and the **consistency of Windows paths**.

It validates **neither the accuracy nor the completeness** of the values: a
wrong field under a right key, a misread date or a parsing offset all produce
perfectly valid JSON. An artefact with "0 entries" is, moreover, impossible to
tell apart from "no trace on the machine".

**That is what the cross-checks are for**: comparing a value *computed by WAC*
with an *independent* value from the same collection. They are what revealed
wrong values in valid JSON:

| Check | What it found |
|---|---|
| a Prefetch `Hash` vs the suffix of its file name | 65 wrong hashes out of 270 (hexadecimal formatted without padding) |
| `X` / `XUtc` pairs carrying the same wall-clock time | double time-zone shift (`sessions`, `.lnk`, `InstallDate`) |
| no session starting before system boot | the first of those shifts — and later a boot time 3.5 s late, estimated from `GetTickCount64` |
| boot time vs the Kernel-General 12 event | two independent sources of the boot instant: 0.00 s apart since the kernel value is used |
| impossible service states, rate of `*_UNKNOWN`, presence of drivers | converters comparing enumeration filters with states |
| `RID` found at the end of the rebuilt `SID` | validation of the SAM reading |
| no process carries `WAC.exe` among its modules | the Idle process inherited the collecting tool's modules |
| `EvtSystemComputer` vs the machine name of `OperatingSystem.json` | check of the logs' BinXML decoding: two unrelated sources (`.evtx` file and SYSTEM hive) |
| record identifiers unique within EACH log file | the real invariant: one channel can be carried by several files whose numbers legitimately overlap. A duplicate within one file, however, reveals a stale chunk read again — the risk of walking every physical chunk |
| MAJORITY machine name of the events matching `OperatingSystem.json` | renaming a machine legitimately leaves old names in the logs: the majority must match, not all of them |
| no event later than the collection time | shift or misreading of an event `FILETIME` |
| an unresolved `%%nnnn` reference left in a message | a provider's parameter file not loaded (3,780 Security messages before the fix) — told apart from a `%N` mark, which only means data absent from the event |
| no hive both replayed AND patched | two independent audit-log operations: a successful replay makes the hive clean, so the patch must no longer apply |
| an undo journal named for every replay | without it the raw copy can no longer be rebuilt, and the report's promise would be false |
| `MANIFESTE.sha256` carries the real fingerprint of `MANIFESTE.json` | the only check that detects a retouched manifest — the very thing that attests to the exhibits |
| every collected exhibit carries its three fingerprints | an exhibit without a fingerprint is unidentified, hence unusable |
| the system drive of `OperatingSystem.json` is among the manifest's volumes read | two independent sources of the same information |
| the files actually present in `consigne/` are exactly those of the manifest | 209 exhibits added after sealing, identified by nothing, while every other check was green |

**WAC's log accumulates.** It is opened in append mode: without purging, it grows
from one test to the next — 636 MB after a series of runs, which made fetching
it useless and buried the current run's traces under the previous ones'.
`run-wac-test.sh` now deletes it before each run.

**The harness can run out of memory.** `qga.py read` used to accumulate the
whole file before writing it: with a 28 MB `events.json`, the base64 responses
and their decoding, with the VM running alongside, were enough for the system to
kill the harness mid-collection. Chunks now go straight to the file.
`check-json.py` still loads `events.json` whole — to revisit if the logs keep
growing.

**The harness can cause the defect it reports.** A 604 s run was cut by
`qga.py`'s 600 s timeout just before the last two JSON files were written: the
report said "collection probably incomplete" — which was true — but WAC had
finished. The collection log (`run.log`, which ends with `END, Time elapsed`)
settles it. Timeout raised to 30 min; to revisit if the collection gets longer.

**Microsoft authenticity is confronted with Windows.** `WAC/authenticode_test.cpp`
verifies the catalogs of a folder, then gives a verdict per file; built for
Windows, it runs in the VM on the binaries collected by a collection, and its
verdicts are compared with `Get-AuthenticodeSignature` on the same files. Out of
2,233 binaries: 2,126 authenticated by both, 99 collected by both, and no file
accepted by WAC that Windows would reject — the only difference that would
matter. For scripts: 462 PowerShell and 11 WSH scripts, all authenticated as
Windows does, and a signed script changed by one word is rejected. The program
reads files through the API: it is a test tool, never used during a collection.

**The manifest is confronted with the actual content of the exhibit store.** The
harness lists the files of `consigne/` in the VM (`LISTE.txt`), and
`check-json.py` checks that every file present is in the manifest, and the other
way round. Without this check, 209 exhibits — the event providers' resource
binaries, extracted after sealing — stayed in the exhibit store identified by
nothing, while every other check (seal, fingerprints, counts) was green: they
only looked at the manifest itself.

**The exhibit store is validated outside the VM too.** `WAC/consigne_test.cpp`
replays the production chain (fingerprints, manifest, verified copy, replay) on
hives given as arguments, and checks what no compilation reveals: that the
exhibit store stays byte-identical while the working copy is modified.
`WAC/sha_test.cpp` confronts the fingerprints with the FIPS 180-4 vectors and
with lengths 55 to 128, which exercise the padding — the one place where an
otherwise correct implementation goes wrong. Both build natively on Linux.

**The EVTX parser is validated outside the VM.** BinXML decoding is too fragile
to be tried only on the logs of a fresh VM, all written by the same Windows
build and all clean. `WAC/evtx_test.cpp` (left out of the build by the
`_test.cpp` pattern) reads an `.evtx` and returns either a summary or the XML of
each record (`--dump`); it runs under `wine`, which makes it possible to
confront it with real logs — deliberately damaged ones included — and to compare
record by record with an independent implementation (`python-evtx`). That is
what showed that a chunk with a wrong signature stopped the reading of the whole
file: 14 records read out of 270. The extracted logs are also checked against
the CRC32 each EVTX chunk carries: all 1,505 chunks of the 404 logs of the test
VM verify.

The `--collecte` mode runs the whole chain (raw file → BinXML → `xml_light` →
`Event` → streamed JSON) on a tree mimicking an extraction, and
`--collecte-memoire` does the same while accumulating everything in memory as
the API-based collection did. That makes the memory argument verifiable instead
of asserted: same records, same binary, same host, only the writing strategy
changes — a 1,281 MB peak against 26 MB, for a byte-identical `events.json`
(which also validates `EcrivainJsonTableau` against `writeJsonFile`).

**After any change, compare the entry counts with the previous run**, not just
the green marks — and write a cross-check for every defect found: that is what
prevents regressions.

## Usage
```bash
# Create the VM (once, ~15-25 min, no interaction)
ISO_WIN=~/Downloads/Win11_25H2_French_x64_v2.iso ./create-vm.sh

# Test WAC (at every code iteration)
./run-wac-test.sh --build        # rebuild + full test
./run-wac-test.sh --raw-only     # raw_hive validation only
python3 qga.py ping              # is the agent answering?
python3 qga.py run --shell "dir C:\\"
```

## Host requirements
`qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst ovmf swtpm swtpm-tools xorriso`
plus `~/vms/virtio-win.iso` (guest-agent + drivers) and the Windows 11 ISO.

## Note
`virt-install --noautoconsole` does not restart the VM after Setup's first
reboot: `create-vm.sh` restarts it when needed and considers the install
finished when the guest-agent answers (no screenshot to interpret).
