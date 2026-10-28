# WAC — instructions for Claude Code

What a clone of the repository needs to build and test WAC, without the
notes of the original working environment.

## Running the tests

Everything is driven from a Linux host; no Windows machine is needed except
the test VMs.

### 1. Build

```bash
./build-windows.sh --test      # WAC.exe, WAC32.exe, raw_hive_test.exe AND the unit tests
```

- Prerequisites: `g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools`
  (and the i686 ones for WAC32). The build must stay free of warnings
  (`-Wall -Wextra`).
- Without `--test` the unit tests are not built: always pass it before
  committing. The executables land in `build-windows/`, the tests in
  `build-windows/tests/`.
- The script copies the result into `bin/` **and stages it** (`git add bin`):
  run `git reset -q -- bin` afterwards, and commit `bin/` with the change it
  belongs to — `bin/` is always the last build of the code committed.

### 2. Unit tests (under Wine)

```bash
cd build-windows/tests
wine ntfs_runs_test.exe        # most tests take no argument
```

Some need a folder or test data, made by the `sources/*_fixtures.sh` scripts
from independent implementations (ntfs-3g, libpff, libmsiecf, openssl):

| Test | Argument |
|---|---|
| `mft_test`, `usn_journal_test` | folder made by `sources/mft_fixtures.sh <folder>` (needs ntfs-3g: `mkntfs`, `ntfscp`, `ntfscat`, `ntfsinfo`) |
| `activities_cache_test` | folder made by `sources/activities_cache_fixtures.sh` |
| `pst_test` | folder made by `sources/pst_fixtures.sh` (`pip install libpff-python`, `$PYTHON`) |
| `ie_index_dat_test` | folder made by `sources/ie_index_fixtures.sh` (`pip install libmsiecf-python`, `$PYTHON`) |
| `hive_recover_test`, `config_test` | an empty scratch folder |
| `third_party_chain_test` | folder made by `sources/third_party_chain_fixtures.sh`; built by hand (command in its header) |
| the others printing `usage:` | real files (hives, `.evtx`, `.lnk`…), see the header of each `*_test.cpp` |

Generate the fixtures in a temporary folder, never in `sources/` (the tests
write next to their data). `system_conversions_test` and `xp_imports_test`
need functions Wine does not implement: they run in the VMs.

A fix comes with the test that catches it, **seen failing**: mutate the fix,
rebuild, watch the test fail, restore — then **rebuild again** and check that
`bin/WAC.exe` is identical to `build-windows/WAC.exe` (`cmp`). A mutant
WAC.exe must never reach `bin/` or a VM cycle.

### 3. VM cycles (`vmtest/`)

The unit tests prove the decoders; only a real Windows proves the
collection. `vmtest/README.md` (and `README_FR.md`) describe the harness in
full; in short:

```bash
cd vmtest
ISO_WIN=<Windows 11 ISO> ./create-vm.sh            # once: win11-test, unattended
./create-vm.sh win7                                  # other profiles: win81 win8 win7 vista winxp srv2012r2…srv2025
WAC_VM=win11-test ./run-wac-test.sh                  # a full cycle, ~1 h 20
WAC_VM=win7-test  ./run-wac-test.sh --only=mft       # a few minutes, one artefact
./run-wac-test-xp.sh                                 # Windows XP (no agent: keyboard + COM1)
```

- The VMs live in the **user's** libvirt session: `virsh -c qemu:///session …`
  (`qemu:///system` shows none). The test account is `wac`/`wac`, an
  administrator with automatic logon; its password never expires
  (`net accounts /maxpwage:unlimited`, set at installation). On a VM made
  before that, run it once — an expired password stops the automatic logon,
  and every witness of the user's hive then fails while WAC is not at fault.
- **Before a cycle**, check the user session is open:
  `virsh -c qemu:///session qemu-agent-command <vm> '{"execute":"guest-get-users"}'`
  must list `wac`.
- **Let a VM rest ~20 minutes after it boots** (or after Windows Update):
  indexers, Superfetch and updates write in the meantime and give failures
  that are noise. Explain each failure before calling it a regression.
- **While a cycle runs, touch nothing it uses**: not `build-windows.sh`
  (it rewrites `build-windows/WAC.exe`, which the cycle uploads), not
  `run-wac-test.sh`, `lib/check-json.py`, `guest/*` nor `bin/`; nothing inside
  the VM either. Starting another VM steals CPU from witnesses that depend on
  timing: wait.
- The results land in `vmtest/results/<date>/` (not versioned). Count
  `✅`/`❌` in the log; a `witness_failed=` line in
  `reference/file-artefacts.txt` means the harness could not place a witness:
  its checks have nothing to confront, the cause is in the VM, not in WAC.
- Leave no traces in a VM beyond what the cycle cleans up: copies, scripts and
  outputs pushed by hand are removed afterwards.
- Never `virsh undefine --remove-all-storage`: it deletes the ISOs the VMs
  share.

### 4. Documentation

`doc/build-docs.sh` builds the manuals (LuaLaTeX); French and English are kept
in step, and the build must report no `Overfull` box.
