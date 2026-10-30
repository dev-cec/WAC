"""hive-diff.py — the registry before and after a measured run, read offline
(B-059): what changed in the hives of the clone, beyond what the control run
changed too.

Sysmon gives the registry writes of the tool's processes (footprint-diff.py);
this is the independent count. Each run of run-footprint.sh boots the clone
from the frozen base, runs the tool, and shuts the clone down cleanly: its
hives are then read from the run's disk layer, the VM off, read-only, and set
against the same hives of the base image. Windows changes keys at every boot
and shutdown (start times, ShimCache, services): what the control run
changed too is set apart, and what remains is the run's own, to explain one
by one.

  extract <disk.qcow2> <base.qcow2 | -> <folder>
      the hives of the disk (its backing image given, or "-" for none) and
      their headers' sequence numbers into <folder>
  diff <base folder> <run folder> [<control folder>]
      keys added, removed or rewritten, values added, removed or changed;
      with a control, those it shows too are counted apart
Run with vmtest/tools/target-venv/bin/python (dissect).
"""
import hashlib
import json
import os
import struct
import sys
import uuid

from dissect.fve.bde import BDE, is_bde_volume
from dissect.hypervisor.disk.qcow2 import QCow2
from dissect.ntfs import NTFS
from dissect.regf import regf

SECTOR = 512
BASIC_DATA = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")   # GPT type of a Windows data partition
HIVES = [
    "Windows/System32/config/SYSTEM", "Windows/System32/config/SOFTWARE",
    "Windows/System32/config/SAM", "Windows/System32/config/SECURITY",
    "Windows/System32/config/DEFAULT", "Windows/AppCompat/Programs/Amcache.hve",
    "Windows/ServiceProfiles/LocalService/NTUSER.DAT",
    "Windows/ServiceProfiles/NetworkService/NTUSER.DAT",
]
PROFILE_HIVES = ["NTUSER.DAT", "AppData/Local/Microsoft/Windows/UsrClass.dat"]


class Partition:
    """The disk seen from a partition's first byte (what dissect.ntfs and
    dissect.fve read), as large as the partition: BitLocker sizes its
    decrypted stream from it."""
    def __init__(self, disk, start, size):
        self.disk, self.start, self.size, self.position = disk, start, size, 0

    def seek(self, offset, whence=0):
        self.position = (offset, self.position + offset, self.size + offset)[whence]
        return self.position

    def tell(self):
        return self.position

    def read(self, size=-1):
        self.disk.seek(self.start + self.position)
        data = self.disk.read(self.size - self.position if size < 0 else min(size, self.size - self.position))
        self.position += len(data)
        return data


def windows_partition(disk):
    """The first byte and the size of the largest GPT data partition: the system volume."""
    disk.seek(SECTOR)
    header = disk.read(92)
    if header[:8] != b"EFI PART":
        sys.exit("no GPT on this disk")
    entries_lba, count, size = struct.unpack_from("<QII", header, 72)
    disk.seek(entries_lba * SECTOR)
    table = disk.read(count * size)
    best = None
    for n in range(count):
        entry = table[n * size:(n + 1) * size]
        if uuid.UUID(bytes_le=entry[:16]) != BASIC_DATA:
            continue
        first, last = struct.unpack_from("<QQ", entry, 32)
        if best is None or last - first > best[1] - best[0]:
            best = (first, last)
    if best is None:
        sys.exit("no data partition in the GPT")
    return best[0] * SECTOR, (best[1] - best[0] + 1) * SECTOR


def system_volume(partition):
    """The NTFS bytes of the partition. Windows 11 encrypts its volume with
    BitLocker even with protection off (the test VM: "used space only",
    no protector): the key is then kept in clear on the volume, and opens it."""
    if not is_bde_volume(partition):
        return partition
    bde = BDE(partition)
    if not bde.has_clear_key():
        sys.exit("BitLocker volume without a clear key: protection on, not read")
    return bde.unlock_with_clear_key().open()


def extract(image, backing, folder):
    """Copies the hives of the disk, and their header's two sequence numbers."""
    base = None if backing == "-" else open(backing, "rb")
    with open(image, "rb") as fh:
        disk = QCow2(fh, backing_file=base).open()
        volume = NTFS(system_volume(Partition(disk, *windows_partition(disk))))
        wanted = list(HIVES)
        for profile in volume.mft.get("Users").listdir(ignore_dos=True):
            wanted += [f"Users/{profile}/{hive}" for hive in PROFILE_HIVES]
        sequences = {}
        for path in wanted:
            try:
                data = volume.mft.get(path).open().read()
            except Exception:
                continue   # a profile without its hive (Public, Default User…)
            target = os.path.join(folder, *path.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(data)
            first, second = struct.unpack_from("<II", data, 4)
            sequences[path] = [first, second]
    if base:
        base.close()
    with open(os.path.join(folder, "sequences.json"), "w") as f:
        json.dump(sequences, f, indent=1)
    unflushed = [p for p, (a, b) in sequences.items() if a != b]
    print(f"   {len(sequences)} hive(s) read" + (f"; not reconciled with their logs: {unflushed}" if unflushed else ""))


def flatten(path):
    """Every key (its last write) and every value (type and digest of its data)."""
    items = {}
    with open(path, "rb") as fh:
        hive = regf.RegistryHive(fh)
        stack = [hive.root()]
        while stack:
            key = stack.pop()
            items[("key", key.path)] = key.timestamp.isoformat()
            for value in key.values():
                items[("value", key.path, value.name)] = (value.type, hashlib.sha1(value.data or b"").hexdigest())
            stack.extend(key.subkeys())
    return items


def changes(before, after):
    """(kind, path…) -> what happened: added, removed, changed (rewritten for a key)."""
    out = {}
    for item in after.keys() - before.keys():
        out[item] = "added"
    for item in before.keys() - after.keys():
        out[item] = "removed"
    for item in before.keys() & after.keys():
        if before[item] != after[item]:
            out[item] = "rewritten" if item[0] == "key" else "changed"
    return out


def hives_of(folder):
    found = []
    for root, _, files in os.walk(folder):
        found += [os.path.relpath(os.path.join(root, f), folder).replace(os.sep, "/") for f in files if not f.endswith(".json")]
    return sorted(found)


def diff(base, run, control=None):
    report = {}
    for hive in hives_of(run):
        if not os.path.exists(os.path.join(base, hive)):
            print(f"   {hive}: not in the base, not compared")
            continue
        before = flatten(os.path.join(base, hive))
        own = changes(before, flatten(os.path.join(run, hive)))
        common = {}
        if control and os.path.exists(os.path.join(control, hive)):
            seen = changes(before, flatten(os.path.join(control, hive)))
            common = {item: what for item, what in own.items() if item in seen}
        remaining = {item: what for item, what in own.items() if item not in common}
        print(f"   {hive}: {len(own)} change(s), {len(common)} also in the control, {len(remaining)} of the run alone")
        for item, what in sorted(remaining.items()):
            print(f"      {what:9} {item[0]:5} {item[1] or '(root)'}" + (f" : {item[2]}" if len(item) > 2 else ""))
        report[hive] = {"changes": len(own), "also_in_control": len(common),
                        "run_alone": [[what] + list(item) for item, what in sorted(remaining.items())]}
    with open(os.path.join(run, "hive-diff.json"), "w") as f:
        json.dump(report, f, indent=1)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) in (4, 5) and sys.argv[1] == "diff":
        diff(*sys.argv[2:])
    else:
        sys.exit(__doc__)
