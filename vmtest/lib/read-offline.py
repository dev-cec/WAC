"""read-offline.py — copies files out of a test VM's disk while the VM is off,
read-only: the first NTFS partition of its qcow2 image, through dissect
(vmtest/tools/target-venv). For a Windows without guest agent (XP), whose
results cannot be fetched while it runs (run-wac-test-xp.sh).

Usage: read-offline.py <disk.qcow2> <output folder> <prefix> <path>...
  <path>   a path on the volume, "/"-separated, without the drive ("wactest/xp/out/events.json");
           "<folder>/*.<ext>" takes the folder's files of that extension
  <prefix> the part of each path left out under the output folder ("wactest/xp/out/"):
           wactest/xp/out/exhibits/MANIFEST.json lands in <output>/exhibits/MANIFEST.json;
           a path outside the prefix lands under its file name
A path absent from the volume is said, not fatal: the checks say what it misses.
"""
import fnmatch
import io
import os
import struct
import sys

from dissect.hypervisor.disk.qcow2 import QCow2
from dissect.ntfs import NTFS

MBR_FIRST_PARTITION = 0x1BE   # the first entry of the partition table
SECTOR = 512


class Partition(io.RawIOBase):
    """The disk seen from a partition's first byte."""
    def __init__(self, disk, start):
        self.disk, self.start, self.position = disk, start, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        self.position = offset if whence == io.SEEK_SET else self.position + offset
        return self.position

    def tell(self):
        return self.position

    def read(self, size=-1):
        self.disk.seek(self.start + self.position)
        data = self.disk.read(size)
        self.position += len(data)
        return data


def main():
    image, output, prefix, paths = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    with open(image, "rb") as fh:
        disk = QCow2(fh).open()
        disk.seek(MBR_FIRST_PARTITION + 8)
        start = struct.unpack("<I", disk.read(4))[0] * SECTOR
        volume = NTFS(Partition(disk, start))
        wanted = []
        for path in paths:
            folder, name = path.rsplit("/", 1) if "/" in path else ("", path)
            if "*" not in name:
                wanted.append(path)
                continue
            try:
                # Long names only: an 8.3 alias ("INVEST~1.JSO") is the same file again.
                entries = volume.mft.get(folder).listdir(ignore_dos=True)
            except Exception as error:
                print(f"   ⚠️ {folder} absent: {error}")
                continue
            wanted += [f"{folder}/{entry}" for entry in entries if fnmatch.fnmatch(entry, name)]
        for path in wanted:
            relative = path[len(prefix):] if path.startswith(prefix) else path.rsplit("/", 1)[-1]
            target = os.path.join(output, *relative.split("/"))
            try:
                data = volume.mft.get(path).open().read()
            except Exception as error:
                print(f"   ⚠️ {path} absent: {error}")
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(data)
        print(f"   {len(wanted)} file(s) read")


if __name__ == "__main__":
    main()
