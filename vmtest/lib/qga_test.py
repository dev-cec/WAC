#!/usr/bin/env python3
"""qga_test.py — read_file of qga.py against a fake agent, without any VM.

The fake agent holds one file and its position, as qemu-guest-agent does,
and answers some reads as virsh does on a timeout: the read is done, the
position moved, and the answer lost ("not responding"). The fetched file
must still be the file, chunk for chunk.

Usage: python3 vmtest/lib/qga_test.py   (exit code 0 if it passes)
"""
import base64, json, os, subprocess, sys, tempfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qga

CHUNK = 256 << 10


class FakeAgent:
    """A file of `size` bytes, each chunk different, read as the agent does;
    the reads numbered in `lost` lose their answer after moving the position."""

    def __init__(self, size, lost):
        self.content = bytes((i // CHUNK + i) % 251 for i in range(size))
        self.position = 0
        self.reads = 0
        self.lost = lost

    def __call__(self, argv, **_):
        cmd = json.loads(argv[-1])
        name, args = cmd["execute"], cmd.get("arguments", {})
        result = {}
        if name == "guest-file-open":
            self.position, result = 0, 1
        elif name == "guest-file-seek":
            self.position = args["offset"]
            result = {"position": self.position, "eof": False}
        elif name == "guest-file-read":
            data = self.content[self.position:self.position + args["count"]]
            self.position += len(data)
            self.reads += 1
            if self.reads in self.lost:
                return subprocess.CompletedProcess(argv, 1, "", "error: Guest agent is not responding")
            result = {"buf-b64": base64.b64encode(data).decode(), "eof": self.position >= len(self.content)}
        return subprocess.CompletedProcess(argv, 0, json.dumps({"return": result}), "")


def main():
    agent = FakeAgent(10 * CHUNK + 1234, lost={4, 9})
    with tempfile.TemporaryDirectory() as folder, \
         mock.patch.object(qga.subprocess, "run", agent), mock.patch.object(qga.time, "sleep"):
        target = os.path.join(folder, "fetched")
        qga.read_file("fake", "C:\\file", target)
        fetched = open(target, "rb").read()
    if fetched != agent.content:
        wrong = [n for n in range(0, len(agent.content), CHUNK) if fetched[n:n + CHUNK] != agent.content[n:n + CHUNK]]
        print(f"FAIL: lost answers to reads 4 and 9, chunks at {[n // CHUNK for n in wrong]} differ")
        return 1
    print("OK: lost answers to two reads, file fetched identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
