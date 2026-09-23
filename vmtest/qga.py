#!/usr/bin/env python3
"""qga.py — drives a Windows VM through qemu-guest-agent (virsh), for autonomous WAC tests.

From the Linux host, with no click and no network, it can:
  - run   : run a command in the VM (SYSTEM context = admin, no UAC)
  - read  : read a file from the VM onto the host
  - write : write a file from the host into the VM
  - ping  : check that the agent answers

Usage:
  qga.py ping [--dom win11-test]
  qga.py run  -- <cmd> [args...]
  qga.py run  --shell "cmd /c ..."
  qga.py read  <guest_path> <host_output>
  qga.py write <host_file> <guest_path>
"""
import argparse, base64, json, subprocess, sys, time

CONN = "qemu:///session"

# Transient agent errors (service busy or restarting): retried.
TRANSIENT = ("not responding", "not available", "not connected", "Broken pipe")

def qga(dom, cmd, attempts=6):
    """Sends a qemu-agent-command and returns its 'return' field.
    Retries with a backoff on the agent's transient unavailability."""
    last = ""
    for n in range(attempts):
        out = subprocess.run(
            ["virsh", "-c", CONN, "qemu-agent-command", dom, json.dumps(cmd)],
            capture_output=True, text=True)
        if out.returncode == 0:
            return json.loads(out.stdout).get("return")
        last = out.stderr.strip()
        if not any(t in last for t in TRANSIENT):
            sys.exit(f"[qga] virsh error: {last}")
        time.sleep(2 * (n + 1))          # 2, 4, 6, 8, 10 s
    sys.exit(f"[qga] agent unreachable after {attempts} attempts: {last}")

# A full collection with --events takes ~10 min on the test VM and grows longer
# as the event log grows. The timeout used to be 600 s: a 604 s run was cut
# JUST before events.json and investigation.json were written, and the harness
# fetched 22 files out of 24, reporting "collection probably incomplete". The
# diagnosis was right, but the cause was the harness itself, not WAC. The margin
# is raised to 30 min.
DEFAULT_TIMEOUT = 1800


def ping(dom):
    qga(dom, {"execute": "guest-ping"})
    print("agent OK")

def run(dom, argv, capture=True, timeout=DEFAULT_TIMEOUT):
    """Runs argv[0] with argv[1:] in the VM; returns (code, stdout, stderr)."""
    pid = qga(dom, {"execute": "guest-exec", "arguments": {
        "path": argv[0], "arg": argv[1:],
        "capture-output": capture}})["pid"]
    t0 = time.time()
    while True:
        st = qga(dom, {"execute": "guest-exec-status", "arguments": {"pid": pid}})
        if st.get("exited"):
            out = base64.b64decode(st.get("out-data", "")).decode("utf-8", "replace")
            err = base64.b64decode(st.get("err-data", "")).decode("utf-8", "replace")
            return st.get("exitcode", 0), out, err
        if time.time() - t0 > timeout:
            sys.exit(f"[qga] execution timeout ({timeout} s) — the command "
                     f"may still be running in the VM")
        time.sleep(1)

def read_file(dom, guest_path, host_path):
    """Fetches a file from the VM, WRITTEN AS IT IS READ.

    The content used to be accumulated in memory before being written: on a
    28 MB events.json, the base64 answers plus their decoding were enough, with
    the VM itself, to have the harness killed for lack of memory. Each chunk now
    goes straight into the file.
    """
    h = qga(dom, {"execute": "guest-file-open",
                  "arguments": {"path": guest_path, "mode": "rb"}})
    total = 0
    try:
        with open(host_path, "wb") as f:
            while True:
                r = qga(dom, {"execute": "guest-file-read",
                              "arguments": {"handle": h, "count": 256 << 10}})
                chunk = base64.b64decode(r["buf-b64"])
                f.write(chunk)
                total += len(chunk)
                if r.get("eof"):
                    break
    finally:
        qga(dom, {"execute": "guest-file-close", "arguments": {"handle": h}})
    print(f"{total} bytes -> {host_path}")

def write_file(dom, host_path, guest_path):
    with open(host_path, "rb") as f:
        data = f.read()
    h = qga(dom, {"execute": "guest-file-open",
                  "arguments": {"path": guest_path, "mode": "wb"}})
    try:
        # 48 KiB raw -> ~64 KiB of base64: stays under Linux's limit of ~128 KiB
        # PER ARGUMENT (MAX_ARG_STRLEN), the JSON being passed in argv.
        CHUNK = 48 << 10
        for i in range(0, len(data), CHUNK):
            encoded = base64.b64encode(data[i:i + CHUNK]).decode()
            qga(dom, {"execute": "guest-file-write",
                      "arguments": {"handle": h, "buf-b64": encoded}})
    finally:
        qga(dom, {"execute": "guest-file-close", "arguments": {"handle": h}})
    print(f"{len(data)} bytes -> VM:{guest_path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dom", default="win11-test")
    sub = ap.add_subparsers(dest="action", required=True)
    sub.add_parser("ping")
    pr = sub.add_parser("run"); pr.add_argument("--shell"); pr.add_argument("cmd", nargs="*")
    rd = sub.add_parser("read"); rd.add_argument("guest"); rd.add_argument("host")
    wr = sub.add_parser("write"); wr.add_argument("host"); wr.add_argument("guest")
    a = ap.parse_args()

    if a.action == "ping":
        ping(a.dom)
    elif a.action == "run":
        argv = ["cmd.exe", "/c", a.shell] if a.shell else a.cmd
        code, out, err = run(a.dom, argv)
        if out: sys.stdout.write(out)
        if err: sys.stderr.write(err)
        sys.exit(code)
    elif a.action == "read":
        read_file(a.dom, a.guest, a.host)
    elif a.action == "write":
        write_file(a.dom, a.host, a.guest)

if __name__ == "__main__":
    # FORESEEABLE errors leave through a message, never through an exception.
    #
    # An uncaught exception in a script marked executable triggers the system's
    # crash reporter, and the operator gets a "qga.py stopped unexpectedly"
    # window for a missing file or a VM that is off — two perfectly ordinary
    # situations during a test. The message must say what is missing, and the
    # return code is enough for the calling script.
    try:
        main()
    except FileNotFoundError as e:
        print(f"[qga] file not found: {e.filename}", file=sys.stderr)
        sys.exit(2)
    except (BrokenPipeError, KeyboardInterrupt):
        sys.exit(130)
    except RuntimeError as e:
        # The failures of the dialogue with the agent are already worded by qga().
        print(f"[qga] {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[qga] input/output error: {e}", file=sys.stderr)
        sys.exit(1)
