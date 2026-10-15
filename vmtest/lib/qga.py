#!/usr/bin/env python3
"""qga.py — drives a Windows VM through qemu-guest-agent (virsh), for autonomous WAC tests.

From the Linux host, with no click and no network, it can:
  - run   : run a command in the VM (SYSTEM context = admin, no UAC)
  - read  : read a file from the VM onto the host
  - write : write a file from the host into the VM
  - ping  : check that the agent answers

Usage:
  qga.py ping [--dom win11-test]
  qga.py run  [--timeout s] -- <cmd> [args...]
  qga.py run  --shell "cmd /c ..."
  qga.py read  <guest_path> <host_output>
  qga.py write <host_file> <guest_path>
"""
import argparse, base64, json, os, re, subprocess, sys, time

CONN = "qemu:///session"

# Transient agent errors (service busy or restarting): retried.
TRANSIENT = ("not responding", "not available", "not connected", "Broken pipe")

def qga(dom, cmd, attempts=6, fatal=True):
    """Sends a qemu-agent-command and returns its 'return' field.
    Retries with a backoff on the agent's transient unavailability.
    fatal=False: a refusal by the agent returns None instead of exiting."""
    last = ""
    for n in range(attempts):
        out = subprocess.run(
            ["virsh", "-c", CONN, "qemu-agent-command", dom, json.dumps(cmd)],
            capture_output=True, text=True)
        if out.returncode == 0:
            return json.loads(out.stdout).get("return")
        last = out.stderr.strip()
        if not any(t in last for t in TRANSIENT):
            if not fatal:
                return None
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

# STALE OUTPUTS. The agent keeps a finished process until its status has been
# read once, and looks a status up by PID. A run interrupted before reading it
# (a harness stopped midway) leaves that process behind; Windows reuses PIDs
# quickly, and a later command given the same PID got the OLD command's
# output: a SHA-256 comparison answered with a list of JSON files. Every PID
# launched is therefore recorded until its status is read, and those left
# behind are read — hence released — before any new command.
PENDING = os.path.join(os.path.expanduser("~"), ".cache", "wac-qga")


def pending_path(dom):
    return os.path.join(PENDING, f"{dom}.pending.json")


def pending_load(dom):
    try:
        with open(pending_path(dom), encoding="utf-8") as f:
            return [int(p) for p in json.load(f)]
    except (OSError, ValueError, TypeError):
        return []


def pending_save(dom, pids):
    os.makedirs(PENDING, exist_ok=True)
    temporary = pending_path(dom) + ".tmp"
    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(sorted(set(pids)), f)
    os.replace(temporary, pending_path(dom))       # never half-written


def release_pending(dom):
    """Reads the status of the processes a previous run left unread: a
    finished one is thereby released; a running one keeps its PID, which no
    new process can then share."""
    kept = []
    for pid in pending_load(dom):
        st = qga(dom, {"execute": "guest-exec-status", "arguments": {"pid": pid}}, fatal=False)
        if st is not None and not st.get("exited"):
            kept.append(pid)
    pending_save(dom, kept)


# POWERSHELL 2 (Windows 7) cannot be started by the agent: its console host
# looks for a console the agent's processes do not have, and fails
# (GetActiveScreenBufferHandle, in Windows Error Reporting) with exit code 1
# and no output. A process started by the Task Scheduler gets a hidden
# console: on such a VM, powershell.exe is run through a one-shot task, its
# output and exit code coming back through files, removed after.
PS_TASK = "WacQgaPowerShell"
PS_DIR = r"C:\wac-qga-ps"


def powershell_two_only(dom):
    """True when the VM has PowerShell 2 and no later one; asked once, kept."""
    cache = os.path.join(PENDING, f"{dom}.powershell")
    try:
        with open(cache, encoding="utf-8") as f:
            return f.read().strip() == "2"
    except OSError:
        pass
    code, _, _ = run_direct(dom, ["reg.exe", "query", r"HKLM\SOFTWARE\Microsoft\PowerShell\3"])
    two = code != 0
    os.makedirs(PENDING, exist_ok=True)
    with open(cache, "w", encoding="utf-8") as f:
        f.write("2" if two else "3+")
    return two


def cmd_quote(arg):
    """One argument on a cmd.exe line: quoted when it holds a space or a
    character cmd would interpret."""
    if arg and not any(c in arg for c in ' \t"&|<>^()%!'):
        return arg
    return '"' + arg.replace('"', '\\"') + '"'


def powershell_through_task(dom, argv, timeout):
    """Runs powershell.exe through a one-shot task of the SYSTEM account."""
    args = list(argv[1:])
    lowered = [a.lower() for a in args]
    # The cmdlets PowerShell 2 lacks (guest/ps2-compat.ps1) are loaded first.
    compat = PS_DIR + "\\compat.ps1"
    prelude = f". '{compat}'; "
    if "-command" in lowered:
        i = lowered.index("-command")
        script = prelude + " ".join(args[i + 1:])
        args = args[:i]
    elif "-file" in lowered:
        # A script and its arguments: called from a command, the prelude before it.
        i = lowered.index("-file")
        quote = lambda a: a if re.fullmatch(r"-[A-Za-z]+", a) else "'" + a.replace("'", "''") + "'"
        # -File gives the script's exit code; a command gives 0 or 1 unless
        # it exits with the script's own.
        script = (prelude + "& " + quote(args[i + 1]) + "".join(" " + quote(a) for a in args[i + 2:])
                  + "; exit $LASTEXITCODE")
        args = args[:i]
    else:
        script = None
    if script is not None:
        # The command as UTF-16 base64: no quoting, no "%" for cmd to expand.
        # The prelude is a script: allowed to run whatever the machine's policy.
        if "-executionpolicy" not in [x.lower() for x in args]:
            args += ["-ExecutionPolicy", "Bypass"]
        args += ["-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode()]
    line = "powershell.exe " + " ".join(cmd_quote(a) for a in args)
    if not line.isascii():
        sys.exit("[qga] a PowerShell 2 command line run through a task must be ASCII (use -Command, encoded)")
    wrapper = ("@echo off\r\n"
               f"{line} > {PS_DIR}\\out.txt 2> {PS_DIR}\\err.txt < NUL\r\n"
               f"(echo %errorlevel%)> {PS_DIR}\\code.txt\r\n")   # "echo 0> f" would redirect handle 0
    run_direct(dom, ["cmd.exe", "/c", f"(if exist {PS_DIR} rmdir /s /q {PS_DIR}) & mkdir {PS_DIR}"])
    write_file(dom, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guest", "ps2-compat.ps1"), compat, quiet=True)
    h = qga(dom, {"execute": "guest-file-open", "arguments": {"path": PS_DIR + "\\run.cmd", "mode": "wb"}})
    try:
        qga(dom, {"execute": "guest-file-write", "arguments": {"handle": h, "buf-b64": base64.b64encode(wrapper.encode("ascii")).decode()}})
    finally:
        qga(dom, {"execute": "guest-file-close", "arguments": {"handle": h}})
    run_direct(dom, ["schtasks.exe", "/create", "/tn", PS_TASK, "/tr", PS_DIR + "\\run.cmd", "/sc", "once",
                     "/st", "00:00", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"])
    run_direct(dom, ["schtasks.exe", "/run", "/tn", PS_TASK])
    t0 = time.time()
    try:
        while not guest_read_text(dom, PS_DIR + "\\code.txt"):
            if time.time() - t0 > timeout:
                sys.exit(f"[qga] execution timeout ({timeout} s) — PowerShell may still be running in the VM")
            time.sleep(1)
        code = int((guest_read_text(dom, PS_DIR + "\\code.txt") or "1").strip() or 1)
        out = guest_read_text(dom, PS_DIR + "\\out.txt") or ""
        err = guest_read_text(dom, PS_DIR + "\\err.txt") or ""
        return code, out, err
    finally:
        run_direct(dom, ["schtasks.exe", "/delete", "/tn", PS_TASK, "/f"])
        run_direct(dom, ["cmd.exe", "/c", f"rmdir /s /q {PS_DIR}"])


def guest_read_text(dom, guest_path):
    """A small file of the VM as text, or None when it is not there."""
    h = qga(dom, {"execute": "guest-file-open", "arguments": {"path": guest_path, "mode": "rb"}}, fatal=False)
    if h is None:
        return None
    data = b""
    try:
        while True:
            r = qga(dom, {"execute": "guest-file-read", "arguments": {"handle": h, "count": 256 << 10}})
            data += base64.b64decode(r["buf-b64"])
            if r.get("eof"):
                break
    finally:
        qga(dom, {"execute": "guest-file-close", "arguments": {"handle": h}})
    # UTF-8 when the script set its output so, the console's code page otherwise.
    # PowerShell 2 heads a redirected UTF-8 output with a byte-order mark: not part of it.
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp850", "replace")


def run(dom, argv, capture=True, timeout=DEFAULT_TIMEOUT):
    """Runs argv[0] with argv[1:] in the VM; returns (code, stdout, stderr).
    powershell.exe goes through a task on a VM with PowerShell 2 only."""
    if os.path.basename(argv[0]).lower() == "powershell.exe" and powershell_two_only(dom):
        return powershell_through_task(dom, argv, timeout)
    return run_direct(dom, argv, capture, timeout)


def run_direct(dom, argv, capture=True, timeout=DEFAULT_TIMEOUT):
    """Runs argv[0] with argv[1:] in the VM through the agent; returns (code, stdout, stderr)."""
    release_pending(dom)
    pid = qga(dom, {"execute": "guest-exec", "arguments": {
        "path": argv[0], "arg": argv[1:],
        "capture-output": capture}})["pid"]
    pending_save(dom, pending_load(dom) + [pid])
    t0 = time.time()
    while True:
        st = qga(dom, {"execute": "guest-exec-status", "arguments": {"pid": pid}})
        if st.get("exited"):
            pending_save(dom, [p for p in pending_load(dom) if p != pid])
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

def write_file(dom, host_path, guest_path, quiet=False):
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
    if not quiet:
        print(f"{len(data)} bytes -> VM:{guest_path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dom", default="win11-test")
    sub = ap.add_subparsers(dest="action", required=True)
    sub.add_parser("ping")
    pr = sub.add_parser("run"); pr.add_argument("--shell"); pr.add_argument("cmd", nargs="*")
    pr.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="seconds before giving up on the command (a footprint run of KAPE takes longer)")
    rd = sub.add_parser("read"); rd.add_argument("guest"); rd.add_argument("host")
    wr = sub.add_parser("write"); wr.add_argument("host"); wr.add_argument("guest")
    a = ap.parse_args()

    if a.action == "ping":
        ping(a.dom)
    elif a.action == "run":
        argv = ["cmd.exe", "/c", a.shell] if a.shell else a.cmd
        code, out, err = run(a.dom, argv, timeout=a.timeout)
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
