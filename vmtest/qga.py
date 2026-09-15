#!/usr/bin/env python3
"""qga.py — pilote une VM Windows via qemu-guest-agent (virsh), pour tests WAC autonomes.

Permet, depuis l'hôte Linux, sans clic ni réseau :
  - run   : exécuter une commande dans la VM (contexte SYSTEM = admin, pas d'UAC)
  - read  : lire un fichier de la VM vers l'hôte
  - write : écrire un fichier de l'hôte vers la VM
  - ping  : vérifier que l'agent répond

Usage :
  qga.py ping [--dom win11-test]
  qga.py run  -- <cmd> [args...]
  qga.py run  --shell "cmd /c ..."
  qga.py read  <chemin_guest> <sortie_hote>
  qga.py write <fichier_hote> <chemin_guest>
"""
import argparse, base64, json, subprocess, sys, time

CONN = "qemu:///session"

# Erreurs transitoires de l'agent (service occupé/qui redémarre) : on réessaie.
TRANSITOIRE = ("not responding", "not available", "not connected", "Broken pipe")

def qga(dom, cmd, essais=6):
    """Envoie une commande qemu-agent-command et retourne le champ 'return'.
    Réessaie avec backoff sur les indisponibilités transitoires de l'agent."""
    last = ""
    for n in range(essais):
        out = subprocess.run(
            ["virsh", "-c", CONN, "qemu-agent-command", dom, json.dumps(cmd)],
            capture_output=True, text=True)
        if out.returncode == 0:
            return json.loads(out.stdout).get("return")
        last = out.stderr.strip()
        if not any(t in last for t in TRANSITOIRE):
            sys.exit(f"[qga] erreur virsh: {last}")
        time.sleep(2 * (n + 1))          # 2,4,6,8,10 s
    sys.exit(f"[qga] agent injoignable après {essais} essais: {last}")

# Une collecte complète avec --events dure ~10 min sur la VM de test et
# s'allonge à mesure que le journal d'événements grossit. Le timeout était de
# 600 s : un run de 604 s a été coupé JUSTE avant l'écriture de events.json et
# d'investigation.json, et le harnais a rapatrié 22 fichiers sur 24 en
# signalant « collecte probablement incomplète ». Le diagnostic était juste,
# mais la cause était le harnais lui-même, pas WAC. Marge portée à 30 min.
TIMEOUT_DEFAUT = 1800


def ping(dom):
    qga(dom, {"execute": "guest-ping"})
    print("agent OK")

def run(dom, argv, capture=True, timeout=TIMEOUT_DEFAUT):
    """Exécute argv[0] avec argv[1:] dans la VM ; retourne (code, stdout, stderr)."""
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
            sys.exit(f"[qga] timeout d'exécution ({timeout} s) — la commande "
                     f"tourne peut-être encore dans la VM")
        time.sleep(1)

def read_file(dom, guest_path, host_path):
    h = qga(dom, {"execute": "guest-file-open",
                  "arguments": {"path": guest_path, "mode": "rb"}})
    data = b""
    try:
        while True:
            r = qga(dom, {"execute": "guest-file-read",
                          "arguments": {"handle": h, "count": 256 << 10}})
            data += base64.b64decode(r["buf-b64"])
            if r.get("eof"):
                break
    finally:
        qga(dom, {"execute": "guest-file-close", "arguments": {"handle": h}})
    with open(host_path, "wb") as f:
        f.write(data)
    print(f"{len(data)} octets -> {host_path}")

def write_file(dom, host_path, guest_path):
    with open(host_path, "rb") as f:
        data = f.read()
    h = qga(dom, {"execute": "guest-file-open",
                  "arguments": {"path": guest_path, "mode": "wb"}})
    try:
        # 48 Ko brut -> ~64 Ko en base64 : reste sous la limite Linux de
        # ~128 Ko PAR ARGUMENT (MAX_ARG_STRLEN), le JSON étant passé en argv.
        TAILLE = 48 << 10
        for i in range(0, len(data), TAILLE):
            chunk = base64.b64encode(data[i:i + TAILLE]).decode()
            qga(dom, {"execute": "guest-file-write",
                      "arguments": {"handle": h, "buf-b64": chunk}})
    finally:
        qga(dom, {"execute": "guest-file-close", "arguments": {"handle": h}})
    print(f"{len(data)} octets -> VM:{guest_path}")

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
    main()
