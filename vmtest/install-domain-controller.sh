#!/usr/bin/env bash
# install-domain-controller.sh — makes a server test VM the domain controller
# of its own forest, wac.test (guest/install-domain-controller.ps1), for the
# witnesses of active_directory. Once: a controller stays one. The VM keeps the
# synthetic password of the server VMs; its account wac becomes a domain's.
#
# Usage: WAC_VM=srv2022dc-test ./install-domain-controller.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DOM="${WAC_VM:-srv2022dc-test}"
QGA="python3 $HERE/lib/qga.py --dom $DOM"
VMDIR='C:\wactest'
$QGA run --shell "mkdir $VMDIR 2>nul & echo." >/dev/null
$QGA write "$HERE/guest/install-domain-controller.ps1" "$VMDIR\\install-domain-controller.ps1" >/dev/null
$QGA run --timeout 1800 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\install-domain-controller.ps1"
# It restarts to become a controller, a minute later; the directory takes a few more to answer.
sleep 120
for _ in $(seq 1 60); do
  if $QGA run -- powershell.exe -NoProfile -Command "Import-Module ActiveDirectory; (Get-ADDomain).DNSRoot" 2>/dev/null | grep -q '^wac\.test'; then
    $QGA run --shell "del $VMDIR\\install-domain-controller.ps1" >/dev/null
    echo "   domain controller of wac.test"
    exit 0
  fi
  sleep 15
done
echo "   the directory does not answer after 15 min" >&2
exit 1
