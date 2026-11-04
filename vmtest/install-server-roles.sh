#!/usr/bin/env bash
# install-server-roles.sh — installs in a server test VM the roles whose
# artefacts WAC reads (guest/install-server-roles.ps1), for B-038's witnesses.
# Once is enough: an installed role stays.
#
# Usage: WAC_VM=srv2022roles-test ./install-server-roles.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DOM="${WAC_VM:-srv2022roles-test}"
QGA="python3 $HERE/lib/qga.py --dom $DOM"
VMDIR='C:\wactest'
$QGA run --shell "mkdir $VMDIR 2>nul & echo." >/dev/null
$QGA write "$HERE/guest/install-server-roles.ps1" "$VMDIR\\install-server-roles.ps1" >/dev/null
$QGA run --timeout 3000 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\install-server-roles.ps1"
sleep 90
until $QGA run --shell "del $VMDIR\\install-server-roles.ps1" >/dev/null 2>&1; do sleep 15; done
echo "   roles installed"
