#!/usr/bin/env bash
# install-replica-controller.sh — a second controller of wac.test, joined to the
# first by a private multicast link (the test VMs' user-mode networks cannot see
# each other), for what one controller cannot show: a real replication, audited
# with DS-Replication-Get-Changes-All (1131f6ad, what a DCSync also leaves), and a
# change whose controller of origin is not the one examined.
# Both VMs are stopped once to receive the link. Once: the pair stays one.
#
# The replica comes from: DOM=srv2022dc2-test ./create-vm.sh srv2022
# Usage: WAC_VM=srv2022dc-test REPLICA=srv2022dc2-test ./install-replica-controller.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FIRST="${WAC_VM:-srv2022dc-test}"
REPLICA="${REPLICA:-srv2022dc2-test}"
VIRSH="virsh -c qemu:///session"
VMDIR='C:\wactest'
SCRIPT=install-replica-controller.ps1

#! Stops the VM, gives it the link under a MAC address the guest finds it by, starts it.
attach_link() {
  local dom=$1 mac=$2 definition
  $VIRSH dumpxml --inactive "$dom" | grep -q "$mac" && return 0
  $VIRSH shutdown "$dom" >/dev/null 2>&1 || true
  for _ in $(seq 1 40); do [[ "$($VIRSH domstate "$dom")" == *ferm* || "$($VIRSH domstate "$dom")" == *shut* ]] && break; sleep 15; done
  definition=$(mktemp)
  cat > "$definition" <<XML
<interface type='mcast'><mac address='$mac'/><source address='230.0.0.1' port='5558'/><model type='e1000e'/></interface>
XML
  $VIRSH attach-device "$dom" "$definition" --config >/dev/null
  rm -f "$definition"
}

#! Runs the guest script on a VM, once started and answering.
guest() {
  local dom=$1 role=$2 administrator=${3:-} qga="python3 $HERE/lib/qga.py --dom $1"
  for _ in $(seq 1 40); do $qga run --shell "exit /b 0" >/dev/null 2>&1 && break; sleep 15; done
  $qga run --shell "mkdir $VMDIR 2>nul & echo." >/dev/null
  $qga write "$HERE/guest/$SCRIPT" "$VMDIR\\$SCRIPT" >/dev/null
  $qga run --timeout 1800 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\$SCRIPT" -Role "$role" ${administrator:+-Administrator "$administrator"}
}

attach_link "$FIRST" 52:54:00:57:41:01
attach_link "$REPLICA" 52:54:00:57:41:02
$VIRSH start "$FIRST" >/dev/null 2>&1 || true
$VIRSH start "$REPLICA" >/dev/null 2>&1 || true
sleep 180
guest "$FIRST" first
# The domain's administrator by its RID: its name follows the language of Windows.
ADMINISTRATOR=$(python3 "$HERE/lib/qga.py" --dom "$FIRST" run -- powershell.exe -NoProfile -Command \
  'Import-Module ActiveDirectory; (Get-ADUser -Identity "$((Get-ADDomain).DomainSID)-500").SamAccountName' 2>/dev/null | tr -d '\r' | tail -1)
# The first run may only rename it, which takes a restart before the promotion.
STATE=$(guest "$REPLICA" replica "$ADMINISTRATOR")
echo "$STATE"
if [[ "$STATE" == *renamed* ]]; then
  sleep 120
  guest "$REPLICA" replica "$ADMINISTRATOR"
fi
# Its restart, then the directory: the replica answers once it has the domain's partition.
sleep 180
QGA="python3 $HERE/lib/qga.py --dom $REPLICA"
for _ in $(seq 1 80); do
  if $QGA run -- powershell.exe -NoProfile -Command "Import-Module ActiveDirectory; (Get-ADDomainController -Server localhost).HostName" 2>/dev/null | grep -qi '^wac-test2'; then
    $QGA run --shell "del $VMDIR\\$SCRIPT" >/dev/null
    python3 "$HERE/lib/qga.py" --dom "$FIRST" run --shell "del $VMDIR\\$SCRIPT" >/dev/null
    echo "   replica controller of wac.test"
    exit 0
  fi
  sleep 15
done
echo "   the replica's directory does not answer" >&2
exit 1
