#!/usr/bin/env bash
# create-rdp-server.sh — creates the RDP server every test VM connects to, so
# that its Remote Desktop client writes a bitmap cache (bcache*.bmc on
# Windows XP and Vista, Cache*.bin from Windows 7 on) for WAC to read.
#
# WHY A VM OF ITS OWN. The test VMs are on QEMU's user network: each is alone
# behind its own NAT and cannot reach another. Windows 7 and later can open a
# session to themselves (127.0.0.2, what run-wac-test.sh does), Windows XP
# cannot (one console session, no loopback connection). This VM publishes its
# port 3389 on the host's 127.0.0.1:33389, which every test VM reaches as
# 10.0.2.2:33389 — one server for all the images, from XP to Server 2025.
#
# WHY WINDOWS. A client keeps a bitmap on disk only when the server sends it
# with a persistent key (CBR2_PERSISTENT_KEY_PRESENT); xrdp never does
# (measured on xrdp 0.9.21: the client wrote no cache at all), Windows does.
# Windows Server 2012 R2 (evaluation medium, created by create-vm.sh) is the
# oldest server image of the harness and still accepts the RDP security layer
# without NLA that the client of XP SP1 speaks.
#
# The session account is the server's local administrator "wac", with the
# synthetic password create-vm.sh gives every throw-away server VM.
#
# Usage: ./create-rdp-server.sh      then: virsh -c qemu:///session start wac-rdp-server
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VMS="${VMS_DIR:-$HOME/vms}"
C="virsh -c qemu:///session"
DOM=wac-rdp-server
PORT=33389
QGA=(python3 "$HERE/lib/qga.py" --dom "$DOM")

echo "== 1. Windows Server 2012 R2 (create-vm.sh) =="
$C dominfo "$DOM" >/dev/null 2>&1 || DOM="$DOM" "$HERE/create-vm.sh" srv2012r2
[[ "$($C domstate "$DOM")" == "running" ]] || $C start "$DOM" >/dev/null
until "${QGA[@]}" ping >/dev/null 2>&1; do sleep 10; done

echo "== 2. Remote Desktop: on, RDP security layer, no NLA =="
# fDenyTSConnections 0: connections allowed. UserAuthentication 0: no NLA
# (CredSSP), which the client of XP SP1 does not have. SecurityLayer 0: the
# RDP security layer, the only one it speaks (no TLS). MinEncryptionLevel 2:
# "client compatible", the highest the client offers. The firewall group is
# named by its resource, the same in every language of the system.
"${QGA[@]}" run -- powershell -NoProfile -Command "
  \$ts = 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server';
  Set-ItemProperty \$ts fDenyTSConnections 0 -Type DWord;
  Set-ItemProperty \"\$ts\\WinStations\\RDP-Tcp\" UserAuthentication 0 -Type DWord;
  Set-ItemProperty \"\$ts\\WinStations\\RDP-Tcp\" SecurityLayer 0 -Type DWord;
  Set-ItemProperty \"\$ts\\WinStations\\RDP-Tcp\" MinEncryptionLevel 2 -Type DWord;
  Enable-NetFirewallRule -Group '@FirewallAPI.dll,-28752'"

echo "== 3. Media out, port 3389 published on 127.0.0.1:$PORT =="
"${QGA[@]}" run --shell "shutdown /s /t 0" >/dev/null 2>&1 || true
until [[ "$($C domstate "$DOM")" == "shut off" ]]; do sleep 5; done
# The installation media and the data disk create-vm.sh adds serve the test
# VMs, not this one: detached (the shared ISO files themselves stay), and the
# data disk, this VM's own, removed.
for target in $($C domblklist "$DOM" | awk 'NR > 2 && $1 != "sda" && $1 != "" { print $1 }'); do
  $C detach-disk "$DOM" "$target" --config >/dev/null
done
rm -f "$VMS/$DOM-data.qcow2"
# libvirt's user network has no port forwarding without passt: the network
# card is QEMU's own, with hostfwd, on a free slot of the root bus.
$C dumpxml --inactive "$DOM" | python3 -c "
import re, sys
xml = sys.stdin.read()
xml = re.sub(r\"\\s*<interface type='user'>.*?</interface>\", '', xml, flags=re.S)
xml = xml.replace('<domain type=', '<domain xmlns:qemu=\"http://libvirt.org/schemas/domain/qemu/1.0\" type=', 1)
xml = xml.replace('</domain>', '''  <qemu:commandline>
    <qemu:arg value='-netdev'/><qemu:arg value='user,id=rdp0,hostfwd=tcp:127.0.0.1:$PORT-:3389'/>
    <qemu:arg value='-device'/><qemu:arg value='e1000e,netdev=rdp0,bus=pcie.0,addr=0x10'/>
  </qemu:commandline>
</domain>''')
sys.stdout.write(xml)" > "$VMS/$DOM.xml.tmp"
$C define "$VMS/$DOM.xml.tmp" >/dev/null
rm -f "$VMS/$DOM.xml.tmp"
echo "$DOM ready: start it, then connect to 10.0.2.2:$PORT from a test VM (account wac)"
