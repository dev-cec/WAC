#!/usr/bin/env bash
# prepare-footprint.sh — prepares, once, the footprint clone of the test VM
# (backlog B-027) and freezes it as the state every measured run starts from.
#
# The clone, win11-footprint, is a copy of win11-test's system disk, defined
# without any network interface, with a USB key (wac-footprint-key.qcow2,
# serial WACFOOT0001) as its only other disk. This script:
#   - installs Sysmon, its signature checked, with sysmon-config.xml, and a
#     1 GiB log so that no run overwrites its own events;
#   - formats the key as K: and puts the tools on it: WAC.exe and its
#     reference wac.yml (bin/), KAPE and the EZ tools (the archives of
#     vmtest/tools/, as install-tools.sh uses them) — and removes C:\Tools, which
#     the clone inherited: on the examined machine the tools come from the
#     key, as on the field; the .NET runtime that KAPE and the EZ tools need
#     stays installed, a prerequisite noted in the report;
#   - shuts the clone down and renames
#     its two disks and its UEFI variables as the base images
#     (…-base.qcow2, …_VARS-base.fd) that run-footprint.sh layers each run on.
#
# Usage: ./prepare-footprint.sh <Sysmon.zip> — the archive of
# https://download.sysinternals.com/files/Sysmon.zip, its SHA-256 printed
# for the report.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DOM=win11-footprint
CONN="qemu:///session"
QGA="python3 $ROOT/vmtest/lib/qga.py --dom $DOM"
VMS="$HOME/vms"
NVRAM="$HOME/.config/libvirt/qemu/nvram"
ZIP="${1:?usage: prepare-footprint.sh <Sysmon.zip>}"

[[ -f "$VMS/win11-footprint-base.qcow2" ]] && { echo "already prepared: $VMS/win11-footprint-base.qcow2 exists"; exit 1; }
$QGA ping >/dev/null

echo "== Sysmon =="
echo "   archive SHA-256: $(sha256sum "$ZIP" | cut -d' ' -f1)"
UNPACKED="$(mktemp -d)"
python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("Sysmon64.exe", sys.argv[2])' "$ZIP" "$UNPACKED"
$QGA run -- powershell.exe -NoProfile -Command 'New-Item -ItemType Directory -Force C:\footprint-setup | Out-Null' >/dev/null
$QGA write "$UNPACKED/Sysmon64.exe" 'C:\footprint-setup\Sysmon64.exe' >/dev/null
$QGA write "$HERE/sysmon-config.xml" 'C:\footprint-setup\sysmon-config.xml' >/dev/null
rm -rf "${UNPACKED:?}"
$QGA run -- powershell.exe -NoProfile -Command '
  $ErrorActionPreference = "Stop"
  if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { "   already installed"; Remove-Item -Recurse -Force C:\footprint-setup; exit 0 }
  $s = Get-AuthenticodeSignature C:\footprint-setup\Sysmon64.exe
  if ($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") { "   signature refused: $($s.Status) $($s.SignerCertificate.Subject)"; exit 1 }
  "   signature: $($s.Status), $($s.SignerCertificate.Subject)"
  "   version: " + (Get-Item C:\footprint-setup\Sysmon64.exe).VersionInfo.FileVersion
  & C:\footprint-setup\Sysmon64.exe -accepteula -i C:\footprint-setup\sysmon-config.xml 2>&1 | Select-String -Pattern "installed|started|error" | ForEach-Object { "   " + $_.Line.Trim() }
  & wevtutil.exe sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
  Remove-Item -Recurse -Force C:\footprint-setup'

echo "== Key K: and tools =="
# Every block stops at its first error: a failed format must not go on to
# the removal of C:\Tools.
$QGA run -- powershell.exe -NoProfile -Command '
  $ErrorActionPreference = "Stop"
  $disk = Get-Disk | Where-Object SerialNumber -eq "WACFOOT0001"
  Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | Remove-Partition -Confirm:$false
  if ($disk.PartitionStyle -eq "RAW") { Initialize-Disk -Number $disk.Number -PartitionStyle MBR }
  $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize
  $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel WACFOOT -Confirm:$false | Out-Null
  $partition | Set-Partition -NewDriveLetter K
  New-Item -ItemType Directory -Force K:\WAC, K:\results, K:\KAPE, K:\EZ | Out-Null
  "   K: formatted"'
$QGA write "$ROOT/bin/WAC.exe" 'K:\WAC\WAC.exe' >/dev/null
$QGA write "$ROOT/bin/wac.yml" 'K:\WAC\wac.yml' >/dev/null
# $1 archive on the host, $2 folder of the key it is unpacked into.
unpack() {
  $QGA write "$1" 'K:\incoming.zip' >/dev/null
  $QGA run -- powershell.exe -NoProfile -Command "\$ErrorActionPreference = 'Stop'; Expand-Archive -LiteralPath K:\\incoming.zip -DestinationPath '$2' -Force; Remove-Item K:\\incoming.zip" >/dev/null
}
unpack "$ROOT/vmtest/tools/kape.zip" 'K:\KAPE'
for archive in "$ROOT"/vmtest/tools/zimmerman/*.zip; do
  name="$(basename "$archive" .zip)"
  case "$name" in
    *Explorer|EZViewer|TimelineExplorer|hasher|iisGeolocate|Get-ZimmermanTools) continue ;;
  esac
  unpack "$archive" "K:\\EZ\\$name"
done
$QGA run -- powershell.exe -NoProfile -Command '
  $ErrorActionPreference = "Stop"
  if (Test-Path C:\Tools) { Remove-Item -Recurse -Force C:\Tools }
  Remove-Item -Force C:\Windows\Temp\footprint-* -ErrorAction SilentlyContinue
  $kape = Get-ChildItem K:\KAPE -Recurse -Filter kape.exe | Select-Object -First 1
  "   KAPE: " + $kape.FullName
  "   EZ: " + ((Get-ChildItem K:\EZ -Directory).Name -join ", ")
  "   K: " + [math]::Round((Get-ChildItem K:\ -Recurse | Measure-Object Length -Sum).Sum / 1MB) + " MiB"'

echo "== Base images =="
virsh -c "$CONN" shutdown "$DOM" >/dev/null
for _ in $(seq 1 120); do virsh -c "$CONN" domstate "$DOM" | grep -q "shut off" && break; sleep 5; done
virsh -c "$CONN" domstate "$DOM" | grep -q "shut off" || { echo "the clone did not shut down"; exit 1; }
mv "$VMS/win11-footprint.qcow2" "$VMS/win11-footprint-base.qcow2"
mv "$VMS/wac-footprint-key.qcow2" "$VMS/wac-footprint-key-base.qcow2"
cp "$NVRAM/win11-footprint_VARS.fd" "$NVRAM/win11-footprint_VARS-base.fd"
chmod a-w "$VMS/win11-footprint-base.qcow2" "$VMS/wac-footprint-key-base.qcow2"
echo "   frozen: win11-footprint-base.qcow2, wac-footprint-key-base.qcow2"
