#!/usr/bin/env bash
# create-vm.sh — creates a Windows test VM from scratch, entirely without interaction.
#
# Usage: ./create-vm.sh [win11|win81|win8|win7|winxp|srv2012r2|srv2016|srv2019|srv2022|srv2025]
#   win11  (default) the VM of the test cycle, Windows 11 — domain win11-test
#   win81  Windows 8.1 x64, for the compatibility with the older versions —
#          domain win81-test; run-wac-test.sh is given it with DOM=win81-test
#   win8   Windows 8 Pro x86 (32 bits: the machine of WAC32.exe) — domain win8-test
#   win7   Windows 7 SP1 Ultimate x64 — domain win7-test
#   srv2012r2, srv2016, srv2019, srv2022, srv2025
#          Windows Server Standard with its graphical interface, from the
#          evaluation media of vmtest/tools/isos — domains srv2012r2-test…
#   winxp  Windows XP Professional SP1 x86 — domain winxp-test. No guest agent
#          exists for it: installed from an answer floppy (WINNT.SIF), driven
#          by the keyboard (lib/vmkeys.py, US layout), its output read on its
#          serial port (see the end of this file)
# What differs from one version to the next (ISO, edition, key, language of the
# medium, firmware, drivers of the guest agent) is in the profile below; the
# answer file is guest/autounattend.xml, adapted by the profile.
#
# Does: autounattend (silent French install + local admin account + auto-install of
# qemu-guest-agent) -> virt-install (UEFI Secure Boot + TPM 2.0 + guest-agent channel)
# -> unblocking of the CD boot by key injection -> wait for the agent to answer.
#
# At the end, the VM can be driven without a click: `./run-wac-test.sh --build`
#
# Prerequisites: qemu/libvirt/virtinst/ovmf/swtpm, xorriso, and the ISOs:
#   - Windows 11 (variable ISO_WIN)
#   - virtio-win.iso (guest agent + drivers)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VMS="${VMS_DIR:-$HOME/vms}"
C="virsh -c qemu:///session"

# --- The profile of the version -------------------------------------------------
# IMAGE: the edition, as an /IMAGE/… key of install.wim. KEY: Microsoft's generic
# installation key of that edition — public, it installs and does not activate.
# MEDIA_LANGUAGE: the language of Setup, which must be one the medium carries.
# GA_DRIVERS: the folder of virtio-win holding the driver of the agent's channel,
# for the versions the guest tools installer no longer handles. ISO_VIRTIO: the
# virtio-win release that still signs its drivers for that version — 0.1.302
# carries a w8.1 folder, but Windows 8.1 refuses its catalogue ("the hash for the
# file is not present in the specified catalog file"); 0.1.189 is accepted.
# OOBE_ENTER: the version shows a page of settings the answer file cannot hide.
# BIOS: started by the BIOS on an MBR disk — Windows 7, whose Setup has no video
# under this UEFI, and every 32-bit Windows, which this UEFI does not start.
# OOBE7: an answer file without the settings Windows 8 introduced, which the
# Setup of Windows 7 refuses. ARCH: amd64 or x86, for the answer file's
# components and the agent's package. CPU: the processor shown to the machine —
# the host's own. MACHINE: q35, or pc (i440FX) for Windows 8 x86, whose Setup
# shows its first page under q35 and then takes neither key nor click.
PROFILE="${1:-win11}"
case "$PROFILE" in
  win11)
    DOM="${DOM:-win11-test}"; OSINFO=win11; MEMORY=6144
    ISO_WIN="${ISO_WIN:-$HOME/Téléchargements/Win11_25H2_French_x64_v2.iso}"
    IMAGE='<Key>/IMAGE/NAME</Key><Value>Windows 11 Pro</Value>'; KEY=VK7JG-NPHTM-C97JM-9MPGT-3V66T
    MEDIA_LANGUAGE=fr-FR; GA_DRIVERS=""; OOBE_ENTER=0; BIOS=0; OOBE7=0; ARCH=amd64; CPU=host-passthrough; MACHINE=q35
    ISO_VIRTIO="${ISO_VIRTIO:-$VMS/virtio-win.iso}"
    FIRMWARE=(--boot firmware=efi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes
              --features smm.state=on --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb) ;;
  win81)
    DOM="${DOM:-win81-test}"; OSINFO=win8.1; MEMORY=4096
    ISO_WIN="${ISO_WIN:-$HERE/tools/isos/Windows 8.1.iso}"
    IMAGE='<Key>/IMAGE/INDEX</Key><Value>1</Value>'; KEY=XHQ8N-C3MCJ-RQXB6-WCHYG-C9WKB   # Professional
    MEDIA_LANGUAGE=nl-NL; GA_DRIVERS='w8.1\amd64'; OOBE_ENTER=1; BIOS=0; OOBE7=0; ARCH=amd64; CPU=host-passthrough; MACHINE=q35
    ISO_VIRTIO="${ISO_VIRTIO:-$HERE/tools/isos/virtio-win-0.1.189.iso}"
    FIRMWARE=(--boot firmware=efi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no) ;;
  win8)
    DOM="${DOM:-win8-test}"; OSINFO=win8; MEMORY=3072
    ISO_WIN="${ISO_WIN:-$HERE/tools/isos/Windows 8.iso}"
    IMAGE='<Key>/IMAGE/INDEX</Key><Value>1</Value>'; KEY=NG4HW-VH26C-733KW-K6F98-J8CK4   # Pro
    MEDIA_LANGUAGE=en-US; GA_DRIVERS='w8\x86'; OOBE_ENTER=1; BIOS=1; OOBE7=0; ARCH=x86; CPU=host-passthrough; MACHINE=pc
    ISO_VIRTIO="${ISO_VIRTIO:-$HERE/tools/isos/virtio-win-0.1.189.iso}"
    FIRMWARE=(--boot hd,cdrom) ;;
  win7)
    DOM="${DOM:-win7-test}"; OSINFO=win7; MEMORY=4096
    ISO_WIN="${ISO_WIN:-$HERE/tools/isos/en_windows_7_ultimate_x64_dvd.iso}"
    IMAGE='<Key>/IMAGE/NAME</Key><Value>Windows 7 ULTIMATE</Value>'; KEY=D4F6K-QK3RD-TMVMJ-BBMRX-3MBMV
    MEDIA_LANGUAGE=en-US; GA_DRIVERS='w7\amd64'; OOBE_ENTER=1; BIOS=1; OOBE7=1; ARCH=amd64; CPU=host-passthrough; MACHINE=q35
    # 0.1.173: the last release whose drivers a Windows 7 SP1 without the
    # SHA-2 update (KB3033929) accepts.
    ISO_VIRTIO="${ISO_VIRTIO:-$HERE/tools/isos/virtio-win-0.1.173.iso}"
    FIRMWARE=(--boot hd,cdrom) ;;
  srv2012r2|srv2016|srv2019|srv2022|srv2025)
    # Evaluation media: no product key (the element is removed from the
    # answer file), the edition by its index — 2, Standard with the graphical
    # interface, on every evaluation medium of 2012 R2 to 2025 (1 is its
    # Server Core). A server refuses the password "wac" (complexity): its
    # accounts get SERVER_PASSWORD, synthetic, for a throwaway VM.
    DOM="${DOM:-$PROFILE-test}"; MEMORY=4096
    IMAGE='<Key>/IMAGE/INDEX</Key><Value>2</Value>'; KEY=""
    OOBE_ENTER=0; BIOS=0; OOBE7=0; ARCH=amd64; CPU=host-passthrough; MACHINE=q35
    SERVER_PASSWORD="Wac-Server-2026!"
    FIRMWARE=(--boot firmware=efi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no)
    case "$PROFILE" in
      srv2012r2) OSINFO=win2k12r2; ISO_WIN="${ISO_WIN:-$HERE/tools/isos/server2012r2_eval_fr-fr.iso}"; MEDIA_LANGUAGE=fr-FR
                 GA_DRIVERS='2k12R2\amd64'; ISO_VIRTIO="${ISO_VIRTIO:-$HERE/tools/isos/virtio-win-0.1.189.iso}" ;;
      srv2016)   OSINFO=win2k16;   ISO_WIN="${ISO_WIN:-$HERE/tools/isos/server2016_eval_fr-fr.iso}";   MEDIA_LANGUAGE=fr-FR
                 GA_DRIVERS='2k16\amd64'; ISO_VIRTIO="${ISO_VIRTIO:-$HERE/tools/isos/virtio-win-0.1.189.iso}" ;;
      srv2019)   OSINFO=win2k19;   ISO_WIN="${ISO_WIN:-$HERE/tools/isos/server2019_eval_fr-fr.iso}";   MEDIA_LANGUAGE=fr-FR
                 GA_DRIVERS=""; ISO_VIRTIO="${ISO_VIRTIO:-$VMS/virtio-win.iso}" ;;
      srv2022)   OSINFO=win2k22;   ISO_WIN="${ISO_WIN:-$HERE/tools/isos/server2022_eval_fr-fr.iso}";   MEDIA_LANGUAGE=fr-FR
                 GA_DRIVERS=""; ISO_VIRTIO="${ISO_VIRTIO:-$VMS/virtio-win.iso}" ;;
      srv2025)   OSINFO=win2k25;   ISO_WIN="${ISO_WIN:-$HERE/tools/isos/server2025_eval_en-us.iso}";   MEDIA_LANGUAGE=en-US
                 GA_DRIVERS=""; ISO_VIRTIO="${ISO_VIRTIO:-$VMS/virtio-win.iso}" ;;
    esac ;;
  winxp)
    DOM="${DOM:-winxp-test}"
    ISO_WIN="${ISO_WIN:-$HERE/tools/isos/Windows XP Professional (SP1) (x86).iso}"
    ISO_VIRTIO="$ISO_WIN" ;;   # no virtio driver: nothing but what XP itself has
  *) echo "Unknown profile $PROFILE (win11, win81, win8, win7, winxp, srv2012r2, srv2016, srv2019, srv2022, srv2025)" >&2; exit 2 ;;
esac

ISO_ANS="$VMS/autounattend-$PROFILE.iso"
ISO_WAC="$VMS/wac-transfer.iso"
DISK="$VMS/$DOM.qcow2"
# A second fixed disk, 2 GB, for the NTFS metadata of a volume other than the
# system's ($MFT, change journal): added once Windows is installed, so that
# Setup sees one disk only; run-wac-test.sh formats it (label WACDATA).
DATA_DISK="$VMS/$DOM-data.qcow2"

[[ -f "$ISO_WIN"    ]] || { echo "Windows ISO missing: $ISO_WIN" >&2; exit 1; }
[[ -f "$ISO_VIRTIO" ]] || { echo "virtio-win.iso missing: $ISO_VIRTIO" >&2; exit 1; }
mkdir -p "$VMS"

# --- Windows XP: another Setup, another way -----------------------------------
# Its Setup reads WINNT.SIF on a floppy, its hardware is the i440FX with an IDE
# disk and a processor of its time, and nothing in it answers a guest agent.
# The machine says it is ready by writing to its serial port (COM1), which
# libvirt keeps in a file: that is also where a command's output is read from
# (`<command> > COM1`), the commands being typed by lib/vmkeys.py.
# The product key is the one the installation medium carries beside its files
# ("CD Key.txt"), or XP_KEY: read here, written to the floppy only — never
# shown, never in the repository.
if [[ "$PROFILE" == winxp ]]; then
  [[ -f "$ISO_WIN" ]] || { echo "Windows ISO missing: $ISO_WIN" >&2; exit 1; }
  mkdir -p "$VMS"
  FLOPPY="$VMS/$DOM-answers.img"; SERIAL="$VMS/$DOM.serial"; DISK="$VMS/$DOM.qcow2"; ISO_WAC="$VMS/wac-transfer.iso"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  mounted() { udisksctl mount -b "$1" ${2:+-o "$2"} | sed -n 's/.* at \(.*\)$/\1/p' | sed 's/\.$//'; }
  # The desktop may still be looking at a medium just mounted: the unmount is retried.
  released() {
    local try
    for try in $(seq 1 30); do udisksctl unmount -b "$1" >/dev/null 2>&1 && break; sleep 1; done
    # The unmount usually detaches the loop device itself; asked to delete one already gone, udisksctl waits for ever.
    ! losetup "$1" >/dev/null 2>&1 || timeout 10 udisksctl loop-delete -b "$1" >/dev/null 2>&1 || true
  }
  if [[ -z "${XP_KEY:-}" ]]; then
    LOOP="$(udisksctl loop-setup -r -f "$ISO_WIN" | grep -o '/dev/loop[0-9]*')"
    MEDIUM="$(mounted "$LOOP" ro)"
    XP_KEY="$(python3 - "$MEDIUM/CD Key.txt" <<'PY'
import re, sys
try:
    raw = open(sys.argv[1], "rb").read()
except OSError:
    raise SystemExit(0)
for encoding in ("utf-16", "utf-8", "latin-1"):
    try:
        found = re.search(r"(?:[A-Z0-9]{5}\s*-\s*){4}[A-Z0-9]{5}", raw.decode(encoding).upper())
    except UnicodeError:
        continue
    if found:
        print(re.sub(r"\s", "", found.group(0)))
        break
PY
)"
    released "$LOOP"
  fi
  [[ -n "$XP_KEY" ]] || { echo "No product key: the medium carries no \"CD Key.txt\"; give XP_KEY=XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" >&2; exit 1; }
  echo "== 1. Answer floppy (WINNT.SIF) =="
  # No AutoPlay: a medium changed under the machine would open a window that takes the keyboard from the prompt.
  # "wac"/"wac": the same throw-away account as the other test machines (see guest/autounattend.xml).
  cat > "$TMP/WINNT.SIF" <<SIF
[Data]
AutoPartition=1
MsDosInitiated=0
UnattendedInstall=Yes
[Unattended]
UnattendMode=FullUnattended
OemSkipEula=Yes
OemPreinstall=No
TargetPath=\\WINDOWS
Repartition=Yes
FileSystem=ConvertNTFS
UnattendSwitch=Yes
WaitForReboot=No
[GuiUnattended]
AdminPassword="wac"
EncryptedAdminPassword=No
OEMSkipRegional=1
TimeZone=105
OemSkipWelcome=1
AutoLogon=Yes
AutoLogonCount=999
[UserData]
ProductKey=$XP_KEY
FullName="wac"
OrgName="wac"
ComputerName=WAC-XP
[Display]
BitsPerPel=32
XResolution=1024
YResolution=768
[Identification]
JoinWorkgroup=WORKGROUP
[Networking]
InstallDefaultComponents=Yes
[GuiRunOnce]
Command0="reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"
Command1="cmd /c echo WAC-XP-READY > COM1"
SIF
  sed -i 's/$/\r/' "$TMP/WINNT.SIF"
  rm -f "$FLOPPY"; mkfs.fat -C "$FLOPPY" 1440 >/dev/null
  LOOP="$(udisksctl loop-setup -f "$FLOPPY" | grep -o '/dev/loop[0-9]*')"
  cp "$TMP/WINNT.SIF" "$(mounted "$LOOP")/WINNT.SIF"
  released "$LOOP"
  echo "== 2. wac-transfer.iso =="
  TMP2="$(mktemp -d)"; cp "$ROOT/build-windows/"*.exe "$ROOT/bin/wac.yml" "$TMP2/" 2>/dev/null || true
  xorriso -as mkisofs -J -R -V WAC_TRANSFER -o "$ISO_WAC" "$TMP2" >/dev/null 2>&1; rm -rf "$TMP2"
  echo "== 3. Removal of an existing VM =="
  $C destroy "$DOM" >/dev/null 2>&1 || true
  $C undefine "$DOM" >/dev/null 2>&1 || true
  rm -f "$DISK" "$SERIAL"
  echo "== 4. virt-install =="
  virt-install --connect qemu:///session --name "$DOM" --osinfo winxp \
    --vcpus 1 --memory 1024 --cpu pentium3 --machine pc \
    --disk "path=$DISK,size=20,format=qcow2,bus=ide" --cdrom "$ISO_WIN" \
    --disk "path=$FLOPPY,device=floppy" --disk "path=$ISO_WAC,device=cdrom,readonly=on" \
    --serial "file,path=$SERIAL" --network user,model=rtl8139 --graphics spice --video vga --noautoconsole
  echo "== 5. Waiting for the end of the install (the machine writes to its serial port, ~30-40 min) =="
  for i in $(seq 1 240); do
    [[ "$($C domstate "$DOM" 2>/dev/null)" == "running" ]] || $C start "$DOM" >/dev/null 2>&1 || true
    if grep -q WAC-XP-READY "$SERIAL" 2>/dev/null; then
      echo "   ✅ Windows XP installed after ~$((i / 4)) min — driven by lib/vmkeys.py --layout us, output on $SERIAL"
      exit 0
    fi
    sleep 15
  done
  echo "   ⚠️ nothing on the serial port after 60 min: check with 'virsh screenshot'" >&2
  exit 1
fi

# --- 1. Answer file (silent install + guest agent) -------------------------
echo "== 1. autounattend.iso =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# The answer file is Windows 11's; the profile changes the edition, the key
# and Setup's language, and adds the agent's channel driver where the guest
# tools installer does not install it (pnputil, the driver store's own tool).
sed -e "s#<Key>/IMAGE/NAME</Key><Value>Windows 11 Pro</Value>#$IMAGE#" \
    -e "s#VK7JG-NPHTM-C97JM-9MPGT-3V66T#${KEY:-VK7JG-NPHTM-C97JM-9MPGT-3V66T}#" \
    -e "s#<UILanguage>fr-FR</UILanguage>#<UILanguage>$MEDIA_LANGUAGE</UILanguage>#g" \
    -e "s#processorArchitecture=\"amd64\"#processorArchitecture=\"$ARCH\"#g" \
    -e "s#qemu-ga-x86_64.msi#qemu-ga-$([[ $ARCH == x86 ]] && echo i386 || echo x86_64).msi#g" \
    "$HERE/guest/autounattend.xml" > "$TMP/autounattend.xml"
if [[ -n "$GA_DRIVERS" ]]; then
  cp "$HERE/guest/install-agent-driver.ps1" "$TMP/"
  # First of the first-logon commands, the others moving down by one: the
  # agent's service starts only once its channel has a driver.
  python3 - "$TMP/autounattend.xml" "$GA_DRIVERS" <<'PY'
import re, sys
path, drivers = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
start, end = text.index("<FirstLogonCommands>"), text.index("</FirstLogonCommands>")
block = re.sub(r"<Order>(\d+)</Order>", lambda m: f"<Order>{int(m.group(1)) + 1}</Order>", text[start:end])
# The script travels on the answer file's own medium (see its header for why
# the publisher is trusted before pnputil is run).
command = (r"cmd /c for %d in (D E F G H I J) do if exist %d:\install-agent-driver.ps1 "
           rf"powershell -NoProfile -ExecutionPolicy Bypass -File %d:\install-agent-driver.ps1 {drivers}")
first = ('<FirstLogonCommands>\n        <SynchronousCommand wcm:action="add">\n          <Order>1</Order>\n'
         "          <Description>Pilote du canal de l'agent (vioserial)</Description>\n"
         f"          <CommandLine>{command}</CommandLine>\n        </SynchronousCommand>")
open(path, "w", encoding="utf-8").write(text[:start] + block.replace("<FirstLogonCommands>", first, 1) + text[end:])
PY
fi
if [[ "$BIOS" == "1" ]]; then
  python3 - "$TMP/autounattend.xml" <<'PY'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
# One active NTFS partition on an MBR disk, instead of EFI + MSR + Windows.
start, end = text.index("<CreatePartitions>"), text.index("</ModifyPartitions>") + len("</ModifyPartitions>")
text = text[:start] + ('<CreatePartitions>\n            <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>\n'
        '          </CreatePartitions>\n          <ModifyPartitions>\n            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID>'
        '<Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter><Active>true</Active></ModifyPartition>\n          </ModifyPartitions>') + text[end:]
text = text.replace("<InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>",
                    "<InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo>")
open(path, "w", encoding="utf-8").write(text)
PY
fi
if [[ "$OOBE7" == "1" ]]; then
  python3 - "$TMP/autounattend.xml" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
# Settings Windows 8 introduced; and the network location, which Windows 7 asks at the first logon.
for setting in ("HideOEMRegistrationScreen", "HideOnlineAccountScreens", "HideLocalAccountScreen"):
    text = re.sub(rf"\s*<{setting}>[^<]*</{setting}>", "", text)
text = text.replace("<ProtectYourPC>3</ProtectYourPC>", "<NetworkLocation>Work</NetworkLocation>\n        <ProtectYourPC>3</ProtectYourPC>")
# And the time zone, which its first start asks for when the file gives none.
text = text.replace("      <UserAccounts>", "      <TimeZone>Romance Standard Time</TimeZone>\n      <UserAccounts>", 1)
open(path, "w", encoding="utf-8").write(text)
PY
fi
if [[ -z "$KEY" ]]; then
  # An evaluation medium: no product key at all.
  python3 - "$TMP/autounattend.xml" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text, count = re.subn(r"\s*<ProductKey><Key>[^<]*</Key><WillShowUI>OnError</WillShowUI></ProductKey>", "", text)
if count != 1:
    sys.exit("answer file: the product key element was not found once")
open(path, "w", encoding="utf-8").write(text)
PY
fi
if [[ -n "${SERVER_PASSWORD:-}" ]]; then
  sed -i "s#<Password><Value>wac</Value>#<Password><Value>$SERVER_PASSWORD</Value>#g" "$TMP/autounattend.xml"
  grep -q "$SERVER_PASSWORD" "$TMP/autounattend.xml" || { echo "answer file: the password was not replaced" >&2; exit 1; }
fi
[[ -z "$KEY" ]] || grep -q "$KEY" "$TMP/autounattend.xml" || { echo "answer file not adapted to $PROFILE" >&2; exit 1; }
xorriso -as mkisofs -J -R -V UNATTEND -o "$ISO_ANS" "$TMP" >/dev/null 2>&1

# --- 2. ISO of the WAC binaries (if the build exists) ----------------------
if [[ -f "$ROOT/build-windows/WAC.exe" ]]; then
  echo "== 2. wac-transfer.iso =="
  TMP2="$(mktemp -d)"; cp "$ROOT/build-windows/"*.exe "$TMP2/" 2>/dev/null || true
  xorriso -as mkisofs -J -R -V WAC_TRANSFER -o "$ISO_WAC" "$TMP2" >/dev/null 2>&1
  rm -rf "$TMP2"
else
  ISO_WAC=""
fi

# --- 3. Clean slate -----------------------------------------------------------
echo "== 3. Removal of an existing VM =="
$C destroy  "$DOM" >/dev/null 2>&1 || true
$C undefine "$DOM" --nvram >/dev/null 2>&1 || true
rm -f "$DISK"

# --- 4. Creation --------------------------------------------------------------
echo "== 4. virt-install =="
ARGS=(
  --connect qemu:///session --name "$DOM" --osinfo "$OSINFO"
  --vcpus 4 --memory "$MEMORY" --cpu "$CPU" --machine "$MACHINE"
  "${FIRMWARE[@]}"
  --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0
  --disk "path=$DISK,size=64,format=qcow2,bus=sata"
  --cdrom "$ISO_WIN"
  --disk "path=$ISO_ANS,device=cdrom,readonly=on"
  --disk "path=$ISO_VIRTIO,device=cdrom,readonly=on"
  --network user,model=e1000e --graphics spice --video qxl --noautoconsole
)
[[ -n "$ISO_WAC" ]] && ARGS+=(--disk "path=$ISO_WAC,device=cdrom,readonly=on")
virt-install "${ARGS[@]}"

# --- 5. Unblocking the boot ----------------------------------------------------
# The Windows CD shows "Press any key to boot from CD" (~5 s). Without a key, the
# firmware falls into its menu. Keys are injected, and if we landed in the OVMF
# menu all the same, we go down to "Boot Manager" and pick the DVD.
echo "== 5. Unblocking the boot (key injection) =="
for _ in $(seq 1 12); do $C send-key "$DOM" --codeset linux KEY_SPACE >/dev/null 2>&1 || true; sleep 0.5; done
sleep 8
# (Not under the BIOS: it has no such menu, and Setup's text screen is as small a capture.)
if [[ "$BIOS" != "1" ]] && $C screenshot "$DOM" --file "$TMP/s.png" >/dev/null 2>&1 && [[ $(stat -c%s "$TMP/s.png") -lt 20000 ]]; then
  echo "   -> firmware menu detected, going through Boot Manager"
  $C send-key "$DOM" --codeset linux KEY_DOWN  >/dev/null 2>&1
  $C send-key "$DOM" --codeset linux KEY_DOWN  >/dev/null 2>&1
  $C send-key "$DOM" --codeset linux KEY_ENTER >/dev/null 2>&1
  sleep 2
  $C send-key "$DOM" --codeset linux KEY_ENTER >/dev/null 2>&1
  for _ in $(seq 1 20); do $C send-key "$DOM" --codeset linux KEY_SPACE >/dev/null 2>&1 || true; sleep 0.5; done
fi

# --- 6. Waiting for the agent (= install finished) ----------------------------
# virt-install --noautoconsole does not restart the VM after Setup's first
# reboot: it is restarted when needed, and the install is considered finished
# when the agent answers.
echo "== 6. Waiting for the end of the install (agent ping, ~15-25 min) =="
for i in $(seq 1 120); do
  if [[ "$($C domstate "$DOM" 2>/dev/null)" != "running" ]]; then
    $C start "$DOM" >/dev/null 2>&1 || true
  fi
  # The settings page of the first start: its default button, by the Enter key
  # (harmless anywhere else in Setup; on the Start screen of Windows 8 it opens
  # the first tile, which the harness does not mind).
  [[ "$OOBE_ENTER" == "1" ]] && { $C send-key "$DOM" --codeset linux KEY_ENTER >/dev/null 2>&1 || true; }
  if python3 "$HERE/lib/qga.py" --dom "$DOM" ping >/dev/null 2>&1; then
    echo "   ✅ agent operational after ~$((i / 4)) min — the VM can be driven"
    [[ -f "$DATA_DISK" ]] || qemu-img create -f qcow2 "$DATA_DISK" 2G >/dev/null
    # SATA has no hot plug: the disk goes into the definition, and the VM
    # restarts to see it. Target sdf: sda to sde are the system disk and the
    # four media (Windows, answer file, virtio-win, WAC).
    $C attach-disk "$DOM" "$DATA_DISK" sdf --driver qemu --subdriver qcow2 --targetbus sata --config >/dev/null \
      && $C shutdown "$DOM" >/dev/null && echo "   data disk added, the VM restarts" \
      && until [[ "$($C domstate "$DOM")" == "shut off" ]]; do sleep 5; done \
      && $C start "$DOM" >/dev/null
    exit 0
  fi
  sleep 15
done
echo "   ⚠️ agent still silent after 30 min: check with 'virsh screenshot'" >&2
exit 1
