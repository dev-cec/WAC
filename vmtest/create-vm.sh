#!/usr/bin/env bash
# create-vm.sh — creates a Windows 11 test VM from scratch, entirely without interaction.
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
DOM="${DOM:-win11-test}"
C="virsh -c qemu:///session"

ISO_WIN="${ISO_WIN:-$HOME/Téléchargements/Win11_25H2_French_x64_v2.iso}"
ISO_VIRTIO="${ISO_VIRTIO:-$VMS/virtio-win.iso}"
ISO_ANS="$VMS/autounattend.iso"
ISO_WAC="$VMS/wac-transfer.iso"
DISK="$VMS/$DOM.qcow2"

[[ -f "$ISO_WIN"    ]] || { echo "Windows ISO missing: $ISO_WIN" >&2; exit 1; }
[[ -f "$ISO_VIRTIO" ]] || { echo "virtio-win.iso missing: $ISO_VIRTIO" >&2; exit 1; }
mkdir -p "$VMS"

# --- 1. Answer file (silent install + guest agent) -------------------------
echo "== 1. autounattend.iso =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp "$HERE/autounattend.xml" "$TMP/autounattend.xml"
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
  --connect qemu:///session --name "$DOM" --osinfo win11
  --vcpus 4 --memory 6144 --cpu host-passthrough --machine q35
  --boot firmware=efi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes
  --features smm.state=on
  --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb
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
if $C screenshot "$DOM" --file "$TMP/s.png" >/dev/null 2>&1 && [[ $(stat -c%s "$TMP/s.png") -lt 20000 ]]; then
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
  if python3 "$HERE/qga.py" --dom "$DOM" ping >/dev/null 2>&1; then
    echo "   ✅ agent operational after ~$((i / 4)) min — the VM can be driven"
    exit 0
  fi
  sleep 15
done
echo "   ⚠️ agent still silent after 30 min: check with 'virsh screenshot'" >&2
exit 1
