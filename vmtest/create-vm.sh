#!/usr/bin/env bash
# create-vm.sh — crée de zéro une VM Windows 11 de test, entièrement sans interaction.
#
# Fait : autounattend (install FR silencieuse + compte admin local + auto-install du
# qemu-guest-agent) -> virt-install (UEFI Secure Boot + TPM 2.0 + canal guest-agent)
# -> déblocage du boot CD par injection de touches -> attente que l'agent réponde.
#
# À la fin, la VM est pilotable sans clic : `./run-wac-test.sh --build`
#
# Prérequis : qemu/libvirt/virtinst/ovmf/swtpm, xorriso, et les ISO :
#   - Windows 11 (variable ISO_WIN)
#   - virtio-win.iso (guest-agent + drivers)
set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RACINE="$(cd "$ICI/.." && pwd)"
VMS="${VMS_DIR:-$HOME/vms}"
DOM="${DOM:-win11-test}"
C="virsh -c qemu:///session"

ISO_WIN="${ISO_WIN:-$HOME/Téléchargements/Win11_25H2_French_x64_v2.iso}"
ISO_VIRTIO="${ISO_VIRTIO:-$VMS/virtio-win.iso}"
ISO_ANS="$VMS/autounattend.iso"
ISO_WAC="$VMS/wac-transfer.iso"
DISQUE="$VMS/$DOM.qcow2"

[[ -f "$ISO_WIN"    ]] || { echo "ISO Windows absente : $ISO_WIN" >&2; exit 1; }
[[ -f "$ISO_VIRTIO" ]] || { echo "virtio-win.iso absente : $ISO_VIRTIO" >&2; exit 1; }
mkdir -p "$VMS"

# --- 1. Fichier de réponse (install muette + guest-agent) -------------------
echo "== 1. autounattend.iso =="
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp "$ICI/autounattend.xml" "$TMP/autounattend.xml"
xorriso -as mkisofs -J -R -V UNATTEND -o "$ISO_ANS" "$TMP" >/dev/null 2>&1

# --- 2. ISO des binaires WAC (si le build existe) ---------------------------
if [[ -f "$RACINE/build-windows/WAC.exe" ]]; then
  echo "== 2. wac-transfer.iso =="
  TMP2="$(mktemp -d)"; cp "$RACINE/build-windows/"*.exe "$TMP2/" 2>/dev/null || true
  xorriso -as mkisofs -J -R -V WAC_TRANSFER -o "$ISO_WAC" "$TMP2" >/dev/null 2>&1
  rm -rf "$TMP2"
else
  : > /dev/null; ISO_WAC=""
fi

# --- 3. Table rase ----------------------------------------------------------
echo "== 3. Nettoyage d'une VM existante =="
$C destroy  "$DOM" >/dev/null 2>&1 || true
$C undefine "$DOM" --nvram >/dev/null 2>&1 || true
rm -f "$DISQUE"

# --- 4. Création -------------------------------------------------------------
echo "== 4. virt-install =="
ARGS=(
  --connect qemu:///session --name "$DOM" --osinfo win11
  --vcpus 4 --memory 6144 --cpu host-passthrough --machine q35
  --boot firmware=efi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes,firmware.feature1.name=enrolled-keys,firmware.feature1.enabled=yes
  --features smm.state=on
  --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb
  --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0
  --disk "path=$DISQUE,size=64,format=qcow2,bus=sata"
  --cdrom "$ISO_WIN"
  --disk "path=$ISO_ANS,device=cdrom,readonly=on"
  --disk "path=$ISO_VIRTIO,device=cdrom,readonly=on"
  --network user,model=e1000e --graphics spice --video qxl --noautoconsole
)
[[ -n "$ISO_WAC" ]] && ARGS+=(--disk "path=$ISO_WAC,device=cdrom,readonly=on")
virt-install "${ARGS[@]}"

# --- 5. Déblocage du boot ----------------------------------------------------
# Le CD Windows affiche « Press any key to boot from CD » (~5 s). Sans touche, le
# firmware tombe dans son menu. On injecte des touches, et si on a malgré tout
# atterri dans le menu OVMF, on descend sur « Boot Manager » et on prend le DVD.
echo "== 5. Déblocage du boot (injection de touches) =="
for _ in $(seq 1 12); do $C send-key "$DOM" --codeset linux KEY_SPACE >/dev/null 2>&1 || true; sleep 0.5; done
sleep 8
if $C screenshot "$DOM" --file "$TMP/s.png" >/dev/null 2>&1 && [[ $(stat -c%s "$TMP/s.png") -lt 20000 ]]; then
  echo "   -> menu firmware détecté, passage par Boot Manager"
  $C send-key "$DOM" --codeset linux KEY_DOWN  >/dev/null 2>&1
  $C send-key "$DOM" --codeset linux KEY_DOWN  >/dev/null 2>&1
  $C send-key "$DOM" --codeset linux KEY_ENTER >/dev/null 2>&1
  sleep 2
  $C send-key "$DOM" --codeset linux KEY_ENTER >/dev/null 2>&1
  for _ in $(seq 1 20); do $C send-key "$DOM" --codeset linux KEY_SPACE >/dev/null 2>&1 || true; sleep 0.5; done
fi

# --- 6. Attente de l'agent (= install terminée) ------------------------------
# virt-install --noautoconsole ne relance pas la VM après le 1er reboot de Setup :
# on la redémarre au besoin, et on considère l'install finie quand l'agent répond.
echo "== 6. Attente de fin d'install (ping de l'agent, ~15-25 min) =="
for i in $(seq 1 120); do
  if [[ "$($C domstate "$DOM" 2>/dev/null)" != "running" ]]; then
    $C start "$DOM" >/dev/null 2>&1 || true
  fi
  if python3 "$ICI/qga.py" --dom "$DOM" ping >/dev/null 2>&1; then
    echo "   ✅ agent opérationnel après ~$((i / 4)) min — VM pilotable"
    exit 0
  fi
  sleep 15
done
echo "   ⚠️ agent toujours muet après 30 min : vérifier avec 'virsh screenshot'" >&2
exit 1
