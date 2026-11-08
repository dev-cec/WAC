#!/usr/bin/env bash
# run-wac-test-xp.sh — a cycle of the harness on Windows XP (B-055): WAC32's
# collection, then its conversion, checked by check-json.py.
#
# WHY A SCRIPT OF ITS OWN. Windows XP has no guest agent and no PowerShell:
# nothing of run-wac-test.sh's driving works there. The VM is driven as
# create-vm.sh installed it — by the keyboard (lib/vmkeys.py, US layout) and
# its serial port (COM1, kept by libvirt in ~/vms/<vm>.serial):
#   1. a transfer ISO carries WAC32.exe, the wac.yml of bin/ and run-xp.cmd,
#      which puts them on the collection key, collects then converts from it,
#      saying each step on COM1, then shuts the machine down;
#   2. the VM starts, run-xp.cmd is typed into the Run box until COM1 says it
#      started;
#   3. once the VM is off, the JSON and the manifest are read on the key,
#      read-only (dissect.ntfs, vmtest/tools/target-venv), and checked.
# The collection key, as on the field: WAC runs from a USB key and writes
# there, never on the examined disk — a raw image (wac-kit-<vm>.img, 64 GiB,
# sparse, as run-wac-test.sh's: WAC reserves twice its estimate, some 12 GiB
# with the deleted files' 4 GiB, and refused 8 GiB on Server 2003, 2026-11-08)
# attached as a removable USB disk of serial WACUSB0003, formatted NTFS on the
# host (mkntfs, label WACKIT) when created: the diskpart of XP
# and Server 2003 partitions no removable disk.
# Few witnesses (no PowerShell): the checks confront what WAC gives with itself
# and with the version's expectations; the decoders of XP's formats were
# confronted with independent tools when they were written (B-037). The one
# placed: the carving's (deleted files, level 3, set in the ISO's wac.yml) — an
# executable of no publisher (an empty program built here by MinGW, not WAC:
# WAC is never on the examined disk) and a PDF copied on the data disk W: (formatted NTFS by diskpart on
# first use), the volume dismounted (fsutil) so that its cache is written to
# the disk — 20 seconds of XP's lazy writer left the last 870 KiB of the
# executable unwritten on Server 2003, and a copy truncated at once never
# reached the disk —, then truncated to nothing and deleted;
# their SHA-256, computed on the host, in reference/carving.txt.
#
# TRACES IN THE VM. The key's wac\xp holds the run until the next one, which
# removes it first; the examined disk receives nothing of WAC's; W: keeps only
# the free clusters of the witnesses, overwritten by the next.
#
# Usage: ./run-wac-test-xp.sh [winxp-test|winxpsp3-test]
set -euo pipefail
# The tools' answers are read as text ("shut off", "Mounted … at …"), in English:
# since Ubuntu 26.04, virsh answers in the session's language ("fermé").
export LC_ALL=C.UTF-8

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DOM="${1:-winxp-test}"
VMS="${VMS_DIR:-$HOME/vms}"
C="virsh -c qemu:///session"
KEYS=(python3 "$HERE/lib/vmkeys.py" --dom "$DOM" --layout us --delay 0.12)
# The serial port's file, as the VM's definition gives it: a VM cloned from
# another keeps the original's (winxpsp3-test writes to winxp-test.serial).
SERIAL="$($C dumpxml "$DOM" | sed -n "/<serial type='file'>/,/<\/serial>/s/.*<source path='\([^']*\)'.*/\1/p" | head -1)"
TARGET="$($C domblklist "$DOM" | awk '$2 ~ /wac-transfer|\.iso$/ { print $1; exit }')"
OUTPUT="$HERE/results/$(date +%Y%m%d-%H%M%S)-$DOM"
WORK="$(mktemp -d)"
# Whatever happens, the VM gets its usual transfer medium back: the temporary
# ISO is removed with the work folder.
restore() { $C change-media "$DOM" "$TARGET" "$VMS/wac-transfer.iso" --config >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap restore EXIT
mkdir -p "$OUTPUT/reference"

echo "== 0. Collection key == ($(date +%H:%M:%S))"
KIT_IMG="$VMS/wac-kit-$DOM.img"
if [[ ! -f "$KIT_IMG" ]]; then
  truncate -s 64G "$KIT_IMG"
  # Whole, without partition table, as many keys are; 512-byte sectors, no hidden sector.
  mkntfs -F -Q -L WACKIT -s 512 -p 0 -H 255 -S 63 "$KIT_IMG" >/dev/null
  echo "   key created and formatted NTFS"
fi
if ! $C domblklist "$DOM" | grep -qF "$KIT_IMG"; then
  printf '%s\n' "<disk type='file' device='disk'>" "  <driver name='qemu' type='raw'/>" \
    "  <source file='$KIT_IMG'/>" "  <target dev='sdx' bus='usb' removable='on'/>" \
    "  <serial>WACUSB0003</serial>" "</disk>" > "$WORK/kit.xml"
  $C attach-device "$DOM" "$WORK/kit.xml" --config >/dev/null && echo "   key attached (WACUSB0003)"
fi

echo "== 1. Transfer ISO: WAC32.exe, wac.yml, run-xp.cmd == ($(date +%H:%M:%S))"
mkdir -p "$WORK/iso"
cp "$ROOT/bin/WAC32.exe" "$WORK/iso/"
# The output in <key>\wac\xp\out, beside WAC32.exe; the deleted files at
# level 3, carving — never the default, asked for here to test it on the
# oldest Windows; the rest as bin/ ships it.
sed -e 's/^output:.*/output: out/' -e 's/^\(    level: *\)[0-9]/\13/' "$ROOT/bin/wac.yml" > "$WORK/iso/wac.yml"
# The carving's witnesses: an executable and a PDF of known SHA-256, written
# on the data disk (W:, formatted on first use), truncated to nothing, then
# deleted — their bytes in the free clusters only. On W: and not C:: whatever
# Windows writes on C: during the collection would take the freed clusters.
printf 'int main(void) { return 0; }\n' > "$WORK/tool.c"
i686-w64-mingw32-gcc -O2 -s -o "$WORK/iso/carve-witness.exe" "$WORK/tool.c"
TOKEN="$(date +%Y%m%d%H%M%S)"
printf '%%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%% WAC carving witness %s\n' "$TOKEN" > "$WORK/iso/carve-witness.pdf"
# Larger than a $MFT record holds: a small file is resident, without a cluster to carve.
for i in $(seq 1 100); do printf '%%%s\n' "$(head -c 78 /dev/zero | tr '\0' x)"; done >> "$WORK/iso/carve-witness.pdf"
XREF=$(stat -c %s "$WORK/iso/carve-witness.pdf")
printf 'xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%s\n%%%%EOF\n' "$XREF" >> "$WORK/iso/carve-witness.pdf"
for f in carve-witness.exe carve-witness.pdf; do
  kind=PE; [[ $f == *.pdf ]] && kind=PDF
  echo "carved=W:\\$f|$(stat -c %s "$WORK/iso/$f")|$(sha256sum "$WORK/iso/$f" | cut -c1-64 | tr a-f A-F)|$kind"
done > "$OUTPUT/reference/carving.txt"
# CRLF: cmd.exe of XP reads a batch file line by line on its line ends. A space
# before ">COM1": "%errorlevel%> COM1" became "0> COM1", a redirection of the
# handle 0, and nothing reached the serial port.
printf '%s\r\n' \
  '@echo off' \
  'echo wac-xp-started> COM1' \
  'set KIT=' \
  'for %%d in (D E F G H I J K L M N O P Q R S T U V X Y Z) do vol %%d: 2>nul | find "WACKIT" >nul && set KIT=%%d:' \
  'if not defined KIT (echo wac-xp-nokey> COM1& shutdown -s -t 5& exit /b 1)' \
  'if exist %KIT%\wac\xp rmdir /s /q %KIT%\wac\xp' \
  'mkdir %KIT%\wac\xp' \
  'copy /y "%~dp0WAC32.exe" %KIT%\wac\xp\ >nul' \
  'copy /y "%~dp0wac.yml" %KIT%\wac\xp\ >nul' \
  'if not exist W:\ (echo select disk 1& echo create partition primary& echo assign letter=W) > %TEMP%\wacdata.txt' \
  'if not exist W:\ (diskpart /s %TEMP%\wacdata.txt >nul & echo Y| format W: /FS:NTFS /Q /V:WACDATA >nul)' \
  'del %TEMP%\wacdata.txt 2>nul' \
  'for %%f in (carve-witness.exe carve-witness.pdf) do copy /y "%~dp0%%f" W:\%%f >nul' \
  'fsutil volume dismount W: >nul' \
  'for %%f in (carve-witness.exe carve-witness.pdf) do (type nul > W:\%%f & del W:\%%f)' \
  'cd /d %KIT%\wac\xp' \
  'WAC32.exe < nul > collect.log 2>&1' \
  'echo wac-xp-collected %errorlevel% >COM1' \
  'WAC32.exe --convert=out < nul > convert.log 2>&1' \
  'echo wac-xp-converted %errorlevel% >COM1' \
  'shutdown -s -t 5' > "$WORK/iso/run-xp.cmd"
xorriso -as mkisofs -quiet -J -o "$WORK/transfer.iso" "$WORK/iso" >/dev/null 2>&1
[[ "$($C domstate "$DOM")" == "shut off" ]] || { echo "   $DOM must be shut off" >&2; exit 1; }
$C change-media "$DOM" "$TARGET" "$WORK/transfer.iso" --config >/dev/null

echo "== 2. Start, then run-xp.cmd typed into the Run box == ($(date +%H:%M:%S))"
# The CD's letter depends on the VM (E: on winxp-test): the line typed looks
# for the drive that carries run-xp.cmd. Enter goes as a key of its own — at
# the end of the typed text, the Run box did not take it (measured).
$C start "$DOM" >/dev/null
started=""
for attempt in 1 2 3 4 5 6; do
  sleep 60
  # Server 2003 from the evaluation kit opens its activation wizard at every
  # logon, over the desktop: the Run box never had the focus (2026-11-08).
  # "No, remind me" (Alt+O), then Next (Alt+N) — not Enter, which on a bare
  # desktop opens the selected icon; neither key does anything there, nor on XP.
  "${KEYS[@]}" key KEY_LEFTALT KEY_O >/dev/null; sleep 2
  "${KEYS[@]}" key KEY_LEFTALT KEY_N >/dev/null; sleep 3
  "${KEYS[@]}" key KEY_LEFTMETA KEY_R >/dev/null; sleep 3
  "${KEYS[@]}" type 'cmd /c for %d in (D E F G H I) do if exist %d:\run-xp.cmd %d:\run-xp.cmd' >/dev/null
  "${KEYS[@]}" key KEY_ENTER >/dev/null
  sleep 20
  if grep -aq wac-xp-started "$SERIAL" 2>/dev/null; then started=1; break; fi
done
[[ -n "$started" ]] || { echo "   ❌ run-xp.cmd did not start (nothing on COM1)" >&2; exit 1; }
echo "   run-xp.cmd started (attempt $attempt)"

echo "== 3. Collection and conversion, followed on COM1 == ($(date +%H:%M:%S))"
until [[ "$($C domstate "$DOM")" == "shut off" ]]; do sleep 15; done
tr -d '\r' < "$SERIAL" | grep -a '^wac-xp' | sed 's/^/   /'
grep -aq "wac-xp-nokey" "$SERIAL" && echo "   ❌ the collection key was not found in the VM"
grep -aq "wac-xp-converted" "$SERIAL" || echo "   ❌ the conversion did not end (nothing on COM1)"

echo "== 4. Results read on the key, read-only == ($(date +%H:%M:%S))"
"$HERE/tools/target-venv/bin/python" -I "$HERE/lib/read-offline.py" "$KIT_IMG" "$OUTPUT" wac/xp/out/ \
  'wac/xp/out/*.json' wac/xp/out/exhibits/MANIFEST.json wac/xp/out/exhibits/MANIFEST.sha256 \
  wac/xp/collect.log wac/xp/convert.log
# The version, as the profile installed it: build 2600, a workstation (ProductType 1).
echo "windows=2600|1" > "$OUTPUT/reference/windows-version.txt"

echo "== 5. JSON validity check == ($(date +%H:%M:%S))"
python3 "$HERE/lib/check-json.py" "$OUTPUT" || echo "   ⚠️ the JSON fail some checks (see above)"
echo "== Results on the host: $OUTPUT == ($(date +%H:%M:%S))"
