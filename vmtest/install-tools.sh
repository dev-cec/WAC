#!/usr/bin/env bash
# install-tools.sh — puts the third-party tools of the comparisons (B-015, B-027)
# into the test VM: KAPE and Eric Zimmerman's command-line tools, from
# vmtest/tools/ (not versioned: KAPE is licensed by Kroll on registration, the
# EZ tools come from Get-ZimmermanTools), and the .NET 9 runtime the EZ tools
# need, by Microsoft's own dotnet-install.ps1.
#
# Idempotent: what is already in place is left as it is. The graphical tools
# (…Explorer, EZViewer, TimelineExplorer, hasher, iisGeolocate) are left out:
# the comparisons run the command-line ones.
#
# Usage: ./install-tools.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QGA="python3 $HERE/lib/qga.py"
TOOLS='C:\Tools'

$QGA ping >/dev/null
$QGA run --shell "if not exist $TOOLS mkdir $TOOLS" >/dev/null

# $1 archive on the host, $2 folder in the VM: sent and unpacked once.
install_zip() {
  local archive="$1" target="$2"
  if $QGA run -- powershell.exe -NoProfile -Command "if (Test-Path '$target') { exit 0 } else { exit 1 }" >/dev/null 2>&1; then
    echo "   = $(basename "$archive") already in $target"
    return
  fi
  $QGA write "$archive" "$TOOLS\\incoming.zip" >/dev/null
  $QGA run -- powershell.exe -NoProfile -Command \
    "Expand-Archive -LiteralPath '$TOOLS\\incoming.zip' -DestinationPath '$target' -Force; Remove-Item '$TOOLS\\incoming.zip'" >/dev/null
  echo "   + $(basename "$archive") -> $target"
}

echo "== .NET 9 runtime (EZ tools) =="
# Bypass: dotnet-install.ps1 is a downloaded script, which the execution policy refuses.
$QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
  if (Test-Path "C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.*") { "   = already installed"; exit 0 }
  $script = "C:\Tools\dotnet-install.ps1"
  Invoke-WebRequest -UseBasicParsing -Uri https://dot.net/v1/dotnet-install.ps1 -OutFile $script
  & $script -Channel 9.0 -Runtime dotnet -InstallDir "C:\Program Files\dotnet" | Out-Null
  "   + installed: " + ((Get-ChildItem "C:\Program Files\dotnet\shared\Microsoft.NETCore.App").Name -join ", ")'

echo "== KAPE =="
[[ -f "$HERE/tools/kape.zip" ]] && install_zip "$HERE/tools/kape.zip" "$TOOLS\\KAPE-archive" \
  || echo "   ⚠️ tools/kape.zip absent"

echo "== EZ tools (command line) =="
for archive in "$HERE"/tools/zimmerman/*.zip; do
  name="$(basename "$archive" .zip)"
  case "$name" in
    *Explorer|EZViewer|TimelineExplorer|hasher|iisGeolocate|Get-ZimmermanTools) continue ;;
  esac
  install_zip "$archive" "$TOOLS\\EZ\\$name"
done

echo "== Check =="
$QGA run -- powershell.exe -NoProfile -Command '
  $kape = Get-ChildItem C:\Tools\KAPE-archive -Recurse -Filter kape.exe | Select-Object -First 1
  "   KAPE: " + $(if ($kape) { $kape.FullName } else { "absent" })
  $mft = "C:\Tools\EZ\MFTECmd\MFTECmd.exe"
  "   MFTECmd: " + $(if (Test-Path $mft) { (& $mft --version 2>&1 | Select-Object -First 1) } else { "absent" })'
