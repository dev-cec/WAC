#!/usr/bin/env bash
# install-browsers.sh — installs Google Chrome and Mozilla Firefox in the test
# VM (guest/install-browsers.ps1), for the web client tests of B-016. The VM
# downloads them itself, from Google's and Mozilla's sites. Idempotent.
#
# Usage: ./install-browsers.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
QGA="python3 $HERE/lib/qga.py"
VMDIR='C:\wactest'
$QGA write "$HERE/guest/install-browsers.ps1" "$VMDIR\\install-browsers.ps1" >/dev/null
$QGA run -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\install-browsers.ps1"
