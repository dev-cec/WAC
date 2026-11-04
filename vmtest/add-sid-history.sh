#!/usr/bin/env bash
# add-sid-history.sh — a real sIDHistory on the witness of a controller already
# made (install-domain-controller.sh, then one cycle to place the witness), for
# active_directory_objects.json. Module: DSInternals from the PowerShell Gallery,
# in vmtest/tools/dsinternals/DSInternals-4.14.nupkg (later versions no longer export
# Add-ADDBSidHistory). It leaves the controller's disk
# with nothing but the value: the module is removed afterwards.
#
# Usage: WAC_VM=srv2022dc-test ./add-sid-history.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DOM="${WAC_VM:-srv2022dc-test}"
QGA="python3 $HERE/lib/qga.py --dom $DOM"
VMDIR='C:\wactest'
# The SID of a domain that does not exist: a migrated account's earlier identity.
HISTORY='S-1-5-21-1111111111-2222222222-3333333333-1234'
trap '$QGA run --shell "del $VMDIR\\dsinternals.zip $VMDIR\\add-sid-history.ps1 & rmdir /s /q $VMDIR\\dsinternals" >/dev/null' EXIT
$QGA write "$HERE/tools/dsinternals/DSInternals-4.14.nupkg" "$VMDIR\\dsinternals.zip" >/dev/null
$QGA write "$HERE/guest/add-sid-history.ps1" "$VMDIR\\add-sid-history.ps1" >/dev/null
$QGA run --timeout 300 -- powershell.exe -NoProfile -Command "Expand-Archive -Force $VMDIR\\dsinternals.zip $VMDIR\\dsinternals"
$QGA run --timeout 600 -- powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$VMDIR\\add-sid-history.ps1" -ModuleFolder "$VMDIR\\dsinternals" -History "$HISTORY"
