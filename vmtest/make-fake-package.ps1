# make-fake-package.ps1 — prepares, in the test folder, a COPY of a signed
# Store package on which WAC's package verification must hold.
#
# Why a copy: the check must not alter the installed applications of the VM.
# WAC finds a package by the folder holding AppxSignature.p7x and
# AppxBlockMap.xml: a copy of those two files, intact, makes the copy a
# package as far as the verification goes. In it:
#   - an UNTOUCHED script of the package: WAC must authenticate it through
#     the package and not collect it;
#   - a MODIFIED script (one byte appended): its blocks no longer match the
#     signed block map, WAC must collect it;
#   - an INTRUDER, a file the block map does not list: WAC must collect it.
# Scripts (.js) are chosen because nothing else authenticates them: a
# Microsoft-signed DLL would pass through its own signature, and the check
# would prove nothing about the package.
#
# Output (stdout): one line per case, "untouched|path", "modified|path",
# "intruder|path" — the reference check-json.py compares WAC's manifest with.
param([string]$Destination = "C:\wactest\fakepkg")

$ErrorActionPreference = "Stop"
if (Test-Path $Destination) { Remove-Item $Destination -Recurse -Force }

foreach ($package in Get-ChildItem "C:\Program Files\WindowsApps" -Directory) {
    $root = $package.FullName
    if (-not (Test-Path "$root\AppxSignature.p7x") -or -not (Test-Path "$root\AppxBlockMap.xml")) { continue }
    $scripts = Get-ChildItem $root -Recurse -File -Filter *.js | Where-Object Length -lt 1MB | Select-Object -First 2
    if (($scripts | Measure-Object).Count -lt 2) { continue }

    New-Item -ItemType Directory -Path $Destination | Out-Null
    Copy-Item "$root\AppxSignature.p7x", "$root\AppxBlockMap.xml" $Destination
    $copies = foreach ($s in $scripts) {
        $relative = $s.FullName.Substring($root.Length + 1)
        $target = Join-Path $Destination $relative
        New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
        Copy-Item $s.FullName $target
        $target
    }
    Add-Content -Path $copies[1] -Value "/* altered */" -NoNewline
    $intruder = Join-Path (Split-Path $copies[0]) "wac-intruder.js"
    Set-Content -Path $intruder -Value "// not in the block map" -NoNewline

    "untouched|$($copies[0])"
    "modified|$($copies[1])"
    "intruder|$intruder"
    exit 0
}
Write-Error "no Store package with two scripts found"
exit 1
