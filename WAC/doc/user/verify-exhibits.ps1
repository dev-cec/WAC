# verify-exhibits.ps1 — checks the seal and every exhibit of a WAC collection.
# Usage: powershell -ExecutionPolicy Bypass -File verify-exhibits.ps1 -Output E:\output
# Exit code: 0 if everything matches, 1 otherwise.

param([string]$Output = '.\output')

# 1. The seal: the manifest's fingerprint must be the one recorded beside it.
$recorded = ((Get-Content -Raw "$Output\exhibits\MANIFEST.sha256") -split '\s+')[0]
$actual   = (Get-FileHash -Algorithm SHA256 "$Output\exhibits\MANIFEST.json").Hash
if ($recorded -ne $actual) { Write-Output "SEAL MISMATCH: the manifest was modified"; exit 1 }
Write-Output "Seal verified ($actual)"

# 2. Every exhibit: its SHA-256 must be the one in the manifest.
$m = Get-Content -Raw -Encoding UTF8 "$Output\exhibits\MANIFEST.json" | ConvertFrom-Json
$ok = 0; $ko = 0; $fingerprintOnly = 0
foreach ($p in ($m.Items | Where-Object { $_.Result -eq 'OK' })) {
    # An authenticated binary that was not copied (--collect --binary): no file.
    if ($p.ContentStored -eq $false) { $fingerprintOnly++; continue }
    $f = Join-Path $Output $p.ExhibitPath
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f -ErrorAction SilentlyContinue).Hash
    if ($h -eq $p.SHA256) { $ok++ } else { $ko++; Write-Output "MISMATCH: $($p.ExhibitPath)" }
}
Write-Output "$ok exhibit(s) verified, $ko mismatch(es)"
Write-Output "$fingerprintOnly binarie(s) authenticated and fingerprinted only (no copy to verify)"
if ($ko) { exit 1 }
