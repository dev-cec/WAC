# verify-exhibits.ps1 — checks the seal and every exhibit of a WAC collection.
# Usage: powershell -ExecutionPolicy Bypass -File verify-exhibits.ps1 -Output E:\output
# Exit code: 0 if everything matches, 1 otherwise, 2 if PowerShell is older than 4.

param([string]$Output = '.\output')

# Get-FileHash, ConvertFrom-Json, Get-Content -Raw and the extended paths
# came with PowerShell 4: on an older one the reading would fail, and its
# failure read as a mismatch of the seal. Said so instead.
if ($PSVersionTable.PSVersion.Major -lt 4) {
    Write-Output "PowerShell 4 or later is needed (this is $($PSVersionTable.PSVersion)): use verify-exhibits.sh, or a more recent Windows"
    exit 2
}

# 1. The seal: the manifest's fingerprint must be the one recorded beside it.
$recorded = ((Get-Content -Raw "$Output\exhibits\MANIFEST.sha256") -split '\s+')[0]
$actual   = (Get-FileHash -Algorithm SHA256 "$Output\exhibits\MANIFEST.json").Hash
if ($recorded -ne $actual) { Write-Output "SEAL MISMATCH: the manifest was modified"; exit 1 }
Write-Output "Seal verified ($actual)"

# 2. Every exhibit: its SHA-256 must be the one in the manifest.
$m = Get-Content -Raw -Encoding UTF8 "$Output\exhibits\MANIFEST.json" | ConvertFrom-Json
# The manifest comes from the examined machine: an exhibit path that leaves
# the collection (.., absolute path, drive) is refused, never read. Checked on
# the string, then read through \\?\: an exhibit's path can pass 260
# characters, where GetFullPath and Get-FileHash fail without it.
$root = (Resolve-Path -LiteralPath $Output).ProviderPath.TrimEnd('\') + '\'
$ok = 0; $ko = 0; $fingerprintOnly = 0
foreach ($p in ($m.Items | Where-Object { $_.Result -eq 'OK' })) {
    # An authenticated binary that was not copied (--collect --binary): no file.
    if ($p.ContentStored -eq $false) { $fingerprintOnly++; continue }
    $rel = ([string]$p.ExhibitPath) -replace '/', '\'
    $h = $null
    if ($rel -and -not [IO.Path]::IsPathRooted($rel) -and $rel -notmatch ':' -and ($rel -split '\\') -notcontains '..') {
        $long = if ($root.StartsWith('\\')) { '\\?\UNC\' + $root.Substring(2) + $rel } else { '\\?\' + $root + $rel }
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $long -ErrorAction SilentlyContinue).Hash
    }
    if ($h -and $h -eq $p.SHA256) { $ok++ } else { $ko++; Write-Output "MISMATCH: $($p.ExhibitPath)" }
}
Write-Output "$ok exhibit(s) verified, $ko mismatch(es)"
Write-Output "$fingerprintOnly binarie(s) authenticated and fingerprinted only (no copy to verify)"
if ($ko) { exit 1 }
