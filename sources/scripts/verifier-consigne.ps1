# verifier-consigne.ps1 — checks the seal and every exhibit of a WAC collection
# (French output messages.) Usage: powershell -ExecutionPolicy Bypass -File verifier-consigne.ps1 -Sortie E:\output
# Exit code: 0 if everything matches, 1 otherwise, 2 if PowerShell is older than 4.

param([string]$Sortie = '.\output')

# Get-FileHash, ConvertFrom-Json, Get-Content -Raw and the extended paths
# came with PowerShell 4: on an older one the reading would fail, and its
# failure read as a mismatch of the seal. Said so instead.
if ($PSVersionTable.PSVersion.Major -lt 4) {
    Write-Output "PowerShell 4 ou plus est nécessaire (version $($PSVersionTable.PSVersion)) : utiliser verifier-consigne.sh, ou un Windows plus récent"
    exit 2
}

# 1. The seal: the manifest's fingerprint must be the one recorded beside it.
$annonce = ((Get-Content -Raw "$Sortie\exhibits\MANIFEST.sha256") -split '\s+')[0]
$reel    = (Get-FileHash -Algorithm SHA256 "$Sortie\exhibits\MANIFEST.json").Hash
if ($annonce -ne $reel) { Write-Output "SCEAU NON CONFORME : manifeste modifie"; exit 1 }
Write-Output "Sceau conforme ($reel)"

# 2. Every exhibit: its SHA-256 must be the one in the manifest.
$m = Get-Content -Raw -Encoding UTF8 "$Sortie\exhibits\MANIFEST.json" | ConvertFrom-Json
# The manifest comes from the examined machine: an exhibit path that leaves
# the collection (.., absolute path, drive) is refused, never read. Checked on
# the string, then read through \\?\: an exhibit's path can pass 260
# characters, where GetFullPath and Get-FileHash fail without it.
$root = (Resolve-Path -LiteralPath $Sortie).ProviderPath.TrimEnd('\') + '\'
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
    if ($h -and $h -eq $p.SHA256) { $ok++ } else { $ko++; Write-Output "DIFFERENTE : $($p.ExhibitPath)" }
}
Write-Output "$ok piece(s) conforme(s), $ko differente(s)"
Write-Output "$fingerprintOnly binaire(s) authentifie(s), empreinte seule (pas de copie a verifier)"
if ($ko) { exit 1 }
