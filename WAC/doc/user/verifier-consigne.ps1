# verifier-consigne.ps1 — checks the seal and every exhibit of a WAC collection
# (French output messages.) Usage: powershell -ExecutionPolicy Bypass -File verifier-consigne.ps1 -Sortie E:\output
# Exit code: 0 if everything matches, 1 otherwise.

param([string]$Sortie = '.\output')

# 1. The seal: the manifest's fingerprint must be the one recorded beside it.
$annonce = ((Get-Content -Raw "$Sortie\exhibits\MANIFEST.sha256") -split '\s+')[0]
$reel    = (Get-FileHash -Algorithm SHA256 "$Sortie\exhibits\MANIFEST.json").Hash
if ($annonce -ne $reel) { Write-Output "SCEAU NON CONFORME : manifeste modifie"; exit 1 }
Write-Output "Sceau conforme ($reel)"

# 2. Every exhibit: its SHA-256 must be the one in the manifest.
$m = Get-Content -Raw -Encoding UTF8 "$Sortie\exhibits\MANIFEST.json" | ConvertFrom-Json
$ok = 0; $ko = 0
foreach ($p in ($m.Items | Where-Object { $_.Result -eq 'OK' })) {
    $f = Join-Path $Sortie $p.ExhibitPath
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f -ErrorAction SilentlyContinue).Hash
    if ($h -eq $p.SHA256) { $ok++ } else { $ko++; Write-Output "DIFFERENTE : $($p.ExhibitPath)" }
}
Write-Output "$ok piece(s) conforme(s), $ko differente(s)"
if ($ko) { exit 1 }
