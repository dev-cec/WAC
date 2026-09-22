# verifier-consigne.ps1 — vérifie le sceau et chaque pièce d'une collecte WAC.
# Usage : powershell -ExecutionPolicy Bypass -File verifier-consigne.ps1 -Sortie E:\output
# Code de retour : 0 si tout est conforme, 1 sinon.

param([string]$Sortie = '.\output')

# 1. Le sceau : l'empreinte du manifeste doit être celle annoncée.
$annonce = ((Get-Content -Raw "$Sortie\consigne\MANIFESTE.sha256") -split '\s+')[0]
$reel    = (Get-FileHash -Algorithm SHA256 "$Sortie\consigne\MANIFESTE.json").Hash
if ($annonce -ne $reel) { Write-Output "SCEAU NON CONFORME : manifeste modifie"; exit 1 }
Write-Output "Sceau conforme ($reel)"

# 2. Chaque pièce : son SHA-256 doit être celui du manifeste.
$m = Get-Content -Raw -Encoding UTF8 "$Sortie\consigne\MANIFESTE.json" | ConvertFrom-Json
$ok = 0; $ko = 0
foreach ($p in ($m.Items | Where-Object { $_.Result -eq 'OK' })) {
    $f = Join-Path $Sortie $p.ExhibitPath
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f -ErrorAction SilentlyContinue).Hash
    if ($h -eq $p.SHA256) { $ok++ } else { $ko++; Write-Output "DIFFERENTE : $($p.ExhibitPath)" }
}
Write-Output "$ok piece(s) conforme(s), $ko differente(s)"
if ($ko) { exit 1 }
