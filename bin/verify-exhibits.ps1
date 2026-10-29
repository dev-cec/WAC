# verify-exhibits.ps1 — checks the seal and every exhibit of a WAC collection.
# Usage: powershell -ExecutionPolicy Bypass -File verify-exhibits.ps1 -Output E:\output [-Seal <SHA-256>] [-Language fr]
#   -Seal      the seal WAC printed at the collection, as written down in the
#              report: compared with MANIFEST.sha256 (see below)
#   -Language  the messages' language; verifier-consigne.ps1 is this script in French
# Exit code: 0 if everything matches, 1 otherwise, 2 if PowerShell is older than 4.
#
# The seal beside the manifest proves only that the manifest is unchanged
# since it was sealed: whoever rewrites the manifest can rewrite its seal.
# Against that, the value written down at the collection (-Seal).

param([string]$Output = '.\output', [string]$Seal = '', [string]$Language = 'en')

# The messages, in the language asked for: {0}, {1} take the values.
$messages = @{
    en = @{
        Version    = 'PowerShell 4 or later is needed (this is {0}): use verify-exhibits.sh, or a more recent Windows'
        Absent     = 'NO MANIFEST: {0} or {1} absent'
        Seal       = 'SEAL MISMATCH: the manifest was modified'
        Noted      = 'SEAL MISMATCH: {0} instead of {1}, written down at the collection'
        Sealed     = 'Seal verified ({0})'
        Unnoted    = 'Seal checked against MANIFEST.sha256 only: give -Seal <value written down at the collection> to hold it against a rewrite'
        Unreadable = 'UNREADABLE MANIFEST: {0}'
        Mismatch   = 'MISMATCH: {0}'
        NotRead    = 'UNREADABLE EXHIBIT: {0}'
        Total      = '{0} exhibit(s) verified, {1} mismatch(es)'
        Binaries   = '{0} binary(ies) authenticated and fingerprinted only (no copy to verify)'
    }
    fr = @{
        Version    = 'PowerShell 4 ou plus est nécessaire (version {0}) : utiliser verifier-consigne.sh, ou un Windows plus récent'
        Absent     = 'MANIFESTE ABSENT : {0} ou {1}'
        Seal       = 'SCEAU NON CONFORME : manifeste modifié'
        Noted      = 'SCEAU NON CONFORME : {0} au lieu de {1}, relevé à la collecte'
        Sealed     = 'Sceau conforme ({0})'
        Unnoted    = 'Sceau comparé à MANIFEST.sha256 seul : donner -Seal <valeur relevée à la collecte> pour l''opposer à une réécriture'
        Unreadable = 'MANIFESTE ILLISIBLE : {0}'
        Mismatch   = 'DIFFÉRENTE : {0}'
        NotRead    = 'PIÈCE ILLISIBLE : {0}'
        Total      = '{0} pièce(s) conforme(s), {1} différente(s)'
        Binaries   = '{0} binaire(s) authentifié(s), empreinte seule (pas de copie à vérifier)'
    }
}
$text = if ($messages.ContainsKey($Language)) { $messages[$Language] } else { $messages['en'] }
function Say([string]$key) { Write-Output ($text[$key] -f $args) }

# Get-FileHash, ConvertFrom-Json and Get-Content -Raw came with PowerShell 4:
# on an older one the reading would fail, and its failure read as a mismatch
# of the seal. Said so instead.
if ($PSVersionTable.PSVersion.Major -lt 4) { Say Version $PSVersionTable.PSVersion; exit 2 }

# Both files first: a missing one is no tampering, and must not read as one.
$manifest = "$Output\exhibits\MANIFEST.json"
$sealFile = "$Output\exhibits\MANIFEST.sha256"
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf) -or -not (Test-Path -LiteralPath $sealFile -PathType Leaf)) {
    Say Absent $manifest $sealFile; exit 1
}

# 1. The seal: the manifest's fingerprint must be the one recorded beside it,
# and the one written down at the collection when it is given.
$recorded = ((Get-Content -Raw -LiteralPath $sealFile) -split '\s+')[0]
$actual   = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifest).Hash
if ($recorded -ne $actual) { Say Seal; exit 1 }
if ($Seal -and $Seal -ne $actual) { Say Noted $actual $Seal; exit 1 }
Say Sealed $actual
if (-not $Seal) { Say Unnoted }

# 2. Every exhibit: its SHA-256 must be the one in the manifest. A manifest
# that is no JSON, or without its list of exhibits, is refused: never taken
# for an empty collection. Read by the serializer ConvertFrom-Json is built
# on, its limit lifted as PowerShell 5 does: that of PowerShell 4, 2 MB of
# text, refused every collection's manifest (tens of MB) on Windows 8.1.
try {
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $m = $serializer.DeserializeObject((Get-Content -Raw -Encoding UTF8 -LiteralPath $manifest))
} catch { $m = $null }
if ($m -isnot [Collections.IDictionary] -or $m['Items'] -isnot [Collections.IList]) { Say Unreadable $manifest; Say Total 0 1; exit 1 }
# The manifest comes from the examined machine: an exhibit path that leaves
# the collection (.., absolute path, drive) is refused, never read. Checked on
# the string. A path past 259 characters is read through \\?\, which .NET
# accepts only from 4.6.2: an ordinary path otherwise, as every version reads.
$root = (Resolve-Path -LiteralPath $Output).ProviderPath.TrimEnd('\') + '\'
$ok = 0; $ko = 0; $fingerprintOnly = 0
foreach ($p in ($m.Items | Where-Object { $_.Result -eq 'OK' })) {
    # An authenticated binary that was not copied (--collect --binary): no file.
    if ($p.ContentStored -eq $false) { $fingerprintOnly++; continue }
    $rel = ([string]$p.ExhibitPath) -replace '/', '\'
    if (-not $rel -or [IO.Path]::IsPathRooted($rel) -or $rel -match ':' -or ($rel -split '\\') -contains '..') {
        $ko++; Say Mismatch $p.ExhibitPath; continue
    }
    $path = $root + $rel
    if ($path.Length -gt 259) { $path = if ($root.StartsWith('\\')) { '\\?\UNC\' + $path.Substring(2) } else { '\\?\' + $path } }
    try { $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $path -ErrorAction Stop).Hash }
    catch { $ko++; Say NotRead $p.ExhibitPath; continue }   # unread is no mismatch: said as such
    if ($h -eq $p.SHA256) { $ok++ } else { $ko++; Say Mismatch $p.ExhibitPath }
}
Say Total $ok $ko
Say Binaries $fingerprintOnly
if ($ko) { exit 1 }
