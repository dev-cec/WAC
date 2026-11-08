# application-traces-witness.ps1 — witnesses of the applications' traces
# (application_traces.h, application_trace_files.h): files of known content
# where products write them, which check-json.py finds again in <group>.json.
#   - TeamViewer's log, a dated line without offset and its continuation, and
#     beside it a decoy the product's filter does not take;
#   - OpenSSH server's log, a line whose time carries its offset;
#   - WinSCP.ini and FileZilla's sitemanager.xml, each holding a password the
#     conversion must leave out;
#   - a pCloud database, listed, not converted;
#   - a crash dump, a product off by default: never taken.
# The values are fixed: the reference is this script, copied into
# <Out>\application-traces-reference.json for check-json.py.
# PowerShell 2 (Server 2008 R2): no cmdlet younger than it.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'Stop'
$profilePath = Join-Path $env:SystemDrive 'Users\wac'
if (-not (Test-Path $profilePath)) { Write-Output 'no profile'; exit 1 }
$utf8 = New-Object Text.UTF8Encoding($false)
function Put([string]$path, [string]$text) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [IO.File]::WriteAllText($path, $text, $utf8)
}
$teamViewer = "$profilePath\AppData\Roaming\TeamViewer\TeamViewer15_Logfile.log"
Put $teamViewer ("header of the witness log`r`n" +
    "2026/11/08 14:03:21.457  4242  5150 S0   wac-trace-witness incoming connection from 10.0.0.5`r`n" +
    "   wac-trace-witness continuation`r`n")
$decoy = "$profilePath\AppData\Roaming\TeamViewer\wac-trace-decoy.txt"
Put $decoy "2026-11-08 14:03:21 wac-trace-decoy: TeamViewer's filter does not take this name`r`n"
$ssh = "$env:ProgramData\ssh\logs\wac-trace-witness.log"
Put $ssh "2026-11-08T14:03:21.123+01:00 sshd[42]: wac-trace-witness accepted publickey`r`n"
$winscp = "$profilePath\AppData\Roaming\WinSCP.ini"
Put $winscp "[Sessions\wac-trace-witness]`r`nHostName=witness.example`r`nPassword=wac-trace-secret-1`r`nPortNumber=2222`r`n"
$filezilla = "$profilePath\AppData\Roaming\FileZilla\sitemanager.xml"
Put $filezilla ('<?xml version="1.0" encoding="UTF-8"?><FileZilla3><Servers><Server><Host>wac-trace-witness.example</Host>' +
    '<User>wac</User><Pass encoding="base64">wac-trace-secret-2</Pass></Server></Servers></FileZilla3>')
$pcloud = "$profilePath\AppData\Local\pCloud\wac-trace-witness.db"
New-Item -ItemType Directory -Force (Split-Path $pcloud) | Out-Null
[IO.File]::WriteAllBytes($pcloud, [byte[]](83, 81, 76, 105, 116, 101, 0, 1, 2, 3))
$dump = "$profilePath\AppData\Local\CrashDumps\wac-trace-witness.dmp"
New-Item -ItemType Directory -Force (Split-Path $dump) | Out-Null
[IO.File]::WriteAllBytes($dump, [byte[]](77, 68, 77, 80, 0, 0))
$reference = @"
{
 "TeamViewerLog": "$($teamViewer.Replace('\', '\\'))",
 "Decoy": "$($decoy.Replace('\', '\\'))",
 "SshLog": "$($ssh.Replace('\', '\\'))",
 "WinScp": "$($winscp.Replace('\', '\\'))",
 "FileZilla": "$($filezilla.Replace('\', '\\'))",
 "PCloud": "$($pcloud.Replace('\', '\\'))",
 "CrashDump": "$($dump.Replace('\', '\\'))"
}
"@
[IO.File]::WriteAllText((Join-Path $Out 'application-traces-reference.json'), $reference, $utf8)
Write-Output 'placed'
