# user-access-log-witness.ps1 — the User Access Logging reference, in two phases
# around WAC's collection.
#   -Phase access     a connection to this server's file sharing, which its User
#                     Access Logging records, then the service stopped, which
#                     writes it to the databases. The service stays stopped: on
#                     Server 2012 R2 a restart loses the rows the stop wrote, so
#                     WAC collects the very files the reference will hold.
#   -Phase reference  after the collection: the databases copied into
#                     C:\wactest\user-access-log.zip, every file but the engine's
#                     own. The service is still left stopped: the separate
#                     collection, later, reads the same files; run-wac-test.sh
#                     starts it again after that one.
# On Server 2016 a past period's database has a name of three random UTF-16 units,
# a lone surrogate among them: it is stored under "u-" and its units in
# hexadecimal ("u-6630-db1c-0239"), which check-json.py turns back into the name.
# The harness may stop a service, WAC never does. Prints "stopped" then "placed",
# or "no service" where the machine has none (a client, a server before 2012).
param([Parameter(Mandatory = $true)][ValidateSet('access', 'reference')][string]$Phase)
$ErrorActionPreference = 'Stop'
$service = Get-Service UALSVC -ErrorAction SilentlyContinue
if (-not $service) { Write-Output 'no service'; exit 0 }
if ($Phase -eq 'access') {
    if ($service.Status -ne 'Running') { Start-Service UALSVC }
    # IPC$: the administrative shares refuse a local account over the network.
    # Through cmd: PowerShell makes an error of anything net.exe writes to stderr.
    & cmd.exe /c 'net use \\127.0.0.1\IPC$ /user:wac Wac-Server-2026! >nul 2>&1 & net use \\127.0.0.1\IPC$ /delete /y >nul 2>&1'
    Stop-Service UALSVC -Force
    Write-Output 'stopped'
    exit 0
}
$folder = "$env:SystemRoot\System32\LogFiles\Sum"
$copy = 'C:\wactest\user-access-log'
New-Item -ItemType Directory -Force $copy | Out-Null
# Without -File and -notin (PowerShell 3): PowerShell 2 parses the whole script.
Get-ChildItem $folder | Where-Object { -not $_.PSIsContainer -and @('.log', '.jrs', '.chk', '.jfm') -notcontains $_.Extension } | ForEach-Object {
    $name = $_.Name
    if ($name -cnotmatch '^[\x20-\x7e]+$') { $name = 'u-' + (($name.ToCharArray() | ForEach-Object { '{0:x4}' -f [int]$_ }) -join '-') }
    Copy-Item -LiteralPath $_.FullName (Join-Path $copy $name)
}
# Zipped by .NET: Compress-Archive arrives with PowerShell 5, Server 2012 has 3.
Add-Type -AssemblyName System.IO.Compression.FileSystem
Remove-Item 'C:\wactest\user-access-log.zip' -ErrorAction SilentlyContinue
[IO.Compression.ZipFile]::CreateFromDirectory($copy, 'C:\wactest\user-access-log.zip')
Remove-Item $copy -Recurse -Force
Write-Output 'placed'
