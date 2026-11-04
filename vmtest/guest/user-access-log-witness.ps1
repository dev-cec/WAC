# user-access-log-witness.ps1 — a connection to this server's file sharing, which
# its User Access Logging records, then the databases as the service leaves them
# once stopped: C:\wactest\user-access-log.zip. The harness may restart a service,
# WAC never does. Prints "placed", or "no service" where the machine has none
# (a client, a server before 2012).
$ErrorActionPreference = 'Stop'
$service = Get-Service UALSVC -ErrorAction SilentlyContinue
if (-not $service) { Write-Output 'no service'; exit 0 }
if ($service.Status -ne 'Running') { Start-Service UALSVC }
$folder = "$env:SystemRoot\System32\LogFiles\Sum"
$copy = 'C:\wactest\user-access-log'
# IPC$: the administrative shares refuse a local account over the network. Through
# cmd: PowerShell makes an error of anything net.exe writes to stderr.
& cmd.exe /c 'net use \\127.0.0.1\IPC$ /user:wac Wac-Server-2026! >nul 2>&1 & net use \\127.0.0.1\IPC$ /delete /y >nul 2>&1'
Stop-Service UALSVC -Force
try {
    New-Item -ItemType Directory -Force $copy | Out-Null
    Copy-Item "$folder\*.mdb" $copy
} finally { Start-Service UALSVC }
# Zipped by .NET: Compress-Archive arrives with PowerShell 5, Server 2012 has 3.
Add-Type -AssemblyName System.IO.Compression.FileSystem
Remove-Item 'C:\wactest\user-access-log.zip' -ErrorAction SilentlyContinue
[IO.Compression.ZipFile]::CreateFromDirectory($copy, 'C:\wactest\user-access-log.zip')
Remove-Item $copy -Recurse -Force
Write-Output 'placed'
