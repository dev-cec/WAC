# place-file-artefacts.ps1 — places, in the test VM, witnesses whose content is
# known for the small file artefacts, and prints what check-json.py must find
# in their JSON: one "key=value" per line.
#
#   powershell   a PSReadLine history of a host "WacTest", three commands, one
#                on two lines (backtick) -> powershell_history.json
#   recycled     a file of the user "wac" sent to the recycle bin from that
#                user's interactive session -> recycle_bin.json, its original path
#   hosts        an entry of the hosts file -> hosts.json
#   startup      a script dropped in the startup folder of all users, with its
#                SHA-256 -> startup_folders.json
#   zone         a file marked as downloaded (Zone.Identifier stream), the
#                stream read back by Windows -> zone_identifiers.json
#   run_default  a Run value of type REG_EXPAND_SZ in the DEFAULT hive (the
#                system account's profile) -> run.json, unexpanded
#   secrets, audit, nl_slots  the SECURITY hive read live by Windows (as
#                SYSTEM): names of the LSA secrets, PolAdtEv in hexadecimal,
#                number of NL$n slots -> security.json
#   setupapi     number of sections of setupapi.dev*.log now; the collection,
#                later, finds at least as many -> setupapi.json
#   mplog        number of Defender support logs -> defender_log.json
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File place-file-artefacts.ps1

$ErrorActionPreference = 'Stop'

# 1. PowerShell history of the user "wac", under a host name of its own.
$history = 'C:\Users\wac\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
New-Item -ItemType Directory -Force $history | Out-Null
$lines = @('whoami /all', 'Get-Process |`', '  Where-Object CPU -gt 10', 'Invoke-WebRequest http://wac-test.invalid/a.ps1')
[IO.File]::WriteAllText("$history\WacTest_history.txt", ($lines -join "`r`n") + "`r`n", (New-Object Text.UTF8Encoding $false))
Write-Output "powershell=WacTest|3|whoami /all"

# 2. A file sent to the recycle bin BY THE USER "wac". Outside an interactive
#    session — SYSTEM, as the harness runs, or a task in batch logon — the
#    "send to the bin" deletes for good, without a word. A scheduled task runs
#    the deletion in the session "wac" has open on the VM's console
#    (autologon), then is removed.
$recycled = "C:\Users\wac\Documents\wac-recycled-$(Get-Date -Format yyyyMMddHHmmss).txt"
Set-Content $recycled 'deleted by the WAC harness'
$script = 'C:\wactest\recycle-witness.ps1'
Set-Content $script ("Add-Type -AssemblyName Microsoft.VisualBasic; " +
  "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile('$recycled', 'OnlyErrorDialogs', 'SendToRecycleBin')")
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
$principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
Register-ScheduledTask -TaskName 'WacRecycleWitness' -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'WacRecycleWitness'
for ($i = 0; $i -lt 60 -and (Test-Path $recycled); $i++) { Start-Sleep -Milliseconds 500 }
Unregister-ScheduledTask -TaskName 'WacRecycleWitness' -Confirm:$false
Remove-Item $script -ErrorAction SilentlyContinue
$sid = (New-Object Security.Principal.NTAccount 'wac').Translate([Security.Principal.SecurityIdentifier]).Value
if (Get-ChildItem -Force "C:\`$Recycle.Bin\$sid\`$I*" -ErrorAction SilentlyContinue) { Write-Output "recycled=$recycled" }

# 3. An entry of the hosts file, added once.
$hostsFile = 'C:\Windows\System32\drivers\etc\hosts'
$entry = '10.11.12.13 wac-test.invalid'
if (-not (Select-String -Path $hostsFile -SimpleMatch $entry -Quiet)) { Add-Content $hostsFile "`r`n$entry" }
Write-Output "hosts=10.11.12.13|wac-test.invalid"

# 4. A script in the startup folder of all users.
$startup = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\wac-startup-test.cmd'
Set-Content $startup '@echo WAC harness startup witness'
Write-Output ("startup=$startup|" + (Get-FileHash -Algorithm SHA256 $startup).Hash)

# 5. A file marked as downloaded from the Internet: its Zone.Identifier
#    stream, written and read back by Windows.
$downloaded = 'C:\Users\wac\Downloads\wac-downloaded.exe'
New-Item -ItemType Directory -Force 'C:\Users\wac\Downloads' | Out-Null
Set-Content $downloaded 'MZ WAC harness download witness'
Set-Content -Path $downloaded -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://wac-test.invalid/wac-downloaded.exe"
$hostUrl = (Get-Content -Path $downloaded -Stream Zone.Identifier | Where-Object { $_ -like 'HostUrl=*' }) -replace '^HostUrl=', ''
Write-Output "zone=$downloaded|3|$hostUrl"

# 6. A Run value in the DEFAULT hive, REG_EXPAND_SZ: Windows writes the
#    registry to the disk a minute or so later, before the first collection.
$runKey = 'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Force $runKey | Out-Null
New-ItemProperty -Force -Path $runKey -Name 'WacTestDefault' -PropertyType ExpandString -Value '%SystemRoot%\wac-default.exe' | Out-Null
Write-Output "run_default=WacTestDefault|%SystemRoot%\wac-default.exe"

# 7. The SECURITY hive as Windows reads it live (the harness runs as SYSTEM).
$secrets = (Get-ChildItem 'HKLM:\SECURITY\Policy\Secrets' | ForEach-Object PSChildName | Sort-Object) -join ','
Write-Output "secrets=$secrets"
$audit = (Get-Item 'HKLM:\SECURITY\Policy\PolAdtEv').GetValue('')
Write-Output ("audit=" + (($audit | ForEach-Object { $_.ToString('X2') }) -join ''))
$slots = @((Get-Item 'HKLM:\SECURITY\Cache' -ErrorAction SilentlyContinue).Property | Where-Object { $_ -match '^NL\$\d+$' }).Count
Write-Output "nl_slots=$slots"

# 8. Reference counts of the logs Windows writes itself.
$sections = (Select-String -Path 'C:\Windows\INF\setupapi.dev*.log' -Pattern '^>>>  \[' -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Output "setupapi=$sections"
$mplog = @(Get-ChildItem -Force 'C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log' -ErrorAction SilentlyContinue).Count
Write-Output "mplog=$mplog"
