# place-file-artefacts.ps1 — places, in the test VM, witnesses whose content is
# known for the small file artefacts, and prints what check-json.py must find
# in their JSON: one "key=value" per line.
#
#   powershell   a PSReadLine history of a host "WacTest", three commands, one
#                on two lines (backtick) -> powershell_history.json
#   recycled     a file sent to the recycle bin (as SYSTEM, since the harness
#                runs as SYSTEM) -> recycle_bin.json, its original path
#   hosts        an entry of the hosts file -> hosts.json
#   startup      a script dropped in the startup folder of all users, with its
#                SHA-256 -> startup_folders.json
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

# 5. Reference counts of the logs Windows writes itself.
$sections = (Select-String -Path 'C:\Windows\INF\setupapi.dev*.log' -Pattern '^>>>  \[' -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Output "setupapi=$sections"
$mplog = @(Get-ChildItem -Force 'C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log' -ErrorAction SilentlyContinue).Count
Write-Output "mplog=$mplog"
