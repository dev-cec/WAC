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
#   ifeo, silent, activesetup, comhijack  persistence witnesses (harmless:
#                they name executables and DLLs that do not exist) -> persistence.json
#   userinit, lsa_security, monitors  values Windows set itself, read live,
#                to compare -> persistence.json
#   trust, typedpath, search, proxy, fwrule  second-lot registry witnesses of
#                the user "wac" and a firewall rule blocking an unused port;
#   roots, fwcount  the machine's root store and rule count, read live
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

# 8. Persistence witnesses. Harmless: they name programs and DLLs that do not
#    exist, for an executable name nothing runs. Written before the first
#    collection, as the Run value above.
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wac-ifeo-test.exe'
New-Item -Force $ifeo | Out-Null
New-ItemProperty -Force -Path $ifeo -Name 'Debugger' -Value 'C:\wactest\wac-debugger.exe' | Out-Null
New-ItemProperty -Force -Path $ifeo -Name 'GlobalFlag' -PropertyType DWord -Value 0x200 | Out-Null
Write-Output "ifeo=wac-ifeo-test.exe|C:\wactest\wac-debugger.exe"
$silent = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\wac-ifeo-test.exe'
New-Item -Force $silent | Out-Null
New-ItemProperty -Force -Path $silent -Name 'MonitorProcess' -Value 'C:\wactest\wac-monitor.exe' | Out-Null
Write-Output "silent=wac-ifeo-test.exe|C:\wactest\wac-monitor.exe"
$setup = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{0000FACE-0000-4AC0-8000-000000000001}'
New-Item -Force $setup | Out-Null
New-ItemProperty -Force -Path $setup -Name 'StubPath' -Value 'C:\wactest\wac-stub.exe /once' | Out-Null
Write-Output "activesetup={0000FACE-0000-4AC0-8000-000000000001}|C:\wactest\wac-stub.exe /once"
$wacSid = (New-Object Security.Principal.NTAccount 'wac').Translate([Security.Principal.SecurityIdentifier]).Value
$com = "Registry::HKEY_USERS\$($wacSid)_Classes\CLSID\{0000FACE-0000-4AC0-8000-000000000002}\InprocServer32"
New-Item -Force $com | Out-Null
Set-ItemProperty -Path $com -Name '(default)' -Value 'C:\wactest\wac-com.dll'
Write-Output "comhijack=$wacSid|{0000FACE-0000-4AC0-8000-000000000002}|C:\wactest\wac-com.dll"
# What Windows set itself, read live, to compare.
Write-Output ("userinit=" + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Userinit)
Write-Output ("lsa_security=" + ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').'Security Packages' -join '|'))
$monitors = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object { $_.PSChildName + '=' + $_.GetValue('Driver') } | Sort-Object
Write-Output ("monitors=" + ($monitors -join '|'))

# 9. Second-lot registry witnesses, in the hive of the user "wac" (loaded: the
#    user is logged on) and in the firewall policy. Harmless.
$user = "Registry::HKEY_USERS\$wacSid"
$trust = "$user\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords"
New-Item -Force $trust | Out-Null
$stamp = [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc())
$record = $stamp + (New-Object byte[] 12) + [byte[]](0xFF, 0xFF, 0xFF, 0x7F)
New-ItemProperty -Force -Path $trust -Name '%USERPROFILE%/Documents/wac-macro-test.docm' -PropertyType Binary -Value $record | Out-Null
Write-Output "trust=$wacSid|%USERPROFILE%/Documents/wac-macro-test.docm"
$typed = "$user\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
New-Item -Force $typed -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Force -Path $typed -Name 'url25' -Value '\\wac-test.invalid\share' | Out-Null
Write-Output "typedpath=$wacSid|25|\\wac-test.invalid\share"
$wheel = "$user\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
if (-not (Test-Path $wheel)) { New-Item -Force $wheel | Out-Null }
$term = [Text.Encoding]::Unicode.GetBytes('wac-secret-search') + [byte[]](0, 0)
New-ItemProperty -Force -Path $wheel -Name '99' -PropertyType Binary -Value $term | Out-Null
$order = (Get-ItemProperty $wheel -ErrorAction SilentlyContinue).MRUListEx
$ids = @()
if ($order) { for ($i = 0; $i + 4 -le $order.Length; $i += 4) { $v = [BitConverter]::ToUInt32($order, $i); if ($v -eq 0xFFFFFFFF) { break }; if ($v -ne 99) { $ids += $v } } }
$bytes = @(); foreach ($v in @(99) + $ids) { $bytes += [BitConverter]::GetBytes([uint32]$v) }; $bytes += [BitConverter]::GetBytes([uint32]::MaxValue)
New-ItemProperty -Force -Path $wheel -Name 'MRUListEx' -PropertyType Binary -Value ([byte[]]$bytes) | Out-Null
Write-Output "search=$wacSid|wac-secret-search"
$internet = "$user\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
New-ItemProperty -Force -Path $internet -Name 'ProxyServer' -Value '127.0.0.1:3128' | Out-Null
Write-Output "proxy=$wacSid|127.0.0.1:3128"
Get-NetFirewallRule -DisplayName 'WAC test rule' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'WAC test rule' -Direction Inbound -Action Block -Protocol TCP -LocalPort 65001 | Out-Null
Write-Output "fwrule=WAC test rule|Block|In|65001"
$rules = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
Write-Output ("fwcount=" + (Get-Item $rules).ValueCount)
$roots = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates' | ForEach-Object PSChildName | Sort-Object
Write-Output ("roots=" + ($roots -join ','))
$first = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $roots -contains $_.Thumbprint } | Select-Object -First 1
if ($first) { Write-Output ("rootsubject=" + $first.Thumbprint + '|' + $first.GetNameInfo('SimpleName', $false)) }

# 10. The data volume (a second fixed NTFS disk, label WACDATA): a file kept,
#     a file created then deleted — the second $MFT and change journal.
$data = Get-Volume -FileSystemLabel WACDATA -ErrorAction SilentlyContinue | Where-Object DriveLetter | Select-Object -First 1
if ($data) {
    $letter = "$($data.DriveLetter):"
    # A data volume has no change journal until a service asks for one: the
    # harness creates it (32 MB, as on C:), idempotent.
    fsutil usn createjournal m=0x2000000 a=0x800000 $letter | Out-Null
    Set-Content "$letter\wac-volume-test.txt" 'WAC harness data volume witness'
    $gone = "$letter\wac-deleted-$(Get-Date -Format HHmmss).txt"
    Set-Content $gone 'deleted by the WAC harness'
    Remove-Item $gone
    Write-Output "datavolume=$letter|$letter\wac-volume-test.txt|$gone"
}

# 11. Reference counts of the logs Windows writes itself.
$sections = (Select-String -Path 'C:\Windows\INF\setupapi.dev*.log' -Pattern '^>>>  \[' -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Output "setupapi=$sections"
$mplog = @(Get-ChildItem -Force 'C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log' -ErrorAction SilentlyContinue).Count
Write-Output "mplog=$mplog"
