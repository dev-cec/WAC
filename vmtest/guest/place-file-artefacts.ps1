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

# -Only key,key…: the witnesses of these artefacts only (run-wac-test.sh --only),
# every one without it.
param([string]$Only = '')
$wanted = @($Only.Split(',') | Where-Object { $_ })
function Wants([string[]]$keys) {
    if (-not $wanted) { return $true }
    foreach ($k in $keys) { if ($wanted -contains $k) { return $true } }
    return $false
}

$ErrorActionPreference = 'Stop'
# The SID of the test user "wac", whose loaded hive several sections write to.
# Defined here: set inside one section, it was empty when --only skipped it.
$wacSid = (New-Object Security.Principal.NTAccount 'wac').Translate([Security.Principal.SecurityIdentifier]).Value
# The references go back in UTF-8: some name a file with accents.
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# 1. PowerShell history of the user "wac", under a host name of its own.
if (Wants 'powershell_history') {
    $history = 'C:\Users\wac\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
    New-Item -ItemType Directory -Force $history | Out-Null
    $lines = @('whoami /all', 'Get-Process |`', '  Where-Object CPU -gt 10', 'Invoke-WebRequest http://wac-test.invalid/a.ps1')
    [IO.File]::WriteAllText("$history\WacTest_history.txt", ($lines -join "`r`n") + "`r`n", (New-Object Text.UTF8Encoding $false))
    Write-Output "powershell=WacTest|3|whoami /all"
}

# 2. A file sent to the recycle bin BY THE USER "wac". Outside an interactive
#    session — SYSTEM, as the harness runs, or a task in batch logon — the
#    "send to the bin" deletes for good, without a word. A scheduled task runs
#    the deletion in the session "wac" has open on the VM's console
#    (autologon), then is removed.
if (Wants 'recycle_bin') {
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
}

# 3. An entry of the hosts file, added once.
if (Wants 'hosts') {
    $hostsFile = 'C:\Windows\System32\drivers\etc\hosts'
    $entry = '10.11.12.13 wac-test.invalid'
    if (-not (Select-String -Path $hostsFile -SimpleMatch $entry -Quiet)) { Add-Content $hostsFile "`r`n$entry" }
    Write-Output "hosts=10.11.12.13|wac-test.invalid"
}

# 4. A script in the startup folder of all users.
if (Wants 'startup_folders') {
    $startup = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\wac-startup-test.cmd'
    Set-Content $startup '@echo WAC harness startup witness'
    Write-Output ("startup=$startup|" + (Get-FileHash -Algorithm SHA256 $startup).Hash)
}

# 5. A file marked as downloaded from the Internet: its Zone.Identifier
#    stream, written and read back by Windows.
if (Wants 'zone_identifiers', 'mft') {
    $downloaded = 'C:\Users\wac\Downloads\wac-downloaded.exe'
    New-Item -ItemType Directory -Force 'C:\Users\wac\Downloads' | Out-Null
    Set-Content $downloaded 'MZ WAC harness download witness'
    Set-Content -Path $downloaded -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://wac-test.invalid/wac-downloaded.exe"
    $hostUrl = (Get-Content -Path $downloaded -Stream Zone.Identifier | Where-Object { $_ -like 'HostUrl=*' }) -replace '^HostUrl=', ''
    Write-Output "zone=$downloaded|3|$hostUrl"
}

# 6. A Run value in the DEFAULT hive, REG_EXPAND_SZ: Windows writes the
#    registry to the disk a minute or so later, before the first collection.
if (Wants 'registry') {
    $runKey = 'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run'
    New-Item -Force $runKey | Out-Null
    New-ItemProperty -Force -Path $runKey -Name 'WacTestDefault' -PropertyType ExpandString -Value '%SystemRoot%\wac-default.exe' | Out-Null
    Write-Output "run_default=WacTestDefault|%SystemRoot%\wac-default.exe"
}

# 7. The SECURITY hive as Windows reads it live (the harness runs as SYSTEM).
if (Wants 'security') {
    $secrets = (Get-ChildItem 'HKLM:\SECURITY\Policy\Secrets' | ForEach-Object PSChildName | Sort-Object) -join ','
    Write-Output "secrets=$secrets"
    $audit = (Get-Item 'HKLM:\SECURITY\Policy\PolAdtEv').GetValue('')
    Write-Output ("audit=" + (($audit | ForEach-Object { $_.ToString('X2') }) -join ''))
    $slots = @((Get-Item 'HKLM:\SECURITY\Cache' -ErrorAction SilentlyContinue).Property | Where-Object { $_ -match '^NL\$\d+$' }).Count
    Write-Output "nl_slots=$slots"
}

# 8. Persistence witnesses. Harmless: they name programs and DLLs that do not
#    exist, for an executable name nothing runs. Written before the first
#    collection, as the Run value above.
if (Wants 'persistence') {
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
    $com = "Registry::HKEY_USERS\$($wacSid)_Classes\CLSID\{0000FACE-0000-4AC0-8000-000000000002}\InprocServer32"
    New-Item -Force $com | Out-Null
    Set-ItemProperty -Path $com -Name '(default)' -Value 'C:\wactest\wac-com.dll'
    Write-Output "comhijack=$wacSid|{0000FACE-0000-4AC0-8000-000000000002}|C:\wactest\wac-com.dll"
    # What Windows set itself, read live, to compare.
    Write-Output ("userinit=" + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Userinit)
    Write-Output ("exefile=" + (Get-ItemProperty 'HKLM:\SOFTWARE\Classes\exefile\shell\open\command').'(default)')
    Write-Output ("lsa_security=" + ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').'Security Packages' -join '|'))
    $monitors = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object { $_.PSChildName + '=' + $_.GetValue('Driver') } | Sort-Object
    Write-Output ("monitors=" + ($monitors -join '|'))
}

# 9. Second-lot registry witnesses, in the hive of the user "wac" (loaded: the
#    user is logged on) and in the firewall policy. Harmless.
if (Wants 'office_trust_records', 'typed_paths', 'word_wheel_query', 'internet_settings', 'firewall', 'root_certificates') {
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
}

# 10. The data volume (a second fixed NTFS disk, label WACDATA): a file kept,
#     a file created then deleted — the second $MFT and change journal.
if (Wants 'mft', 'usn_journal') {
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
}

# 11. A Defender detection and quarantine of known dates: the EICAR test
#     string — harmless by design, made for this — written in a folder
#     excluded for a moment, dated, then scanned once the exclusion is gone.
#     MSFT_MpThreatDetection is the reference; the file's dates and its SHA-1
#     are what the quarantine must give back.
if (Wants 'defender') {
    $held = 'C:\wactest\eicar-held'
    New-Item -ItemType Directory -Force $held | Out-Null
    $eicar = "$held\wac-eicar-$(Get-Date -Format HHmmss).txt"
    Add-MpPreference -ExclusionPath $held
    Start-Sleep 3
    [IO.File]::WriteAllText($eicar, 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
    $item = Get-Item $eicar
    $item.CreationTimeUtc = [datetime]::new(2021, 1, 2, 3, 4, 5, [DateTimeKind]::Utc)
    $item.LastWriteTimeUtc = [datetime]::new(2022, 3, 4, 5, 6, 7, [DateTimeKind]::Utc)
    Remove-MpPreference -ExclusionPath $held
    Start-Sleep 3
    Start-MpScan -ScanType CustomScan -ScanPath $eicar
    Start-Sleep 10
    $detection = Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpThreatDetection |
        Where-Object { $_.Resources -contains "file:_$eicar" } | Select-Object -First 1
    if ($detection) {
        $iso = { param($d) $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff') }
        Write-Output ("defender=" + (@($detection.DetectionID, $eicar, (& $iso $detection.InitialDetectionTime),
            $detection.DomainUser, $detection.ProcessName, $detection.ThreatID, $detection.CurrentThreatExecutionStatusID) -join '|'))
    }
}

# 12. WMI subscriptions, harmless: the filter waits for hour 99, which never
#     comes, so neither consumer ever runs. Created once and kept — WMI
#     writes its repository to disk minutes later, not at once. One filter
#     more in root\default: subscriptions are not only in root\subscription.
if (Wants 'wmi') {
    $sub = 'root\subscription'
    $filter = Get-CimInstance -Namespace $sub -ClassName __EventFilter -Filter "Name='WacTestFilter'"
    if (-not $filter) {
        $filter = New-CimInstance -Namespace $sub -ClassName __EventFilter -Property @{
            Name = 'WacTestFilter'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 99" }
    }
    $consumers = @(
        @{ Class = 'CommandLineEventConsumer'; Name = 'WacTestConsumer'; Property = @{ CommandLineTemplate = 'cmd.exe /c echo wac-test-consumer' } },
        @{ Class = 'ActiveScriptEventConsumer'; Name = 'WacTestScript'; Property = @{ ScriptingEngine = 'VBScript'; ScriptText = "' WAC test: never run" } })
    foreach ($c in $consumers) {
        $consumer = Get-CimInstance -Namespace $sub -ClassName $c.Class -Filter "Name='$($c.Name)'"
        if (-not $consumer) {
            $properties = $c.Property + @{ Name = $c.Name }
            $consumer = New-CimInstance -Namespace $sub -ClassName $c.Class -Property $properties
        }
        $bound = Get-CimInstance -Namespace $sub -ClassName __FilterToConsumerBinding |
            Where-Object { "$($_.Consumer)" -like "*$($c.Name)*" }
        if (-not $bound) { New-CimInstance -Namespace $sub -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$filter; Consumer = [ref]$consumer } | Out-Null }
    }
    if (-not (Get-CimInstance -Namespace 'root\default' -ClassName __EventFilter -Filter "Name='WacTestFilterDefault'")) {
        New-CimInstance -Namespace 'root\default' -ClassName __EventFilter -Property @{
            Name = 'WacTestFilterDefault'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceCreationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 99" } | Out-Null
    }
    Write-Output "wmi=$($filter.Query)"
    # Every namespace, from root: the reference counts of the four kinds.
    $counts = @{ Filter = 0; Consumer = 0; Binding = 0; Timer = 0; Namespaces = 0 }
    $pending = [System.Collections.Generic.Stack[string]]::new(); $pending.Push('root')
    while ($pending.Count) {
        $ns = $pending.Pop(); $counts.Namespaces++
        foreach ($child in @(Get-CimInstance -Namespace $ns -ClassName __NAMESPACE -ErrorAction SilentlyContinue)) { $pending.Push("$ns\$($child.Name)") }
        $counts.Filter += @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue).Count
        $counts.Consumer += @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue).Count
        $counts.Binding += @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue).Count
        $counts.Timer += @(Get-CimInstance -Namespace $ns -ClassName __TimerInstruction -ErrorAction SilentlyContinue).Count
    }
    Write-Output "wmicount=$($counts.Filter)|$($counts.Consumer)|$($counts.Binding)|$($counts.Timer)|$($counts.Namespaces)"
}

# 13. A BITS job, harmless: never resumed, it never transfers, so its
#     notification command never runs. Its properties are set BEFORE its
#     file: BITS writes a job to qmgr.db when created and when a file is
#     added, not when a property changes. BITS is restarted once, so that the
#     database holds it (a live copy misses what is still in edb.log).
if (Wants 'bits') {
    $job = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'WacTestJob' | Select-Object -First 1
    if (-not $job) {
        & bitsadmin /create WacTestJob | Out-Null
        & bitsadmin /SetNotifyCmdLine WacTestJob 'C:\Windows\System32\cmd.exe' '/c echo wac-bits-test' | Out-Null
        & bitsadmin /SetDescription WacTestJob 'WAC harness witness, never resumed' | Out-Null
        & bitsadmin /addfile WacTestJob https://wac-test.invalid/wac-bits.bin C:\wactest\wac-bits.bin | Out-Null
        Restart-Service BITS -Force -WarningAction SilentlyContinue
        $job = Get-BitsTransfer -AllUsers | Where-Object DisplayName -eq 'WacTestJob' | Select-Object -First 1
    }
    Write-Output ("bits=" + (@($job.JobId.ToString('B').ToUpper(), $job.Description, $job.JobState,
        $job.CreationTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')) -join '|'))
}

# 14. FAT32 and exFAT volumes, on the two virtual USB keys (a suspect's keys):
#     formatted by Windows itself on first use, then filled on every cycle
#     with known content — a long name with accents, a subfolder, a file and a
#     folder deleted —, and listed back by Windows: what fat_volumes.json must
#     give, deleted entries included.
if (Wants 'fat_volumes') {
    foreach ($key in @(@{ Serial = 'WACUSB0001'; Label = 'WACFAT'; FileSystem = 'FAT32' },
                       @{ Serial = 'WACUSB0002'; Label = 'WACEXFAT'; FileSystem = 'exFAT' })) {
        $disk = Get-Disk | Where-Object { $_.SerialNumber -like "*$($key.Serial)*" } | Select-Object -First 1
        if (-not $disk) { continue }
        $volume = $disk | Get-Partition -ErrorAction SilentlyContinue | Get-Volume -ErrorAction SilentlyContinue |
            Where-Object { $_.FileSystemLabel -eq $key.Label -and $_.DriveLetter } | Select-Object -First 1
        if (-not $volume) {
            # The key's partition, created if none, given a letter if it has none.
            if ($disk.PartitionStyle -eq 'RAW') { $disk | Initialize-Disk -PartitionStyle MBR }
            $part = $disk | Get-Partition -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $part) { $part = $disk | New-Partition -UseMaximumSize }
            if (-not $part.DriveLetter) {
                $part | Add-PartitionAccessPath -AssignDriveLetter
                $part = Get-Partition -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber
            }
            $volume = $part | Format-Volume -FileSystem $key.FileSystem -NewFileSystemLabel $key.Label -Confirm:$false
        }
        $root = "$($volume.DriveLetter):\"
        Get-ChildItem -LiteralPath $root -Force | Where-Object Name -ne 'System Volume Information' | Remove-Item -Recurse -Force
        # Built by code points: PowerShell 5.1 reads this script as ANSI.
        $long = Join-Path $root "Wac Long Name $([char]0x2013) $([char]0xE9)t$([char]0xE9).txt"
        [IO.File]::WriteAllText($long, 'wac fat witness')
        # A summer date: Windows writes a FAT local time with the offset of the
        # moment, WAC reads it with the offset of its date — the same in summer.
        (Get-Item -LiteralPath $long).LastWriteTimeUtc = [datetime]::new(2022, 7, 4, 5, 6, 8, [DateTimeKind]::Utc)
        New-Item -ItemType Directory -Path (Join-Path $root 'DIR1') | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $root 'DIR1\sub file.bin'), [byte[]](1..5000 | ForEach-Object { $_ % 256 }))
        # A program run from the key, as a suspect would: a copy of whoami.exe,
        # run once (harmless). Its Prefetch cites it on the key: with --binary,
        # WAC must fingerprint it there, through the FAT reader.
        if ($key.FileSystem -eq 'FAT32') {
            $tool = Join-Path $root 'wac-tool.exe'
            Copy-Item C:\Windows\System32\whoami.exe $tool
            # whoami.exe's date is kept by the copy: a summer one instead (see above).
            (Get-Item -LiteralPath $tool).LastWriteTimeUtc = [datetime]::new(2022, 7, 4, 5, 6, 10, [DateTimeKind]::Utc)
            & $tool | Out-Null
            Write-Output "fattool=$tool|$((Get-FileHash $tool -Algorithm SHA256).Hash)"
        }
        # A winter file copied onto the key now, as an exfiltration would: the
        # copy keeps its modification date, which Windows writes on FAT with the
        # offset of the moment of the copy. Its UTC date must come back exact.
        $winter = 'C:\wactest\wac-winter-source.txt'
        [IO.File]::WriteAllText($winter, 'modified in winter, copied later')
        (Get-Item -LiteralPath $winter).LastWriteTimeUtc = [datetime]::new(2022, 1, 10, 12, 0, 0, [DateTimeKind]::Utc)
        Copy-Item -LiteralPath $winter -Destination (Join-Path $root 'copied-winter.txt')
        # The deletions last: no entry created after them takes their places.
        [IO.File]::WriteAllText((Join-Path $root 'deleted-file.txt'), 'deleted by the harness')
        Remove-Item -LiteralPath (Join-Path $root 'deleted-file.txt')
        New-Item -ItemType Directory -Path (Join-Path $root 'DELDIR') | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'DELDIR\inner.txt'), 'inside a deleted folder')
        Remove-Item -LiteralPath (Join-Path $root 'DELDIR') -Recurse
        Write-Output "fat=$($volume.DriveLetter):|$($key.Label)|$($key.FileSystem)"
        foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Force -File | Where-Object FullName -notlike '*System Volume Information*') {
            Write-Output ("fatfile=" + (@($f.FullName, $f.Length, $f.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss')) -join '|'))
        }
    }
}

# 15. A shortcut made now (summer) to a file dated in winter: its target's
#     item keeps the target's dates in local time, computed by Windows with the
#     offset of NOW; the shortcut's header keeps them in UTC. Both must give
#     the same instant.
if (Wants 'recent_documents') {
    $target = 'C:\wactest\wac-winter-target.txt'
    [IO.File]::WriteAllText($target, 'a file of winter')
    $item = Get-Item -LiteralPath $target
    $item.CreationTimeUtc = [datetime]::new(2022, 1, 5, 8, 0, 0, [DateTimeKind]::Utc)
    $item.LastWriteTimeUtc = [datetime]::new(2022, 1, 10, 12, 0, 0, [DateTimeKind]::Utc)
    $link = 'C:\Users\wac\AppData\Roaming\Microsoft\Windows\Recent\wac-winter-target.lnk'
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($link)
    $shortcut.TargetPath = $target
    $shortcut.Save()
    Write-Output "lnkwinter=$link|$target|2022-01-10T12:00:00|2022-01-05T08:00:00"
    # The target's NTFS object identifier, as Windows gives it: the shortcut's
    # tracker block carries the same identifiers (DROID). fsutil prints them as
    # raw bytes, in the order object, birth volume, birth object.
    $ids = @(fsutil objectid query $target | ForEach-Object { if ($_ -match '([0-9a-f]{32})\s*$') { $Matches[1] } })
    if ($ids.Count -ge 3) { Write-Output ("lnkobjid=" + (@($link) + $ids[0..2] -join '|')) }
}

# 16. A folder inside a ZIP, opened by the user's Explorer: the shellbag's
#     archive item copies the ZIP entry's date, a clock time without time
#     zone (13:00 here), which must be given as written. Made once: the
#     shellbag stays.
if (Wants 'registry') {
    $zipPath = 'C:\Users\wac\Documents\wac-archive.zip'
    if (-not (Test-Path $zipPath)) {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::Open($zipPath, 'Create')
        $dir = $zip.CreateEntry('winterdir/')
        $dir.LastWriteTime = [DateTimeOffset]::new(2022, 1, 10, 13, 0, 0, [TimeSpan]::FromHours(1))
        $file = $zip.CreateEntry('winterdir/inner.txt')
        $file.LastWriteTime = [DateTimeOffset]::new(2022, 1, 10, 14, 30, 0, [TimeSpan]::FromHours(1))
        $w = New-Object IO.StreamWriter($file.Open()); $w.Write('inside a zip'); $w.Close()
        $zip.Dispose()
        $script = 'C:\wactest\zipnav-user.ps1'
        Set-Content $script @'
Start-Process explorer.exe 'C:\Users\wac\Documents\wac-archive.zip\winterdir'
Start-Sleep 12
(New-Object -ComObject Shell.Application).Windows() | Where-Object { "$($_.LocationURL)$($_.LocationName)" -like '*winterdir*' } | ForEach-Object { $_.Quit() }
'@
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
        $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
        Register-ScheduledTask -TaskName WacZipNav -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName WacZipNav
        Start-Sleep 25
        Unregister-ScheduledTask -TaskName WacZipNav -Confirm:$false
    }
    Write-Output "zipentry=winterdir|2022-01-10T13:00:00"
}

# 17. Event values as Windows renders them in the event's XML (what the Event
#     Viewer shows): hexadecimal integers, GUIDs, booleans, dates, floats,
#     binary data, and the ProcessingErrorData the service writes when it could
#     not lay out a provider's data — the forms events.json must give. One event
#     of each kind, by its record number.
if (Wants 'events') {
    $picked = @()
    foreach ($q in @(@('Security', '*[System[EventID=4624]]'), @('Security', '*[System[EventID=4672]]'),
                     @('Microsoft-Windows-Ntfs/Operational', '*[System[EventID=170]]'),
                     @('Microsoft-Windows-AppReadiness/Admin', "*[EventData[Data[@Name='Elapsed']]]"),
                     @('Microsoft-Windows-CodeIntegrity/Operational', "*[EventData[Data[@Name='PolicyHash']]]"))) {
        $picked += Get-WinEvent -LogName $q[0] -FilterXPath $q[1] -MaxEvents 1 -ErrorAction SilentlyContinue
    }
    # No XPath selects on ProcessingErrorData: the recent events are scanned.
    $picked += Get-WinEvent -LogName 'Microsoft-Windows-AppModel-Runtime/Admin' -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { ([xml]$_.ToXml()).Event.ProcessingErrorData } | Select-Object -First 1
    foreach ($e in $picked | Where-Object { $_ }) {
        $xml = ([xml]$e.ToXml()).Event
        $items = @($xml.EventData.Data | Where-Object { $_ } | ForEach-Object { , @($_.Name, $_.'#text') })
        if ($xml.ProcessingErrorData) {
            $items += @($xml.ProcessingErrorData.ChildNodes | ForEach-Object { , @($_.LocalName, $_.InnerText) })
        }
        foreach ($item in $items) {
            $value = "$($item[1])" -replace '\s+', ' '
            Write-Output ("evtval=" + (@($e.LogName, $e.RecordId, $item[0], $value) -join '|'))
        }
    }
}

# 17b. A cleared log: a classic log of its own, three events, then cleared.
#      Windows then sees none, but the chunk keeps them past its free-space
#      offset — events.json must give them flagged as recovered, never as live.
if (Wants 'events') {
    if (-not [System.Diagnostics.EventLog]::SourceExists('WACWitness')) { New-EventLog -LogName WACWitness -Source WACWitness }
    1..3 | ForEach-Object { Write-EventLog -LogName WACWitness -Source WACWitness -EventId (4200 + $_) -Message "WAC witness cleared $_" }
    Clear-EventLog -LogName WACWitness
    $live = @(Get-WinEvent -LogName WACWitness -ErrorAction SilentlyContinue).Count
    Write-Output "evtcleared=WACWitness.evtx|$live|4201,4202,4203"
}

# 18. Reference counts of the logs Windows writes itself.
if (Wants 'setupapi', 'defender') {
    $sections = (Select-String -Path 'C:\Windows\INF\setupapi.dev*.log' -Pattern '^>>>  \[' -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Output "setupapi=$sections"
    $mplog = @(Get-ChildItem -Force 'C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log' -ErrorAction SilentlyContinue).Count
    Write-Output "mplog=$mplog"
}

# 19. B-031 — installed programs: a witness program in the machine's Uninstall
#     key (harmless: values only, nothing installed), and the number of
#     programs Windows lists in each Uninstall key — machine, 32-bit, user.
if (Wants 'installed_programs') {
    $witness = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WacTestProgram'
    New-Item -Force $witness | Out-Null
    Set-ItemProperty $witness -Name DisplayName -Value 'WAC test program'
    Set-ItemProperty $witness -Name Publisher -Value 'WAC test publisher'
    Set-ItemProperty $witness -Name DisplayVersion -Value '1.2.3'
    Set-ItemProperty $witness -Name InstallDate -Value '20260930'
    Set-ItemProperty $witness -Name InstallLocation -Value 'C:\wactest\wac-program'
    Write-Output "program=WacTestProgram|WAC test program|WAC test publisher|1.2.3|20260930"
    $machine = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue).Count
    $machine32 = @(Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue).Count
    $user = @(Get-ChildItem "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue).Count
    Write-Output "programs=$machine|$machine32|$wacSid|$user"
    $msi = foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData' -ErrorAction SilentlyContinue) {
        $k.PSChildName + ':' + @(Get-ChildItem "$($k.PSPath)\Products" -ErrorAction SilentlyContinue | Where-Object { Test-Path "$($_.PSPath)\InstallProperties" }).Count
    }
    Write-Output ("msiproducts=" + ($msi -join '|'))
}

# 20. B-031 — Defender exclusions: a path, an extension and a process
#     excluded from scanning (harmless: test names, nothing placed there),
#     then every exclusion Defender lists, kind by kind.
if (Wants 'defender_configuration') {
    Add-MpPreference -ExclusionPath 'C:\wactest\wac-excluded' -ExclusionExtension 'wactestext' -ExclusionProcess 'wac-excluded.exe'
    $p = Get-MpPreference
    foreach ($kind in @(@('Paths', $p.ExclusionPath), @('Extensions', $p.ExclusionExtension), @('Processes', $p.ExclusionProcess), @('IpAddresses', $p.ExclusionIpAddress))) {
        Write-Output ("exclusions=" + $kind[0] + '|' + (@($kind[1] | Where-Object { $_ }) -join '|'))
    }
}

# 21. B-031 — Explorer's RecentDocs: a file of a unique extension (.wacrd)
#     added to the user's recent documents by the shell itself
#     (SHAddToRecentDocs), in their interactive session. Harmless: a text file
#     of the test folder, and the shortcut Explorer makes in Recent.
if (Wants 'explorer_recent_docs') {
    $doc = 'C:\Users\wac\Documents\wac-recent-witness.wacrd'
    Set-Content -Path $doc -Value 'a recent document'
    $script = 'C:\wactest\recentdocs-user.ps1'
    Set-Content $script @'
Add-Type -Namespace Wac -Name Shell -MemberDefinition '[DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern void SHAddToRecentDocs(uint flags, string path);'
[Wac.Shell]::SHAddToRecentDocs(3, 'C:\Users\wac\Documents\wac-recent-witness.wacrd')
Start-Sleep 3
'@
    $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
    $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
    Register-ScheduledTask -TaskName WacRecentDocs -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName WacRecentDocs
    Start-Sleep 15
    Unregister-ScheduledTask -TaskName WacRecentDocs -Confirm:$false
    Write-Output "recentdoc=$wacSid|.wacrd|wac-recent-witness.wacrd"
}

# 22. B-031 — MountPoints2: a share of the VM (WacShare, read-only for "wac", the test
#     folder) mounted by the user in their session, which Explorer records as
#     ##127.0.0.1#WacShare; then every entry of the user's MountPoints2 as the
#     live registry lists it. Not the entries of CPC\Volume: they are
#     volatile (reg save keeps the key, empty), never in the hive's file.
if (Wants 'mount_points') {
    if (-not (Get-SmbShare -Name WacShare -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name WacShare -Path 'C:\wactest' -ReadAccess 'wac' | Out-Null
    }
    $script = 'C:\wactest\mountpoints-user.ps1'
    Set-Content $script @'
net use W: \\127.0.0.1\WacShare | Out-Null
Start-Process explorer.exe '\\127.0.0.1\WacShare'
Start-Sleep 8
(New-Object -ComObject Shell.Application).Windows() | Where-Object { "$($_.LocationURL)" -like '*WacShare*' } | ForEach-Object { $_.Quit() }
net use W: /delete /y | Out-Null
'@
    $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
    $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
    Register-ScheduledTask -TaskName WacMountPoints -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName WacMountPoints
    Start-Sleep 20
    Unregister-ScheduledTask -TaskName WacMountPoints -Confirm:$false
    $base = "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    $names = @(Get-ChildItem $base -ErrorAction SilentlyContinue | Where-Object PSChildName -ne 'CPC' | ForEach-Object PSChildName)
    Write-Output ("mountpoints=$wacSid|" + ($names -join '|'))
}

# 23. B-031 — known networks: every NetworkList profile as the live registry
#     lists it (GUID, name, gateway hardware addresses of its signatures),
#     and the last connection to each name in the NetworkProfile log
#     (event 10000, UTC): the reference for DateLastConnected, stored in
#     local time. Nothing is changed.
if (Wants 'known_networks') {
    $list = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'
    foreach ($k in Get-ChildItem "$list\Profiles") {
        $guid = $k.PSChildName
        $name = (Get-ItemProperty $k.PSPath).ProfileName
        $macs = @(Get-ChildItem "$list\Signatures\Managed", "$list\Signatures\Unmanaged" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.ProfileGuid -eq $guid } |
            ForEach-Object { ($_.DefaultGatewayMac | ForEach-Object { $_.ToString('X2') }) -join '-' })
        Write-Output ("network=$guid|$name|" + ($macs -join ','))
    }
    Get-WinEvent -LogName Microsoft-Windows-NetworkProfile/Operational -FilterXPath '*[System[EventID=10000]]' -ErrorAction SilentlyContinue |
        Group-Object { $_.Properties[0].Value } | ForEach-Object {
            $last = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            Write-Output ("netconnected=" + $_.Name + '|' + $last.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss'))
        }
}

# 24. B-031 — settings that decide how the other artefacts read, from the live
#     registry (OperatingSystem.json, Settings), and the last shutdown as the
#     System log records it (Kernel-General 13, "the operating system is
#     shutting down", UTC): the reference for ShutdownTime. Nothing is changed.
if (Wants 'registry') {
    $cs = 'HKLM:\SYSTEM\CurrentControlSet\Control'
    foreach ($w in @(@("$cs\FileSystem", 'NtfsDisableLastAccessUpdate'), @("$cs\Session Manager\Memory Management\PrefetchParameters", 'EnablePrefetcher'),
                     @("$cs\Terminal Server", 'fDenyTSConnections'), @('HKLM:\SYSTEM\Select', 'Current'),
                     @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI', 'LastLoggedOnSAMUser'))) {
        $v = (Get-ItemProperty $w[0] -ErrorAction SilentlyContinue).($w[1])
        if ($null -ne $v) { Write-Output ("setting=" + $w[1] + '|' + $v) }
    }
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $down = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=13]]" -MaxEvents 20 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -lt $boot } | Select-Object -First 1
    if ($down) { Write-Output ("shutdown=" + $down.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')) }
}

# 25. B-031 — startup state: every StartupApproved and RunNotification value of
#     the machine and of the user "wac", as the live registry holds it (the
#     status code's first 4 bytes, or the notification's value). Nothing is
#     changed.
if (Wants 'registry') {
    $roots = @(@('HKLM', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'),
               @($wacSid, "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Windows\CurrentVersion"))
    foreach ($r in $roots) {
        foreach ($sub in @('Explorer\StartupApproved\Run', 'Explorer\StartupApproved\Run32', 'Explorer\StartupApproved\StartupFolder', 'RunNotification')) {
            $k = Get-Item (Join-Path $r[1] $sub) -ErrorAction SilentlyContinue
            if (-not $k) { continue }
            foreach ($n in $k.GetValueNames()) {
                $v = $k.GetValue($n)
                $text = if ($v -is [byte[]]) { (($v | Select-Object -First 4) | ForEach-Object { $_.ToString('X2') }) -join '' } else { "$v" }
                Write-Output ("startupstate=" + $r[0] + '|' + ($sub -replace '^Explorer\\', '') + '|' + $n + '|' + $text)
            }
        }
    }
}

# 26. B-031 — program usage: a compatibility layer set by the user "wac" on a
#     test program (harmless: a value, no program there), then the names each
#     source of program_usage.json holds in the live registry, and the number
#     of the taskbar's pinned items (FavoritesResolve: one size, one shortcut).
if (Wants 'program_usage') {
    $u = "Registry::HKEY_USERS\$wacSid\Software\Microsoft"
    $layers = "$u\Windows NT\CurrentVersion\AppCompatFlags\Layers"
    if (-not (Test-Path $layers)) { New-Item -Force $layers | Out-Null }
    Set-ItemProperty $layers -Name 'C:\wactest\wac-layer.exe' -Value '~ WIN7RTM'
    $sources = @(@('JumplistData', "$u\Windows\CurrentVersion\Search\JumplistData"),
                 @('CompatibilityAssistant\Store', "$u\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"),
                 @('AppCompatFlags\Layers', $layers))
    foreach ($k in Get-ChildItem "$u\Windows\CurrentVersion\Explorer\FeatureUsage" -ErrorAction SilentlyContinue) {
        $sources += ,@("FeatureUsage\$($k.PSChildName)", $k.PSPath)
    }
    foreach ($s in $sources) {
        $i = Get-Item $s[1] -ErrorAction SilentlyContinue
        if ($i) { Write-Output ("usage=" + $s[0] + '|' + (($i.GetValueNames() | Sort-Object) -join '|')) }
    }
    $fav = (Get-Item "$u\Windows\CurrentVersion\Explorer\Taskband" -ErrorAction SilentlyContinue).GetValue('FavoritesResolve')
    $count = 0; $o = 0
    while ($fav -and $o + 4 -le $fav.Length) { $n = [BitConverter]::ToUInt32($fav, $o); if ($n -lt 76 -or $o + 4 + $n -gt $fav.Length) { break }; $count++; $o += 4 + $n }
    Write-Output "pinned=$wacSid|$count"
    # FileExts: a witness extension opened with two programs, wordpad the most
    # recent; then every OpenWithList of the user, in its MRUList order.
    $exts = "$u\Windows\CurrentVersion\Explorer\FileExts"
    $witness = "$exts\.wacwitness\OpenWithList"
    New-Item -Force $witness | Out-Null
    Set-ItemProperty $witness -Name a -Value 'notepad.exe'
    Set-ItemProperty $witness -Name b -Value 'wordpad.exe'
    Set-ItemProperty $witness -Name MRUList -Value 'ba'
    foreach ($e in Get-ChildItem $exts -ErrorAction SilentlyContinue) {
        $list = Get-Item "$($e.PSPath)\OpenWithList" -ErrorAction SilentlyContinue
        if (-not $list) { continue }
        $order = [string]$list.GetValue('MRUList')
        for ($p = 0; $p -lt $order.Length; $p++) {
            $program = $list.GetValue([string]$order[$p])
            if ($program) { Write-Output ("openwith=" + $e.PSChildName + '|' + $program + '|' + $p) }
        }
    }
}

# 27. B-031 — devices: every USB and SCSI device Windows knows, present or not,
#     with its first install, last arrival and last removal dates as
#     Get-PnpDeviceProperty gives them (UTC). Nothing is changed.
if (Wants 'devices') {
    Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'USB\*' -or $_.InstanceId -like 'SCSI\*' } | ForEach-Object {
        $id = $_.InstanceId
        $dates = foreach ($key in 'DEVPKEY_Device_FirstInstallDate', 'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_LastRemovalDate') {
            $p = Get-PnpDeviceProperty -InstanceId $id -KeyName $key -ErrorAction SilentlyContinue
            if ($p.Data) { $p.Data.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') } else { '' }
        }
        Write-Output ("device=" + $id + '|' + ($dates -join '|'))
    }
}

# 28. B-031 — network shares: the WacShare of section 22 (read-only for "wac",
#     the test folder), then every non-administrative share Windows lists.
if (Wants 'network_shares') {
    if (-not (Get-SmbShare -Name WacShare -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name WacShare -Path 'C:\wactest' -ReadAccess 'wac' | Out-Null
    }
    Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { Write-Output ("share=" + $_.Name + '|' + $_.Path) }
    # Who may use the witness, as Windows reads its security descriptor.
    Get-SmbShareAccess -Name WacShare | ForEach-Object {
        $sid = (New-Object Security.Principal.NTAccount $_.AccountName).Translate([Security.Principal.SecurityIdentifier]).Value
        Write-Output ("shareaccess=WacShare|$sid|" + $_.AccessControlType)
    }
}

# 29. B-031 — network configuration: each present adapter as Windows lists it
#     live (GUID, description, MAC, IPv4 address and how it was obtained).
#     Nothing is changed.
if (Wants 'network_configuration') {
    Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $ip = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        Write-Output ("adapter=" + $_.InterfaceGuid + '|' + $_.InterfaceDescription + '|' + $_.MacAddress + '|' + $ip.IPAddress + '|' + $ip.PrefixOrigin)
    }
}

# 30. B-031 — event log configuration: each log as Windows lists it live, with
#     its state (enabled or not), and each boot ETW session with its Start.
#     Nothing is changed.
if (Wants 'event_log_configuration') {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output ("eventlog=" + $_.LogName + '|' + $_.IsEnabled)
    }
    Get-AutologgerConfig -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output ("autologger=" + $_.Name + '|' + $_.Start)
    }
}
