# place-file-artefacts.ps1 — places, in the test VM, witnesses whose content is
# known for the small file artefacts, and prints what check-json.py must find
# in their JSON: one "key=value" per line.
#
#   psprofile    a profile for every user and one for "wac", comments only, with
#                their SHA-256 -> powershell_profiles.json
#   powershell   a PSReadLine history of a host "WacTest", three commands, one
#                on two lines (backtick) -> powershell_history.json
#   recycled     a file of the user "wac" sent to the recycle bin from that
#                user's interactive session -> recycle_bin.json, its original path
#   hosts        an entry of the hosts file -> hosts.json
#   pfnew        a Prefetch file written by hand, of a version WAC has no
#                decoder for, 32 (not seen yet) -> prefetchs.json, declared
#                "unsupported format", nothing decoded
#   startup      a script dropped in the startup folder of all users, with its
#                SHA-256 -> startup_folders.json
#   shortcut, shortcutfile  a shortcut on the public desktop and one pinned to
#                the task bar of "wac", then every shortcut Windows lists in the
#                Start menus, desktops and Quick Launch -> shortcuts.json
#   zone         a file marked as downloaded (Zone.Identifier stream), the
#                stream read back by Windows -> zone_identifiers.json
#   run_default  a Run value of type REG_EXPAND_SZ in the DEFAULT hive (the
#                system account's profile) -> run.json, unexpanded
#   sdswitness, sdsowner  a file owned by "wac" whose DACL grants Everyone
#                read, and the owner Get-Acl gives for a few dozen files
#                -> mft.json SecurityId -> security_descriptors.json
#   ntfsvolume, usnjournal  each fixed NTFS volume as Windows describes it
#                (DeviceIoControl) -> ntfs_volumes.json, read raw in $Boot and $Max
#   defenderwpp  Defender's WPP traces (Support\*.bin) -> the exhibit manifest
#   dpapikey, dpapipreferred  every DPAPI master key file and what each
#                Preferred names -> dpapi_master_keys.json
#   usf          each User Shell Folders value of "wac", unexpanded; its
#                Desktop redirected to OneDrive\Desktop -> user_shell_folders.json
#   typedurl     two TypedURLs of "wac" with their TypedURLsTime -> web_client.json
#   webvisit, websearch, webdownload, webhta, webiedownload  real browsing of
#                "wac": Chrome and Firefox visits and downloads, a Google
#                search, an HTA run by mshta.exe, a download by Internet
#                Explorer -> web_client.json (install-browsers.sh first)
#   rundefault   a Run value in the NTUSER.DAT of the Default profile (template
#                of new profiles) -> run.json, SID S-0-0-0, Profile "Default"
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
#   thumbcache   the witness picture's System.ThumbnailCacheId and path
#                -> thumbcache.json
#   thunderbird  token, attachment name (RFC 2231 encoded), its SHA-256 and the
#                Inbox Thunderbird wrote -> emails.json
#   shadowrun, shadowevent  a Run value and an event erased after the harness's
#                copy -> shadow_copy_registry.json, shadow_copy_events.json
#   deleted      files of known content written to the disk, then deleted —
#                a resident one, a text of 300 KiB, an unsigned executable
#                (WAC.exe) and a Microsoft one (notepad.exe) — with their
#                SHA-256 and what WAC must do of them -> deleted_files.json;
#   slack        150 of 450 files moved from a folder to another: their former
#                names in the released index blocks of the first -> deleted_files.json (level 2)
#   shadowcopy, shadowfile  every shadow copy Windows lists for C: (identifier,
#                set, creation in UTC), one made here by the harness — through
#                the VSS service, which WAC itself never calls — and the SHA-256
#                Windows reads of a few of its files through the copy's device
#                -> shadow_copies.json and the exhibit manifest
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
# Written for Windows PowerShell 4 and later (Windows 8.1): New-Object rather
# than [type]::new(), no -Depth. A section that needs a cmdlet of Windows 10
# fails alone on an older Windows (see WitnessFailure).

# The files of a folder and of its subfolders, down to a depth: what
# Get-ChildItem -Recurse -Depth does from PowerShell 5 on.
function FilesToDepth([string]$folder, [int]$depth) {
    Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
    if ($depth -gt 0) {
        Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } |
            ForEach-Object { FilesToDepth $_.FullName ($depth - 1) }
    }
}

# EACH SECTION BELOW STANDS ALONE: one that fails — a cmdlet an older Windows
# lacks, a program not installed — says so in the reference, with its line and
# reason, and the others are still placed. The whole script used to stop at
# the first failure, silently: every later witness was missing, and its check
# failed for a reason nothing showed.
function WitnessFailure([string]$section, $failure) {
    $reason = ($failure.Exception.Message -replace '\s+', ' ').Trim()
    Write-Output "witness_failed=$section|line $($failure.InvocationInfo.ScriptLineNumber)|$reason"
}
# Local accounts through net.exe and the WinNT provider of ADSI, which every
# Windows has: Get-LocalUser and its kin came with Windows 10. Measured on the
# Windows 11 VM: the groups and members read here are those Get-LocalGroup and
# Get-LocalGroupMember give.
# [ADSI]::Exists throws, rather than answer false, for an account that is not there.
function LocalUserExists([string]$name) {
    try { [ADSI]::Exists("WinNT://$env:COMPUTERNAME/$name,user") } catch { $false }
}
function NetCommand([string[]]$arguments) {
    & net.exe @arguments 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "net $($arguments[0..1] -join ' ') failed ($LASTEXITCODE)" }
}
# Creates the account or sets its password, through ADSI — net.exe asks
# whether to go on with a password longer than 14 characters, and fails with
# no one to answer; its password never expires.
function SetLocalUser([string]$name, [string]$password) {
    $user = if (LocalUserExists $name) { [ADSI]"WinNT://$env:COMPUTERNAME/$name,user" }
            else { ([ADSI]"WinNT://$env:COMPUTERNAME,computer").Create('user', $name) }
    $user.SetPassword($password)
    $user.SetInfo()
    $user.UserFlags.Value = $user.UserFlags.Value -bor 0x10000   # ADS_UF_DONT_EXPIRE_PASSWD
    $user.SetInfo()
}
function RemoveLocalUser([string]$name) { if (LocalUserExists $name) { NetCommand @('user', $name, '/delete') } }
function AccountSid([string]$name) { (New-Object Security.Principal.NTAccount $name).Translate([Security.Principal.SecurityIdentifier]).Value }
# Adds a member to the local group of that SID, named in the system's language.
function AddToLocalGroup([string]$groupSid, [string]$member) {
    $group = (New-Object Security.Principal.SecurityIdentifier $groupSid).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    $present = @(([ADSI]"WinNT://$env:COMPUTERNAME/$group,group").Invoke('Members')) |
        ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) }
    if ($present -notcontains $member) { NetCommand @('localgroup', $group, $member, '/add') }
}
# Each local group by SID, with the SIDs of its direct members.
function LocalGroupMembers {
    foreach ($g in @(([ADSI]"WinNT://$env:COMPUTERNAME,computer").Children | Where-Object { $_.SchemaClassName -eq 'group' })) {
        $members = @($g.Invoke('Members')) | ForEach-Object {
            (New-Object Security.Principal.SecurityIdentifier ([byte[]]$_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)), 0).Value
        }
        New-Object PSObject -Property @{ Sid = (New-Object Security.Principal.SecurityIdentifier ([byte[]]$g.objectSid.Value), 0).Value; Members = @($members) }
    }
}
# The SID of the test user "wac", whose loaded hive several sections write to.
# Defined here: set inside one section, it was empty when --only skipped it.
$wacSid = (New-Object Security.Principal.NTAccount 'wac').Translate([Security.Principal.SecurityIdentifier]).Value
# The references go back in UTF-8: some name a file with accents.
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# The Windows Search witness (section 39) is written FIRST: the indexer takes
# it while the other witnesses are placed, and section 39 has nothing left to
# wait for — waiting there delayed the collection past what the BAM check
# allows after the harness's taskkill. One witness at a time: those of earlier
# cycles are removed, or each cycle would leave one more document in the
# profile and the index.
# 0. The shadow copies' event witness, written FIRST: the event log service
#    keeps its writes in memory, and an event written 15 s before the copy
#    was not in the copy's file (Windows 11, measured); the copy is made at
#    the end of this script, minutes later. A small log, overwritten after
#    the copy: a cleared log keeps its records in its free space, where WAC
#    finds them (EvtRecovered), and the volume would give the witness already.
$shadowEventToken = $null
try { if (Wants 'shadow_copies') {
    if (-not [Diagnostics.EventLog]::SourceExists('WacShadow')) { New-EventLog -LogName WacShadow -Source WacShadow }
    Limit-EventLog -LogName WacShadow -MaximumSize 64KB -OverflowAction OverwriteAsNeeded
    $shadowEventToken = 'wacshadow' + (Get-Date).ToString('yyyyMMddHHmmss')
    Write-EventLog -LogName WacShadow -Source WacShadow -EventId 1 -Message $shadowEventToken
} } catch { WitnessFailure 'shadow_copies' $_ }

try { if (Wants 'search_index') {
    Get-ChildItem -LiteralPath C:\Users\wac\Documents -Filter 'wac-search-*.txt' -Force | Remove-Item -Force
    $searchStamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $searchName = "wac-search-$searchStamp.txt"
    [IO.File]::WriteAllText("C:\Users\wac\Documents\$searchName", "wacsearchwitness$searchStamp contenu du document temoin")
} } catch { WitnessFailure 'search_index' $_ }

# 1. PowerShell history of the user "wac", under a host name of its own.
try { if (Wants 'powershell_history') {
    $history = 'C:\Users\wac\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
    New-Item -ItemType Directory -Force $history | Out-Null
    $lines = @('whoami /all', 'Get-Process |`', '  Where-Object { $_.CPU -gt 10 }', 'Invoke-WebRequest http://wac-test.invalid/a.ps1')
    [IO.File]::WriteAllText("$history\WacTest_history.txt", ($lines -join "`r`n") + "`r`n", (New-Object Text.UTF8Encoding $false))
    Write-Output "powershell=WacTest|3|whoami /all"
} } catch { WitnessFailure 'powershell_history' $_ }

# 1b. PowerShell profiles: one for every user, one for "wac" — comments only,
#     so that nothing runs when the harness or Windows starts PowerShell.
#     Overwritten each cycle, with the cycle's token.
try { if (Wants 'powershell_profiles') {
    $token = (Get-Date).ToString('yyyyMMddHHmmss')
    $machine = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1"
    $user = 'C:\Users\wac\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
    New-Item -ItemType Directory -Force (Split-Path $user) | Out-Null
    foreach ($file in $machine, $user) {
        [IO.File]::WriteAllText($file, "# WAC witness profile $token`r`n", (New-Object Text.UTF8Encoding $false))
        Write-Output ("psprofile=$file|" + (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash + "|$token")
    }
} } catch { WitnessFailure 'powershell_profiles' $_ }

# 2. A file sent to the recycle bin BY THE USER "wac". Outside an interactive
#    session — SYSTEM, as the harness runs, or a task in batch logon — the
#    "send to the bin" deletes for good, without a word. A scheduled task runs
#    the deletion in the session "wac" has open on the VM's console
#    (autologon), then is removed.
try { if (Wants 'recycle_bin') {
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
} } catch { WitnessFailure 'recycle_bin' $_ }

# 3. An entry of the hosts file, added once.
try { if (Wants 'hosts') {
    $hostsFile = 'C:\Windows\System32\drivers\etc\hosts'
    $entry = '10.11.12.13 wac-test.invalid'
    if (-not (Select-String -Path $hostsFile -SimpleMatch $entry -Quiet)) { Add-Content $hostsFile "`r`n$entry" }
    Write-Output "hosts=10.11.12.13|wac-test.invalid"
} } catch { WitnessFailure 'hosts' $_ }

# 3b. A Prefetch file of a version WAC has no decoder for — none known is
# left undecoded: one nobody has seen yet —, written by hand and always the
# same: an uncompressed SCCA header (version, "SCCA", the executable's name
# at 16, the path hash at 76), zeros after it. Windows does not read it: no
# program of that name is ever run. The witnesses of versions 23 and 17,
# decoded since, are removed where an earlier cycle left them.
try { if (Wants 'prefetch') {
    Remove-Item -LiteralPath 'C:\Windows\Prefetch\WACV23.EXE-0BADF023.pf', 'C:\Windows\Prefetch\WACV17.EXE-0BADF017.pf' -ErrorAction SilentlyContinue
    foreach ($witness in @(,@('pfnew', 32, 'WACV32.EXE', 0x0BADF032))) {
        $bytes = New-Object byte[] 512
        [BitConverter]::GetBytes([int]$witness[1]).CopyTo($bytes, 0)
        [Text.Encoding]::ASCII.GetBytes('SCCA').CopyTo($bytes, 4)
        [BitConverter]::GetBytes([int]$bytes.Length).CopyTo($bytes, 12)
        [Text.Encoding]::Unicode.GetBytes($witness[2]).CopyTo($bytes, 16)
        [BitConverter]::GetBytes([int]$witness[3]).CopyTo($bytes, 76)
        $hash = '{0:X8}' -f $witness[3]
        $file = "C:\Windows\Prefetch\$($witness[2])-$hash.pf"
        [IO.File]::WriteAllBytes($file, $bytes)
        Write-Output "$($witness[0])=$file|$($witness[1])|$($witness[2])|$hash"
    }
} } catch { WitnessFailure 'prefetch' $_ }

# 4. A script in the startup folder of all users.
try { if (Wants 'startup_folders') {
    $startup = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\wac-startup-test.cmd'
    Set-Content $startup '@echo WAC harness startup witness'
    Write-Output ("startup=$startup|" + (Get-FileHash -Algorithm SHA256 $startup).Hash)
} } catch { WitnessFailure 'startup_folders' $_ }

# 5. A file marked as downloaded from the Internet: its Zone.Identifier
#    stream, written and read back by Windows.
try { if (Wants 'zone_identifiers', 'mft') {
    $downloaded = 'C:\Users\wac\Downloads\wac-downloaded.exe'
    New-Item -ItemType Directory -Force 'C:\Users\wac\Downloads' | Out-Null
    Set-Content $downloaded 'MZ WAC harness download witness'
    if ($PSVersionTable.PSVersion.Major -ge 3) {
        Set-Content -Path $downloaded -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://wac-test.invalid/wac-downloaded.exe"
        $hostUrl = (Get-Content -Path $downloaded -Stream Zone.Identifier | Where-Object { $_ -like 'HostUrl=*' }) -replace '^HostUrl=', ''
    }
    else {
        # PowerShell 2 has no -Stream: the stream written and read by cmd, the same three lines.
        & cmd.exe /c "(echo [ZoneTransfer]& echo ZoneId=3& echo HostUrl=https://wac-test.invalid/wac-downloaded.exe)> `"${downloaded}:Zone.Identifier`""
        $hostUrl = (& cmd.exe /c "more < `"${downloaded}:Zone.Identifier`"" | Where-Object { $_ -like 'HostUrl=*' }) -replace '^HostUrl=', ''
    }
    Write-Output "zone=$downloaded|3|$hostUrl"
} } catch { WitnessFailure 'zone_identifiers,mft' $_ }

# 6. A Run value in the DEFAULT hive, REG_EXPAND_SZ: Windows writes the
#    registry to the disk a minute or so later, before the first collection.
try { if (Wants 'run_keys') {
    $runKey = 'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run'
    New-Item -Force $runKey | Out-Null
    New-ItemProperty -Force -Path $runKey -Name 'WacTestDefault' -PropertyType ExpandString -Value '%SystemRoot%\wac-default.exe' | Out-Null
    Write-Output "run_default=WacTestDefault|%SystemRoot%\wac-default.exe"

    # A small script with many hard links (B-045): its names overflow the MFT
    # record, and NTFS moves attributes — its resident $DATA among them, as
    # for winrm.cmd — to an extension record listed by $ATTRIBUTE_LIST. Cited
    # by a Run value, it is collected. Made once.
    $links = 'C:\wactest\b045'
    $script = "$links\wac-links.cmd"
    if (-not (Test-Path $script)) {
        New-Item -ItemType Directory -Force $links | Out-Null
        [IO.File]::WriteAllText($script, "@echo off`r`nrem WAC B-045 witness`r`n")
        foreach ($k in 1..8) {
            $name = "$links\wac-links-" + ('{0:D2}' -f $k) + '-' + ('x' * 110) + '.cmd'
            # mklink rather than New-Item -ItemType HardLink, which came with PowerShell 5.
            & cmd.exe /c "mklink /H `"$name`" `"$script`"" | Out-Null
        }
    }
    New-ItemProperty -Force -Path $runKey -Name 'WacTestLinks' -Value $script | Out-Null
    # "fsutil file layout" exists from Windows 10 on: before, the layout is unknown.
    $layout = (& fsutil.exe file layout $script) -join ' '
    $listed = if ($LASTEXITCODE -ne 0 -or $layout -notmatch 'STANDARD_INFORMATION') { 'unknown' }
              elseif ($layout -match 'ATTRIBUTE_LIST') { 'list' } else { 'nolist' }
    Write-Output ("links=$script|" + (Get-FileHash -Algorithm SHA256 -LiteralPath $script).Hash + "|$listed")
} } catch { WitnessFailure 'run_keys' $_ }

# 6b. A script whose path passes MAX_PATH (B-049): 261 characters on the
#     volume, near 290 once under the exhibit store. The collection reads every
#     executable and takes the unsigned ones; WAC wrote none of those paths
#     (0x8007001d) before it used the extended form. Placed by robocopy, which
#     writes long paths on every Windows: .NET refuses the path, and before
#     4.6.2 (Windows 8.1 and earlier) refuses its \\?\ form too; cmd's mkdir
#     as well. An identical file already there is left as it is: made once.
try { if (Wants 'binaries') {
    $deep = 'C:\wactest\b049\' + ((1..9 | ForEach-Object { 'wac-long-path-segment-' + ('{0:D2}' -f $_) }) -join '\')
    $source = 'C:\wactest\b049-source'
    New-Item -ItemType Directory -Force $source | Out-Null
    [IO.File]::WriteAllText("$source\wac-long-witness.cmd", "@echo off`r`nrem WAC B-049 witness`r`n")
    & robocopy.exe $source $deep wac-long-witness.cmd /R:0 /W:0 /NJH /NJS /NFL /NDL | Out-Null
    $copied = $LASTEXITCODE
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath "$source\wac-long-witness.cmd").Hash
    Remove-Item -LiteralPath $source -Recurse -Force
    if ($copied -ge 8) { throw "long-path witness not placed (robocopy $copied)" }
    Write-Output "longpath=$deep\wac-long-witness.cmd|$hash"
} } catch { WitnessFailure 'binaries' $_ }

# 7. The SECURITY hive as Windows reads it live (the harness runs as SYSTEM).
try { if (Wants 'security') {
    $secrets = (Get-ChildItem 'HKLM:\SECURITY\Policy\Secrets' | ForEach-Object { $_.PSChildName } | Sort-Object) -join ','
    Write-Output "secrets=$secrets"
    # Through reg.exe: the value is of type REG_NONE, which .NET 2 (Windows 7)
    # reads as nothing; reg.exe gives its bytes in hexadecimal on every Windows.
    $audit = & reg.exe query 'HKLM\SECURITY\Policy\PolAdtEv' /ve | Where-Object { $_ -match '\sREG_NONE\s' }
    Write-Output ("audit=" + ($audit -split '\s+')[-1])
    $slots = @((Get-Item 'HKLM:\SECURITY\Cache' -ErrorAction SilentlyContinue).Property | Where-Object { $_ -match '^NL\$\d+$' }).Count
    Write-Output "nl_slots=$slots"
} } catch { WitnessFailure 'security' $_ }

# 8. Persistence witnesses. Harmless: they name programs and DLLs that do not
#    exist, for an executable name nothing runs. Written before the first
#    collection, as the Run value above.
try { if (Wants 'persistence') {
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
    # What Windows set itself, read live, to compare.
    Write-Output ("userinit=" + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Userinit)
    Write-Output ("exefile=" + (Get-ItemProperty 'HKLM:\SOFTWARE\Classes\exefile\shell\open\command').'(default)')
    Write-Output ("lsa_security=" + ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').'Security Packages' -join '|'))
    $monitors = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object { $_.PSChildName + '=' + $_.GetValue('Driver') } | Sort-Object
    Write-Output ("monitors=" + ($monitors -join '|'))
    # Last: in the user's hive, absent when it is not loaded, and its failure
    # must not lose the machine's references above.
    $com = "Registry::HKEY_USERS\$($wacSid)_Classes\CLSID\{0000FACE-0000-4AC0-8000-000000000002}\InprocServer32"
    New-Item -Force $com | Out-Null
    Set-ItemProperty -Path $com -Name '(default)' -Value 'C:\wactest\wac-com.dll'
    Write-Output "comhijack=$wacSid|{0000FACE-0000-4AC0-8000-000000000002}|C:\wactest\wac-com.dll"
} } catch { WitnessFailure 'persistence' $_ }

# 9. Second-lot registry witnesses, in the hive of the user "wac" (loaded: the
#    user is logged on) and in the firewall policy. Harmless.
try { if (Wants 'office_trust_records', 'typed_paths', 'word_wheel_query', 'internet_settings', 'firewall', 'root_certificates') {
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
    $roots = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates' | ForEach-Object { $_.PSChildName } | Sort-Object
    Write-Output ("roots=" + ($roots -join ','))
    $first = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $roots -contains $_.Thumbprint } | Select-Object -First 1
    if ($first) { Write-Output ("rootsubject=" + $first.Thumbprint + '|' + $first.GetNameInfo('SimpleName', $false)) }
} } catch { WitnessFailure 'office_trust_records,typed_paths,word_wheel_query,internet_settings,firewall,root_certificates' $_ }

# 10. The data volume (a second fixed NTFS disk, label WACDATA): a file kept,
#     a file created then deleted — the second $MFT and change journal.
try { if (Wants 'mft', 'usn_journal') {
    # Through WMI, which Vista and 7 have (Get-Volume came with Windows 8).
    $data = Get-WmiObject Win32_Volume | Where-Object { $_.Label -eq 'WACDATA' -and $_.DriveLetter } | Select-Object -First 1
    if ($data) {
        $letter = $data.DriveLetter
        # A data volume has no change journal until a service asks for one: the
        # harness creates it (32 MB, as on C:), idempotent.
        fsutil usn createjournal m=0x2000000 a=0x800000 $letter | Out-Null
        Set-Content "$letter\wac-volume-test.txt" 'WAC harness data volume witness'
        $gone = "$letter\wac-deleted-$(Get-Date -Format HHmmss).txt"
        Set-Content $gone 'deleted by the WAC harness'
        Remove-Item $gone
        # WAC reads the volume raw: a journal record still in Windows' cache is
        # not on the disk yet. A --only cycle collects seconds later, so the
        # cache is written now — what the minutes of a full cycle did by chance.
        if (Get-Command Write-VolumeCache -ErrorAction SilentlyContinue) { Write-VolumeCache -DriveLetter $letter.Substring(0, 1) }
        Write-Output "datavolume=$letter|$letter\wac-volume-test.txt|$gone"
    }
} } catch { WitnessFailure 'mft,usn_journal' $_ }

# 11. A Defender detection and quarantine of known dates: the EICAR test
#     string — harmless by design, made for this — written in a folder
#     excluded for a moment, dated, then scanned once the exclusion is gone.
#     MSFT_MpThreatDetection is the reference; the file's dates and its SHA-1
#     are what the quarantine must give back.
try { if (Wants 'defender') {
    $held = 'C:\wactest\eicar-held'
    New-Item -ItemType Directory -Force $held | Out-Null
    $eicar = "$held\wac-eicar-$(Get-Date -Format HHmmss).txt"
    Add-MpPreference -ExclusionPath $held
    Start-Sleep 3
    [IO.File]::WriteAllText($eicar, 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
    $item = Get-Item $eicar
    $item.CreationTimeUtc = (New-Object datetime 2021, 1, 2, 3, 4, 5, ([DateTimeKind]::Utc))
    $item.LastWriteTimeUtc = (New-Object datetime 2022, 3, 4, 5, 6, 7, ([DateTimeKind]::Utc))
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
} } catch { WitnessFailure 'defender' $_ }

# 12. WMI subscriptions, harmless: the filter waits for hour 99, which never
#     comes, so neither consumer ever runs. Created once and kept — WMI
#     writes its repository to disk minutes later, not at once. One filter
#     more in root\default: subscriptions are not only in root\subscription.
try { if (Wants 'wmi') {
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
    $pending = (New-Object 'System.Collections.Generic.Stack[string]'); $pending.Push('root')
    while ($pending.Count) {
        $ns = $pending.Pop(); $counts.Namespaces++
        foreach ($child in @(Get-CimInstance -Namespace $ns -ClassName __NAMESPACE -ErrorAction SilentlyContinue)) { $pending.Push("$ns\$($child.Name)") }
        $counts.Filter += @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue).Count
        $counts.Consumer += @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue).Count
        $counts.Binding += @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue).Count
        $counts.Timer += @(Get-CimInstance -Namespace $ns -ClassName __TimerInstruction -ErrorAction SilentlyContinue).Count
    }
    Write-Output "wmicount=$($counts.Filter)|$($counts.Consumer)|$($counts.Binding)|$($counts.Timer)|$($counts.Namespaces)"
} } catch { WitnessFailure 'wmi' $_ }

# 13. A BITS job, harmless: never resumed, it never transfers, so its
#     notification command never runs. Its properties are set BEFORE its
#     file: BITS writes a job to qmgr.db when created and when a file is
#     added, not when a property changes. BITS is restarted once, so that the
#     database holds it (a live copy misses what is still in edb.log).
try { if (Wants 'bits') {
    $job = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'WacTestJob' } | Select-Object -First 1
    if (-not $job) {
        & bitsadmin /create WacTestJob | Out-Null
        & bitsadmin /SetNotifyCmdLine WacTestJob 'C:\Windows\System32\cmd.exe' '/c echo wac-bits-test' | Out-Null
        & bitsadmin /SetDescription WacTestJob 'WAC harness witness, never resumed' | Out-Null
        & bitsadmin /addfile WacTestJob https://wac-test.invalid/wac-bits.bin C:\wactest\wac-bits.bin | Out-Null
        Restart-Service BITS -Force -WarningAction SilentlyContinue
        $job = Get-BitsTransfer -AllUsers | Where-Object { $_.DisplayName -eq 'WacTestJob' } | Select-Object -First 1
    }
    # CreationTime is BITS's UTC instant turned local with the offset in force
    # NOW, not the one of its date: undone with that same offset, to the
    # minute. ToUniversalTime used the date's — the job, of the summer, came
    # out an hour early once the clocks went back (2026-10-25).
    $offsetNow = [TimeSpan]::FromMinutes([Math]::Round(([DateTime]::Now - [DateTime]::UtcNow).TotalMinutes))
    Write-Output ("bits=" + (@($job.JobId.ToString('B').ToUpper(), $job.Description, $job.JobState,
        ($job.CreationTime - $offsetNow).ToString('yyyy-MM-ddTHH:mm:ss')) -join '|'))
} } catch { WitnessFailure 'bits' $_ }

# 14. FAT32 and exFAT volumes, on the two virtual USB keys (a suspect's keys):
#     formatted by Windows itself on first use, then filled on every cycle
#     with known content — a long name with accents, a subfolder, a file and a
#     folder deleted —, and listed back by Windows: what fat_volumes.json must
#     give, deleted entries included.
try { if (Wants 'fat_volumes') {
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
        Get-ChildItem -LiteralPath $root -Force | Where-Object { $_.Name -ne 'System Volume Information' } | Remove-Item -Recurse -Force
        # Built by code points: PowerShell 5.1 reads this script as ANSI.
        $long = Join-Path $root "Wac Long Name $([char]0x2013) $([char]0xE9)t$([char]0xE9).txt"
        [IO.File]::WriteAllText($long, 'wac fat witness')
        # A summer date: Windows writes a FAT local time with the offset of the
        # moment, WAC reads it with the offset of its date — the same in summer.
        (Get-Item -LiteralPath $long).LastWriteTimeUtc = (New-Object datetime 2022, 7, 4, 5, 6, 8, ([DateTimeKind]::Utc))
        New-Item -ItemType Directory -Path (Join-Path $root 'DIR1') | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $root 'DIR1\sub file.bin'), [byte[]](1..5000 | ForEach-Object { $_ % 256 }))
        # A program run from the key, as a suspect would: a copy of whoami.exe,
        # run once (harmless). Its Prefetch cites it on the key: with --binary,
        # WAC must fingerprint it there, through the FAT reader.
        if ($key.FileSystem -eq 'FAT32') {
            $tool = Join-Path $root 'wac-tool.exe'
            Copy-Item C:\Windows\System32\whoami.exe $tool
            # whoami.exe's date is kept by the copy: a summer one instead (see above).
            (Get-Item -LiteralPath $tool).LastWriteTimeUtc = (New-Object datetime 2022, 7, 4, 5, 6, 10, ([DateTimeKind]::Utc))
            & $tool | Out-Null
            Write-Output "fattool=$tool|$((Get-FileHash $tool -Algorithm SHA256).Hash)"
        }
        # A winter file copied onto the key now, as an exfiltration would: the
        # copy keeps its modification date, which Windows writes on FAT with the
        # offset of the moment of the copy. Its UTC date must come back exact.
        $winter = 'C:\wactest\wac-winter-source.txt'
        [IO.File]::WriteAllText($winter, 'modified in winter, copied later')
        (Get-Item -LiteralPath $winter).LastWriteTimeUtc = (New-Object datetime 2022, 1, 10, 12, 0, 0, ([DateTimeKind]::Utc))
        Copy-Item -LiteralPath $winter -Destination (Join-Path $root 'copied-winter.txt')
        # Its creation dates the copy, whose offset WAC applies: recreated within
        # 15 s of the key being emptied, the file is given back by tunneling the
        # creation of an earlier cycle — a summer one, an hour off in winter.
        (Get-Item -LiteralPath (Join-Path $root 'copied-winter.txt')).CreationTime = Get-Date
        # The deleted files' witnesses (deleted_files), created before any
        # deletion and deleted after them all — an entry created after a
        # deletion takes its place: a text of 20 KB to delete (level 1, its
        # first cluster and size in its entry, its chain erased) and a PDF to
        # truncate to nothing then delete (level 3, its bytes in the free
        # clusters only).
        $fatWitnesses = @()
        if (Wants 'deleted_files') {
            $lines = New-Object Text.StringBuilder
            foreach ($i in 1..500) { [void]$lines.Append("WAC FAT deleted witness, $($key.FileSystem), line $i`r`n") }
            $text = [Text.Encoding]::ASCII.GetBytes($lines.ToString())
            [IO.File]::WriteAllBytes((Join-Path $root 'deleted-witness.txt'), $text)
            $pdfText = "%PDF-1.4`n1 0 obj`n<< /Type /Catalog >>`nendobj`n% WAC FAT carving witness $($key.FileSystem) $(Get-Date -Format yyyyMMddHHmmss)`n"
            $xref = $pdfText.Length
            $pdfText += "xref`n0 2`n0000000000 65535 f `n0000000009 00000 n `ntrailer`n<< /Size 2 /Root 1 0 R >>`nstartxref`n$xref`n%%EOF`n"
            $pdf = [Text.Encoding]::ASCII.GetBytes($pdfText)
            [IO.File]::WriteAllBytes((Join-Path $root 'carve-witness.pdf'), $pdf)
            $fatWitnesses = @(@('deleted-witness.txt', $text, 'fatdeleted'), @('carve-witness.pdf', $pdf, 'carved'))
        }
        # The deletions last: no entry created after them takes their places.
        [IO.File]::WriteAllText((Join-Path $root 'deleted-file.txt'), 'deleted by the harness')
        Remove-Item -LiteralPath (Join-Path $root 'deleted-file.txt')
        New-Item -ItemType Directory -Path (Join-Path $root 'DELDIR') | Out-Null
        [IO.File]::WriteAllText((Join-Path $root 'DELDIR\inner.txt'), 'inside a deleted folder')
        Remove-Item -LiteralPath (Join-Path $root 'DELDIR') -Recurse
        foreach ($w in $fatWitnesses) {
            $path = Join-Path $root $w[0]
            if ($w[2] -eq 'carved') {
                $stream = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
                $stream.SetLength(0)
                $stream.Close()
            }
            Remove-Item -LiteralPath $path
            $digest = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($w[1]) | ForEach-Object { $_.ToString('X2') })
            if ($w[2] -eq 'carved') { Write-Output "carved=$path|$($w[1].Length)|$digest|PDF" }
            else { Write-Output "fatdeleted=$path|$($w[1].Length)|$digest" }
        }
        Write-Output "fat=$($volume.DriveLetter):|$($key.Label)|$($key.FileSystem)"
        foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object { -not $_.PSIsContainer } | Where-Object { $_.FullName -notlike '*System Volume Information*' }) {
            # The path percent-encoded (UTF-8): PowerShell 4 writes its output in
            # the console's code page, where the long name's accents are lost.
            # Its local time too: on FAT, as stored, while Windows turns it into
            # UTC with the offset of the day it reads it, not of the date.
            Write-Output ("fatfile=" + (@([uri]::EscapeDataString($f.FullName), $f.Length, $f.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss'),
                $f.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:ss')) -join '|'))
        }
    }
} } catch { WitnessFailure 'fat_volumes' $_ }

# 15. A shortcut made now (summer) to a file dated in winter: its target's
#     item keeps the target's dates in local time, computed by Windows with the
#     offset of NOW; the shortcut's header keeps them in UTC. Both must give
#     the same instant.
try { if (Wants 'recent_documents') {
    $target = 'C:\wactest\wac-winter-target.txt'
    [IO.File]::WriteAllText($target, 'a file of winter')
    $item = Get-Item -LiteralPath $target
    $item.CreationTimeUtc = (New-Object datetime 2022, 1, 5, 8, 0, 0, ([DateTimeKind]::Utc))
    $item.LastWriteTimeUtc = (New-Object datetime 2022, 1, 10, 12, 0, 0, ([DateTimeKind]::Utc))
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
} } catch { WitnessFailure 'recent_documents' $_ }

# 16. A folder inside a ZIP, opened by the user's Explorer: the shellbag's
#     archive item copies the ZIP entry's date, a clock time without time
#     zone (13:00 here), which must be given as written. Then a folder of a
#     7z and of a tar.gz. Made once: the shellbags stay.
try { if (Wants 'shellbags') {
    # Whether a value of the user's BagMRU names $text (UTF-16 or ASCII):
    # Explorer recorded the folder.
    $bags = "Registry::HKEY_USERS\$($wacSid)_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
    function BagNamed([string]$text) {
        foreach ($k in @(Get-Item $bags -ErrorAction SilentlyContinue) + @(Get-ChildItem $bags -Recurse -ErrorAction SilentlyContinue)) {
            foreach ($n in $k.GetValueNames()) {
                $v = $k.GetValue($n)
                if ($v -is [byte[]] -and ([Text.Encoding]::Unicode.GetString($v) + [Text.Encoding]::ASCII.GetString($v)).Contains($text)) { return $true }
            }
        }
        return $false
    }
    $zipPath = 'C:\Users\wac\Documents\wac-archive.zip'
    if (-not (Test-Path $zipPath)) {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::Open($zipPath, 'Create')
        $dir = $zip.CreateEntry('winterdir/')
        $dir.LastWriteTime = (New-Object DateTimeOffset 2022, 1, 10, 13, 0, 0, ([TimeSpan]::FromHours(1)))
        $file = $zip.CreateEntry('winterdir/inner.txt')
        $file.LastWriteTime = (New-Object DateTimeOffset 2022, 1, 10, 14, 30, 0, ([TimeSpan]::FromHours(1)))
        $w = New-Object IO.StreamWriter($file.Open()); $w.Write('inside a zip'); $w.Close()
        $zip.Dispose()
    }
    # Navigated again as long as Explorer has not recorded the folder: the
    # witness is announced only once its shellbag exists (on the Windows 8.1
    # VM, a first navigation left none, and the check blamed WAC).
    if (-not (BagNamed 'winterdir')) {
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
        Remove-Item $script
    }
    if (BagNamed 'winterdir') { Write-Output "zipentry=winterdir|2022-01-10T13:00:00" }
    else { Write-Output "witness_failed=shellbags|zip|Explorer recorded no shellbag for the ZIP folder" }

    # Windows 11 reads 7z and tar.gz through libarchive, made by its tar.exe:
    # neither exists before Windows 10, and the rest is not attempted.
    if (Get-Command tar.exe -ErrorAction SilentlyContinue) {

    # The same for the archives Windows 11 reads through libarchive (B-029): a
    # 7z and a tar.gz made by its own tar.exe. Their item is laid out
    # otherwise, and its date is a UTC instant, given as such.
    $sevenPath = 'C:\Users\wac\Documents\wac-seven.7z'
    $tarPath = 'C:\Users\wac\Documents\wac-tarball.tar.gz'
    if (-not (Test-Path $sevenPath)) {
        $source = 'C:\wactest\archive-source'
        New-Item -ItemType Directory "$source\sevendir" -Force | Out-Null
        Set-Content "$source\sevendir\a.txt" 'seven'
        (Get-Item "$source\sevendir").LastWriteTimeUtc = [datetime]::SpecifyKind([datetime]'2023-03-05 08:15:30', 'Utc')
        Push-Location $source
        & tar.exe --format 7zip -cf $sevenPath sevendir
        & tar.exe -czf $tarPath sevendir
        Pop-Location
        Remove-Item -Recurse -Force $source
        $script = 'C:\wactest\archivenav-user.ps1'
        Set-Content $script @'
foreach ($p in 'C:\Users\wac\Documents\wac-seven.7z\sevendir', 'C:\Users\wac\Documents\wac-tarball.tar.gz\sevendir') {
    Start-Process explorer.exe $p
    Start-Sleep 12
}
(New-Object -ComObject Shell.Application).Windows() | Where-Object { "$($_.LocationURL)$($_.LocationName)" -like '*sevendir*' } | ForEach-Object { $_.Quit() }
'@
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
        $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
        Register-ScheduledTask -TaskName WacArchiveNav -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName WacArchiveNav
        Start-Sleep 40
        Unregister-ScheduledTask -TaskName WacArchiveNav -Confirm:$false
        Remove-Item $script
    }
    Write-Output "readerentry=sevendir|2023-03-05T08:15:30"
    }
} } catch { WitnessFailure 'shellbags' $_ }

# 17. Event values as Windows renders them in the event's XML (what the Event
#     Viewer shows): hexadecimal integers, GUIDs, booleans, dates, floats,
#     binary data, and the ProcessingErrorData the service writes when it could
#     not lay out a provider's data — the forms events.json must give. One event
#     of each kind, by its record number.
try { if (Wants 'events') {
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
} } catch { WitnessFailure 'events' $_ }

# 17b. A cleared log: a classic log of its own, three events, then cleared.
#      Windows then sees none, but the chunk keeps them past its free-space
#      offset — events.json must give them flagged as recovered, never as live.
try { if (Wants 'events') {
    if (-not [System.Diagnostics.EventLog]::SourceExists('WACWitness')) { New-EventLog -LogName WACWitness -Source WACWitness }
    1..3 | ForEach-Object { Write-EventLog -LogName WACWitness -Source WACWitness -EventId (4200 + $_) -Message "WAC witness cleared $_" }
    Clear-EventLog -LogName WACWitness
    $live = @(Get-WinEvent -LogName WACWitness -ErrorAction SilentlyContinue).Count
    Write-Output "evtcleared=WACWitness.evtx|$live|4201,4202,4203"
} } catch { WitnessFailure 'events' $_ }

# 18. Reference counts of the logs Windows writes itself.
try { if (Wants 'setupapi', 'defender') {
    $sections = (Select-String -Path 'C:\Windows\INF\setupapi.dev*.log' -Pattern '^>>>  \[' -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Output "setupapi=$sections"
    $mplog = @(Get-ChildItem -Force 'C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log' -ErrorAction SilentlyContinue).Count
    Write-Output "mplog=$mplog"
} } catch { WitnessFailure 'setupapi,defender' $_ }

# 19. B-031 — installed programs: a witness program in the machine's Uninstall
#     key (harmless: values only, nothing installed), and the number of
#     programs Windows lists in each Uninstall key — machine, 32-bit, user.
try { if (Wants 'installed_programs') {
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
} } catch { WitnessFailure 'installed_programs' $_ }

# 20. B-031 — Defender exclusions: a path, an extension and a process
#     excluded from scanning (harmless: test names, nothing placed there),
#     then every exclusion Defender lists, kind by kind.
try { if (Wants 'defender_configuration') {
    Add-MpPreference -ExclusionPath 'C:\wactest\wac-excluded' -ExclusionExtension 'wactestext' -ExclusionProcess 'wac-excluded.exe'
    $p = Get-MpPreference
    foreach ($kind in @(@('Paths', $p.ExclusionPath), @('Extensions', $p.ExclusionExtension), @('Processes', $p.ExclusionProcess), @('IpAddresses', $p.ExclusionIpAddress))) {
        Write-Output ("exclusions=" + $kind[0] + '|' + (@($kind[1] | Where-Object { $_ }) -join '|'))
    }
} } catch { WitnessFailure 'defender_configuration' $_ }

# 39. B-016 — real browsing by "wac", in the session open on the console: a
#     local HTTP server (HttpListener, 127.0.0.1:8765, this script's job)
#     serves a page, a file sent as an attachment and an HTA. Chrome (headless)
#     visits the page and searches Google; Chrome and Firefox (windows) each
#     download the file; Firefox (headless) visits the page; mshta.exe runs the
#     HTA, as an attack would — WinINet caches it. Names are unique to the
#     cycle. Each browser is stopped hard afterwards: its databases keep their
#     journals, as on a machine seized running. Placed BEFORE section 21:
#     the downloads enter Explorer's RecentDocs, whose witness must stay the
#     most recent entry.
try { if (Wants 'web_client') {
    $token = Get-Date -Format 'yyyyMMddHHmmss'
    $server = Start-Job -ScriptBlock {
        $listener = New-Object Net.HttpListener
        $listener.Prefixes.Add('http://127.0.0.1:8765/')
        $listener.Start()
        $deadline = (Get-Date).AddSeconds(240)
        while ((Get-Date) -lt $deadline) {
            $task = $listener.GetContextAsync()
            while (-not $task.Wait(500) -and (Get-Date) -lt $deadline) { }
            if (-not $task.IsCompleted) { break }
            $context = $task.Result
            $path = $context.Request.Url.AbsolutePath
            if ($path -like '*.txt') {
                $context.Response.AddHeader('Content-Disposition', 'attachment; filename="' + [IO.Path]::GetFileName($path) + '"')
                $body = 'WAC download witness'; $context.Response.ContentType = 'text/plain'
            } elseif ($path -like '*.png') {
                # The page's icon (B-048): a 1x1 PNG, for the browsers' favicon databases.
                $png = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==')
                $context.Response.ContentType = 'image/png'
                $context.Response.OutputStream.Write($png, 0, $png.Length)
                $context.Response.Close()
                continue
            } elseif ($path -like '*.hta') {
                $body = '<html><head><title>WAC HTA</title><HTA:APPLICATION/></head><body><script>window.close();</script></body></html>'
                $context.Response.ContentType = 'application/hta'
            } else {
                $body = '<html><head><title>WAC witness page</title><link rel="icon" href="/wac-icon.png"></head><body>WAC</body></html>'; $context.Response.ContentType = 'text/html'
            }
            $bytes = [Text.Encoding]::ASCII.GetBytes($body)
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.Close()
        }
        $listener.Stop()
    }
    Start-Sleep 2
    $base = 'http://127.0.0.1:8765'
    $script = 'C:\wactest\browse-witness.ps1'
    Set-Content $script (@'
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$firefox = 'C:\Program Files\Mozilla Firefox\firefox.exe'
$data = "$env:LOCALAPPDATA\Google\Chrome\User Data"
# A browser closed as a user would, then killed if still there: killed at
# once, it may not have written its history yet — Chrome's download row left
# in a pending transaction (History-journal), a headless Firefox's visit
# never written to places.sqlite (both measured): the file there, the trace
# absent, and WAC reading the disk right.
function Close-Browser([string]$name) {
    Get-Process $name -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | ForEach-Object { $null = $_.CloseMainWindow() }
    Start-Sleep 8
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force
}
if (Test-Path $chrome) {
    & $chrome --headless=new --disable-gpu --no-first-run --user-data-dir="$data" --dump-dom "BASE/page?wac=chrome-TOKEN" | Out-Null
    & $chrome --headless=new --disable-gpu --no-first-run --user-data-dir="$data" --dump-dom "https://www.google.com/search?q=wacsearchTOKEN" | Out-Null
    # In a window, the page first — its tab and its icon go to the session file
    # and to Favicons (B-048) —, then the download.
    Start-Process $chrome -ArgumentList '--no-first-run', "BASE/page?wac=chrome-window-TOKEN", "BASE/c/wac-dl-chrome-TOKEN.txt"; Start-Sleep 12
    Close-Browser chrome
}
if (Test-Path $firefox) {
    Start-Process $firefox -ArgumentList "BASE/page?wac=firefox-TOKEN"; Start-Sleep 12
    Close-Browser firefox
    Start-Process $firefox -ArgumentList "BASE/f/wac-dl-firefox-TOKEN.txt"; Start-Sleep 15
    Close-Browser firefox
}
# mshta.exe stopped only once WinINet has cached the HTA: killed after a fixed
# 8 s, it had sometimes not fetched it yet (three cycles in a row after a
# restart of the VM), and the witness had nothing to find.
Start-Process mshta.exe -ArgumentList "BASE/wac-TOKEN.hta"
$cache = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
foreach ($i in 1..30) {
    if (Get-ChildItem $cache -Recurse -Force -Filter 'wac-TOKEN*.hta' -ErrorAction SilentlyContinue) { break }
    Start-Sleep 1
}
Start-Sleep 2
Get-Process mshta -ErrorAction SilentlyContinue | Stop-Process -Force
# Internet Explorer itself (its COM server; iexplore.exe alone opens Edge): its
# download manager asks "Open / Save", answered by a click on Save — the dialog
# shows no buttons to UI Automation — then IE is closed as a user would, when
# it writes the saved path into the WebCache's iedownload container.
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class WacUi {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern IntPtr PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
}
"@
try {
    $ie = New-Object -ComObject InternetExplorer.Application
    $ie.Visible = $true
    $ie.Navigate("BASE/ie/wac-dl-ie-TOKEN.txt")
    $window = $null
    for ($try = 0; $try -lt 30 -and -not $window; $try++) {
        Start-Sleep -Milliseconds 500
        $window = Get-Process iexplore -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like '*Internet Explorer*' } | Select-Object -First 1
    }
    if ($window) {
        $rect = New-Object WacUi+RECT
        [WacUi]::GetWindowRect($window.MainWindowHandle, [ref]$rect) | Out-Null
        [WacUi]::SetForegroundWindow($window.MainWindowHandle) | Out-Null; Start-Sleep 1
        # "Save", 517 x 139 from the "View downloads" dialog's corner (100 % scaling).
        [WacUi]::SetCursorPos($rect.Left + 517, $rect.Top + 139) | Out-Null; Start-Sleep -Milliseconds 300
        [WacUi]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); [WacUi]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep 8
    }
} catch { }
Get-Process iexplore -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } |
    ForEach-Object { [WacUi]::PostMessage($_.MainWindowHandle, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null }
Start-Sleep 20
Get-Process iexplore -ErrorAction SilentlyContinue | Stop-Process -Force
'done' | Set-Content C:\wactest\browse-witness.done
'@).Replace('BASE', $base).Replace('TOKEN', $token)
    Remove-Item C:\wactest\browse-witness.done -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
    $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
    Register-ScheduledTask -TaskName 'WacBrowseWitness' -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'WacBrowseWitness'
    for ($i = 0; $i -lt 400 -and -not (Test-Path C:\wactest\browse-witness.done); $i++) { Start-Sleep -Milliseconds 500 }
    Unregister-ScheduledTask -TaskName 'WacBrowseWitness' -Confirm:$false
    Stop-Job $server; Remove-Job $server -Force
    Remove-Item $script, C:\wactest\browse-witness.done -ErrorAction SilentlyContinue
    if (Test-Path 'C:\Program Files\Google\Chrome\Application\chrome.exe') {
        Write-Output "webvisit=Chrome|$base/page?wac=chrome-$token"
        Write-Output "webvisit=Chrome|$base/page?wac=chrome-window-$token"
        Write-Output "websearch=Chrome|wacsearch$token"
        Write-Output "webdownload=Chrome|$base/c/wac-dl-chrome-$token.txt|C:\Users\wac\Downloads\wac-dl-chrome-$token.txt"
    }
    if (Test-Path 'C:\Program Files\Mozilla Firefox\firefox.exe') {
        Write-Output "webvisit=Firefox|$base/page?wac=firefox-$token"
        Write-Output "webdownload=Firefox|$base/f/wac-dl-firefox-$token.txt|C:\Users\wac\Downloads\wac-dl-firefox-$token.txt"
    }
    # The HTA's SHA-256, the body the server sent: its cached copy must be the same bytes.
    $hta = [Text.Encoding]::ASCII.GetBytes('<html><head><title>WAC HTA</title><HTA:APPLICATION/></head><body><script>window.close();</script></body></html>')
    $digest = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($hta) | ForEach-Object { $_.ToString('X2') })
    # Given only if Windows itself cached it: mshta.exe sometimes fetches nothing
    # (see above), and a witness Windows never wrote is not one WAC can miss.
    if (Get-ChildItem 'C:\Users\wac\AppData\Local\Microsoft\Windows\INetCache' -Recurse -Force -Filter "wac-$token*.hta" -ErrorAction SilentlyContinue) {
        Write-Output "webhta=$base/wac-$token.hta|$digest"
    } else {
        Write-Output "webhta_unplaced=$base/wac-$token.hta"
    }
    $ieTarget = "C:\Users\wac\Downloads\wac-dl-ie-$token.txt"
    if (Test-Path $ieTarget) { Write-Output "webiedownload=$base/ie/wac-dl-ie-$token.txt|$ieTarget" }
} } catch { WitnessFailure 'web_client' $_ }

# 21. B-031 — Explorer's RecentDocs: a file of a unique extension (.wacrd)
#     added to the user's recent documents by the shell itself
#     (SHAddToRecentDocs), in their interactive session. Harmless: a text file
#     of the test folder, and the shortcut Explorer makes in Recent.
try { if (Wants 'explorer_recent_docs') {
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
} } catch { WitnessFailure 'explorer_recent_docs' $_ }

# 22. B-031 — MountPoints2: a share of the VM (WacShare, read-only for "wac", the test
#     folder) mounted by the user in their session, which Explorer records as
#     ##127.0.0.1#WacShare; then every entry of the user's MountPoints2 as the
#     live registry lists it. Not the entries of CPC\Volume: they are
#     volatile (reg save keeps the key, empty), never in the hive's file.
try { if (Wants 'mount_points') {
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
    $names = @(Get-ChildItem $base -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne 'CPC' } | ForEach-Object { $_.PSChildName })
    Write-Output ("mountpoints=$wacSid|" + ($names -join '|'))
} } catch { WitnessFailure 'mount_points' $_ }

# 23. B-031 — known networks: every NetworkList profile as the live registry
#     lists it (GUID, name, gateway hardware addresses of its signatures),
#     and the last connection to each name in the NetworkProfile log
#     (event 10000, UTC): the reference for DateLastConnected, stored in
#     local time. Nothing is changed.
try { if (Wants 'known_networks') {
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
} } catch { WitnessFailure 'known_networks' $_ }

# 24. B-031 — settings that decide how the other artefacts read, from the live
#     registry (OperatingSystem.json, Settings), and the last shutdown as the
#     System log records it (Kernel-General 13, "the operating system is
#     shutting down", UTC; EventLog 6006 on Vista): the reference for
#     ShutdownTime. Nothing is changed.
try { if (Wants 'operating_system') {
    $cs = 'HKLM:\SYSTEM\CurrentControlSet\Control'
    foreach ($w in @(@("$cs\FileSystem", 'NtfsDisableLastAccessUpdate'), @("$cs\Session Manager\Memory Management\PrefetchParameters", 'EnablePrefetcher'),
                     @("$cs\Terminal Server", 'fDenyTSConnections'), @('HKLM:\SYSTEM\Select', 'Current'),
                     @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI', 'LastLoggedOnSAMUser'))) {
        $v = (Get-ItemProperty $w[0] -ErrorAction SilentlyContinue).($w[1])
        if ($null -ne $v) { Write-Output ("setting=" + $w[1] + '|' + $v) }
    }
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    # Through WMI (PowerShell 2, ps2-compat.ps1) the date is WMI's text.
    if ($boot -is [string]) { $boot = [Management.ManagementDateTimeConverter]::ToDateTime($boot) }
    $down = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=13]]" -MaxEvents 20 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -lt $boot } | Select-Object -First 1
    # Vista has no Kernel-General 13 (it came with Windows 7): its shutdown is
    # the event log service stopping, EventLog 6006.
    if (-not $down) {
        $down = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='EventLog'] and EventID=6006]]" -MaxEvents 20 -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -lt $boot } | Select-Object -First 1
    }
    if ($down) { Write-Output ("shutdown=" + $down.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')) }
} } catch { WitnessFailure 'operating_system' $_ }

# 25. B-031 — startup state: every StartupApproved and RunNotification value of
#     the machine and of the user "wac", as the live registry holds it (the
#     status code's first 4 bytes, or the notification's value). Nothing is
#     changed.
try { if (Wants 'run_keys') {
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
} } catch { WitnessFailure 'run_keys' $_ }

# 26. B-031 — program usage: a compatibility layer set by the user "wac" on a
#     test program (harmless: a value, no program there), then the names each
#     source of program_usage.json holds in the live registry, and the number
#     of the taskbar's pinned items (FavoritesResolve: one size, one shortcut).
try { if (Wants 'program_usage') {
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
} } catch { WitnessFailure 'program_usage' $_ }

# 27. B-031 — devices: every USB and SCSI device Windows knows, present or not,
#     with its first install, last arrival and last removal dates as
#     Get-PnpDeviceProperty gives them (UTC). Nothing is changed.
try { if (Wants 'devices') {
    if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) { throw 'Get-PnpDevice absent (Windows 10 and later)' }
    Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'USB\*' -or $_.InstanceId -like 'SCSI\*' } | ForEach-Object {
        $id = $_.InstanceId
        $dates = foreach ($key in 'DEVPKEY_Device_FirstInstallDate', 'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_LastRemovalDate') {
            $p = Get-PnpDeviceProperty -InstanceId $id -KeyName $key -ErrorAction SilentlyContinue
            if ($p.Data) { $p.Data.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') } else { '' }
        }
        Write-Output ("device=" + $id + '|' + ($dates -join '|'))
    }
} } catch { WitnessFailure 'devices' $_ }

# 28. B-031 — network shares: the WacShare of section 22 (read-only for "wac",
#     the test folder), then every non-administrative share Windows lists.
try { if (Wants 'network_shares') {
    if (-not (Get-SmbShare -Name WacShare -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name WacShare -Path 'C:\wactest' -ReadAccess 'wac' | Out-Null
    }
    Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { Write-Output ("share=" + $_.Name + '|' + $_.Path) }
    # Who may use the witness, as Windows reads its security descriptor.
    Get-SmbShareAccess -Name WacShare | ForEach-Object {
        $sid = (New-Object Security.Principal.NTAccount $_.AccountName).Translate([Security.Principal.SecurityIdentifier]).Value
        Write-Output ("shareaccess=WacShare|$sid|" + $_.AccessControlType)
    }
} } catch { WitnessFailure 'network_shares' $_ }

# 29. B-031 — network configuration: each present adapter as Windows lists it
#     live (GUID, description, MAC, IPv4 address and how it was obtained).
#     Nothing is changed.
try { if (Wants 'network_configuration') {
    Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $ip = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        Write-Output ("adapter=" + $_.InterfaceGuid + '|' + $_.InterfaceDescription + '|' + $_.MacAddress + '|' + $ip.IPAddress + '|' + $ip.PrefixOrigin)
    }
} } catch { WitnessFailure 'network_configuration' $_ }

# 30. B-031 — event log configuration: each log as Windows lists it live, with
#     its state (enabled or not), and each boot ETW session with its Start.
#     Nothing is changed.
try { if (Wants 'event_log_configuration') {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output ("eventlog=" + $_.LogName + '|' + $_.IsEnabled)
    }
    if (-not (Get-Command Get-AutologgerConfig -ErrorAction SilentlyContinue)) { throw 'Get-AutologgerConfig absent (Windows 10 and later)' }
    Get-AutologgerConfig -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output ("autologger=" + $_.Name + '|' + $_.Start)
    }
} } catch { WitnessFailure 'event_log_configuration' $_ }

# 31. B-034 — SAM hashes: two witness accounts, one with a known password, one
#     with an empty one. WAC must decrypt their NT hashes; the check confronts
#     each with MD4 of the password (the empty one gives the known constant).
#     The password is synthetic, for a throwaway VM account — not a real secret.
try { if (Wants 'users') {
    # A witness account with a known password: WAC must decrypt its NT hash to
    # MD4 of that password (checked in check-json.py), which exercises the whole
    # boot key / AES / DES chain against an independent computation. The password
    # is synthetic, for a throwaway VM account — not a real secret. Wrapped so a
    # failure here cannot break the rest of the witness script.
    # The account is given a first password then a second, so the SAM holds a
    # hash history: WAC must decrypt the current hash (MD4 of the second) and the
    # history (MD4 of the first among it).
    # A standalone machine keeps no password history by default (policy 0), so
    # the SAM would store no previous hash: the policy is raised first, then the
    # password changed through `net user`, which honours it.
    try {
        $pwOld = 'Wac-Old-2026!'; $pwNew = 'Wac-Test-2026!'
        net accounts /uniquepw:5 | Out-Null
        RemoveLocalUser 'wacpw'
        SetLocalUser 'wacpw' $pwOld
        NetCommand @('user', 'wacpw', $pwNew)
        Write-Output ("samhash=wacpw|" + $pwNew + '|' + $pwOld)
    } catch { Write-Output ("samhasherror=" + $_.Exception.Message) }

    # Security questions (ResetData): not scriptable through a cmdlet, so written
    # straight into wacpw's SAM key (SYSTEM can) as the system stores them, a
    # REG_BINARY of the JSON in UTF-16LE, for WAC to read back.
    try {
        $rid = [int]((AccountSid 'wacpw').Split('-')[-1])
        $ridHex = '{0:X8}' -f $rid
        $qjson = '{"version":1,"questions":[{"question":"First pet name?","answer":"rex"},{"question":"Birth city?","answer":"paris"}]}'
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($qjson)
        $hex = ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ''
        reg add "HKLM\SAM\SAM\Domains\Account\Users\$ridHex" /v ResetData /t REG_BINARY /d $hex /f | Out-Null
        Write-Output ("resetdata=" + $qjson)
    } catch { Write-Output ("resetdataerror=" + $_.Exception.Message) }

    # Local groups: wacpw added to Administrators (S-1-5-32-544), so a group has a
    # non-trivial membership; each group's direct members (by SID) are recorded,
    # for WAC's local_groups.json to be confronted with Windows' own list.
    try { AddToLocalGroup 'S-1-5-32-544' 'wacpw' } catch {}
    foreach ($g in LocalGroupMembers) { Write-Output ("localgroup=" + $g.Sid + '|' + ($g.Members -join ',')) }

    # Account rights: Windows' own export of the user-rights assignment, to
    # confront with security.json (Policy\Accounts). Each line maps a privilege
    # or logon right to the SIDs that hold it.
    try {
        $inf = 'C:\wactest\secedit-rights.inf'
        secedit /export /areas USER_RIGHTS /cfg $inf /quiet 2>$null | Out-Null
        foreach ($line in Get-Content $inf -Encoding Unicode) {
            if ($line -match '^\s*(Se\w+)\s*=\s*(.+)$') {
                # secedit writes a holder either as *<SID> or as an account name:
                # every name is resolved to its SID so the check compares SIDs.
                $sids = foreach ($a in ($matches[2] -split ',')) {
                    $a = $a.Trim()
                    if ($a.StartsWith('*')) { $a.Substring(1) }
                    else { try { (New-Object System.Security.Principal.NTAccount($a)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $a } }
                }
                Write-Output ("userright=" + $matches[1] + '|' + ($sids -join ','))
            }
        }
    } catch { Write-Output ("userrighterror=" + $_.Exception.Message) }
} } catch { WitnessFailure 'users' $_ }

# 31b. B-032 — a desktop redirected, as OneDrive does: the Desktop of "wac"
#     moved to C:\Users\wac\OneDrive\Desktop (once; it stays), a shortcut
#     dropped there. Then every User Shell Folders value of the loaded hive of
#     "wac", unexpanded, for user_shell_folders.json.
try { if (Wants 'shortcuts', 'user_shell_folders') {
    $shellFolders = "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    New-Item -ItemType Directory -Force 'C:\Users\wac\OneDrive\Desktop' | Out-Null
    Set-ItemProperty -Path $shellFolders -Name Desktop -Value '%USERPROFILE%\OneDrive\Desktop' -Type ExpandString
    # WAC copies the hive raw seconds later: the change is written to it now
    # (RegFlushKey), not left in memory for Windows' lazy flush.
    $writable = [Microsoft.Win32.Registry]::Users.OpenSubKey("$wacSid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", $true)
    $writable.Flush()
    $writable.Close()
    $link = (New-Object -ComObject WScript.Shell).CreateShortcut('C:\Users\wac\OneDrive\Desktop\wac-redirected-test.lnk')
    $link.TargetPath = 'C:\Windows\System32\calc.exe'
    $link.Save()
    Write-Output 'shortcut=C:\Users\wac\OneDrive\Desktop\wac-redirected-test.lnk|C:\Windows\System32\calc.exe||Desktop'
    $key = [Microsoft.Win32.Registry]::Users.OpenSubKey("$wacSid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
    foreach ($name in $key.GetValueNames()) {
        Write-Output ("usf=" + $wacSid + '|' + $name + '|' + $key.GetValue($name, $null, 'DoNotExpandEnvironmentNames'))
    }
    $key.Close()
} } catch { WitnessFailure 'shortcuts,user_shell_folders' $_ }

# 32. B-032 — shortcuts outside Recent: one on the public desktop with a known
#     target and arguments, one pinned to the task bar of "wac". Then every
#     .lnk and .url Windows lists in the folders shortcuts.json covers — Start
#     menu (Startup aside, it belongs to startup_folders.json), desktops, Quick
#     Launch — for the machine and each profile of ProfileList: shortcuts.json
#     must hold the same files, no more, no less.
try { if (Wants 'shortcuts') {
    $wsh = New-Object -ComObject WScript.Shell
    $witnesses = @(
        @('C:\Users\Public\Desktop\wac-shortcut-test.lnk', 'C:\Windows\System32\cmd.exe', '/c echo wac-shortcut-witness', 'Desktop'),
        @('C:\Users\wac\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\wac-pinned-test.lnk', 'C:\Windows\System32\notepad.exe', '', 'TaskBar'))
    foreach ($w in $witnesses) {
        New-Item -ItemType Directory -Force (Split-Path $w[0]) | Out-Null
        $link = $wsh.CreateShortcut($w[0])
        $link.TargetPath = $w[1]
        $link.Arguments = $w[2]
        $link.Save()
        Write-Output ("shortcut=" + ($w -join '|'))
    }
    $folders = @(@('C:\ProgramData\Microsoft\Windows\Start Menu', $true), @('C:\Users\Public\Desktop', $false))
    # Every profile of ProfileList, and the Default profile, a value of the key itself.
    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $paths = @((Get-ChildItem $profileList | ForEach-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath }) + (Get-ItemProperty $profileList).Default)
    $paths | ForEach-Object {
        $profile = [Environment]::ExpandEnvironmentVariables($_)
        $folders += ,@("$profile\AppData\Roaming\Microsoft\Windows\Start Menu", $true)
        $folders += ,@("$profile\Desktop", $false)
        $folders += ,@("$profile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch", $true)
    }
    # A desktop moved elsewhere, as each loaded hive says (Explorer's own view).
    # The value is read unexpanded: expanded here, %USERPROFILE% would be SYSTEM's.
    foreach ($hku in Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }) {
        $usf = [Microsoft.Win32.Registry]::Users.OpenSubKey("$($hku.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        $profileHome = (Get-ItemProperty "$profileList\$($hku.PSChildName)" -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $usf -or -not $profileHome) { continue }
        $desktop = [string]$usf.GetValue('Desktop', $null, 'DoNotExpandEnvironmentNames') -replace '^%USERPROFILE%', $profileHome
        $usf.Close()
        if ($desktop -and $desktop -ne "$profileHome\Desktop") { $folders += ,@($desktop, $false) }
    }
    foreach ($f in $folders) {
        if (-not (Test-Path -LiteralPath $f[0])) { continue }
        $found = if ($f[1]) { FilesToDepth $f[0] 6 }
                 else { Get-ChildItem -LiteralPath $f[0] -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } }
        $found | Where-Object { @('.lnk', '.url') -contains $_.Extension -and $_.FullName -notmatch '\\Start Menu\\Programs\\Startup\\' } |
            ForEach-Object { Write-Output ("shortcutfile=" + $_.FullName) }
    }
} } catch { WitnessFailure 'shortcuts' $_ }

# 33. B-032 — the Default profile, template of every new profile: a Run value
#     planted in its NTUSER.DAT (loaded, written, unloaded), which run.json must
#     give under the SID S-0-0-0 with Profile "Default". Harmless: it names an
#     executable that does not exist.
try { if (Wants 'run_keys') {
    $hive = 'C:\Users\Default\NTUSER.DAT'
    reg load 'HKU\WacDefault' $hive 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        reg add 'HKU\WacDefault\Software\Microsoft\Windows\CurrentVersion\Run' /v WacDefaultWitness /t REG_SZ /d 'C:\wactest\wac-default-witness.exe' /f | Out-Null
        [GC]::Collect()
        reg unload 'HKU\WacDefault' 2>$null | Out-Null
        Write-Output 'rundefault=WacDefaultWitness|C:\wactest\wac-default-witness.exe'
    } else { Write-Output 'rundefaulterror=reg load failed' }
} } catch { WitnessFailure 'run_keys' $_ }

# 34. B-032 — NTFS security descriptors: a witness file whose owner is set to
#     "wac" and whose DACL grants Everyone read, then the owner Windows gives
#     for a few dozen files (Get-Acl). mft.json's SecurityId must lead, through
#     security_descriptors.json, to the same owner.
try { if (Wants 'security_descriptors') {
    $witness = 'C:\wactest\wac-sds-witness.txt'
    Set-Content $witness 'WAC security descriptor witness'
    icacls $witness /setowner wac | Out-Null
    icacls $witness /grant '*S-1-1-0:(R)' | Out-Null
    Write-Output ("sdswitness=" + $witness + '|' + $wacSid)
    $files = @(Get-ChildItem 'C:\Windows\System32\drivers\etc', 'C:\Users\wac\Documents', 'C:\wactest' -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Select-Object -First 40)
    foreach ($f in $files) {
        try { Write-Output ("sdsowner=" + $f.FullName + '|' + (Get-Acl -LiteralPath $f.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value) } catch {}
    }
} } catch { WitnessFailure 'security_descriptors' $_ }

# 35. B-032 — NTFS volumes: what Windows itself says of each fixed NTFS volume
#     (FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_QUERY_USN_JOURNAL — what fsutil shows,
#     without its localised text): serial, sector, cluster and record sizes,
#     $MFT and $MFTMirr clusters, and the journal's identifier, size, delta and
#     lowest valid USN. ntfs_volumes.json reads them raw in $Boot and $Max.
try { if (Wants 'ntfs_volumes') {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WacNtfs {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, uint inSize, byte[] outBuf, uint outSize, out uint returned, IntPtr ov);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    public static byte[] Query(string letter, uint code) {
        IntPtr h = CreateFile(@"\\.\" + letter, 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);   // GENERIC_READ: the two queries need it
        if (h == new IntPtr(-1)) return null;
        byte[] buffer = new byte[256];
        uint returned;
        bool ok = DeviceIoControl(h, code, IntPtr.Zero, 0, buffer, (uint)buffer.Length, out returned, IntPtr.Zero);
        CloseHandle(h);
        return ok ? buffer : null;
    }
}
'@
    foreach ($v in Get-Volume | Where-Object { $_.FileSystem -eq 'NTFS' -and $_.DriveType -eq 'Fixed' -and $_.DriveLetter }) {
        $letter = "$($v.DriveLetter):"
        $d = [WacNtfs]::Query($letter, 0x00090064)
        if ($d) {
            Write-Output ("ntfsvolume=" + $letter + '|' + ('{0:X16}' -f [BitConverter]::ToUInt64($d, 0)) + '|' +
                [BitConverter]::ToUInt32($d, 40) + '|' + [BitConverter]::ToUInt32($d, 44) + '|' + [BitConverter]::ToUInt32($d, 48) + '|' +
                [BitConverter]::ToUInt64($d, 64) + '|' + [BitConverter]::ToUInt64($d, 72))
        }
        $j = [WacNtfs]::Query($letter, 0x000900F4)
        if ($j) {
            Write-Output ("usnjournal=" + $letter + '|' + ('{0:X16}' -f [BitConverter]::ToUInt64($j, 0)) + '|' +
                [BitConverter]::ToUInt64($j, 40) + '|' + [BitConverter]::ToUInt64($j, 48) + '|' + [BitConverter]::ToUInt64($j, 24))
        }
    }
} } catch { WitnessFailure 'ntfs_volumes' $_ }

# 36. B-032 — Defender's WPP traces (Support\*.bin), copied raw only: the
#     names Windows lists, each to be found in the exhibit manifest. Their
#     content changes as Defender writes, so only their presence is compared.
try { if (Wants 'defender') {
    Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Support' -Filter *.bin -Force -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Output ("defenderwpp=" + $_.FullName) }
} } catch { WitnessFailure 'defender' $_ }

# 37. B-032 — DPAPI master keys: every key file Windows lists in the Protect
#     folder of the system and of each profile, and what each Preferred file
#     names (read here by Windows, raw by WAC). Nothing is decrypted.
try { if (Wants 'dpapi_master_keys') {
    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $folders = @('C:\Windows\System32\Microsoft\Protect') + @(Get-ChildItem $profileList | ForEach-Object {
        [Environment]::ExpandEnvironmentVariables((Get-ItemProperty $_.PSPath).ProfileImagePath) + '\AppData\Roaming\Microsoft\Protect' })
    foreach ($protect in $folders) {
        if (-not (Test-Path -LiteralPath $protect)) { continue }
        foreach ($sidFolder in Get-ChildItem -LiteralPath $protect -Force -Filter 'S-1-*' -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }) {
            foreach ($folder in @($sidFolder.FullName, (Join-Path $sidFolder.FullName 'User'))) {
                if (-not (Test-Path -LiteralPath $folder)) { continue }
                Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } |
                    Where-Object { $_.Name -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' } |
                    ForEach-Object { Write-Output ("dpapikey=" + $_.FullName) }
                $preferred = Join-Path $folder 'Preferred'
                if (Test-Path -LiteralPath $preferred) {
                    $b = [IO.File]::ReadAllBytes($preferred)
                    if ($b.Length -eq 24) {
                        $guid = New-Object Guid (,[byte[]]$b[0..15])
                        Write-Output ("dpapipreferred=" + $folder + '|' + $guid + '|' + [BitConverter]::ToInt64($b, 16))
                    }
                }
            }
        }
    }
    # When the list was read: a key Windows creates later (a service account's
    # first one, during the cycle) is the collection's, not a key WAC made up.
    Write-Output ("dpapilisted=" + [DateTime]::UtcNow.ToString('o'))
} } catch { WitnessFailure 'dpapi_master_keys' $_ }

# 38. B-016 — TypedURLs: two addresses typed by "wac", with their instants in
#     TypedURLsTime (FILETIME, known values), written to the hive at once.
try { if (Wants 'web_client') {
    $typed = "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Internet Explorer\TypedURLs"
    $times = "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Internet Explorer\TypedURLsTime"
    New-Item -Force $typed | Out-Null
    New-Item -Force $times | Out-Null
    $witnesses = @(@('url1', 'http://wac-typed.invalid/recent', (New-Object datetime 2026, 3, 4, 5, 6, 7, ([DateTimeKind]::Utc))),
                   @('url2', 'http://wac-typed.invalid/older', (New-Object datetime 2025, 11, 12, 13, 14, 15, ([DateTimeKind]::Utc))))
    foreach ($w in $witnesses) {
        Set-ItemProperty -Path $typed -Name $w[0] -Value $w[1]
        Set-ItemProperty -Path $times -Name $w[0] -Value ([BitConverter]::GetBytes($w[2].ToFileTimeUtc())) -Type Binary
        Write-Output ("typedurl=" + $w[0] + '|' + $w[1] + '|' + $w[2].ToString('yyyy-MM-ddTHH:mm:ss'))
    }
    foreach ($k in @('TypedURLs', 'TypedURLsTime')) {
        $writable = [Microsoft.Win32.Registry]::Users.OpenSubKey("$wacSid\Software\Microsoft\Internet Explorer\$k", $true)
        $writable.Flush()
        $writable.Close()
    }
} } catch { WitnessFailure 'web_client' $_ }

# 39. B-010 — Windows Search index: the document written at the start (unique
#     name and text, in the Documents of "wac", an indexed place), waited for
#     in case the indexer has not taken it yet; then what Windows' own query
#     (OLE DB, Search.CollatorDSO) returns of every item — URL, modification
#     (UTC, to the second), size — and the instant of that query: an item
#     indexed again after it is no longer comparable.
try { if (Wants 'search_index') {
    $name = $searchName
    $query = { param($sql)
        $connection = New-Object -ComObject ADODB.Connection
        $connection.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
        $rows = $connection.Execute($sql)
        $result = @()
        while (-not $rows.EOF) {
            $result += ,@(0..($rows.Fields.Count - 1) | ForEach-Object { $rows.Fields.Item($_).Value })
            $rows.MoveNext()
        }
        $connection.Close()
        return ,$result
    }
    $found = $null
    for ($i = 0; $i -lt 60 -and -not $found; $i++) {
        Start-Sleep 3
        $rows = & $query "SELECT System.ItemUrl, System.Size, System.Search.AutoSummary FROM SystemIndex WHERE System.FileName = '$name'"
        if ($rows.Count -gt 0 -and $rows[0][2]) { $found = $rows[0] }
    }
    if ($found) { Write-Output ("searchwitness=" + $found[0] + '|' + $found[1] + '|' + $found[2]) }
    # Windows 7's and 8's indexer keeps what it just indexed in memory for minutes:
    # its database on disk, which WAC reads, did not hold the witness yet.
    # Stopping the service writes it there; the query waits for it to answer
    # again. TEST VM ONLY: WAC itself never restarts a service on the
    # examined machine — there, the index read is the one on disk, minutes
    # behind on Windows 7 and 8, and the documentation says so.
    if ($found -and $PSVersionTable.PSVersion.Major -lt 4) {
        Restart-Service WSearch
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep 3
            try { if ((& $query "SELECT System.ItemUrl FROM SystemIndex WHERE System.FileName = '$name'").Count -gt 0) { break } } catch {}
        }
    }
    Write-Output ("searchquery=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss'))
    foreach ($row in (& $query "SELECT System.ItemUrl, System.DateModified, System.Size FROM SystemIndex")) {
        $modified = if ($row[1] -is [datetime]) { $row[1].ToString('yyyy-MM-ddTHH:mm:ss') } else { '' }
        Write-Output ("searchitem=" + $row[0] + '|' + $modified + '|' + $row[2])
    }
} } catch { WitnessFailure 'search_index' $_ }

# 40. B-011 — Remote Desktop, outgoing and incoming at once: "wac" opens a real
#     session to this very machine (127.0.0.2) with a test account, then
#     closes its client as a user would — mstsc writes its bitmap cache only
#     then (Cache0000.bin), and the MRU of its recent connections. The machine
#     logs the incoming side (authentication, session, Security logons). A
#     server of known values is added to "wac"'s Servers key (a real logon
#     writes its own only once the session is open). Everything the witness
#     needs is undone afterwards: credential, RDP, firewall rule, account.
#     `mstsc /v:` and not a .rdp file: Windows now asks before opening one.
try { if (Wants 'rdp_client', 'rdp_server') {
    # One cache at a time: those of earlier cycles are removed, or each cycle
    # would add a Cache<NNNN>.bin to the profile.
    Remove-Item 'C:\Users\wac\AppData\Local\Microsoft\Terminal Server Client\Cache\*' -Force -ErrorAction SilentlyContinue
    $rdpSince = (Get-Date).ToUniversalTime()
    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $denied = (Get-ItemProperty $tsKey).fDenyTSConnections
    # Everything opened for the session is closed in the finally block, even
    # when a step fails: a failure once left RDP allowed on the VM.
    try {
    Set-ItemProperty $tsKey -Name fDenyTSConnections -Value 0
    Enable-NetFirewallRule -DisplayGroup '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue
    $rdpPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ }) + '!a1'
    SetLocalUser 'wacrdp' $rdpPassword
    AddToLocalGroup 'S-1-5-32-555' 'wacrdp'
    $rdpTask = @'
cmdkey /generic:TERMSRV/127.0.0.2 /user:wacrdp /pass:PASSWORD | Out-Null
$client = 'HKCU:\Software\Microsoft\Terminal Server Client'
New-Item -Force $client | Out-Null
Set-ItemProperty $client -Name AuthenticationLevelOverride -Value 0 -Type DWord
Start-Process mstsc.exe -ArgumentList '/v:127.0.0.2'
Start-Sleep 25
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class WacRdpUi { [DllImport("user32.dll")] public static extern IntPtr PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l); }'
Get-Process mstsc -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } |
    ForEach-Object { [WacRdpUi]::PostMessage($_.MainWindowHandle, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null }
Start-Sleep 10
Get-Process mstsc -ErrorAction SilentlyContinue | Stop-Process -Force
cmdkey /delete:TERMSRV/127.0.0.2 | Out-Null
Remove-ItemProperty $client -Name AuthenticationLevelOverride -ErrorAction SilentlyContinue
'done' | Set-Content C:\wactest\rdp-witness.done
'@
    [IO.File]::WriteAllText('C:\wactest\rdp-witness.ps1', $rdpTask.Replace('PASSWORD', $rdpPassword))
    Remove-Item C:\wactest\rdp-witness.done -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\wactest\rdp-witness.ps1'
    $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
    Register-ScheduledTask -TaskName 'WacRdpWitness' -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'WacRdpWitness'
    for ($i = 0; $i -lt 120 -and -not (Test-Path C:\wactest\rdp-witness.done); $i++) { Start-Sleep 1 }
    } finally {
        Unregister-ScheduledTask -TaskName 'WacRdpWitness' -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item C:\wactest\rdp-witness.ps1, C:\wactest\rdp-witness.done -ErrorAction SilentlyContinue
        Set-ItemProperty $tsKey -Name fDenyTSConnections -Value $denied
        if ($denied) { Disable-NetFirewallRule -DisplayGroup '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue }
        RemoveLocalUser 'wacrdp'
    }

    # A server of known values in "wac"'s hive, flushed to the disk.
    $servers = "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Terminal Server Client\Servers\wac-rdp-witness.invalid"
    New-Item -Force $servers | Out-Null
    Set-ItemProperty $servers -Name UsernameHint -Value 'WACTEST\witness'
    Set-ItemProperty $servers -Name CertHash -Value ([byte[]](0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02)) -Type Binary
    $writable = [Microsoft.Win32.Registry]::Users.OpenSubKey("$wacSid\Software\Microsoft\Terminal Server Client\Servers\wac-rdp-witness.invalid", $true)
    $writable.Flush(); $writable.Close()
    Write-Output 'rdpserver=wac-rdp-witness.invalid|WACTEST\witness|DEADBEEF0102'
    $mru = (Get-ItemProperty "Registry::HKEY_USERS\$wacSid\Software\Microsoft\Terminal Server Client\Default" -ErrorAction SilentlyContinue).MRU0
    if ($mru) { Write-Output "rdpmru=$mru" }
    $cache = Get-ChildItem 'C:\Users\wac\AppData\Local\Microsoft\Terminal Server Client\Cache' -Filter 'Cache*.bin' -ErrorAction SilentlyContinue
    foreach ($c in $cache) { Write-Output ("rdpcache=" + $c.FullName + '|' + $c.Length) }

    # The incoming side, as Windows lists it: record, user, source.
    $logs = @{ 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 1149
               'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' = 131 }
    foreach ($log in $logs.Keys) {
        foreach ($e in (Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $logs[$log]; StartTime = $rdpSince.ToLocalTime() } -ErrorAction SilentlyContinue)) {
            $d = @{}; foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
            $who = if ($d['Param1']) { $d['Param1'] } else { '' }
            $from = if ($d['Param3']) { $d['Param3'] } else { $d['ClientIP'] }
            Write-Output ("rdpin=$log|" + $e.RecordId + "|$who|$from")
        }
    }
    foreach ($e in (Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $rdpSince.ToLocalTime() } -ErrorAction SilentlyContinue)) {
        $d = @{}; foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
        if ($d['LogonType'] -eq '10' -and $d['TargetUserName'] -eq 'wacrdp') { Write-Output ("rdpin=Security|" + $e.RecordId + "|wacrdp|" + $d['IpAddress']) }
    }
} } catch { WitnessFailure 'rdp_client,rdp_server' $_ }

# 41. B-026 — a picture seen in Explorer: "wac" opens its Pictures, where a PNG
#     witness lies (made once, never piled up), and Windows gives the
#     picture's System.ThumbnailCacheId — the hash of its entry in
#     thumbcache_<size>.db. The task, its script and its answer are removed.
try { if (Wants 'thumbcache') {
    $picture = 'C:\Users\wac\Pictures\wac-thumbcache-witness.png'
    if (-not (Test-Path $picture)) {
        Add-Type -AssemblyName System.Drawing
        $bitmap = New-Object System.Drawing.Bitmap 320, 200
        $g = [System.Drawing.Graphics]::FromImage($bitmap)
        $g.Clear([System.Drawing.Color]::FromArgb(30, 90, 160))
        $g.FillEllipse([System.Drawing.Brushes]::Orange, 60, 30, 200, 140)
        $g.DrawString('WAC', (New-Object System.Drawing.Font 'Arial', 32), [System.Drawing.Brushes]::White, 105, 75)
        $g.Dispose()
        $bitmap.Save($picture, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
    }
    $answer = 'C:\wactest\thumbcache-id.txt'
    $script = 'C:\wactest\thumbcache-user.ps1'
    Remove-Item $answer -ErrorAction SilentlyContinue
    Set-Content $script @'
$folder = 'C:\Users\wac\Pictures'
Start-Process explorer.exe $folder
Start-Sleep 12
$item = (New-Object -ComObject Shell.Application).Namespace($folder).ParseName('wac-thumbcache-witness.png')
$id = $item.ExtendedProperty('System.ThumbnailCacheId')
if ($id) { Set-Content 'C:\wactest\thumbcache-id.txt' ('{0:x16}' -f [uint64]$id) }
(New-Object -ComObject Shell.Application).Windows() | Where-Object { "$($_.LocationURL)" -like '*Pictures*' } | ForEach-Object { $_.Quit() }
'@
    $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
    $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
    Register-ScheduledTask -TaskName WacThumbcache -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName WacThumbcache
    Start-Sleep 25
    Unregister-ScheduledTask -TaskName WacThumbcache -Confirm:$false
    if (Test-Path $answer) { Write-Output ("thumbcache=" + (Get-Content $answer).Trim() + "|" + $picture) }
    Remove-Item $answer, $script -ErrorAction SilentlyContinue
} } catch { WitnessFailure 'thumbcache' $_ }

# 42. B-017 — a message written by Thunderbird itself: a witness profile of
#     "wac" with a POP3 account on 127.0.0.1:1110 (no first-run dialog), a POP3
#     server here serving one message — a subject in an
#     RFC 2047 encoded word, an accented quoted-printable body, an attachment
#     in base64 whose name is RFC 2231 —, Thunderbird run by "wac" on that
#     profile, fetching it into its Inbox, then closed as a user would. The
#     Inbox is emptied first: the witness is never piled up.
try { if (Wants 'emails') {
    $thunderbird = 'C:\Program Files\Mozilla Thunderbird\thunderbird.exe'
    if (Test-Path $thunderbird) {
        $token = Get-Date -Format 'yyyyMMddHHmmss'
        $profileDir = 'C:\Users\wac\AppData\Roaming\Thunderbird\Profiles\wacwitness.default'
        $inbox = Join-Path $profileDir 'Mail\127.0.0.1\Inbox'
        New-Item -ItemType Directory -Force (Split-Path $inbox) | Out-Null
        Remove-Item "$inbox", "$inbox.msf" -Force -ErrorAction SilentlyContinue
        Set-Content -Encoding ASCII (Join-Path $profileDir 'user.js') @'
user_pref("mail.accountmanager.accounts", "account1,account2");
user_pref("mail.accountmanager.defaultaccount", "account1");
user_pref("mail.accountmanager.localfoldersserver", "server2");
user_pref("mail.account.account1.identities", "id1");
user_pref("mail.account.account1.server", "server1");
user_pref("mail.account.account2.server", "server2");
user_pref("mail.identity.id1.useremail", "wac@wac-test.invalid");
user_pref("mail.identity.id1.fullName", "WAC");
user_pref("mail.server.server1.type", "pop3");
user_pref("mail.server.server1.hostname", "127.0.0.1");
user_pref("mail.server.server1.port", 1110);
user_pref("mail.server.server1.userName", "wac");
user_pref("mail.server.server1.name", "wac@127.0.0.1");
user_pref("mail.server.server1.socketType", 0);
user_pref("mail.server.server1.authMethod", 3);
user_pref("mail.server.server1.download_on_biff", true);
user_pref("mail.server.server1.login_at_startup", true);
user_pref("mail.server.server1.leave_on_server", false);
user_pref("mail.server.server1.directory-rel", "[ProfD]Mail/127.0.0.1");
user_pref("mail.server.server2.type", "none");
user_pref("mail.server.server2.hostname", "Local Folders");
user_pref("mail.server.server2.userName", "nobody");
user_pref("mail.server.server2.directory-rel", "[ProfD]Mail/Local Folders");
user_pref("mail.shell.checkDefaultClient", false);
user_pref("mail.rights.version", 1);
user_pref("mailnews.start_page.enabled", false);
user_pref("mail.provider.enabled", false);
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);
user_pref("app.update.disabledForTesting", true);
'@
        # The message: unique by its token; the attachment's bytes known.
        $attachment = [Text.Encoding]::UTF8.GetBytes("WAC mail attachment witness $token")
        $sha = (([Security.Cryptography.SHA256]::Create()).ComputeHash($attachment) | ForEach-Object { $_.ToString('x2') }) -join ''
        # Accents through [char]: Windows PowerShell reads a script without BOM as cp1252.
        $subject = "T$([char]0xE9)moin WAC $token"
        $encodedSubject = '=?UTF-8?B?' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($subject)) + '?='
        $name = "r%C3%A9sum%C3%A9-$token.bin"
        $message = @"
From: =?UTF-8?Q?T=C3=A9moin?= <temoin@wac-test.invalid>
To: WAC <wac@wac-test.invalid>
Subject: $encodedSubject
Date: $((Get-Date).ToUniversalTime().ToString('ddd, dd MMM yyyy HH:mm:ss +0000', [Globalization.CultureInfo]::InvariantCulture))
Message-ID: <wac-$token@wac-test.invalid>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="wac-boundary-$token"

--wac-boundary-$token
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

Corps du t=C3=A9moin $token
--wac-boundary-$token
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename*=UTF-8''$name

$([Convert]::ToBase64String($attachment))
--wac-boundary-$token--
"@ -replace "`r?`n", "`r`n"
        $server = 'C:\wactest\pop3-witness.ps1'
        Set-Content -Encoding UTF8 $server @'
param([string]$MessageFile)
$message = [IO.File]::ReadAllText($MessageFile)
$listener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback), 1110
$listener.Start()
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
    if (-not $listener.Pending()) { Start-Sleep -Milliseconds 200; continue }
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII)
    $writer = New-Object IO.StreamWriter($stream, [Text.Encoding]::ASCII)
    $writer.NewLine = "`r`n"; $writer.AutoFlush = $true
    $writer.WriteLine('+OK WAC witness')
    while (($line = $reader.ReadLine()) -ne $null) {
        $command = ($line -split ' ')[0].ToUpper()
        switch ($command) {
            'CAPA' { $writer.WriteLine("+OK`r`nUIDL`r`nUSER`r`n.") }
            'STAT' { $writer.WriteLine("+OK 1 $($message.Length)") }
            'LIST' { $writer.WriteLine("+OK`r`n1 $($message.Length)`r`n.") }
            'UIDL' { $writer.WriteLine("+OK`r`n1 wac-$([IO.Path]::GetFileNameWithoutExtension($MessageFile))`r`n.") }
            'RETR' {
                $writer.WriteLine("+OK $($message.Length) octets")
                $writer.Write($message -replace "(?m)^\.", '..')
                # The terminating "." on a line of its own, after the message's own last line break.
                if ($message.EndsWith("`r`n")) { $writer.WriteLine('.') } else { $writer.WriteLine("`r`n.") }
            }
            'QUIT' { $writer.WriteLine('+OK'); break }
            default { $writer.WriteLine('+OK') }
        }
        if ($command -eq 'QUIT') { break }
    }
    $client.Close()
}
$listener.Stop()
'@
        $messageFile = "C:\wactest\pop3-$token.eml"
        [IO.File]::WriteAllText($messageFile, $message)
        $pop = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $server -MessageFile $messageFile" -WindowStyle Hidden -PassThru
        $script = 'C:\wactest\thunderbird-user.ps1'
        # Thunderbird fetches without authentication from no POP3 server, and in
        # NTLM it asks for a password too (measured): the account authenticates
        # by USER/PASS, and the user answers the prompt — a dummy password the
        # server does not check, not a secret.
        Set-Content $script @"
`$tb = Start-Process '$thunderbird' -ArgumentList '-profile "$profileDir"' -PassThru
Start-Sleep 12
`$shell = New-Object -ComObject WScript.Shell
`$null = `$shell.AppActivate(`$tb.Id)
Start-Sleep 1
`$shell.SendKeys('witness{ENTER}')
Start-Sleep 30
`$tb.CloseMainWindow() | Out-Null
Start-Sleep 10
if (-not `$tb.HasExited) { `$tb | Stop-Process -Force }
"@
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $script"
        $principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive
        Register-ScheduledTask -TaskName WacThunderbird -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName WacThunderbird
        Start-Sleep 60
        Unregister-ScheduledTask -TaskName WacThunderbird -Confirm:$false
        if (-not $pop.HasExited) { $pop | Stop-Process -Force }
        Remove-Item $server, $script, $messageFile -ErrorAction SilentlyContinue
        if ((Test-Path $inbox) -and (Select-String -LiteralPath $inbox -SimpleMatch "wac-$token@" -Quiet)) {
            # The name as the message encodes it (RFC 2231): no accent through the agent's console.
            Write-Output "thunderbird=$token|$name|$sha|$inbox"
        }
    }
} } catch { WitnessFailure 'emails' $_ }

# A shadow copy of C:, made through the service (the harness may, WAC never
# does). The previous cycle's copy is deleted first: one at a time. A value
# changed after it keeps the copy's SOFTWARE different from the volume's, so
# that WAC stores it rather than share it. Windows then reads a few files
# through the copy's own device: their SHA-256 is the reference of WAC's raw
# reading of the same files.
try { if (Wants 'shadow_copies') {
    $marker = 'C:\wactest\shadow-copy-id.txt'
    if (Test-Path $marker) {
        $previous = (Get-Content $marker | Select-Object -First 1).Trim()
        Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $previous } | ForEach-Object { $_.Delete() }
        Remove-Item $marker
    }
    $key = 'HKLM:\SOFTWARE\WacTest'
    New-Item -Force $key | Out-Null
    $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
    Set-ItemProperty $key ShadowWitness "before-$stamp"
    # Erased after the copy, kept by it: a Run value, and an event of a log of
    # its own, cleared — what shadow_copy_registry.json and
    # shadow_copy_events.json must give, and the volume's JSON no longer.
    $run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    Set-ItemProperty $run WacShadowWitness "C:\wactest\shadow-$stamp.exe"
    # A shadow copy holds the DISK, and Windows writes the registry and the
    # event logs to it late: read by Windows itself through the copy's device
    # (reg load of its SOFTWARE with its logs, Get-WinEvent of its .evtx),
    # the Run value and the event were both absent from a copy made 15 s
    # after them — RegFlushKey changing nothing — and both there 90 s after
    # (Windows 11, 2026-10-24, B-056). 120 s, with a margin: the witness
    # event is written at the start of this script, the value here.
    Start-Sleep 120
    $created = (Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')
    if ($created.ReturnValue -ne 0) { throw "Win32_ShadowCopy.Create returned $($created.ReturnValue)" }
    Set-Content $marker $created.ShadowID
    Set-ItemProperty $key ShadowWitness "after-$stamp"
    Remove-ItemProperty $run WacShadowWitness
    Clear-EventLog -LogName WacShadow
    foreach ($i in 1..3000) { Write-EventLog -LogName WacShadow -Source WacShadow -EventId 2 -Message "filler $i of the harness, overwriting the witness" }
    Write-Output "shadowrun=$($created.ShadowID)|WacShadowWitness|C:\wactest\shadow-$stamp.exe"
    if ($shadowEventToken) { Write-Output "shadowevent=$($created.ShadowID)|WacShadow|$shadowEventToken" }
    $volume = (Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter -eq 'C:' }).DeviceID
    foreach ($copy in Get-WmiObject Win32_ShadowCopy | Where-Object { $_.VolumeName -eq $volume }) {
        $utc = [Management.ManagementDateTimeConverter]::ToDateTime($copy.InstallDate).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
        Write-Output "shadowcopy=$($copy.ID)|$($copy.SetID)|$utc"
        if ($copy.ID -ne $created.ShadowID) { continue }
        foreach ($file in 'Windows\System32\config\SOFTWARE', 'Windows\System32\config\SYSTEM',
                          'Windows\System32\winevt\Logs\System.evtx', 'Users\wac\NTUSER.DAT') {
            # Through cmd: called from PowerShell, certutil gave nothing for the
            # copy's device path (Windows 11, measured). The digest is the line
            # of hexadecimal digits, spaced or not as the version writes it:
            # SHA-256, or SHA-1 where certutil knows no other (Vista refuses
            # an algorithm, measured).
            $said = @(& cmd.exe /c "certutil -hashfile `"$($copy.DeviceObject)\$file`" SHA256 2>&1")
            $hash = $said | ForEach-Object { $_ -replace '\s', '' } | Where-Object { $_ -match '^[0-9a-fA-F]{64}$' } | Select-Object -First 1
            if (-not $hash) {
                $said = @(& cmd.exe /c "certutil -hashfile `"$($copy.DeviceObject)\$file`" 2>&1")
                $hash = $said | ForEach-Object { $_ -replace '\s', '' } | Where-Object { $_ -match '^[0-9a-fA-F]{40}$' } | Select-Object -First 1
            }
            if ($hash) { Write-Output "shadowfile=$($copy.ID)|C:\$file|$($hash.ToUpper())" }
            else { Write-Output ("shadowfile_failed=C:\$file|" + (($said -join ' ') -replace '\s+', ' ')) }
        }
    }
} } catch { WitnessFailure 'shadow_copies' $_ }

# Last. Deleted files of known content: the most recent deletions of the
# volume, so that the bound of max_total_mib reaches them first. Written
# through (FILE_FLAG_WRITE_THROUGH) before they are deleted: a content still
# in the cache when its file is deleted never reaches the disk, and what the
# clusters hold would be another's. A folder of its own, emptied first.
# On the data volume (WACDATA) when the VM has one: on C:, Defender and
# WAC's own output reused the witnesses' records within two minutes
# (Windows 11, measured) — their content then out of any recovery's reach.
try { if (Wants 'deleted_files') {
    $token = (Get-Date).ToString('yyyyMMddHHmmss')
    $data = Get-WmiObject Win32_Volume | Where-Object { $_.Label -eq 'WACDATA' -and $_.DriveLetter } | Select-Object -First 1
    $folder = if ($data) { "$($data.DriveLetter)\WacDeleted" } else { 'C:\Users\wac\Documents\WacDeleted' }
    if (Test-Path $folder) { Remove-Item -Recurse -Force $folder }
    New-Item -ItemType Directory -Force $folder | Out-Null
    $text = New-Object Text.StringBuilder
    foreach ($i in 1..6000) { [void]$text.Append("WAC deleted witness $token, line $i of 6000`r`n") }
    $witnesses = @(
        @('deleted-resident.txt', [Text.Encoding]::ASCII.GetBytes("WAC deleted witness $token`r`n"), 'copied'),
        @('deleted-text.txt', [Text.Encoding]::ASCII.GetBytes($text.ToString()), 'copied'),
        @('deleted-tool.exe', [IO.File]::ReadAllBytes('C:\wactest\WAC.exe'), 'copied'),
        @('deleted-notepad.exe', [IO.File]::ReadAllBytes("$env:SystemRoot\System32\notepad.exe"), 'cleared'))
    # NTFS gives out the lowest free record first: a witness deleted before
    # the next was created gave it its record (Vista: all four in record
    # 63346, measured), and whatever was created after took them. Empty
    # files take the low free records first, then the witnesses are
    # created, each in a record of its own, and deleted; the buffer, deleted
    # last, leaves the records the system takes next below the witnesses'.
    $buffer = "$folder\buffer"
    New-Item -ItemType Directory -Force $buffer | Out-Null
    foreach ($i in 1..3000) { [IO.File]::WriteAllBytes("$buffer\$i", (New-Object byte[] 0)) }
    foreach ($w in $witnesses) {
        $stream = New-Object IO.FileStream("$folder\$($w[0])", [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 65536, [IO.FileOptions]::WriteThrough)
        $stream.Write($w[1], 0, $w[1].Length)
        $stream.Close()
    }
    # Level 3, carving: an executable and a PDF written now, with the others —
    # a file written after a deletion takes the freed clusters, and two
    # witnesses on the same clusters test neither —, truncated to nothing and
    # deleted with them: their bytes in the free clusters only, their record
    # naming no cluster. Contents of their own: the executable is WAC.exe with
    # one letter of its DOS stub changed (its structure intact, its SHA-256
    # not the level 1 witness's); the PDF is larger than a record holds
    # (a small file is resident: no cluster to carve).
    $exe = [IO.File]::ReadAllBytes('C:\wactest\WAC.exe')
    $stub = [Text.Encoding]::ASCII.GetString($exe, 0, [Math]::Min(512, $exe.Length)).IndexOf('This program')
    if ($stub -ge 0) { $exe[$stub] = [byte][char]'t' }
    $pdfText = "%PDF-1.4`n1 0 obj`n<< /Type /Catalog >>`nendobj`n% WAC carving witness $token`n" + ('%' + ('x' * 78) + "`n") * 100
    $xref = $pdfText.Length
    $pdfText += "xref`n0 2`n0000000000 65535 f `n0000000009 00000 n `ntrailer`n<< /Size 2 /Root 1 0 R >>`nstartxref`n$xref`n%%EOF`n"
    $carved = @(@('carve-witness.exe', $exe, 'PE'), @('carve-witness.pdf', [Text.Encoding]::ASCII.GetBytes($pdfText), 'PDF'))
    foreach ($c in $carved) {
        $stream = New-Object IO.FileStream("$folder\$($c[0])", [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 65536, [IO.FileOptions]::WriteThrough)
        $stream.Write($c[1], 0, $c[1].Length)
        $stream.Close()
    }
    # One more, overwritten after its deletion: a file that already holds a
    # record of its own (so that it takes not the witness's) is written once
    # the witness is deleted — on its freed clusters, NTFS giving those first —
    # then deleted in turn. The witness's clusters read free again: only the
    # runs of that later deleted record say they were written since. It must
    # never come out Recovered with another content (Windows 11, measured).
    $over = [Text.Encoding]::ASCII.GetBytes(($text.ToString()).Replace('witness', 'OVERWRITTEN'))
    $overPath = "$folder\deleted-overwritten.txt"
    $later = "$folder\overwriter.bin"
    [IO.File]::WriteAllBytes($later, (New-Object byte[] 0))
    $stream = New-Object IO.FileStream($overPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 65536, [IO.FileOptions]::WriteThrough)
    $stream.Write($over, 0, $over.Length)
    $stream.Close()
    $overDigest = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($over) | ForEach-Object { $_.ToString('X2') })
    # Its clusters, as Windows gives them (fsutil file queryextents, Windows 10
    # and later; "Clusters :" in French, a space before the colon): the later
    # file grows until it covers one of them.
    function Extents([string]$file) {
        $said = @(& fsutil file queryextents $file 2>$null)
        foreach ($line in $said) {
            if ($line -match 'Clusters\s*:\s*0x([0-9a-fA-F]+)\s+LCN\s*:\s*0x([0-9a-fA-F]+)') {
                $n = [Convert]::ToInt64($Matches[1], 16); $l = [Convert]::ToInt64($Matches[2], 16)
                ,@($l, ($l + $n))
            }
        }
    }
    $held = @(Extents $overPath)
    Remove-Item -Force $overPath
    # The later file, of the witness's size, written then MOVED onto the
    # clusters the witness held (FSCTL_MOVE_FILE, the defragmenters' call):
    # left to NTFS, it grew after its own clusters and never covered the
    # witness's, even at 256 MB (Windows 11, measured).
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WacMove {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, uint inSize, IntPtr outBuf, uint outSize, out uint returned, IntPtr ov);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    // Moves `clusters` clusters of a file, from its first, to `lcn` of its volume. @return the Win32 error, 0 on success
    public static int Move(string letter, string file, long lcn, uint clusters) {
        IntPtr volume = CreateFile(@"\\.\" + letter, 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (volume == new IntPtr(-1)) return Marshal.GetLastWin32Error();
        IntPtr handle = CreateFile(file, 0x80, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);   // FILE_READ_ATTRIBUTES
        int error = 0;
        if (handle == new IntPtr(-1)) error = Marshal.GetLastWin32Error();
        else {
            byte[] data = new byte[32];   // MOVE_FILE_DATA: handle, starting VCN, starting LCN, cluster count
            BitConverter.GetBytes(handle.ToInt64()).CopyTo(data, 0);
            BitConverter.GetBytes(0L).CopyTo(data, 8);
            BitConverter.GetBytes(lcn).CopyTo(data, 16);
            BitConverter.GetBytes(clusters).CopyTo(data, 24);
            uint returned;
            if (!DeviceIoControl(volume, 0x00090074, data, (uint)data.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero)) error = Marshal.GetLastWin32Error();
            CloseHandle(handle);
        }
        CloseHandle(volume);
        return error;
    }
}
'@
    $filler = New-Object byte[] ($over.Length); for ($i = 0; $i -lt $filler.Length; ++$i) { $filler[$i] = 0x5A }
    $stream = New-Object IO.FileStream($later, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None, 65536, [IO.FileOptions]::WriteThrough)
    $stream.Write($filler, 0, $filler.Length)
    $stream.Close()
    $overlap = 'unknown'
    if ($held) {
        $count = [uint32][Math]::Min($held[0][1] - $held[0][0], [Math]::Ceiling($filler.Length / 4096))
        $moved = [WacMove]::Move($later.Substring(0, 2), $later, $held[0][0], $count)
        $overlap = 'no'
        foreach ($mine in @(Extents $later)) {
            foreach ($his in $held) { if ($mine[0] -lt $his[1] -and $his[0] -lt $mine[1]) { $overlap = 'yes' } }
        }
        if ($moved -ne 0) { $overlap = "no (move: error $moved)" }
    }
    Remove-Item -Force $later
    Write-Output "overwrite=$overPath|$overlap"
    Write-Output "deleted=$overPath|$($over.Length)|$overDigest|overwritten|$token"
    foreach ($w in $witnesses) {
        $path = "$folder\$($w[0])"
        $digest = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($w[1]) | ForEach-Object { $_.ToString('X2') })
        Remove-Item -Force $path
        Write-Output "deleted=$path|$($w[1].Length)|$digest|$($w[2])|$token"
    }
    foreach ($c in $carved) {
        $path = "$folder\$($c[0])"
        $stream = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
        $stream.SetLength(0)
        $stream.Close()
        Remove-Item -Force $path
        $digest = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($c[1]) | ForEach-Object { $_.ToString('X2') })
        Write-Output "carved=$path|$($c[1].Length)|$digest|$($c[2])"
    }
    Remove-Item -Recurse -Force $buffer
    # Level 2, the slack of the directory indexes: 450 files in a folder,
    # the 150 in the middle of the name order moved to another. The leaf
    # blocks they filled are released with their entries, the folder keeping
    # its index blocks for the others: a folder emptied whole went back to an
    # index held in its record, its blocks out of any run (Windows 11,
    # measured). The records live on under the new folder — no deleted record
    # names them (level 1), only the slack does.
    $from = "$folder\slack-from"
    $to = "$folder\slack-to"
    New-Item -ItemType Directory -Force $from, $to | Out-Null
    foreach ($prefix in 'a', 'm', 'z') {
        foreach ($i in 1..150) { Set-Content "$from\$prefix-slack-$('{0:D3}' -f $i)-$token.txt" "WAC slack witness $prefix $i" }
    }
    foreach ($i in 1..150) {
        $name = "m-slack-$('{0:D3}' -f $i)-$token.txt"
        Move-Item "$from\$name" "$to\$name"
    }
    Write-Output "slack=$from|$to|$token|150"
} } catch { WitnessFailure 'deleted_files' $_ }
