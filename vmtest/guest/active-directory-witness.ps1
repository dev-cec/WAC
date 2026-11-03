# active-directory-witness.ps1 — on a domain controller, places the witnesses of
# active_directory and writes what the directory says through its own tools in
# C:\wactest\active-directory.json. Placed once: a tombstone or a removed value
# re-made at each cycle would pile up. Prints "placed", or "not a controller".
$ErrorActionPreference = 'Stop'
if ((Get-WmiObject Win32_OperatingSystem).ProductType -ne 2) { Write-Output 'not a controller'; exit 0 }
Import-Module ActiveDirectory
$domain = Get-ADDomain
$base = $domain.DistinguishedName
$usersFolder = "CN=Users,$base"
$userName = 'wacwitness'; $removedGroupName = 'wacwitness-removed'; $deletedName = 'wacwitness-deleted'
$delegateTo = "cifs/$($domain.PDCEmulator)"
$replicationRight = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All

function Find-Object($name) { Get-ADObject -Filter "sAMAccountName -eq '$name'" -SearchBase $base }

$user = Find-Object $userName
if (-not $user) {
    # Disabled: it never needs a password. Its privileges are what is witnessed.
    New-ADUser -Name $userName -SamAccountName $userName -Path $usersFolder -Enabled $false
    Set-ADObject -Identity "CN=$userName,$usersFolder" -Add @{
        servicePrincipalName = "wac/$userName.$($domain.DNSRoot)"; 'msDS-AllowedToDelegateTo' = $delegateTo; adminCount = 1
    }
    $user = Find-Object $userName
    # The privileged groups are named by SID: their names follow the language of Windows.
    Add-ADGroupMember -Identity "$($domain.DomainSID)-512" -Members $user.DistinguishedName
    New-ADGroup -Name $removedGroupName -SamAccountName $removedGroupName -Path $usersFolder -GroupScope Global
    Add-ADGroupMember -Identity $removedGroupName -Members $user.DistinguishedName
    Remove-ADGroupMember -Identity $removedGroupName -Members $user.DistinguishedName -Confirm:$false
    New-ADUser -Name $deletedName -SamAccountName $deletedName -Path $usersFolder -Enabled $false
    Remove-ADUser -Identity $deletedName -Confirm:$false
    Set-ADUser -Identity $userName -PrincipalsAllowedToDelegateToAccount (Get-ADUser -Identity "$($domain.DomainSID)-500")
    $sid = (Get-ADUser -Identity $userName).SID
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $replicationRight)
    $acl = Get-Acl "AD:\$base"
    $acl.AddAccessRule($rule)
    Set-Acl "AD:\$base" $acl
}

# A policy of known content, its link disabled: never applied, even to this controller.
$policyName = 'wacwitness-policy'
$witnessKey = 'HKLM\Software\WacWitness'; $witnessValue = 'Marker'; $witnessData = 'wac-policy-witness'
$witnessScript = 'wac-startup-witness.cmd'; $witnessParameters = '-witness'
$witnessTask = 'wac-task-witness'; $witnessCommand = 'cmd.exe'
$storedAccount = 'wacstored'; $storedValue = 'd2l0bmVzcy1ub3QtYS1wYXNzd29yZA'   # no password: only what must not come out
Import-Module GroupPolicy
$gpo = Get-GPO -Name $policyName -ErrorAction SilentlyContinue
if (-not $gpo) {
    $gpo = New-GPO -Name $policyName
    Set-GPRegistryValue -Name $policyName -Key $witnessKey -ValueName $witnessValue -Type String -Value $witnessData | Out-Null
    New-GPLink -Name $policyName -Target $base -LinkEnabled No | Out-Null
    $root = "C:\Windows\SYSVOL\domain\Policies\{$($gpo.Id)}\Machine"
    New-Item -ItemType Directory -Force "$root\Scripts\Startup", "$root\Preferences\ScheduledTasks", "$root\Preferences\Groups" | Out-Null
    [IO.File]::WriteAllText("$root\Scripts\scripts.ini", "[Startup]`r`n0CmdLine=$witnessScript`r`n0Parameters=$witnessParameters`r`n", [Text.Encoding]::Unicode)
    [IO.File]::WriteAllText("$root\Scripts\Startup\$witnessScript", "rem witness`r`n")
    [IO.File]::WriteAllText("$root\Preferences\ScheduledTasks\ScheduledTasks.xml",
        "<?xml version=`"1.0`" encoding=`"utf-8`"?><ScheduledTasks clsid=`"{CC63F200-7309-4ba0-B154-A71CD118DBCC}`"><ImmediateTaskV2 clsid=`"{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}`" name=`"$witnessTask`" changed=`"2026-11-03 08:00:00`"><Properties action=`"C`" name=`"$witnessTask`" runAs=`"NT AUTHORITY\System`"><Task version=`"1.3`"><Actions><Exec><Command>$witnessCommand</Command><Arguments>/c rem</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2></ScheduledTasks>")
    [IO.File]::WriteAllText("$root\Preferences\Groups\Groups.xml",
        "<?xml version=`"1.0`" encoding=`"utf-8`"?><Groups clsid=`"{3125E937-EB16-4b4c-9934-544FC6D24D26}`"><User clsid=`"{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}`" name=`"$storedAccount`"><Properties action=`"U`" userName=`"$storedAccount`" cpassword=`"$storedValue`"/></User></Groups>")
}

function Utc($date) { if ($date) { ([datetime]$date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') } }

# Every object of every naming context, deleted ones included.
# The directory goes on living while the cycle runs: the check needs this instant
# to tell what changed after these references from what WAC read wrong.
$referenceTaken = Utc (Get-Date)
$objects = New-Object System.Collections.ArrayList
$properties = 'objectGUID', 'objectClass', 'objectSid', 'sAMAccountName', 'userAccountControl', 'adminCount', 'servicePrincipalName', 'whenCreated', 'isDeleted'
$seen = @{}
foreach ($context in (Get-ADRootDSE).namingContexts) {
    foreach ($o in Get-ADObject -Filter * -SearchBase $context -IncludeDeletedObjects -Properties $properties) {
        if ($seen.ContainsKey($o.ObjectGUID)) { continue }
        $seen[$o.ObjectGUID] = $true
        # The module gives the most derived class alone: found among those WAC reads.
        [void]$objects.Add(@{
            dn = $o.DistinguishedName; guid = "$($o.ObjectGUID)"; class = $o.ObjectClass
            sid = $(if ($o.objectSid) { $o.objectSid.Value } else { '' }); account = "$($o.sAMAccountName)"
            control = $o.userAccountControl; adminCount = $o.adminCount
            spn = @($o.servicePrincipalName | Where-Object { $_ }); created = Utc $o.whenCreated
        })
    }
}

$witness = Get-ADUser -Identity $userName
$privileged = Get-ADGroup -Identity "$($domain.DomainSID)-512"
$removedGroup = Get-ADGroup -Identity $removedGroupName
$removedValue = Get-ADReplicationAttributeMetadata -Object $removedGroup.DistinguishedName -Server $env:COMPUTERNAME -ShowAllLinkedValues |
    Where-Object { $_.AttributeName -eq 'member' -and $_.AttributeValue -eq $witness.DistinguishedName }
# A tombstone's name starts with its last one; msDS-LastKnownRDN needs the recycle bin.
$deleted = Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties lastKnownParent |
    Where-Object { $_.Name -like "$deletedName*" }

# The changes of three objects, attribute by attribute: only plain attributes (a linked value has its own row).
$replication = New-Object System.Collections.ArrayList
foreach ($dn in $witness.DistinguishedName, $privileged.DistinguishedName, $base) {
    foreach ($m in Get-ADReplicationAttributeMetadata -Object $dn -Server $env:COMPUTERNAME) {
        if ($m.IsLinkValue) { continue }
        [void]$replication.Add(@{
            object = $dn; attribute = $m.AttributeName; version = $m.Version; changed = Utc $m.LastOriginatingChangeTime
            invocation = "$($m.LastOriginatingChangeDirectoryServerInvocationId)"; usn = $m.LastOriginatingChangeUsn
        })
    }
}

$policies = @(Get-GPO -All | ForEach-Object {
    @{ id = "$($_.Id)"; name = $_.DisplayName; computerVersion = $_.Computer.SysvolVersion; userVersion = $_.User.SysvolVersion }
})
$policyValue = Get-GPRegistryValue -Name $policyName -Key $witnessKey -ValueName $witnessValue

# A replication requested, with what ships with Windows and no offensive tool: a
# DirSync search needs DS-Replication-Get-Changes, audited as a 4662 on the
# domain's root. Only cn is asked for: no secret is requested, and none comes
# back. Without PublicDataOnly as well it was measured leaving that same right
# and not Get-Changes-All (1131f6ad), so a real DCSync stays without a witness.
# Each cycle adds this one event to the Security log, which rolls over by itself.
Add-Type -AssemblyName System.DirectoryServices.Protocols
$replicationStart = Get-Date
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection 'localhost'
$search = New-Object System.DirectoryServices.Protocols.SearchRequest($base, '(objectClass=domainDNS)', 'Subtree', @('cn'))
[void]$search.Controls.Add((New-Object System.DirectoryServices.Protocols.DirSyncRequestControl($null, [System.DirectoryServices.Protocols.DirectorySynchronizationOptions]::PublicDataOnly, 100)))
[void]$ldap.SendRequest($search)
$ldap.Dispose()
$replicationEvent = $null
foreach ($attempt in 1..30) {
    $replicationEvent = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662; StartTime = $replicationStart } -ErrorAction SilentlyContinue |
        Where-Object { $_.ToXml() -match '1131f6aa' } | Select-Object -First 1
    if ($replicationEvent) { break }
    Start-Sleep -Seconds 1
}

# What Windows itself reads of the event logs, confronted with what WAC converts
# from its raw copies: the witnesses' own traces, and the latest event of each
# kind a controller adds, which shows the channel is taken. A log that has rolled
# over simply gives nothing: the check then says so.
function EventReference($record) {
    @{
        log = $record.LogName; id = $record.Id; recordId = $record.RecordId
        time = $record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffff\Z', [Globalization.CultureInfo]::InvariantCulture)
    }
}
$witnessEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 4726, 4728, 4729 } -ErrorAction SilentlyContinue |
    Where-Object { $_.ToXml() -match $userName } | ForEach-Object { EventReference $_ })
$controllerEvents = @(
    foreach ($id in 4768, 4769, 4662) { Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $id } -MaxEvents 1 -ErrorAction SilentlyContinue }
    foreach ($log in 'Directory Service', 'DFS Replication') { Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue }
) | ForEach-Object { EventReference $_ }

$reference = @{
    takenAt = $referenceTaken
    objects = $objects; replication = $replication; policies = $policies
    witnessEvents = $witnessEvents; controllerEvents = @($controllerEvents)
    replicationEvent = $(if ($replicationEvent) { EventReference $replicationEvent })
    policyWitness = @{
        id = "$($gpo.Id)"; domain = $base; key = ($witnessKey -replace '^HKLM\\', ''); valueName = $policyValue.ValueName; valueData = "$($policyValue.Value)".TrimEnd([char]0)
        script = $witnessScript; scriptParameters = $witnessParameters; task = $witnessTask; taskCommand = $witnessCommand
        storedAccount = $storedAccount; storedValue = $storedValue
    }
    witness = @{
        guid = "$($witness.ObjectGUID)"; sid = $witness.SID.Value; delegateTo = $delegateTo
        privilegedGroup = $privileged.DistinguishedName; removedGroup = $removedGroup.DistinguishedName
        removedAt = Utc $removedValue.LastOriginatingDeleteTime
        deletedGuid = "$($deleted.ObjectGUID)"; deletedName = $deletedName; deletedParent = $deleted.lastKnownParent
        domainGuid = "$($domain.ObjectGUID)"; replicationRight = "$replicationRight"
    }
}
$text = $reference | ConvertTo-Json -Depth 5 -Compress
[IO.File]::WriteAllText('C:\wactest\active-directory.json', $text, (New-Object Text.UTF8Encoding($false)))
Write-Output 'placed'
