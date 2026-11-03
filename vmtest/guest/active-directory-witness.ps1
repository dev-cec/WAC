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

function Utc($date) { if ($date) { ([datetime]$date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') } }

# Every object of every naming context, deleted ones included.
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

$reference = @{
    objects = $objects; replication = $replication
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
