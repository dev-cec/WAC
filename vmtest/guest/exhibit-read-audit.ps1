# exhibit-read-audit.ps1 — Windows' own audit of the reads of an exhibit
# store (B-040): the reference that the conversion reads the store only to
# check and copy it, and never afterwards.
#
#   -Start <folder>  enables the "File System" audit (by its GUID, whatever
#                    the language of Windows) and puts on the folder a read
#                    audit rule (SACL) for Everyone, inherited by its files;
#   -Stop <folder> -Since <ISO UTC> -Output <file>
#                    removes the rule, disables the audit, and lists each read
#                    of a file of the folder by WAC.exe since that instant
#                    (Security event 4663): "instant UTC to 100 ns|file".
# Test VM only: the harness runs it around the conversion of the separate
# collection, after the main collection has read the logs. Get-Acl and
# Set-Acl by -Path: PowerShell 2 (Windows 7) has no -LiteralPath for them,
# and the store's path holds no wildcard.
param([string]$Start, [string]$Stop, [string]$Since, [string]$Output)
$ErrorActionPreference = 'Stop'
$fileSystem = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$everyone = New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'
# Whether the first file of the folder's top level holds an audit rule: its
# own, and with $inherited one it inherits. True without any such file.
function firstFileAudited([string]$folder, [bool]$inherited) {
    $first = @([IO.Directory]::GetFiles($folder)) | Select-Object -First 1
    if (-not $first) { return $inherited }
    [bool]@([IO.File]::GetAccessControl($first, 'Audit').GetAuditRules($true, $inherited, [Security.Principal.SecurityIdentifier])).Count
}
# Every file of the store, by its extended path.
function storeFiles([string]$folder) {
    Get-ChildItem -LiteralPath ('\\?\' + $folder) -Recurse -Force | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName }
}
if ($Start) {
    auditpol /set /subcategory:$fileSystem /success:enable | Out-Null
    $acl = Get-Acl -Path $Start -Audit
    $rule = New-Object Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData',
        'ContainerInherit,ObjectInherit', 'None', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -Path $Start -AclObject $acl
    # Server 2025 does not propagate the folder's rule to the files already in
    # it (measured on 2026-10-31: the rule on the folder, none on its files, no
    # read audited): the rule then goes on each file. Tested on one file of the
    # top level, so that elsewhere the store is not walked; walked by its
    # extended path (\\?\: the long-path witness), the rules set by .NET (a
    # name may hold brackets, which -Path reads as a wildcard).
    if (-not (firstFileAudited $Start $true)) {
        $fileRule = New-Object Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData', 'None', 'None', 'Success')
        foreach ($f in storeFiles $Start) {
            $security = [IO.File]::GetAccessControl($f, 'Audit')
            $security.AddAuditRule($fileRule)
            [IO.File]::SetAccessControl($f, $security)
        }
    }
    (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
}
if ($Stop) {
    # The reads are listed BEFORE the rule is removed: removing it changes the
    # audit settings of every file of the store, one event 4907 each (and
    # reads by PowerShell), which filled the 20 MB Security log and overwrote
    # WAC's reads (Windows 11, 34 000 exhibits: 22 174 events 4907).
    auditpol /set /subcategory:$fileSystem /success:disable | Out-Null
    $from = [datetime]::Parse($Since, $null, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    $prefix = $Stop.TrimEnd('\') + '\'
    # On a removable disk (the collection key) the event names the file by its
    # device path, \Device\HarddiskVolumeN\..., not by its letter (measured
    # on 2026-11-07, Windows 11): that path is brought back to the letter.
    Add-Type -Namespace Wac -Name Dos -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern uint QueryDosDevice(string name, System.Text.StringBuilder target, uint size);'
    $drive = $prefix.Substring(0, 2)
    $target = New-Object Text.StringBuilder 1024
    $device = $null
    if ([Wac.Dos]::QueryDosDevice($drive, $target, 1024) -gt 0) { $device = $target.ToString() + '\' }
    $lines = foreach ($e in (Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $from.ToLocalTime() } -ErrorAction SilentlyContinue)) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        $object = $data['ObjectName']
        if ($device -and $object -and $object.StartsWith($device, [StringComparison]::OrdinalIgnoreCase)) { $object = $drive + '\' + $object.Substring($device.Length) }
        if ($data['ProcessName'] -like '*\WAC.exe' -and $object -like "$prefix*") {
            $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffff') + '|' + $object
        }
    }
    # No read: $lines is $null, which @() counts as one element on PowerShell 2.
    $lines = @($lines | Where-Object { $_ })
    [IO.File]::WriteAllLines($Output, [string[]]$lines, (New-Object Text.UTF8Encoding $false))
    # The rules put on each file (Server 2025), when a file holds its own.
    if (firstFileAudited $Stop $false) {
        foreach ($f in storeFiles $Stop) {
            $security = [IO.File]::GetAccessControl($f, 'Audit')
            foreach ($r in @($security.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]))) { [void]$security.RemoveAuditRule($r) }
            [IO.File]::SetAccessControl($f, $security)
        }
    }
    $acl = Get-Acl -Path $Stop -Audit
    $acl.SetAuditRuleProtection($false, $false)
    foreach ($r in @($acl.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]))) { [void]$acl.RemoveAuditRule($r) }
    Set-Acl -Path $Stop -AclObject $acl
    "$($lines.Count) read(s)"
}
