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
if ($Start) {
    auditpol /set /subcategory:$fileSystem /success:enable | Out-Null
    $acl = Get-Acl -Path $Start -Audit
    $rule = New-Object Security.AccessControl.FileSystemAuditRule($everyone, 'ReadData',
        'ContainerInherit,ObjectInherit', 'None', 'Success')
    $acl.AddAuditRule($rule)
    Set-Acl -Path $Start -AclObject $acl
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
    $lines = foreach ($e in (Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $from.ToLocalTime() } -ErrorAction SilentlyContinue)) {
        $x = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        if ($data['ProcessName'] -like '*\WAC.exe' -and $data['ObjectName'] -like "$prefix*") {
            $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffff') + '|' + $data['ObjectName']
        }
    }
    # No read: $lines is $null, which @() counts as one element on PowerShell 2.
    $lines = @($lines | Where-Object { $_ })
    [IO.File]::WriteAllLines($Output, [string[]]$lines, (New-Object Text.UTF8Encoding $false))
    $acl = Get-Acl -Path $Stop -Audit
    $acl.SetAuditRuleProtection($false, $false)
    foreach ($r in @($acl.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]))) { [void]$acl.RemoveAuditRule($r) }
    Set-Acl -Path $Stop -AclObject $acl
    "$($lines.Count) read(s)"
}
