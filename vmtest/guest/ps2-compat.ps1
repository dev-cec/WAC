# ps2-compat.ps1 — the cmdlets the harness uses that PowerShell 2 (Windows 7)
# does not have, as functions of the same name and the same use. Loaded by
# qga.py before every command on a VM with PowerShell 2 only; never on a later
# PowerShell, whose own cmdlets stay in charge. Each one covers the way the
# harness calls it, not every parameter of the real cmdlet.
#
# What has no simple equivalent — the storage, SMB, firewall, Defender and
# PnP modules of Windows 8 — is left out: the sections that need it report
# their witnesses as not placed (witness_failed=), as on Windows 8.1.

# The console the task gives PowerShell is 80 columns wide, and its host cuts
# every line written there at that width: a SID, a reference line, came out
# truncated. Widened to the most a console takes.
try {
    $raw = $Host.UI.RawUI
    $raw.BufferSize = New-Object Management.Automation.Host.Size(32766, $raw.BufferSize.Height)
} catch {}

# Modules are not loaded on demand before PowerShell 3: those the harness uses
# and Windows 7 has.
Import-Module BitsTransfer -ErrorAction SilentlyContinue

# Get-FileHash: the hash of a file, upper-case hexadecimal, as PowerShell 4 gives it.
function Get-FileHash {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [string]$Algorithm = 'SHA256')
    $file = if ($LiteralPath) { $LiteralPath } else { $Path }
    $hasher = [Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    $stream = [IO.File]::OpenRead($file)
    try { $bytes = $hasher.ComputeHash($stream) } finally { $stream.Close() }
    New-Object PSObject -Property @{
        Algorithm = $Algorithm.ToUpperInvariant()
        Hash = (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
        Path = $file
    }
}

# Get-CimInstance through WMI. A namespace written with "/" is given with "\";
# dates stay WMI's text (yyyymmddHHMMSS.ffffff±UUU) — a caller that needs a
# date converts it ([Management.ManagementDateTimeConverter]).
function Get-CimInstance {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$ClassName, [string]$Namespace = 'root\cimv2', [string]$Filter)
    $arguments = @{ Class = $ClassName; Namespace = ($Namespace -replace '/', '\') }
    if ($Filter) { $arguments.Filter = $Filter }
    Get-WmiObject @arguments
}

# New-CimInstance through WMI: a [ref] to an instance (a binding's Filter and
# Consumer) becomes that instance's path, as WMI takes it.
function New-CimInstance {
    [CmdletBinding()]
    param([string]$Namespace, [string]$ClassName, [hashtable]$Property)
    $arguments = @{}
    foreach ($key in $Property.Keys) {
        $value = $Property[$key]
        $arguments[$key] = if ($value -is [ref]) { $value.Value.__PATH } else { $value }
    }
    $namespace = $Namespace -replace '/', '\'
    $created = Set-WmiInstance -Namespace $namespace -Class $ClassName -Arguments $arguments
    # What Set-WmiInstance returns carries no path, which a binding needs:
    # the instance read again by its name, when it has one.
    if (-not $created.__PATH -and $arguments.Name) {
        $created = Get-WmiObject -Namespace $namespace -Class $ClassName -Filter ("Name='" + ($arguments.Name -replace "'", "\'") + "'")
    }
    $created
}

# The ScheduledTasks module, as the harness uses it: a program run once, now,
# in the session of a logged-on user, then the task removed — through
# schtasks.exe, which every Windows has.
function New-ScheduledTaskAction {
    [CmdletBinding()]
    param([string]$Execute, [string]$Argument)
    New-Object PSObject -Property @{ Execute = $Execute; Arguments = $Argument }
}

function New-ScheduledTaskPrincipal {
    [CmdletBinding()]
    param([string]$UserId, [string]$LogonType)
    New-Object PSObject -Property @{ UserId = $UserId; LogonType = $LogonType }
}

function Register-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, $Action, $Principal, [switch]$Force)
    $command = $Action.Execute + $(if ($Action.Arguments) { ' ' + $Action.Arguments } else { '' })
    # /it: run only while that user is logged on, in that session — no password asked.
    # Through cmd: schtasks warns on its error stream that 00:00 is past, which
    # PowerShell 2 would turn into an error of the script.
    $output = & cmd.exe /c "schtasks.exe /create /tn `"$TaskName`" /tr `"$command`" /sc once /st 00:00 /ru $($Principal.UserId) /it /f 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "schtasks /create $TaskName failed: $output" }
    New-Object PSObject -Property @{ TaskName = $TaskName }
}

function Start-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName)
    $output = & cmd.exe /c "schtasks.exe /run /tn `"$TaskName`" 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "schtasks /run $TaskName failed: $output" }
}

function Unregister-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [switch]$Confirm)
    & cmd.exe /c "schtasks.exe /delete /tn `"$TaskName`" /f 2>&1" | Out-Null
}
