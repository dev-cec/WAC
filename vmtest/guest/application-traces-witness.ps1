# application-traces-witness.ps1 — witnesses of the applications' traces
# (application_traces.h, application_trace_files.h): files of known content
# where products write them, which check-json.py finds again in <group>.json.
#   - TeamViewer's log, a line dated NOW in local time, without offset — the
#     conversion reads it as the machine's local time: its UTC, as Windows
#     computes it here, is the reference —, its continuation, and beside it a
#     decoy the product's filter does not take;
#   - OpenSSH server's log, a line whose time carries its offset;
#   - sshd's own log, provoked: where Windows ships sshd (Server 2025), sshd.exe
#     is run by hand — never its service — on 127.0.0.1:2222 with a temporary
#     configuration (SyslogFacility LOCAL0: its file log) and host key, and one
#     connection of an unknown user is refused; its instant, taken from the
#     system clock before and after, is the reference of the line sshd writes
#     ("<pid> yyyy-MM-dd HH:mm:ss.fff", local time: measured 2026-11-10). The
#     temporary files go; sshd.log stays for the collection, removed by the
#     next witness when it holds only the witness's lines — a real one is kept;
#   - WinSCP.ini and FileZilla's sitemanager.xml, each holding a password the
#     conversion must leave out;
#   - a pCloud database, listed, not converted;
#   - a crash dump, a product off by default: never taken;
#   - a second TeamViewer log whose lines straddle a change of time zone: one
#     line written while India's zone (+05:30, no daylight saving) is in force,
#     one after the machine's zone is back. A local time is that of the zone in
#     force when it was written, which the System log keeps (Kernel-General 22);
#     the conversion must apply that zone, not the current one. The change is
#     made by tzutil and undone in a finally block; it stays written in the
#     System log, as any change of zone — the trace the witness needs, six
#     events per cycle. tzutil appears with Windows 7 and Server 2008 R2: on an
#     older Windows the witness is not placed, and said;
#   - a third TeamViewer log, the changes of daylight saving time: one line in
#     the local hour repeated in autumn (lived twice: its first occurrence
#     dated, the second said possible), one in the hour skipped in spring, of
#     the current year in the machine's zone; Windows' own conversion of each
#     (TzSpecificLocalTimeToSystemTime) recorded beside. Not placed in a zone
#     without daylight saving.
# The values are fixed but TeamViewer's time, the moment of the run: the
# reference, with that time and its UTC, goes to
# <Out>\application-traces-reference.json for check-json.py.
# PowerShell 2 (Server 2008 R2): no cmdlet younger than it.
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'Stop'
$profilePath = Join-Path $env:SystemDrive 'Users\wac'
if (-not (Test-Path $profilePath)) { Write-Output 'no profile'; exit 1 }
$utf8 = New-Object Text.UTF8Encoding($false)
function Put([string]$path, [string]$text) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [IO.File]::WriteAllText($path, $text, $utf8)
}
$now = Get-Date
$written = $now.ToString('yyyy/MM/dd HH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
$expectedUtc = $now.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
$teamViewer = "$profilePath\AppData\Roaming\TeamViewer\TeamViewer15_Logfile.log"
Put $teamViewer ("header of the witness log`r`n" +
    "$written  4242  5150 S0   wac-trace-witness incoming connection from 10.0.0.5`r`n" +
    "   wac-trace-witness continuation`r`n")
$decoy = "$profilePath\AppData\Roaming\TeamViewer\wac-trace-decoy.txt"
Put $decoy "2026-11-08 14:03:21 wac-trace-decoy: TeamViewer's filter does not take this name`r`n"
$ssh = "$env:ProgramData\ssh\logs\wac-trace-witness.log"
Put $ssh "2026-11-08T14:03:21.123+01:00 sshd[42]: wac-trace-witness accepted publickey`r`n"
$winscp = "$profilePath\AppData\Roaming\WinSCP.ini"
Put $winscp "[Sessions\wac-trace-witness]`r`nHostName=witness.example`r`nPassword=wac-trace-secret-1`r`nPortNumber=2222`r`n"
$filezilla = "$profilePath\AppData\Roaming\FileZilla\sitemanager.xml"
Put $filezilla ('<?xml version="1.0" encoding="UTF-8"?><FileZilla3><Servers><Server><Host>wac-trace-witness.example</Host>' +
    '<User>wac</User><Pass encoding="base64">wac-trace-secret-2</Pass></Server></Servers></FileZilla3>')
$pcloud = "$profilePath\AppData\Local\pCloud\wac-trace-witness.db"
New-Item -ItemType Directory -Force (Split-Path $pcloud) | Out-Null
[IO.File]::WriteAllBytes($pcloud, [byte[]](83, 81, 76, 105, 116, 101, 0, 1, 2, 3))
$dump = "$profilePath\AppData\Local\CrashDumps\wac-trace-witness.dmp"
New-Item -ItemType Directory -Force (Split-Path $dump) | Out-Null
[IO.File]::WriteAllBytes($dump, [byte[]](77, 68, 77, 80, 0, 0))
# Each time read from the system, not from .NET, which caches the zone it found
# first: GetSystemTime, then SystemTimeToTzSpecificLocalTime with no zone given,
# which converts by the zone active at the moment of the call.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WacWitnessClock {
    [StructLayout(LayoutKind.Sequential)]
    public struct SystemTime { public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds; }
    [DllImport("kernel32.dll")] static extern void GetSystemTime(out SystemTime time);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SystemTimeToTzSpecificLocalTime(IntPtr zone, ref SystemTime utc, out SystemTime local);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TzSpecificLocalTimeToSystemTime(IntPtr zone, ref SystemTime local, out SystemTime utc);
    static DateTime Of(SystemTime t) { return new DateTime(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, t.Milliseconds); }
    // The UTC instant Windows gives a local time of the active zone.
    public static string ToUtc(DateTime l) {
        SystemTime local = new SystemTime { Year = (ushort)l.Year, Month = (ushort)l.Month, Day = (ushort)l.Day,
                                            Hour = (ushort)l.Hour, Minute = (ushort)l.Minute, Second = (ushort)l.Second };
        SystemTime utc;
        if (!TzSpecificLocalTimeToSystemTime(IntPtr.Zero, ref local, out utc)) throw new System.ComponentModel.Win32Exception();
        return Of(utc).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
    }
    // The instant in UTC, the local time the active zone gives it, and their difference in minutes.
    public static object[] Now() {
        SystemTime utc, local;
        GetSystemTime(out utc);
        if (!SystemTimeToTzSpecificLocalTime(IntPtr.Zero, ref utc, out local)) throw new System.ComponentModel.Win32Exception();
        DateTime u = Of(utc), l = Of(local);
        return new object[] { u.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture),
                              l.ToString("yyyy/MM/dd HH:mm:ss.fff", System.Globalization.CultureInfo.InvariantCulture),
                              (int)Math.Round((l - u).TotalMinutes) };
    }
}
'@
$openssh = "$env:windir\System32\OpenSSH"
$sshdReference = ''
if ((Test-Path "$openssh\sshd.exe") -and (Test-Path "$openssh\ssh.exe") -and (Test-Path "$openssh\ssh-keygen.exe")) {
    $sshdLog = "$env:ProgramData\ssh\logs\sshd.log"
    if (Test-Path $sshdLog) {
        $foreign = @(Get-Content $sshdLog | Where-Object { $_ -notmatch '127\.0\.0\.1 port 2222|wacnobody' })
        if ($foreign.Count -eq 0) { Remove-Item -Force $sshdLog }
    }
    $sshdWork = "$env:SystemDrive\wac-sshd-witness"
    New-Item -ItemType Directory -Force $sshdWork | Out-Null
    New-Item -ItemType Directory -Force (Split-Path $sshdLog) | Out-Null
    $sshd = $null
    try {
        # sshd refuses a host key others may read.
        & icacls.exe $sshdWork /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
        & "$openssh\ssh-keygen.exe" -q -t ed25519 -N '""' -f "$sshdWork\host_key" | Out-Null
        Set-Content -Encoding ascii "$sshdWork\sshd_config" @('Port 2222', 'ListenAddress 127.0.0.1',
            "HostKey $sshdWork\host_key", 'SyslogFacility LOCAL0', 'LogLevel INFO', "PidFile $sshdWork\sshd.pid")
        $sshd = Start-Process -FilePath "$openssh\sshd.exe" -ArgumentList @('-D', '-f', "$sshdWork\sshd_config") -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 3
        $sshdBefore = [WacWitnessClock]::Now()
        # ssh writes its warnings on stderr: not an error of the witness.
        $ErrorActionPreference = 'Continue'
        & "$openssh\ssh.exe" -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL wacnobody@127.0.0.1 exit 2>&1 | Out-Null
        $ErrorActionPreference = 'Stop'
        $sshdAfter = [WacWitnessClock]::Now()
        Start-Sleep -Seconds 2
    } finally {
        if ($sshd -and -not $sshd.HasExited) { Stop-Process -Id $sshd.Id -Force }
        # The child that handled the connection, if it outlived it.
        Get-Process sshd -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$openssh*" -and $_.StartTime -gt $now } | Stop-Process -Force
        Start-Sleep -Seconds 1
        Remove-Item -Recurse -Force $sshdWork -ErrorAction SilentlyContinue
    }
    if (-not (Select-String -Path $sshdLog -Pattern 'Invalid user wacnobody' -Quiet)) { Write-Output 'sshd wrote no refused connection'; exit 1 }
    $sshdReference = @"
,
 "SshdLog": "$($sshdLog.Replace('\', '\\'))",
 "SshdBeforeUtc": "$($sshdBefore[0])",
 "SshdAfterUtc": "$($sshdAfter[0])"
"@
}
$zoneLog = "$profilePath\AppData\Roaming\TeamViewer\TeamViewer15_Logfile_zone.log"
$zoneReference = ''
if (Get-Command tzutil.exe -ErrorAction SilentlyContinue) {
    $original = (& tzutil.exe /g | Out-String).Trim()
    if (-not $original) { Write-Output 'zone not read'; exit 1 }
    $other = 'India Standard Time'
    try {
        & tzutil.exe /s $other
        if ($LASTEXITCODE -ne 0) { throw "tzutil /s ${other}: $LASTEXITCODE" }
        Start-Sleep -Seconds 2
        $during = [WacWitnessClock]::Now()
        Start-Sleep -Seconds 2
    } finally {
        & tzutil.exe /s $original
    }
    if ($LASTEXITCODE -ne 0 -or (& tzutil.exe /g | Out-String).Trim() -ne $original) { Write-Output 'zone not restored'; exit 1 }
    Start-Sleep -Seconds 2
    $after = [WacWitnessClock]::Now()
    if ($during[2] -ne 330) { Write-Output "zone change not effective: $($during[2]) min"; exit 1 }
    Put $zoneLog ("$($during[1])  4242  5150 S0   wac-zone-witness written under +05:30`r`n" +
        "$($after[1])  4242  5150 S0   wac-zone-witness written after the zone came back`r`n")
    $zoneReference = @"
,
 "ZoneLog": "$($zoneLog.Replace('\', '\\'))",
 "ZoneDuringWritten": "$($during[1])",
 "ZoneDuringUtc": "$($during[0])",
 "ZoneAfterWritten": "$($after[1])",
 "ZoneAfterUtc": "$($after[0])",
 "ZoneAfterOffset": $($after[2])
"@
}
# The changes of daylight saving time of the current year: the first local
# half hour that is ambiguous (repeated) and the first invalid (skipped),
# searched by half hours in the machine's zone.
$dstLog = "$profilePath\AppData\Roaming\TeamViewer\TeamViewer15_Logfile_dst.log"
$dstReference = ''
$zone = [TimeZoneInfo]::Local
$repeated = $null; $skipped = $null
$start = New-Object DateTime ((Get-Date).Year), 1, 1, 0, 30, 0
for ($t = $start; $t.Year -eq $start.Year -and -not ($repeated -and $skipped); $t = $t.AddMinutes(30)) {
    if (-not $repeated -and $zone.IsAmbiguousTime($t)) { $repeated = $t }
    if (-not $skipped -and $zone.IsInvalidTime($t)) { $skipped = $t }
}
if ($repeated -and $skipped) {
    $format = 'yyyy/MM/dd HH:mm:ss.fff'
    $culture = [Globalization.CultureInfo]::InvariantCulture
    Put $dstLog ("$($repeated.ToString($format, $culture))  4242  5150 S0   wac-dst-witness written in the repeated hour`r`n" +
        "$($skipped.ToString($format, $culture))  4242  5150 S0   wac-dst-witness written in the skipped hour`r`n")
    $dstReference = @"
,
 "DstLog": "$($dstLog.Replace('\', '\\'))",
 "DstRepeatedWritten": "$($repeated.ToString($format, $culture))",
 "DstRepeatedWindowsUtc": "$([WacWitnessClock]::ToUtc($repeated))",
 "DstSkippedWritten": "$($skipped.ToString($format, $culture))",
 "DstSkippedWindowsUtc": "$([WacWitnessClock]::ToUtc($skipped))"
"@
}
$reference = @"
{
 "TeamViewerLog": "$($teamViewer.Replace('\', '\\'))",
 "TeamViewerWritten": "$written",
 "TeamViewerUtc": "$expectedUtc",
 "Decoy": "$($decoy.Replace('\', '\\'))",
 "SshLog": "$($ssh.Replace('\', '\\'))",
 "WinScp": "$($winscp.Replace('\', '\\'))",
 "FileZilla": "$($filezilla.Replace('\', '\\'))",
 "PCloud": "$($pcloud.Replace('\', '\\'))",
 "CrashDump": "$($dump.Replace('\', '\\'))"$zoneReference$sshdReference$dstReference
}
"@
[IO.File]::WriteAllText((Join-Path $Out 'application-traces-reference.json'), $reference, $utf8)
Write-Output 'placed'
