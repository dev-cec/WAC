<#
  measure-run.ps1 — measures what one tool leaves on the footprint clone
  (backlog B-027), run by run-footprint.sh through the guest agent.

  THE BOUNDS. The change journal's next USN and the clock are read just
  before the tool starts and just after it ends: every file the tool created,
  changed, renamed or deleted on C: lies between the two USNs, those created
  then deleted during the run included. The exports below are written to the
  key (K:), another volume: they add nothing to C:'s journal inside the
  bounds, and whatever they cause on C: comes after the end bound.

  THE LAUNCH. Each tool is started the same way — a scheduled task of the
  interactive user "wac", with its highest rights, as an examiner running a
  tool from an elevated prompt — so that the launcher's own traces are the
  same in every run, and the run "control" (a command that does nothing)
  measures them, with Windows' own background activity.

  Usage: measure-run.ps1 -Label <run> -Command <command line run by cmd.exe>
#>
param(
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$Command,
    [int]$TimeoutMinutes = 180
)
$ErrorActionPreference = 'Stop'
$out = "K:\results\$Label"
New-Item -ItemType Directory -Force $out | Out-Null

# The journal's next USN: the bound of the run. fsutil words its labels in
# the system's language ("USN suivant"): the value is taken by its place, the
# third line, in hexadecimal.
function Get-NextUsn {
    $lines = @(& fsutil.exe usn queryjournal C:)
    $value = ($lines[2] -split ':')[-1].Trim()
    if ($value -notmatch '^0x[0-9a-fA-F]+$') { throw "fsutil usn queryjournal: unexpected line '$($lines[2])'" }
    [Convert]::ToUInt64($value.Substring(2), 16)
}

$startUsn = Get-NextUsn
$startUtc = (Get-Date).ToUniversalTime()

$task = "WacFootprint-$Label"
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c $Command > K:\results\$Label\console.txt 2>&1"
$principal = New-ScheduledTaskPrincipal -UserId 'wac' -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $TimeoutMinutes)
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task
Start-Sleep 5
$deadline = (Get-Date).AddMinutes($TimeoutMinutes + 5)
while ((Get-ScheduledTask -TaskName $task).State -eq 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep 5 }
$result = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
Unregister-ScheduledTask -TaskName $task -Confirm:$false

$endUtc = (Get-Date).ToUniversalTime()
$endUsn = Get-NextUsn

# The journal from the start bound; the records past the end bound are the
# exports' own, and are dropped by the analysis.
& fsutil.exe usn readjournal C: startusn=$startUsn csv > "$out\usn.csv"

# The journal names a file by its name and its parent folder's identifier
# only: each parent of the run is resolved to its path, now that the run is
# over (fsutil's labels are localised: the path is the text after "\\?\").
# A folder deleted since cannot be resolved; the analysis says so.
$parents = @{}
foreach ($line in Get-Content "$out\usn.csv") {
    if ($line -notmatch '^(\d+),') { continue }
    if ([uint64]$Matches[1] -ge $endUsn) { continue }
    $fields = $line -split ','
    $parent = ($fields | Where-Object { $_ -match '^[0-9a-f]{32}$' } | Select-Object -Skip 1 -First 1)
    if ($parent) { $parents[$parent] = $true }
}
$resolved = foreach ($id in $parents.Keys) {
    $answer = (& fsutil.exe file queryfilenamebyid C:\ ('0x' + $id.Substring(16)) 2>$null) -join ' '
    $path = if ($answer -match '\\\\\?\\(.+)$') { $Matches[1].Trim() } else { '' }
    [pscustomobject]@{ ParentId = $id; Path = $path }
}
$resolved | Export-Csv -NoTypeInformation -Encoding UTF8 "$out\parents.csv"

# Sysmon's events of the run: who did what.
$from = $startUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$to = $endUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
& wevtutil.exe qe Microsoft-Windows-Sysmon/Operational /q:"*[System[TimeCreated[@SystemTime>='$from' and @SystemTime<='$to']]]" /f:xml /e:Events > "$out\sysmon.xml"

# Every other event log that recorded something during the run: what an
# analyst of the machine would find there afterwards.
$written = @()
foreach ($log in Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 -and $_.LogName -ne 'Microsoft-Windows-Sysmon/Operational' }) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log.LogName; StartTime = $startUtc.ToLocalTime(); EndTime = $endUtc.ToLocalTime() } -ErrorAction SilentlyContinue)
    if ($events.Count -eq 0) { continue }
    $written += [pscustomobject]@{ Log = $log.LogName; Count = $events.Count }
    $file = "$out\events-" + ($log.LogName -replace '[\\/:*?"<>|]', '_') + '.xml'
    & wevtutil.exe qe $log.LogName /q:"*[System[TimeCreated[@SystemTime>='$from' and @SystemTime<='$to']]]" /f:xml /e:Events > $file
}

# What the tool produced on the key: files and bytes per output folder, and
# the record of each copy — WAC's manifest, KAPE's copy log — for comparing
# what each one took, and what it recorded of each piece.
$outputs = foreach ($folder in @(Get-ChildItem K:\WAC, K:\out -Directory -ErrorAction SilentlyContinue)) {
    $files = @(Get-ChildItem $folder.FullName -Recurse -File -ErrorAction SilentlyContinue)
    [pscustomobject]@{ Folder = $folder.FullName; Files = $files.Count; Bytes = ($files | Measure-Object Length -Sum).Sum }
}
$outputs | ConvertTo-Json | Set-Content -Encoding UTF8 "$out\outputs.json"
Get-ChildItem K:\WAC -Recurse -Filter MANIFEST.json -ErrorAction SilentlyContinue | Select-Object -First 1 | Copy-Item -Destination "$out\manifest.json"
Get-ChildItem K:\out -Recurse -Filter *_CopyLog.csv -ErrorAction SilentlyContinue | Select-Object -First 1 | Copy-Item -Destination "$out\kape-copylog.csv"

[pscustomobject]@{
    Label = $Label; Command = $Command; TaskResult = $result
    StartUsn = $startUsn; EndUsn = $endUsn
    StartUtc = $from; EndUtc = $to
    EventLogs = $written
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 "$out\run.json"
"$Label measured: USN $startUsn to $endUsn, $from to $to, task result $result"
