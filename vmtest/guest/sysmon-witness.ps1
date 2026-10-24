# sysmon-witness.ps1 — the Sysmon witness of the harness (B-053): Sysmon
# installed with a known configuration for the time of a cycle, then removed.
#
#   -Action Install   installs Sysmon from the folder (Sysmon64.exe, or
#                     Sysmon.exe on a 32-bit Windows, put there by
#                     run-wac-test.sh and deleted once installed) with a configuration of
#                     two rules — ProcessCreate of wac-sysmon-witness.exe,
#                     FileDelete archived of any "wac-sysmon" file —, runs the
#                     witness, deletes an archived file, moves Sysmon's log to
#                     the data volume (WACDATA), runs the witness again; prints
#                     what check-json.py must find, one "key=value" per line:
#       sysmon_service   service|driver
#       sysmon_rules     SHA-256 of the Rules value, read live by Windows
#       sysmon_config    the configuration file|its SHA-256|the ConfigHash value
#       sysmon_archive   the archived file|its size|its SHA-256, read live
#       sysmon_log       the moved log, as the channel's File value gives it
#       sysmon_event     the record ids of the witness's ProcessCreate (event 1)
#                        in the moved log, Get-WinEvent's reading, comma-separated
#   -Action Remove    uninstalls Sysmon and removes what the witness left: the
#                     archive folder, the moved log and the default one, the
#                     configuration, the witness and its Prefetch files — no
#                     trace kept in the VM.
#
# Usage: sysmon-witness.ps1 -Action Install|Remove -Folder C:\wactest
param([Parameter(Mandatory)][ValidateSet('Install', 'Remove')][string]$Action,
      [Parameter(Mandatory)][string]$Folder)
$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$archive = 'C:\WacSysmonArchive'
$config = Join-Path $Folder 'sysmon-config.xml'
$witness = Join-Path $Folder 'wac-sysmon-witness.exe'
$exe = if ([Environment]::Is64BitOperatingSystem) { 'Sysmon64.exe' } else { 'Sysmon.exe' }
$service = [IO.Path]::GetFileNameWithoutExtension($exe)

# A native program run quietly, its exit code returned: under 'Stop', what it
# writes to its error stream, redirected, became an error of PowerShell 5.1.
function Native([string]$program, [string[]]$arguments) {
    $ErrorActionPreference = 'Continue'
    & $program @arguments *> $null
    return $LASTEXITCODE
}

function Uninstall {
    $installed = Join-Path $env:windir $exe
    if (Test-Path -LiteralPath $installed) { Native $installed @('-u', 'force') | Out-Null }
    # -u leaves the executable in the Windows folder (measured, Sysmon 15.2).
    foreach ($path in @($installed, $archive, $witness, $config,
                        "$env:windir\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx")) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    # The witness's Prefetch files, one per folder it ran from.
    Get-ChildItem "$env:windir\Prefetch" -Filter 'WAC-SYSMON-WITNESS.EXE-*.pf' -Force | Remove-Item -Force
    $data = (Get-Volume -FileSystemLabel WACDATA -ErrorAction SilentlyContinue).DriveLetter
    if ($data -and (Test-Path "${data}:\wacsysmon")) { Remove-Item "${data}:\wacsysmon" -Recurse -Force }
}

if ($Action -eq 'Remove') { Uninstall; exit 0 }

# A cycle interrupted may have left one: removed first, never two.
Uninstall
@'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <ArchiveDirectory>WacSysmonArchive</ArchiveDirectory>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include"><Image condition="end with">wac-sysmon-witness.exe</Image></ProcessCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileDelete onmatch="include"><TargetFilename condition="contains">wac-sysmon</TargetFilename></FileDelete>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Set-Content -LiteralPath $config -Encoding ASCII
$code = Native (Join-Path $Folder $exe) @('-accepteula', '-i', $config)
if ($code -ne 0) { throw "Sysmon not installed ($code)" }
Remove-Item -LiteralPath (Join-Path $Folder $exe)   # installed in the Windows folder

Copy-Item -LiteralPath "$env:windir\System32\whoami.exe" $witness
Native $witness @() | Out-Null
$deleted = Join-Path $Folder 'wac-sysmon-deleted.txt'
Set-Content -LiteralPath $deleted -Value "WAC Sysmon witness $(Get-Date -Format o)" -Encoding ASCII
Remove-Item -LiteralPath $deleted
$data = (Get-Volume -FileSystemLabel WACDATA).DriveLetter
New-Item -ItemType Directory -Force "${data}:\wacsysmon" | Out-Null
$moved = "${data}:\wacsysmon\Sysmon-moved.evtx"
$code = Native wevtutil @('sl', $channel, "/lfn:$moved")
if ($code -ne 0) { throw "log not moved ($code)" }
Native $witness @() | Out-Null
Start-Sleep -Seconds 5

$parameters = "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
$rules = (Get-ItemProperty $parameters).Rules
$sha = [Security.Cryptography.SHA256]::Create()
"sysmon_service=$service|SysmonDrv"
"sysmon_rules=" + (($sha.ComputeHash($rules) | ForEach-Object { $_.ToString('X2') }) -join '')
"sysmon_config=$config|$((Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash)|$((Get-ItemProperty $parameters).ConfigHash)"
foreach ($f in Get-ChildItem -LiteralPath $archive -File -Force) {
    "sysmon_archive=$($f.FullName)|$($f.Length)|$((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash)"
}
"sysmon_log=" + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$channel").File
$ids = Get-WinEvent -Path $moved -FilterXPath '*[System[EventID=1]]' -ErrorAction SilentlyContinue |
       Where-Object { $_.Message -match 'wac-sysmon-witness\.exe' } | ForEach-Object { $_.RecordId }
"sysmon_event=" + ($ids -join ',')
