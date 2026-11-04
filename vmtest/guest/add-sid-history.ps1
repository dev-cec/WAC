# add-sid-history.ps1 — gives the directory's witness a sIDHistory (see
# add-sid-history.sh). Windows gives no way to write one short of a migration
# between two forests: DSInternals writes it in ntds.dit, with the directory's
# service stopped. On a throw-away controller of the harness, never on one examined.
param([string]$ModuleFolder, [string]$History)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $ModuleFolder 'DSInternals.psd1')
$database = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters').'DSA Database file'
Stop-Service NTDS -Force
try { Add-ADDBSidHistory -SamAccountName 'wacwitness' -SidHistory $History -DatabasePath $database -Force }
finally { Start-Service NTDS }
Import-Module ActiveDirectory
foreach ($attempt in 1..40) {
    try { $user = Get-ADUser -Identity 'wacwitness' -Properties sIDHistory; break } catch { Start-Sleep -Seconds 15 }
}
Write-Output "sIDHistory: $($user.sIDHistory)"
