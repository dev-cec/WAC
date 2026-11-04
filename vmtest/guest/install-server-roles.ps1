# install-server-roles.ps1 — the roles B-038's artefacts read, on this server
# (see install-server-roles.sh): DNS, DHCP, Hyper-V, Remote Desktop Session Host,
# licensing and gateway, File Server Resource Manager. Idempotent; restarts the
# VM when a role asks for it. Only a throw-away VM gets these.
$ErrorActionPreference = 'Stop'
$roles = 'DNS','DHCP','Hyper-V','RDS-RD-Server','RDS-Licensing','RDS-Gateway','FS-Resource-Manager'
$result = Install-WindowsFeature $roles -IncludeManagementTools
$result.FeatureResult | ForEach-Object { Write-Output ('   ' + $_.Name + ': ' + $_.Success) }
if ($result.RestartNeeded -eq 'Yes') {
    & shutdown.exe /r /t 20 /c 'WAC: server roles' | Out-Null
    Write-Output '   the VM restarts'
}
