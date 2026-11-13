# install-server-roles.ps1 — the roles B-038's artefacts read, on this server
# (see install-server-roles.sh): DNS, DHCP, Hyper-V, Remote Desktop Session Host,
# licensing and gateway, File Server Resource Manager, and a certification
# authority (Active Directory Certificate Services, standalone root: B-071's
# witness, its database under System32\CertLog). Idempotent; restarts the
# VM when a role asks for it. Only a throw-away VM gets these.
$ErrorActionPreference = 'Stop'
$roles = 'DNS','DHCP','Hyper-V','RDS-RD-Server','RDS-Licensing','RDS-Gateway','FS-Resource-Manager','ADCS-Cert-Authority'
$result = Install-WindowsFeature $roles -IncludeManagementTools
$result.FeatureResult | ForEach-Object { Write-Output ('   ' + $_.Name + ': ' + $_.Success) }
# The authority configured once: a standalone root (no domain on this VM).
if (-not (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active -ErrorAction SilentlyContinue)) {
    Import-Module ADCSDeployment
    Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName 'wac-test-ca' -Force | Out-Null
    Write-Output '   certification authority wac-test-ca configured'
}
if ($result.RestartNeeded -eq 'Yes') {
    & shutdown.exe /r /t 20 /c 'WAC: server roles' | Out-Null
    Write-Output '   the VM restarts'
}
