# install-domain-controller.ps1 — the forest wac.test on this server (see
# install-domain-controller.sh). The Directory Services Restore password and the
# accounts are those of a throw-away VM. The automatic logon then names the
# domain: the local account wac has become WACTEST\wac.
$ErrorActionPreference = 'Stop'
if ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2) { Write-Output '   already a domain controller'; exit 0 }
$password = 'Wac-Server-2026!'
# The local Administrator becomes the domain's, and promotion refuses its empty
# password. Found by its RID: its name depends on the language of Windows. Through
# WMI and net.exe: Get-LocalUser needs PowerShell 5, which Server 2012 R2 has not.
$administrator = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -like '*-500' }
& net.exe user $administrator.Name $password | Out-Null
$administrator.PasswordExpires = $false
$administrator.Put() | Out-Null
if ($PSVersionTable.PSVersion.Major -ge 3) {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
    Import-Module ADDSDeployment
    Install-ADDSForest -DomainName 'wac.test' -DomainNetbiosName 'WACTEST' -SafeModeAdministratorPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
        -InstallDns -Force -NoRebootOnCompletion -WarningAction SilentlyContinue | Out-Null
} else {
    # Server 2008 R2: no deployment module, dcpromo and its answer file.
    $answers = Join-Path $env:TEMP 'wac-dcpromo.txt'
    @('[DCInstall]', 'ReplicaOrNewDomain=Domain', 'NewDomain=Forest', 'NewDomainDNSName=wac.test', 'DomainNetBiosName=WACTEST',
      'ForestLevel=4', 'DomainLevel=4', 'InstallDNS=Yes', "SafeModeAdminPassword=$password", 'RebootOnCompletion=No') | Set-Content $answers
    & dcpromo.exe "/unattend:$answers" | Out-Null
    Remove-Item $answers
}
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value 'WACTEST'
& shutdown.exe /r /t 20 /c 'WAC: domain controller' | Out-Null
Write-Output '   forest wac.test created, the VM restarts'
