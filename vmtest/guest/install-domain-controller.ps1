# install-domain-controller.ps1 — the forest wac.test on this server (see
# install-domain-controller.sh). The Directory Services Restore password and the
# accounts are those of a throw-away VM. The automatic logon then names the
# domain: the local account wac has become WACTEST\wac.
$ErrorActionPreference = 'Stop'
if ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2) { Write-Output '   already a domain controller'; exit 0 }
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
$safeMode = ConvertTo-SecureString 'Wac-Server-2026!' -AsPlainText -Force
# The local Administrator becomes the domain's, and promotion refuses its empty
# password. Found by its RID: its name depends on the language of Windows.
$administrator = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
$administrator | Set-LocalUser -Password $safeMode -PasswordNeverExpires $true
Install-ADDSForest -DomainName 'wac.test' -DomainNetbiosName 'WACTEST' -SafeModeAdministratorPassword $safeMode `
    -InstallDns -Force -NoRebootOnCompletion -WarningAction SilentlyContinue | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value 'WACTEST'
& shutdown.exe /r /t 20 /c 'WAC: domain controller' | Out-Null
Write-Output '   forest wac.test created, the VM restarts'
