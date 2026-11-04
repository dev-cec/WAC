# install-replica-controller.ps1 — one side of the pair of controllers made by
# install-replica-controller.sh. On the first controller: the address on the
# private link, its records in the zone corrected. On the replica: the same link,
# then its promotion. Throw-away VMs: the password is the synthetic one of the
# server VMs, and the firewall is opened on the private link alone.
param([ValidateSet('first', 'replica')][string]$Role, [string]$Administrator)
$ErrorActionPreference = 'Stop'
$password = 'Wac-Server-2026!'
$firstAddress = '10.50.0.1'
$macAddress = $(if ($Role -eq 'first') { '52-54-00-57-41-01' } else { '52-54-00-57-41-02' })
$address = $(if ($Role -eq 'first') { $firstAddress } else { '10.50.0.2' })

$link = Get-NetAdapter | Where-Object { $_.MacAddress -eq $macAddress }
if (-not $link) { throw "no adapter $macAddress" }
if (-not (Get-NetIPAddress -InterfaceIndex $link.ifIndex -IPAddress $address -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $link.ifIndex -IPAddress $address -PrefixLength 24 | Out-Null
}
Set-DnsClientServerAddress -InterfaceIndex $link.ifIndex -ServerAddresses $firstAddress
Set-NetFirewallProfile -All -DisabledInterfaceAliases $link.Name
$outside = Get-NetAdapter | Where-Object { $_.MacAddress -ne $macAddress }

if ($Role -eq 'first') {
    # Every test VM has 10.0.2.15 on its user-mode network, which the other cannot
    # reach: a record of that address would send the replica to itself.
    $outside | ForEach-Object { Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $false }
    foreach ($zone in 'wac.test', '_msdcs.wac.test') {
        Get-DnsServerResourceRecord -ZoneName $zone -RRType A -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordData.IPv4Address.ToString() -eq '10.0.2.15' } |
            ForEach-Object { Remove-DnsServerResourceRecord -ZoneName $zone -InputObject $_ -Force }
    }
    & ipconfig.exe /registerdns | Out-Null
    Restart-Service Netlogon
    Write-Output '   first controller on the private link'
    exit 0
}

# Its only way out is the link: the user-mode network would answer for 10.0.2.15.
$outside | Disable-NetAdapter -Confirm:$false
if ($env:COMPUTERNAME -ne 'WAC-TEST2') {
    Rename-Computer -NewName 'WAC-TEST2' -Force
    Write-Output 'renamed'
    & shutdown.exe /r /t 5 /c 'WAC: replica' | Out-Null
    exit 0
}
if ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2) { Write-Output '   already a controller'; exit 0 }
$secure = ConvertTo-SecureString $password -AsPlainText -Force
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
Install-ADDSDomainController -DomainName 'wac.test' -InstallDns -SafeModeAdministratorPassword $secure `
    -Credential (New-Object System.Management.Automation.PSCredential("WACTEST\$Administrator", $secure)) `
    -Force -NoRebootOnCompletion -WarningAction SilentlyContinue | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultDomainName -Value 'WACTEST'
& shutdown.exe /r /t 20 /c 'WAC: replica controller' | Out-Null
Write-Output '   replica promoted, the VM restarts'
