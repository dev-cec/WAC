# server-roles-witness.ps1 — witnesses of the role artefacts (dns_server,
# dhcp_server, hyperv): what WAC must find, set by Windows' own tools, then listed
# by the same tools as the reference: <out>\server-roles-reference.json.
# Idempotent: a witness in place is not added twice. Throw-away VM only: the
# plug-in and callout values name no real DLL, the services are not restarted on them.
param([Parameter(Mandatory = $true)] [string] $Out)
$ErrorActionPreference = 'Stop'
# Parsed by PowerShell 2 too (Server 2008 R2): no [ordered], which is
# PowerShell 3; an ordered dictionary keeps the order of the sections.
$reference = New-Object Collections.Specialized.OrderedDictionary

# DNS: a file-backed zone with one record per common type, debug logging on, one query answered.
if (Get-Service DNS -ErrorAction SilentlyContinue) {
    Import-Module DnsServer
    if (-not (Get-DnsServerZone -Name 'wac-witness.test' -ErrorAction SilentlyContinue)) {
        Add-DnsServerPrimaryZone -Name 'wac-witness.test' -ZoneFile 'wac-witness.test.dns'
        Add-DnsServerResourceRecordA -ZoneName 'wac-witness.test' -Name 'host1' -IPv4Address '192.0.2.10' -TimeToLive 00:10:00
        Add-DnsServerResourceRecordAAAA -ZoneName 'wac-witness.test' -Name 'host1' -IPv6Address '2001:db8::10'
        Add-DnsServerResourceRecordCName -ZoneName 'wac-witness.test' -Name 'alias' -HostNameAlias 'host1.wac-witness.test'
        Add-DnsServerResourceRecordMX -ZoneName 'wac-witness.test' -Name '.' -MailExchange 'mail.wac-witness.test' -Preference 10
        Add-DnsServerResourceRecord -ZoneName 'wac-witness.test' -Name 'note' -Txt -DescriptiveText 'wac witness; quoted "text"'
        dnscmd.exe localhost /ZoneWriteBack wac-witness.test | Out-Null
    }
    Add-DnsServerForwarder -IPAddress '192.0.2.53' -ErrorAction SilentlyContinue
    Set-DnsServerDiagnostics -Queries $true -Answers $true -ReceivePackets $true -SendPackets $true -UdpPackets $true -TcpPackets $true -QuestionTransactions $true -EnableLoggingToFile $true
    # A plug-in DLL is how a DnsAdmins member runs code as SYSTEM: the value only, never loaded (no restart).
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name ServerLevelPluginDll -Value 'C:\wactest\wac-plugin-witness.dll'
    Resolve-DnsName 'host1.wac-witness.test' -Server 127.0.0.1 -DnsOnly | Out-Null
    dnscmd.exe localhost /ZoneWriteBack wac-witness.test | Out-Null
    $reference.DnsZones = @(Get-DnsServerZone | Select-Object ZoneName, ZoneType, ZoneFile, IsDsIntegrated, IsReverseLookupZone)
    $reference.DnsRecords = @(Get-DnsServerResourceRecord -ZoneName 'wac-witness.test' | ForEach-Object { @{ Name = $_.HostName; Type = $_.RecordType; Ttl = [int]$_.TimeToLive.TotalSeconds } })
    $reference.DnsForwarders = @((Get-DnsServerForwarder).IPAddress | ForEach-Object { $_.IPAddressToString })
}

# DHCP: a scope, a reservation, a lease; the callout value, as for DNS.
if (Get-Service DHCPServer -ErrorAction SilentlyContinue) {
    Import-Module DhcpServer
    if (-not (Get-DhcpServerv4Scope -ScopeId 192.0.2.0 -ErrorAction SilentlyContinue)) {
        Add-DhcpServerv4Scope -Name 'wac witness scope' -StartRange 192.0.2.100 -EndRange 192.0.2.200 -SubnetMask 255.255.255.0
        Add-DhcpServerv4Reservation -ScopeId 192.0.2.0 -IPAddress 192.0.2.150 -ClientId '00-15-5d-00-00-01' -Name 'reserved.wac-witness.test'
        Add-DhcpServerv4Lease -ScopeId 192.0.2.0 -IPAddress 192.0.2.151 -ClientId '00-15-5d-00-00-02' -HostName 'leased.wac-witness.test' -LeaseExpiryTime (Get-Date).AddDays(3)
    }
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters' -Name CalloutDlls -Type MultiString -Value @('C:\wactest\wac-callout-witness.dll')
    $reference.DhcpScopes = @(Get-DhcpServerv4Scope | ForEach-Object { @{ ScopeId = $_.ScopeId.IPAddressToString; Name = $_.Name } })
    $reference.DhcpLeases = @(Get-DhcpServerv4Lease -ScopeId 192.0.2.0 | ForEach-Object { @{ Address = $_.IPAddress.IPAddressToString; ClientId = $_.ClientId; HostName = $_.HostName; State = $_.AddressState; ExpiresUtc = if ($_.LeaseExpiryTime) { $_.LeaseExpiryTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') } } })
}

# Hyper-V: a machine never started, with a disk file named in its configuration.
if (Get-Service vmms -ErrorAction SilentlyContinue) {
    Import-Module Hyper-V
    if (-not (Get-VM -Name 'wac-witness-vm' -ErrorAction SilentlyContinue)) {
        New-VHD -Path 'C:\wactest\wac-witness-vm.vhdx' -SizeBytes 64MB -Dynamic | Out-Null
        New-VM -Name 'wac-witness-vm' -MemoryStartupBytes 64MB -Generation 2 -VHDPath 'C:\wactest\wac-witness-vm.vhdx' | Out-Null
    }
    # A machine kept outside the default folder, as a real host's usually are.
    if (-not (Get-VM -Name 'wac-witness-elsewhere' -ErrorAction SilentlyContinue)) {
        New-VM -Name 'wac-witness-elsewhere' -MemoryStartupBytes 64MB -Generation 2 -NoVHD -Path 'C:\wactest\vmext' | Out-Null
    }
    $reference.HyperVMachines = @(Get-VM | ForEach-Object { @{ Name = $_.Name; Id = $_.Id.ToString(); ConfigurationLocation = $_.ConfigurationLocation; Disks = @($_.HardDrives.Path) } })
}

# The Remote Desktop licensing server's database, taken raw.
$reference.RdsLicensingDatabase = Test-Path 'C:\Windows\System32\lserver\TLSLic.edb'

$file = Join-Path $Out 'server-roles-reference.json'
if (Get-Command ConvertTo-Json -ErrorAction SilentlyContinue) {
    $reference | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $file
} else {
    # PowerShell 2 has no ConvertTo-Json, nor the roles' modules: a role there
    # stopped the script above, and the reference holds the database alone.
    "{ `"RdsLicensingDatabase`": $($reference.RdsLicensingDatabase.ToString().ToLower()) }" | Set-Content -Encoding UTF8 $file
}
