# install-agent-driver.ps1 — installs the driver of the guest agent's channel
# (vioserial) in a test VM, without a question asked.
#
# Run at the first logon by the answer file create-vm.sh builds, for the
# versions of Windows the virtio-win guest tools installer does not handle.
# Windows asks "Would you like to install this device software?" for a driver
# whose publisher it does not trust yet, and nobody is there to answer: the
# publisher's certificate, read on the driver's signed catalogue, is put in the
# machine's trusted publishers first. Written for PowerShell 2 (Windows 7).
#
# Usage: install-agent-driver.ps1 <folder of the driver under vioserial>, e.g. w8\x86
# What it did is in %SystemRoot%\Temp\wac-agent-driver.log.
param([string]$Drivers)

$log = Join-Path $env:SystemRoot 'Temp\wac-agent-driver.log'
function Note([string]$text) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format s), $text) }

$folder = $null
foreach ($drive in [IO.DriveInfo]::GetDrives()) {
    if (-not $drive.IsReady) { continue }
    $candidate = Join-Path $drive.RootDirectory.FullName "vioserial\$Drivers"
    if (Test-Path (Join-Path $candidate 'vioser.inf')) { $folder = $candidate; break }
}
if (-not $folder) { Note "no vioserial\$Drivers\vioser.inf on any drive"; exit 1 }
Note "driver found in $folder"

try {
    $signer = [Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile((Join-Path $folder 'vioser.cat'))
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($signer)
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine')
    $store.Open('ReadWrite')
    $store.Add($certificate)
    $store.Close()
    Note "publisher trusted: $($certificate.Subject)"
} catch {
    Note "publisher NOT trusted: $($_.Exception.Message)"
}

$output = & pnputil.exe -i -a (Join-Path $folder 'vioser.inf') 2>&1
Note ("pnputil: " + (($output | Out-String).Trim() -replace '\s+', ' '))
exit $LASTEXITCODE
