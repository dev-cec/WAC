# prepare-wac-key.ps1 — the collection key: the virtual USB disk of serial
# WACUSB0003 that run-wac-test.sh attaches, which holds WAC.exe, its wac.yml,
# its trust set and every output, as on the field — WAC runs from a key and
# writes there, never on the examined disk. Formatted NTFS, label WACKIT, on
# first use; its letter, W: when free, kept by Windows from one run to the next.
# Through WMI and diskpart: the Storage cmdlets arrive with Windows 8 and
# Server 2012, the harness also runs on Windows 7 and Server 2008 R2.
# Prints the key's letter ("W"), or "absent" when Windows shows no such disk.
$ErrorActionPreference = 'Stop'
$label = 'WACKIT'
function KeyVolume { Get-WmiObject Win32_Volume | Where-Object { $_.Label -eq $label -and $_.DriveLetter } | Select-Object -First 1 }
$volume = KeyVolume
if (-not $volume) {
    $disk = Get-WmiObject Win32_DiskDrive | Where-Object { $_.PNPDeviceID -like '*WACUSB0003*' } | Select-Object -First 1
    if (-not $disk) { Write-Output 'absent'; exit 0 }
    $taken = @(Get-WmiObject Win32_LogicalDisk | ForEach-Object { $_.DeviceID.Substring(0, 1) })
    $letter = @('W', 'V', 'U', 'T', 'S') | Where-Object { $taken -notcontains $_ } | Select-Object -First 1
    $script = Join-Path $env:TEMP 'wac-key-diskpart.txt'
    # "clean" only on that disk, found by its serial: the examined disks are never touched.
    Set-Content -Path $script -Encoding ASCII -Value @(
        "select disk $($disk.Index)", 'clean', 'create partition primary',
        "format fs=ntfs label=$label quick", "assign letter=$letter")
    try { $said = & diskpart.exe /s $script } finally { Remove-Item $script -ErrorAction SilentlyContinue }
    for ($i = 0; $i -lt 30 -and -not $volume; $i++) { Start-Sleep 2; $volume = KeyVolume }
    # What diskpart said, before the verdict: the reason of a failure.
    if (-not $volume) { $said | Where-Object { $_ -match '\S' } | ForEach-Object { "diskpart: $_" }; Write-Output 'not formatted'; exit 1 }
}
Write-Output $volume.DriveLetter.Substring(0, 1)
