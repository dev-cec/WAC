# install-browsers.ps1 — installs Google Chrome and Mozilla Firefox in the test
# VM, silently, for the web client tests (backlog B-016): the browsers' real
# databases, written by the browsers themselves, are what web_client.json is
# confronted with. Idempotent: an installed browser is left as it is.
# Prints one "browser=<name>|<version>" line per browser.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$work = 'C:\wactest\installers'
New-Item -ItemType Directory -Force $work | Out-Null

$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
if (-not (Test-Path $chrome)) {
    # The enterprise MSI: installs for all users, without a prompt.
    $msi = "$work\chrome.msi"
    Invoke-WebRequest -UseBasicParsing 'https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi' -OutFile $msi
    Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait
}
if (Test-Path $chrome) { Write-Output ("browser=Chrome|" + (Get-Item $chrome).VersionInfo.ProductVersion) }

$firefox = 'C:\Program Files\Mozilla Firefox\firefox.exe'
if (-not (Test-Path $firefox)) {
    $setup = "$work\firefox-setup.exe"
    Invoke-WebRequest -UseBasicParsing 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=fr' -OutFile $setup
    Start-Process $setup -ArgumentList '/S' -Wait
}
if (Test-Path $firefox) { Write-Output ("browser=Firefox|" + (Get-Item $firefox).VersionInfo.ProductVersion) }
