# kape-compare.ps1 — collects the test VM with WAC then with KAPE, one right
# after the other, and times both (B-015): what each copies, and how fast.
#
# WAC runs with the configuration of its kit (bin/wac.yml, sent beside WAC.exe
# by the host), as a responder would launch it; KAPE with its recommended target, KapeTriage, without shadow
# copies (its default). Both outputs are written to C:\kape and zipped for the
# host: WAC's exhibit manifest, KAPE's copy log.
#
# Usage: kape-compare.ps1 [-Target KapeTriage]
param([string]$Target = 'KapeTriage')
$ErrorActionPreference = 'Stop'

$root = 'C:\kape'
$kape = 'C:\Tools\KAPE-archive\KAPE\kape.exe'
if (Test-Path $root) { Remove-Item -Recurse -Force $root }
New-Item -ItemType Directory $root | Out-Null

Set-Location C:\wactest
if (-not (Test-Path wac.yml)) { throw "wac.yml of the kit absent beside WAC.exe" }
if (Test-Path kapecmp) { Remove-Item -Recurse -Force kapecmp }
$wac = Measure-Command { & .\WAC.exe --collect --output=kapecmp > "$root\wac-console.txt" 2>&1 }
$wacExit = $LASTEXITCODE

$tdest = "$root\tdest"
$k = Measure-Command { & $kape --tsource C: --target $Target --tdest $tdest --tflush > "$root\kape-console.txt" 2>&1 }
$kapeExit = $LASTEXITCODE

Copy-Item C:\wactest\kapecmp\exhibits\MANIFEST.json "$root\wac-manifest.json"
Get-ChildItem $tdest -Recurse -Filter *CopyLog*.csv | Copy-Item -Destination $root
Get-ChildItem $tdest -Recurse -Filter *SkipLog*.csv -ErrorAction SilentlyContinue | Copy-Item -Destination $root
$wacBytes = (Get-ChildItem C:\wactest\kapecmp -Recurse -File | Measure-Object Length -Sum).Sum
$kapeBytes = (Get-ChildItem $tdest -Recurse -File | Measure-Object Length -Sum).Sum
Compress-Archive -Force "$root\*.csv", "$root\*.json", "$root\*.txt" "$root\kape-compare.zip"
"wac_seconds={0:N1}" -f $wac.TotalSeconds
"wac_exit=$wacExit"
"wac_bytes=$wacBytes"
"kape_seconds={0:N1}" -f $k.TotalSeconds
"kape_exit=$kapeExit"
"kape_bytes=$kapeBytes"
"kape_target=$Target"
