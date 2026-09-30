# ez-time.ps1 — times WAC's conversion and Eric Zimmerman's tool on the same
# exhibits, in the test VM (B-015).
#
# Both read the exhibit store of the last collection (C:\wactest\split\exhibits),
# never the live system: same input, and neither touches what the other reads.
# WAC converts only the artefact asked (a wac.yml of that one key); the EZ tool
# writes its CSV under C:\wactest\ez\<artefact>. Both outputs are zipped in
# C:\wactest\ez\<artefact>.zip for the host, which compares them.
#
# Usage: ez-time.ps1 -Artefact <WAC key>
param([Parameter(Mandatory)][string]$Artefact)
$ErrorActionPreference = 'Stop'

$exhibits = 'C:\wactest\split\exhibits'
$ez = 'C:\Tools\EZ'
$out = "C:\wactest\ez\$Artefact"

# WAC key -> the EZ tool, its arguments (after the output ones), and WAC's JSON files.
$tools = @{
    mft      = @{ Exe = "$ez\MFTECmd\MFTECmd.exe";            Args = @('-f', "$exhibits\`$MFT");                          Json = @('mft.json') }
    events   = @{ Exe = "$ez\EvtxECmd\EvtxeCmd\EvtxECmd.exe"; Args = @('-d', "$exhibits\Windows\System32\winevt\Logs");  Json = @('events.json') }
}
$tool = $tools[$Artefact]
if (-not $tool) { throw "no EZ tool known for '$Artefact' (known: $($tools.Keys -join ', '))" }

Set-Location C:\wactest
# Registry and events are on by default and the heaviest: off, unless asked.
# (A key repeated would refuse the configuration.)
$yaml = "artefacts:`n"
foreach ($k in @('registry', 'events')) { if ($k -ne $Artefact) { $yaml += "  $k`: false`n" } }
$yaml += "  $Artefact`: true`n"
Set-Content wac.yml $yaml
$wac = Measure-Command { & .\WAC.exe --convert=split > C:\wactest\ez-time-wac.log 2>&1 }
$wacExit = $LASTEXITCODE
Remove-Item wac.yml

if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory $out | Out-Null
$ezArgs = @($tool.Args) + @('--csv', $out)
$zim = Measure-Command { & $tool.Exe @ezArgs > "$out\console.txt" 2>&1 }
$zimExit = $LASTEXITCODE

foreach ($j in $tool.Json) { Copy-Item "C:\wactest\split\$j" $out }
Compress-Archive -Force "$out\*" "C:\wactest\ez\$Artefact.zip"
"wac_seconds={0:N1}" -f $wac.TotalSeconds
"wac_exit=$wacExit"
"ez_seconds={0:N1}" -f $zim.TotalSeconds
"ez_exit=$zimExit"
"ez_tool=" + (Split-Path -Leaf $tool.Exe)
