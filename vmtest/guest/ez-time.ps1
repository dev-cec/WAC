# ez-time.ps1 — times WAC's conversion and Eric Zimmerman's tool on the same
# exhibits, in the test VM (B-015).
#
# Both read the exhibit store of the last collection (C:\wactest\split\exhibits),
# never the live system: same input, and neither touches what the other reads.
# WAC converts only the artefact asked (a wac.yml of that one key); the EZ tool
# writes its CSV under C:\wactest\ez\<artefact>. Both outputs are zipped in
# C:\wactest\ez\<artefact>.zip for the host, which compares them.
#
# Usage: ez-time.ps1 -Comparison <comparison> (see the table below)
param([Parameter(Mandatory)][string]$Comparison)
$ErrorActionPreference = 'Stop'

$exhibits = 'C:\wactest\split\exhibits'
$ez = 'C:\Tools\EZ'
$out = "C:\wactest\ez\$Comparison"

# Comparison -> the WAC key it converts, the EZ tool, its arguments (after the
# output ones), and WAC's JSON files. Several comparisons share the registry key.
$hives = "$exhibits\Windows\system32\config"
$tools = @{
    mft      = @{ Key = 'mft';      Exe = "$ez\MFTECmd\MFTECmd.exe";            Args = @('-f', "$exhibits\`$MFT");                          Json = @('mft.json') }
    events   = @{ Key = 'events';   Exe = "$ez\EvtxECmd\EvtxeCmd\EvtxECmd.exe"; Args = @('-d', "$exhibits\Windows\System32\winevt\Logs");  Json = @('events.json') }
    recent_documents = @{ Key = 'recent_documents'; Exe = "$ez\LECmd\LECmd.exe"; Args = @('-d', "$exhibits\Users", '-q', '--all', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('recentdocs.json') }
    jump_lists = @{ Key = 'jump_lists'; Exe = "$ez\JLECmd\JLECmd.exe";        Args = @('-d', "$exhibits\Users", '-q', '--mp', '--ld');   Json = @('jumplistAutomaticDestinations.json', 'jumplistCustomDestinations.json') }
    prefetch = @{ Key = 'prefetch'; Exe = "$ez\PECmd\PECmd.exe";                 Args = @('-d', "$exhibits\Windows\Prefetch", '-q', '--mp'); Json = @('prefetchs.json') }
    shellbags = @{ Key = 'registry'; Exe = "$ez\SBECmd\SBECmd.exe";              Args = @('-d', "$exhibits\Users", '--dedupe', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('shellbags.json') }
    shimcache = @{ Key = 'registry'; Exe = "$ez\AppCompatCacheParser\AppCompatCacheParser.exe"; Args = @('-f', "$hives\SYSTEM", '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('shimcache.json') }
    amcache  = @{ Key = 'registry'; Exe = "$ez\AmcacheParser\AmcacheParser.exe"; Args = @('-f', "$exhibits\Windows\AppCompat\Programs\Amcache.hve", '-i', '--mp'); Json = @('amcache_applications.json', 'amcache_application_files.json', 'amcache_inventory.json') }
}
$tool = $tools[$Comparison]
if (-not $tool) { throw "no EZ tool known for '$Comparison' (known: $($tools.Keys -join ', '))" }
$key = $tool.Key

Set-Location C:\wactest
# Registry and events are on by default and the heaviest: off, unless asked.
# (A key repeated would refuse the configuration.)
$yaml = "artefacts:`n"
foreach ($k in @('registry', 'events')) { if ($k -ne $key) { $yaml += "  $k`: false`n" } }
$yaml += "  $key`: true`n"
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
Compress-Archive -Force "$out\*" "C:\wactest\ez\$Comparison.zip"
"wac_seconds={0:N1}" -f $wac.TotalSeconds
"wac_exit=$wacExit"
"ez_seconds={0:N1}" -f $zim.TotalSeconds
"ez_exit=$zimExit"
"ez_tool=" + (Split-Path -Leaf $tool.Exe)
