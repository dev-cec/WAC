# ez-time.ps1 — times Eric Zimmerman's tool for one artefact on the exhibits of
# the last collection, in the test VM (B-015), and packs its output with WAC's.
#
# The tool reads the exhibit store of the last collection
# (C:\wactest\split\exhibits), never the live system. WAC is NOT run again here:
# its JSON and its time are those of the cycle's one full conversion of that
# collection (split\conversion.json, time of each step). Converting one
# artefact at a time made WAC pay its fixed cost — seal and fingerprints
# checked, working copy rebuilt, hives replayed — once per artefact, when a
# conversion pays it once for all. The tool's CSV and WAC's JSON are zipped in
# C:\wactest\ez\<artefact>.zip for the host, which compares them.
#
# Usage: ez-time.ps1 -Comparison <comparison> (see the table below)
param([Parameter(Mandatory)][string]$Comparison)
$ErrorActionPreference = 'Stop'

$exhibits = 'C:\wactest\split\exhibits'
$ez = 'C:\Tools\EZ'
$out = "C:\wactest\ez\$Comparison"

# Comparison -> the EZ tool, its arguments (after the output ones), and WAC's
# JSON files to compare with.
$hives = "$exhibits\Windows\system32\config"
$tools = @{
    mft      = @{ Exe = "$ez\MFTECmd\MFTECmd.exe";            Args = @('-f', "$exhibits\`$MFT");                          Json = @('mft.json') }
    events   = @{ Exe = "$ez\EvtxECmd\EvtxeCmd\EvtxECmd.exe"; Args = @('-d', "$exhibits\Windows\System32\winevt\Logs");  Json = @('events.json') }
    recent_documents = @{ Exe = "$ez\LECmd\LECmd.exe"; Args = @('-d', "$exhibits\Users", '-q', '--all', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('recentdocs.json') }
    jump_lists = @{ Exe = "$ez\JLECmd\JLECmd.exe";        Args = @('-d', "$exhibits\Users", '-q', '--mp', '--ld');   Json = @('jumplistAutomaticDestinations.json', 'jumplistCustomDestinations.json') }
    prefetch = @{ Exe = "$ez\PECmd\PECmd.exe";                 Args = @('-d', "$exhibits\Windows\Prefetch", '-q', '--mp'); Json = @('prefetchs.json') }
    shellbags = @{ Exe = "$ez\SBECmd\SBECmd.exe";              Args = @('-d', "$exhibits\Users", '--dedupe', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('shellbags.json') }
    shimcache = @{ Exe = "$ez\AppCompatCacheParser\AppCompatCacheParser.exe"; Args = @('-f', "$hives\SYSTEM", '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('shimcache.json') }
    recycle_bin = @{ Exe = "$ez\RBCmd\RBCmd.exe"; Args = @('-d', "$exhibits\`$Recycle.Bin", '-q', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('recycle_bin.json') }
    srum     = @{ Exe = "$ez\SrumECmd\SrumECmd.exe"; Args = @('-f', "$exhibits\Windows\system32\sru\SRUDB.dat", '-r', "$hives\SOFTWARE", '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('srum.json') }
    registry = @{ Exe = "$ez\RECmd\RECmd\RECmd.exe"; Args = @('-d', $exhibits, '--bn', "$ez\RECmd\RECmd\BatchExamples\Kroll_Batch.reb", '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Json = @('userassists.json', 'bams.json', 'run.json', 'typed_paths.json', 'word_wheel_query.json', 'mounted_device.json', 'Usbstor.json', 'mrus.json', 'mruApps.json', 'muicache.json', 'services.json', 'persistence.json', 'internet_settings.json', 'firewall.json', 'OperatingSystem.json', 'users.json', 'office_trust_records.json') }
    amcache  = @{ Exe = "$ez\AmcacheParser\AmcacheParser.exe"; Args = @('-f', "$exhibits\Windows\AppCompat\Programs\Amcache.hve", '-i', '--mp'); Json = @('amcache_applications.json', 'amcache_application_files.json', 'amcache_inventory.json') }
}
$tool = $tools[$Comparison]
if (-not $tool) { throw "no EZ tool known for '$Comparison' (known: $($tools.Keys -join ', '))" }
Set-Location C:\wactest
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory $out | Out-Null
$ezArgs = @($tool.Args) + @('--csv', $out)
$zim = Measure-Command { & $tool.Exe @ezArgs > "$out\console.txt" 2>&1 }
$zimExit = $LASTEXITCODE

foreach ($j in $tool.Json) { Copy-Item "C:\wactest\split\$j" $out }
Compress-Archive -Force "$out\*" "C:\wactest\ez\$Comparison.zip"
"ez_seconds={0:N1}" -f $zim.TotalSeconds
"ez_exit=$zimExit"
"ez_tool=" + (Split-Path -Leaf $tool.Exe)
