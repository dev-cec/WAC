# ez-time.ps1 — times Eric Zimmerman's tool for one artefact on a copy of the
# exhibits of the last collection, in the test VM (B-015), and packs its output with WAC's.
#
# The tool reads a COPY of its inputs, taken from the exhibit store of the last
# collection (C:\wactest\split\exhibits) into C:\wactest\ez\input, never the
# live system and never the store itself: SrumECmd opens SRUDB.dat with
# JetInit, which writes its checkpoint and logs beside the database — run on
# the store, it altered four sealed exhibits and WAC refused the next
# conversion. The copy is not timed and is removed afterwards. WAC is NOT run
# again here:
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

$store = 'C:\wactest\split\exhibits'
$exhibits = 'C:\wactest\ez\input'
$ez = 'C:\Tools\EZ'
$out = "C:\wactest\ez\$Comparison"

# Comparison -> the EZ tool, its arguments (after the output ones), the parts
# of the store it reads (copied), and WAC's JSON files to compare with.
$hives = "$exhibits\Windows\system32\config"
$tools = @{
    mft      = @{ Exe = "$ez\MFTECmd\MFTECmd.exe";            Args = @('-f', "$exhibits\`$MFT");                          Inputs = @('$MFT'); Json = @('mft.json') }
    events   = @{ Exe = "$ez\EvtxECmd\EvtxeCmd\EvtxECmd.exe"; Args = @('-d', "$exhibits\Windows\System32\winevt\Logs");  Inputs = @('Windows\System32\winevt\Logs'); Json = @('events.json') }
    recent_documents = @{ Exe = "$ez\LECmd\LECmd.exe"; Args = @('-d', "$exhibits\Users", '-q', '--all', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Inputs = @('Users'); Json = @('recentdocs.json') }
    jump_lists = @{ Exe = "$ez\JLECmd\JLECmd.exe";        Args = @('-d', "$exhibits\Users", '-q', '--mp', '--ld');   Inputs = @('Users'); Json = @('jumplistAutomaticDestinations.json', 'jumplistCustomDestinations.json') }
    prefetch = @{ Exe = "$ez\PECmd\PECmd.exe";                 Args = @('-d', "$exhibits\Windows\Prefetch", '-q', '--mp'); Inputs = @('Windows\Prefetch'); Json = @('prefetchs.json') }
    shellbags = @{ Exe = "$ez\SBECmd\SBECmd.exe";              Args = @('-d', "$exhibits\Users", '--dedupe', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Inputs = @('Users'); Json = @('shellbags.json') }
    shimcache = @{ Exe = "$ez\AppCompatCacheParser\AppCompatCacheParser.exe"; Args = @('-f', "$hives\SYSTEM", '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Inputs = @('Windows\system32\config'); Json = @('shimcache.json') }
    recycle_bin = @{ Exe = "$ez\RBCmd\RBCmd.exe"; Args = @('-d', "$exhibits\`$Recycle.Bin", '-q', '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Inputs = @('$Recycle.Bin'); Json = @('recycle_bin.json') }
    srum     = @{ Exe = "$ez\SrumECmd\SrumECmd.exe"; Args = @('-f', "$exhibits\Windows\system32\sru\SRUDB.dat", '-r', "$hives\SOFTWARE", '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Inputs = @('Windows\system32\sru', 'Windows\system32\config'); Json = @('srum.json') }
    registry = @{ Exe = "$ez\RECmd\RECmd\RECmd.exe"; Args = @('-d', $exhibits, '--bn', "$ez\RECmd\RECmd\BatchExamples\Kroll_Batch.reb", '--dt', 'yyyy-MM-dd HH:mm:ss.fffffff'); Inputs = @('.'); Json = @('userassists.json', 'bams.json', 'run.json', 'typed_paths.json', 'word_wheel_query.json', 'mounted_device.json', 'Usbstor.json', 'mrus.json', 'mruApps.json', 'muicache.json', 'services.json', 'persistence.json', 'internet_settings.json', 'firewall.json', 'OperatingSystem.json', 'users.json', 'office_trust_records.json') }
    amcache  = @{ Exe = "$ez\AmcacheParser\AmcacheParser.exe"; Args = @('-f', "$exhibits\Windows\AppCompat\Programs\Amcache.hve", '-i', '--mp'); Inputs = @('Windows\AppCompat\Programs'); Json = @('amcache_applications.json', 'amcache_application_files.json', 'amcache_inventory.json') }
}
$tool = $tools[$Comparison]
if (-not $tool) { throw "no EZ tool known for '$Comparison' (known: $($tools.Keys -join ', '))" }
Set-Location C:\wactest
# Removed through \\?\ (cmd's rd) and copied by robocopy: the store holds paths
# past 260 characters (B-049), which Remove-Item and Copy-Item fail on.
function Remove-Tree([string]$folder) {
    if (Test-Path -LiteralPath $folder) { cmd /c "rd /s /q \\?\$folder" }
}
function Copy-Part([string]$source, [string]$target, [string]$file) {
    $options = @('/R:0', '/W:0', '/NJH', '/NJS', '/NFL', '/NDL', '/NP')
    if ($file) { robocopy $source $target $file @options | Out-Null } else { robocopy $source $target /E @options | Out-Null }
    if ($LASTEXITCODE -ge 8) { throw "robocopy $source -> $target failed ($LASTEXITCODE)" }
}
Remove-Tree $out
New-Item -ItemType Directory $out | Out-Null
Remove-Tree $exhibits
foreach ($part in $tool.Inputs) {
    $source = Join-Path $store $part
    if ($part -eq '.') { Copy-Part $store $exhibits '' }        # RECmd looks for the hives in the whole store
    elseif (Test-Path -LiteralPath $source -PathType Leaf) { Copy-Part (Split-Path $source) (Split-Path (Join-Path $exhibits $part)) (Split-Path -Leaf $source) }
    else { Copy-Part $source (Join-Path $exhibits $part) '' }
}
$ezArgs = @($tool.Args) + @('--csv', $out)
$zim = Measure-Command { & $tool.Exe @ezArgs > "$out\console.txt" 2>&1 }
$zimExit = $LASTEXITCODE
Remove-Tree $exhibits

foreach ($j in $tool.Json) { Copy-Item "C:\wactest\split\$j" $out }
Compress-Archive -Force "$out\*" "C:\wactest\ez\$Comparison.zip"
"ez_seconds={0:N1}" -f $zim.TotalSeconds
"ez_exit=$zimExit"
"ez_tool=" + (Split-Path -Leaf $tool.Exe)
