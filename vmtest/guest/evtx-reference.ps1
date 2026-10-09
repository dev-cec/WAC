# evtx-reference.ps1 — the arbiter of the events comparison (ez-compare.sh
# events): for each record WAC and EvtxECmd disagree on, the EventData values
# Windows itself renders (Get-WinEvent, its XML), read from the same .evtx of
# the exhibit store — a copy of it, never the store itself, which stays as
# sealed (removed afterwards). Written to C:\wactest\ez\windows-eventdata.json, as
# { "<log file>|<record id>": [values…] }.
$ErrorActionPreference = 'Stop'
$store = 'C:\wactest\split\exhibits\Windows\System32\winevt\Logs'
$logs = 'C:\wactest\ez\input-evtx'
New-Item -ItemType Directory -Force $logs | Out-Null
$rendered = [ordered]@{}
foreach ($line in Get-Content C:\wactest\ez\evtx-differences.txt) {
    if (-not $line) { continue }
    $log, $record = $line -split '\|'
    if (-not (Test-Path -LiteralPath (Join-Path $logs $log))) { Copy-Item -LiteralPath (Join-Path $store $log) $logs }
    $event = Get-WinEvent -Path (Join-Path $logs $log) -FilterXPath "*[System[EventRecordID=$record]]" -ErrorAction SilentlyContinue
    if (-not $event) { continue }
    $xml = ([xml]$event.ToXml()).Event
    if ($xml.EventData) {
        $values = @($xml.EventData.Data | ForEach-Object { if ($_ -is [string]) { $_ } else { $_.'#text' } })
    } else {
        # A manifest event's UserData: one element, its children the values, in order.
        $values = @($xml.UserData.FirstChild.ChildNodes | ForEach-Object { $_.InnerText })
    }
    $rendered[$line] = @($values | Where-Object { $_ -ne $null -and $_ -ne '' })
}
$rendered | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 C:\wactest\ez\windows-eventdata.json
"$($rendered.Count) record(s) rendered by Windows"
Remove-Item -Recurse -Force $logs
