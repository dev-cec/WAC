# harmlessness.ps1 — records the metadata of witness files, before and after a
# WAC collection, for the harmlessness check of run-wac-test.sh.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File harmlessness.ps1 <file> [<file>...]
# Output: one line per file, "path|creation|write|access|usn", UTC
# dates in ISO 8601; "path|absent" for a missing file.
#
# WHY THESE VALUES. Opening a file through Windows can change its access date
# (when the file system keeps it) and reading nothing else; any write changes
# the others and gives the file a new change number in the NTFS journal (the
# USN kept in its $STANDARD_INFORMATION). WAC reads the volume raw: none of the
# four may move.

foreach ($path in $args) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if (-not $item) { Write-Output "$path|absent"; continue }
    # fsutil prints "Usn : 0x..." whatever the display language; the labels
    # of the other lines are translated, so only that one is read.
    $usn = ''
    foreach ($line in (fsutil usn readdata $path 2>$null)) {
        if ($line -match '^\s*Usn\s*:\s*(\S+)') { $usn = $Matches[1] }
    }
    $dates = @($item.CreationTimeUtc, $item.LastWriteTimeUtc, $item.LastAccessTimeUtc) |
        ForEach-Object { $_.ToString('o') }
    Write-Output ("$path|" + ($dates -join '|') + "|$usn")
}
