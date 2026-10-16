# event-messages-reference.ps1 — what Windows itself makes of each kind of
# event of the machine: the reference of the messages of events.json (B-023).
#
# For every log, the first event of each provider / identifier / version /
# qualifiers is given with the message Windows renders for it
# (EventLogRecord.Message, that is EvtFormatMessage). The message is only
# asked of that first event: rendering every event would take minutes and
# tell nothing more, the template being the provider's.
#
# One line per kind, UTF-8:
#   provider|id|version|qualifiers|log|recordId|message
# the message on one line, escaped — "\\" for a backslash, "\r" and "\n" for
# the carriage returns and line feeds of the message, which are part of it
# (a %r of a template is one) —, empty when Windows has none.
# Reads only: nothing written to the logs.
param([string]$Output = 'C:\wactest\event-messages.txt')
$ErrorActionPreference = 'SilentlyContinue'
# In the interface language, as the Event Viewer shows it: .NET hands
# EvtFormatMessage the regional culture, and a binary holding its messages in
# several languages (msimsg.dll) then answered in French on a Windows 8 whose
# interface is English and whose formats are French.
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::CurrentUICulture
$seen = @{}
$lines = New-Object System.Collections.Generic.List[string]
foreach ($log in (Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 })) {
    foreach ($e in (Get-WinEvent -LogName $log.LogName -Oldest)) {
        $qualifiers = if ($null -ne $e.Qualifiers) { $e.Qualifiers } else { '' }
        $key = "$($e.ProviderName)|$($e.Id)|$($e.Version)|$qualifiers"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $message = try { $e.Message } catch { $null }
        if ($null -eq $message) { $message = '' }
        $escaped = $message.Replace('\', '\\').Replace("`r", '\r').Replace("`n", '\n')
        $lines.Add("$key|$($log.LogName)|$($e.RecordId)|" + $escaped)
    }
}
[IO.File]::WriteAllLines($Output, $lines, (New-Object Text.UTF8Encoding $false))
"$($lines.Count) kind(s) of event"
