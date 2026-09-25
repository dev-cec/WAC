# register-test-guids.ps1 — registers, in the test VM, three GUIDs that WAC's
# reference table does not know, one per source WAC reads them from, and a
# disabled scheduled task per GUID that references it as its COM handler.
#
# WHY. WAC names a GUID its table does not know from the examined machine's
# own registrations (WAC/trans_id.cpp, evidenceGuidName): the machine's classes
# (SOFTWARE\Classes\CLSID), its known folders (Explorer\FolderDescriptions),
# each user's classes (UsrClass.dat). A reference Windows — the test VM — has
# nothing its table misses on purpose: these three entries make each source
# exercised on every cycle, including on a VM recreated from scratch, and
# check-json.py expects exactly the names given here.
#
# Idempotent: run by run-wac-test.sh before every collection. The tasks are
# disabled and have no trigger: they never run.
$ErrorActionPreference = 'Stop'
$tests = @(
  @{ Guid = '{57AC0001-7E57-4000-8000-000000000001}'; Name = 'WAC test COM handler (machine)'; Where = 'machine' },
  @{ Guid = '{57AC0002-7E57-4000-8000-000000000002}'; Name = 'WAC test COM handler (user)';    Where = 'user' },
  @{ Guid = '{57AC0003-7E57-4000-8000-000000000003}'; Name = 'WacTestKnownFolder';             Where = 'folder' }
)
$module = 'C:\wactest\wac-test-handler.dll'

# The classes of the autologon user "wac", loaded under HKEY_USERS while it is
# logged on.
$sid = (Get-LocalUser -Name 'wac').SID.Value
$userClasses = "Registry::HKEY_USERS\${sid}_Classes"

foreach ($t in $tests) {
  switch ($t.Where) {
    'machine' {
      $key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$($t.Guid)"
      New-Item -Path "$key\InprocServer32" -Force | Out-Null
      Set-Item -Path $key -Value $t.Name
      Set-Item -Path "$key\InprocServer32" -Value $module
    }
    'user' {
      if (-not (Test-Path $userClasses)) { Write-Output "user classes of wac not loaded: skipped"; continue }
      $key = "$userClasses\CLSID\$($t.Guid)"
      New-Item -Path "$key\InprocServer32" -Force | Out-Null
      Set-Item -Path $key -Value $t.Name
      Set-Item -Path "$key\InprocServer32" -Value $module
    }
    'folder' {
      $key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\$($t.Guid)"
      New-Item -Path $key -Force | Out-Null
      New-ItemProperty -Path $key -Name 'Name' -Value $t.Name -PropertyType String -Force | Out-Null
    }
  }
  $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>WAC test: a COM handler WAC must name from the hive ($($t.Where))</Description></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions Context="Author"><ComHandler><ClassId>$($t.Guid)</ClassId></ComHandler></Actions>
</Task>
"@
  Register-ScheduledTask -TaskName "WacTestComHandler-$($t.Where)" -TaskPath '\WAC\' -Xml $xml -Force | Out-Null
  Write-Output "$($t.Guid)|$($t.Name)"
}

# WAC reads the hives RAW from the disk: a change still in memory would be
# invisible to it. Flush both hives (RegFlushKey) before the collection.
[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE').Flush()
$classes = [Microsoft.Win32.Registry]::Users.OpenSubKey("${sid}_Classes")
if ($classes) { $classes.Flush() }
