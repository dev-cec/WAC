@echo off
rem ez-live.cmd - Eric Zimmerman's tools run on the live machine, from the
rem key, as an examiner without KAPE would (backlog B-027): the $MFT, the
rem event logs, the registry hives, Prefetch, Amcache and ShimCache, each
rem written as CSV to the key. Their own way of reading a locked file is
rem part of what the comparison measures.
set OUT=K:\out\ez
K:\EZ\MFTECmd\MFTECmd.exe -f "C:\$MFT" --csv %OUT%\mft
K:\EZ\EvtxECmd\EvtxeCmd\EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv %OUT%\evtx
K:\EZ\RECmd\RECmd\RECmd.exe -d C:\Windows\System32\config --bn K:\EZ\RECmd\RECmd\BatchExamples\Kroll_Batch.reb --csv %OUT%\recmd
K:\EZ\PECmd\PECmd.exe -d C:\Windows\Prefetch --csv %OUT%\prefetch
K:\EZ\AmcacheParser\AmcacheParser.exe -f C:\Windows\appcompat\Programs\Amcache.hve --csv %OUT%\amcache
K:\EZ\AppCompatCacheParser\AppCompatCacheParser.exe --csv %OUT%\appcompatcache
