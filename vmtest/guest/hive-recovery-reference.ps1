# hive-recovery-reference.ps1 — WAC's replay of a hive's transaction logs
# against Windows' own recovery of the same files.
#
# For each hive named, of the collection given:
#   - "windows": a copy of the hive AS COLLECTED (exhibit store) with its
#     .LOG1/.LOG2, loaded by `reg load` — Windows replays the logs itself;
#   - "wac": a copy of the hive WAC replayed (working folder), loaded alone.
# Both are walked whole: number of keys and of values, and a SHA-256 over every
# key path, value name, type and data. Same hive, same logs: the two must be
# identical. A replay that drops an entry gives a hive that still loads — it
# showed only here, as a few keys fewer.
#
# Works on copies, in a folder removed at the end: neither the exhibit store nor
# the working folder is written. Prints one line per hive:
#   hive=<name>|windows=<keys>,<values>,<sha256>|wac=<keys>,<values>,<sha256>
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File hive-recovery-reference.ps1
#          -Collection C:\wactest\out [-Hives SOFTWARE,SYSTEM]
param([Parameter(Mandatory = $true)][string]$Collection, [string[]]$Hives = @('SOFTWARE', 'SYSTEM'))
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

public static class WacHiveWalk {
    static long keys, values;
    static SHA256 sha;

    static void Feed(string text) {
        byte[] b = Encoding.Unicode.GetBytes(text + "\n");
        sha.TransformBlock(b, 0, b.Length, null, 0);
    }

    static void Walk(RegistryKey key, string path) {
        ++keys;
        Feed("K|" + path);
        string[] names = key.GetValueNames();
        Array.Sort(names, StringComparer.Ordinal);
        foreach (string name in names) {
            ++values;
            object data = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            string text;
            if (data is byte[]) text = BitConverter.ToString((byte[])data);
            else if (data is string[]) text = string.Join("\u0001", (string[])data);
            else text = Convert.ToString(data, System.Globalization.CultureInfo.InvariantCulture);
            Feed("V|" + name + "|" + key.GetValueKind(name) + "|" + text);
        }
        string[] subkeys = key.GetSubKeyNames();
        Array.Sort(subkeys, StringComparer.Ordinal);
        foreach (string name in subkeys) {
            RegistryKey sub = null;
            try { sub = key.OpenSubKey(name); } catch (Exception e) { Feed("DENIED|" + path + "\\" + name + "|" + e.GetType().Name); }
            if (sub != null) { Walk(sub, path + "\\" + name); sub.Close(); }
        }
    }

    // "<keys>,<values>,<sha256>" of the hive mounted under HKLM\<mount>.
    public static string Digest(string mount) {
        keys = 0; values = 0;
        sha = SHA256.Create();
        using (RegistryKey root = Registry.LocalMachine.OpenSubKey(mount)) Walk(root, "");
        sha.TransformFinalBlock(new byte[0], 0, 0);
        return keys + "," + values + "," + BitConverter.ToString(sha.Hash).Replace("-", "");
    }
}
'@

# Loads a hive file under HKLM, digests it, unloads it.
function HiveDigest([string]$file, [string]$mount) {
    & reg.exe load "HKLM\$mount" $file | Out-Null
    if ($LASTEXITCODE -ne 0) { return 'not loaded' }
    try { return [WacHiveWalk]::Digest($mount) }
    finally { [gc]::Collect(); [gc]::WaitForPendingFinalizers(); & reg.exe unload "HKLM\$mount" | Out-Null }
}

$scratch = 'C:\wactest\hive-recovery-reference'
if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
New-Item -ItemType Directory -Force $scratch | Out-Null
try {
    foreach ($hive in $Hives) {
        $collected = "$Collection\exhibits\Windows\System32\config\$hive"
        $replayed = "$Collection\working\Windows\System32\config\$hive"
        if (-not (Test-Path -LiteralPath $collected) -or -not (Test-Path -LiteralPath $replayed)) { continue }
        foreach ($suffix in '', '.LOG1', '.LOG2') {
            if (Test-Path -LiteralPath "$collected$suffix") { Copy-Item -LiteralPath "$collected$suffix" -Destination "$scratch\W$hive$suffix" -Force }
        }
        Copy-Item -LiteralPath $replayed -Destination "$scratch\M$hive" -Force
        Write-Output ("hive=$hive|windows=" + (HiveDigest "$scratch\W$hive" 'WACREFWINDOWS') + '|wac=' + (HiveDigest "$scratch\M$hive" 'WACREFWAC'))
    }
}
finally { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
