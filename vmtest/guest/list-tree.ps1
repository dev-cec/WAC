# list-tree.ps1 — every file under a folder, one full path per line, written
# in UTF-8 without BOM: the listing of the exhibit store the checks read.
#
# Through FindFirstFileW on the \\?\ form, the only way that holds on every
# Windows of the harness: Get-ChildItem stops at MAX_PATH and .NET refuses the
# \\?\ form before 4.6.2 (Windows 8.1 and earlier); cmd's dir refuses a folder
# past 248 characters on Windows 7, and robocopy's /UNILOG writes there its
# text in the OEM code page, a name outside it turned into "?". An exhibit's
# path can pass MAX_PATH (B-049), and names carry accents.
param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Output)

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class WacTree {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FindData {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
        public uint SizeHigh, SizeLow, Reserved0, Reserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string ShortName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstFileW(string name, out FindData data);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool FindNextFileW(IntPtr handle, out FindData data);
    [DllImport("kernel32.dll")]
    static extern bool FindClose(IntPtr handle);

    const uint DIRECTORY = 0x10, REPARSE_POINT = 0x400;
    static readonly IntPtr INVALID = new IntPtr(-1);

    // The files under a folder, depth first; a junction is not followed.
    public static List<string> Files(string root) {
        List<string> files = new List<string>();
        Stack<string> folders = new Stack<string>();
        folders.Push(root.TrimEnd('\\'));
        while (folders.Count > 0) {
            string folder = folders.Pop();
            FindData data;
            IntPtr handle = FindFirstFileW(@"\\?\" + folder + @"\*", out data);
            if (handle == INVALID) continue;
            try {
                do {
                    if (data.Name == "." || data.Name == "..") continue;
                    string full = folder + @"\" + data.Name;
                    if ((data.Attributes & DIRECTORY) == 0) files.Add(full);
                    else if ((data.Attributes & REPARSE_POINT) == 0) folders.Push(full);
                } while (FindNextFileW(handle, out data));
            } finally { FindClose(handle); }
        }
        return files;
    }
}
'@

[IO.File]::WriteAllLines($Output, [string[]]([WacTree]::Files($Path)), (New-Object Text.UTF8Encoding $false))
