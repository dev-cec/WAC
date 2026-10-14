# authenticode-reference.ps1 — Windows' own verdict on the signatures of the
# executables of System32, for the executables WAC authenticates in memory and
# does not copy.
#
# One line per executable: <path>|<status>|<signer>|<catalog>
#   - status and signer: Get-AuthenticodeSignature;
#   - catalog: for a file whose status is not Valid, the catalog Windows itself
#     finds for it (CryptCATAdminCalcHashFromFileHandle, then
#     CryptCATAdminEnumCatalogFromHash), empty when none. Before PowerShell 5.1
#     (Windows 8.1 and earlier) Get-AuthenticodeSignature reads the embedded
#     signature only: a file signed by a catalog comes out NotSigned, or
#     UnknownError when its embedded chain ends at a root this machine does not
#     hold — the catalog lookup is then Windows' word on it.
#
# Reads only. Usage: powershell -NoProfile -ExecutionPolicy Bypass -File authenticode-reference.ps1
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;

public static class WacCatalog {
    [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminAcquireContext(out IntPtr admin, IntPtr subsystem, uint flags);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr file, ref uint size, byte[] hash, uint flags);
    [DllImport("wintrust.dll")] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint size, uint flags, IntPtr previous);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CatalogInfo { public uint cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string file; }
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);

    // The catalog that holds the file's Authenticode hash, "" when none.
    public static string Of(string path) {
        IntPtr admin;
        if (!CryptCATAdminAcquireContext(out admin, IntPtr.Zero, 0)) return "";
        try {
            using (FileStream stream = File.OpenRead(path)) {
                IntPtr handle = stream.SafeFileHandle.DangerousGetHandle();
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle(handle, ref size, null, 0);
                byte[] hash = new byte[size];
                if (size == 0 || !CryptCATAdminCalcHashFromFileHandle(handle, ref size, hash, 0)) return "";
                IntPtr catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                if (catalog == IntPtr.Zero) return "";
                CatalogInfo info = new CatalogInfo();
                info.cbStruct = (uint)Marshal.SizeOf(typeof(CatalogInfo));
                string found = CryptCATCatalogInfoFromContext(catalog, ref info, 0) ? info.file : "";
                CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                return found;
            }
        }
        catch (IOException) { return ""; }
        catch (UnauthorizedAccessException) { return ""; }
        finally { CryptCATAdminReleaseContext(admin, 0); }
    }
}
'@
Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object {
    $s = Get-AuthenticodeSignature $_.FullName
    $catalog = if ($s.Status -ne 'Valid') { [WacCatalog]::Of($_.FullName) } else { '' }
    '{0}|{1}|{2}|{3}' -f $_.FullName, $s.Status, $s.SignerCertificate.Subject, $catalog
}
