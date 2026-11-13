/*! \file
 *  \brief Test of normalizeFilePath (path_normalization.h), portable: built
 *         and run on the build machine by build-windows.sh --test. The
 *         cases are forms measured in a real collection (2026-11-13).
 */
#include "path_normalization.h"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

int failures = 0;

void expect(const std::wstring& path, const std::wstring& expected) {
	const std::wstring got = normalizeFilePath(path, L"C:");
	if (got != expected) {
		std::fprintf(stderr, "normalizeFilePath(%ls): %ls, expected %ls\n", path.c_str(), got.c_str(), expected.c_str());
		++failures;
	}
}

}  // namespace

int main() {
	expect(L"C:\\Windows\\bootstat.dat", L"C:\\Windows\\bootstat.dat");
	expect(L"c:\\windows\\system32\\inetsrv\\appcmd.exe", L"C:\\windows\\system32\\inetsrv\\appcmd.exe");   // case kept, drive upper
	expect(L"%windir%\\system32\\radardt.dll", L"C:\\Windows\\system32\\radardt.dll");
	expect(L"%SystemRoot%\\system32\\msdtc.exe", L"C:\\Windows\\system32\\msdtc.exe");
	expect(L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe", L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
	expect(L"%SystemDrive%\\inetpub\\wwwroot", L"C:\\inetpub\\wwwroot");
	expect(L"\\SystemRoot\\System32\\drivers\\1394ohci.sys", L"C:\\Windows\\System32\\drivers\\1394ohci.sys");
	expect(L"\\??\\C:\\pagefile.sys", L"C:\\pagefile.sys");
	expect(L"\\\\?\\C:\\Windows\\UUS\\AMD64\\wuauengcore.dll", L"C:\\Windows\\UUS\\AMD64\\wuauengcore.dll");
	expect(L"SYSVOL\\Windows\\System32\\cmd.exe", L"C:\\Windows\\System32\\cmd.exe");
	expect(L"\"C:\\Program Files\\Virtio-Win\\Balloon\\blnsvr.exe\"", L"C:\\Program Files\\Virtio-Win\\Balloon\\blnsvr.exe");
	// Not a determinable local file: empty.
	expect(L"%USERPROFILE%\\AppData\\Roaming", L"");      // a user's variable
	expect(L"%UNKNOWN%\\x", L"");
	expect(L"System32\\drivers\\3ware.sys", L"");          // relative
	expect(L"\\??\\UNC\\server\\share\\x", L"");           // network share
	expect(L"\\\\127.0.0.1\\WacShare", L"");
	expect(L"", L"");
	expect(L"%windir", L"");                               // unclosed variable
	if (failures == 0) std::printf("normalizeFilePath: every case as expected\n");
	return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
