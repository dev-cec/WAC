/*! \file
 *  \brief Confronts the reading of version resources with Windows's, then
 *  with damaged resources.
 *
 *  WHY THIS TEST. A driver's original name decides whether Microsoft's
 *  blocklist denies it: read wrong, a vulnerable driver passes for another.
 *  The reference is Windows itself: in the VM, PowerShell's VersionInfo on the
 *  same files ("path|OriginalFilename|InternalName|ProductName|
 *  FileDescription|a.b.c.d"). Windows reads the texts of a localised binary
 *  from its .mui satellite — the blocklist does not, it reads the binary's
 *  own —: for those (OriginalFilename ending in .mui), only the version is
 *  compared. Then every resource truncated and damaged at random (fixed
 *  seed) must never make the reading leave its bounds — AddressSanitizer and
 *  UBSan.
 *
 *  Usage: version_info_test `<reference>` `<folder>` — the files are
 *         `<folder>`/f1.bin, f2.bin… in the order of the reference.
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. pe_resource.cpp version_info.cpp version_info_test.cpp -o version_info_test
 */
#include "pe_resource.h"
#include "version_info.h"
#include <cstdio>
#include <fstream>
#include <random>
#include <sstream>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! UTF-8 to UTF-16 code units (the reference is UTF-8; the texts are UTF-16).
std::wstring widen(const std::string& s) {
	std::wstring w;
	for (size_t i = 0; i < s.size();) {
		const unsigned char c = (unsigned char)s[i];
		uint32_t cp = c;
		size_t n = 1;
		if (c >= 0xF0 && i + 3 < s.size()) { cp = ((c & 7u) << 18) | ((s[i + 1] & 0x3Fu) << 12) | ((s[i + 2] & 0x3Fu) << 6) | (s[i + 3] & 0x3Fu); n = 4; }
		else if (c >= 0xE0 && i + 2 < s.size()) { cp = ((c & 15u) << 12) | ((s[i + 1] & 0x3Fu) << 6) | (s[i + 2] & 0x3Fu); n = 3; }
		else if (c >= 0xC0 && i + 1 < s.size()) { cp = ((c & 31u) << 6) | (s[i + 1] & 0x3Fu); n = 2; }
		if (cp >= 0x10000) { cp -= 0x10000; w += (wchar_t)(0xD800 + (cp >> 10)); w += (wchar_t)(0xDC00 + (cp & 0x3FF)); }
		else w += (wchar_t)cp;
		i += n;
	}
	return w;
}

std::string narrow(const std::wstring& w) {
	std::string s;
	for (wchar_t c : w) s += c < 0x80 ? (char)c : '?';
	return s;
}

} // namespace

int main(int argc, char** argv) {
	if (argc != 3) { std::printf("usage: version_info_test <reference> <folder>\n"); return 2; }
	std::ifstream reference(argv[1]);
	std::mt19937_64 rng(20260926);
	size_t files = 0, localised = 0;
	int index = 0;
	for (std::string line; std::getline(reference, line);) {
		if (!line.empty() && line.back() == '\r') line.pop_back();
		std::vector<std::string> f;
		std::stringstream parts(line);
		for (std::string part; std::getline(parts, part, '|');) f.push_back(part);
		if (line.back() == '|') f.push_back("");
		++index;
		if (f.size() != 6) continue;
		const std::string file = std::string(argv[2]) + "/f" + std::to_string(index) + ".bin";
		std::ifstream in(file, std::ios::binary);
		PeResource pe;
		if (!pe.load(std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()))) continue;
		const std::vector<uint8_t> resource = pe.resource(PE_RT_VERSION);
		VersionInfo v;
		const bool read = ReadVersionInfo(resource, v);
		++files;
		uint64_t expected = 0;
		ParseFileVersion(widen(f[5]), expected);
		// No version resource: Windows shows 0.0.0.0 and no text.
		if (expected == 0 && f[1].empty() && f[2].empty()) { check(!read || !v.fixed, f[0] + ": a version Windows does not see"); continue; }
		check(read && v.fixed && v.fileVersion == expected, f[0] + ": version differs from Windows'");
		const bool fromMui = f[1].size() > 4 && f[1].compare(f[1].size() - 4, 4, ".mui") == 0;
		if (fromMui) { ++localised; continue; }
		const char* KEYS[] = { "", "OriginalFilename", "InternalName", "ProductName", "FileDescription" };
		for (int k = 1; k <= 4; ++k) {
			const auto found = v.strings.find(widen(KEYS[k]));
			const std::wstring mine = found == v.strings.end() ? L"" : found->second;
			check(mine == widen(f[k]), f[0] + ": " + KEYS[k] + " \"" + narrow(mine) + "\", Windows \"" + f[k] + "\"");
		}
		// Damaged: the resource truncated, then altered at random — within bounds, whatever it yields.
		for (size_t cut = 0; cut < resource.size(); cut += 1 + resource.size() / 32) {
			VersionInfo w;
			ReadVersionInfo(std::vector<uint8_t>(resource.begin(), resource.begin() + (long)cut), w);
			++g_checks;
		}
		for (int m = 0; m < 200 && !resource.empty(); ++m) {
			std::vector<uint8_t> damaged = resource;
			for (int e = 0; e < 4; ++e) damaged[rng() % damaged.size()] = (uint8_t)rng();
			VersionInfo w;
			ReadVersionInfo(damaged, w);
			++g_checks;
		}
	}
	uint64_t v = 0;
	check(ParseFileVersion(L"10.0.26100.1150", v) && v == ((10ULL << 48) | (26100ULL << 16) | 1150), "ParseFileVersion");
	check(!ParseFileVersion(L"1.2.3", v) && !ParseFileVersion(L"1.2.3.70000", v), "ParseFileVersion refuses");
	std::printf("  %zu file(s), %zu with texts from a .mui (version only)\n", files, localised);
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
