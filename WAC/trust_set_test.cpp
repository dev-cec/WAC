/*! \file
 *  \brief Checks that the collection refuses a trust set altered on the key.
 *
 *  WHY THIS TEST. The trust set clears third-party binaries: accepted
 *  altered, it leaves an attacker's binary on the examined machine, and
 *  nothing shows it. From a set written by --update-trust, copies are altered
 *  one way each, and each must be refused, for the reason expected:
 *    - intact: usable;
 *    - no manifest: absent;
 *    - a root certificate changed: its SHA-256 no longer the manifest's;
 *    - the same, the manifest's SHA-256 rewritten to match — the forger's
 *      move: refused by the SHA-1 the SIGNED list names;
 *    - authroot.stl changed and its SHA-256 rewritten: refused by its
 *      signature;
 *    - a manifest naming a file outside the set: refused.
 *
 *  Usage (runs under wine): trust_set_test.exe `<trust set folder>` `<scratch folder>`
 */
#include "trust_set.h"
#include "json.h"
#include "sha.h"
#include "tools.h"
#include <cstdio>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! A fresh copy of the set in `scratch`/`name`.
fs::path copySet(const fs::path& set, const fs::path& scratch, const char* name) {
	const fs::path copy = scratch / name;
	fs::remove_all(copy);
	fs::copy(set, copy, fs::copy_options::recursive);
	return copy;
}

//! Flips one byte of a file, in its middle.
void alter(const fs::path& file) {
	std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
	f.seekg(0, std::ios::end);
	const std::streamoff middle = f.tellg() / 2;
	f.seekg(middle);
	char c = 0;
	f.get(c);
	f.seekp(middle);
	f.put((char)(c ^ 0x01));
}

//! Rewrites, in the manifest, the SHA-256 of `path` to the file's current one — the forger's move.
void forgeManifest(const fs::path& set, const std::wstring& path, const std::wstring& replacementPath = L"") {
	std::ifstream in(set / "trust-manifest.json", std::ios::binary);
	const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();
	Json manifest = Json::null();
	std::wstring error;
	Json::parse(decodeText(text, CP_UTF8), manifest, error);
	Json files = Json::arr();
	for (const auto& [unused, file] : manifest.find(L"Files")->members()) {
		const std::wstring name = file.find(L"Path")->text();
		if (name != path) { files.push(file); continue; }
		std::ifstream f(set / name, std::ios::binary);
		const std::string bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		uint8_t digest[32];
		sha256Bytes((const uint8_t*)bytes.data(), bytes.size(), digest);
		files.push(Json::obj().add(L"Path", Json::str(replacementPath.empty() ? name : replacementPath))
		                      .add(L"Bytes", Json::num(bytes.size()))
		                      .add(L"SHA256", Json::str(toHexadecimal(digest, sizeof(digest)))));
	}
	Json forged = Json::obj();
	for (const auto& [key, value] : manifest.members()) forged.add(key, key == L"Files" ? files : value);
	std::ofstream out(set / "trust-manifest.json", std::ios::binary | std::ios::trunc);
	out << encodeText(forged.dump(0));
}

//! The set in `folder` must be refused, for a reason containing `expected`.
void expectRefused(const fs::path& folder, const std::string& expected, const std::string& what) {
	const TrustSet set = LoadTrustSet(folder.wstring());
	check(!set.usable, what + ": accepted");
	check(set.reason.find(expected) != std::string::npos, what + ": refused for \"" + set.reason + "\", not \"" + expected + "\"");
	check(set.rootCertificates.empty() && set.driverHashes.empty(), what + ": refused but half loaded");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc != 3) { std::printf("usage: trust_set_test <trust set folder> <scratch folder>\n"); return 2; }
	const fs::path set(argv[1]), scratch(argv[2]);
	fs::create_directories(scratch);

	const TrustSet intact = LoadTrustSet(set.wstring());
	check(intact.usable, "intact set refused: " + intact.reason);
	check(intact.rootCertificates.size() > 500 && !intact.driverHashes.empty() && !intact.crlsByAuthority.empty()
	      && !intact.revokedAuthorities.empty(), "intact set not loaded whole");
	std::printf("  intact: %zu roots, %zu driver fingerprints, %zu authorities with a CRL, %zu revoked\n",
	            intact.rootCertificates.size(), intact.driverHashes.size(), intact.crlsByAuthority.size(),
	            intact.revokedAuthorities.size());

	fs::path copy = copySet(set, scratch, "no-manifest");
	fs::remove(copy / "trust-manifest.json");
	expectRefused(copy, "absent", "no manifest");

	const fs::path someRoot = fs::directory_iterator(set / "roots")->path();
	const std::wstring rootPath = L"roots\\" + someRoot.filename().wstring();
	copy = copySet(set, scratch, "root-altered");
	alter(copy / "roots" / someRoot.filename());
	expectRefused(copy, "file altered", "root certificate changed");

	copy = copySet(set, scratch, "root-forged");
	alter(copy / "roots" / someRoot.filename());
	forgeManifest(copy, rootPath);
	expectRefused(copy, "not the one authroot.stl names", "root certificate changed, manifest rewritten");

	copy = copySet(set, scratch, "authroot-forged");
	alter(copy / "authroot.stl");
	forgeManifest(copy, L"authroot.stl");
	expectRefused(copy, "authroot.stl refused", "authroot.stl changed, manifest rewritten");

	copy = copySet(set, scratch, "outside");
	forgeManifest(copy, L"roots.pem", L"..\\outside.txt");
	expectRefused(copy, "outside the set", "manifest naming a file outside the set");

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
