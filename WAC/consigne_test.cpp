/*! \file
 *  \brief Checks the exhibit-store / working-directory procedure.
 *
 *  What this test tries to catch, and what no compilation reveals: the exhibit
 *  store being modified. That is the one thing that must NEVER happen, and it
 *  is silent when it does — the report still looks right, only the exhibit is
 *  lost.
 *
 *  Raw NTFS reading is not exercised here (it requires a real volume): the
 *  exhibits are files given as arguments, and the rest of the chain is the
 *  production one — same fingerprints, same manifest, same verified copy, same
 *  replay.
 *
 *  Usage: consigne_test.exe `<output directory>` `<hive>` [hive...]
 *  Excluded from WAC's build by the "_test.cpp" pattern of build-windows.sh.
 */
#include "consigne.h"
#include "hive_recover.h"
#include "sha.h"
#include "quickdigest5.h"
#include "tools.h"
#include "audit.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <map>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

std::string narrow(const std::wstring& w){
	std::string r;
	for (wchar_t c : w) r += (char)(c < 128 ? (char)c : '?');
	return r;
}

//! Copies a file into the exhibit store and returns its record, fingerprints included.
RawHiveExtraction putInExhibitStore(const std::filesystem::path& source,
                                 const std::wstring& simulatedVolumePath){
	RawHiveExtraction e;
	e.volumePath = simulatedVolumePath;
	e.outputPath = pathUnder(exhibitStoreFolder(), simulatedVolumePath);

	std::error_code ec;
	std::filesystem::create_directories(
		std::filesystem::path(e.outputPath).parent_path(), ec);

	std::ifstream in(source, std::ios::binary);
	std::ofstream out(std::filesystem::path(e.outputPath), std::ios::binary | std::ios::trunc);
	if (!in || !out){ e.result = E_FAIL; return e; }

	// Fingerprints computed while writing, as the extraction does.
	Md5Stream m; Sha1Stream s1; Sha256Stream s2;
	std::vector<char> buffer(1 << 16);
	uint64_t total = 0;
	while (in.read(buffer.data(), (std::streamsize)buffer.size()) || in.gcount()){
		const size_t n = (size_t)in.gcount();
		out.write(buffer.data(), (std::streamsize)n);
		m.update((const uint8_t*)buffer.data(), n);
		s1.update((const uint8_t*)buffer.data(), n);
		s2.update((const uint8_t*)buffer.data(), n);
		total += n;
	}
	e.fingerprints.md5    = m.hexDigest();
	e.fingerprints.sha1   = s1.hexDigest();
	e.fingerprints.sha256 = s2.hexDigest();
	e.fingerprints.bytes = total;
	e.fingerprints.declaredSize = total;
	e.fingerprints.mftEntry = 42;          // simulated value: no $MFT here
	FILETIME f = { 0, 0 };
	GetSystemTimeAsFileTime(&f);
	e.fingerprints.extractedUtc = ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime;
	e.result = ERROR_SUCCESS;
	return e;
}

int failures = 0;
void check(bool ok, const std::string& label){
	std::cout << (ok ? "  ok     " : "  FAILED  ") << label << "\n";
	if (!ok) ++failures;
}

} // namespace

/*! Runs the test.
 * @param argc,argv `<output directory>` `<hive>` [hive...]
 * @return 0 if every check passed */
int wmain(int argc, wchar_t** argv){
	if (argc < 3){
		std::cout << "usage: consigne_test <output directory> <hive> [hive...]\n";
		return 2;
	}
	conf._outputDir = argv[1];
	conf.systemDrive = L"C:";
	auditInit({ L"consigne_test" });

	std::error_code ec;
	std::filesystem::remove_all(exhibitStoreFolder(), ec);
	std::filesystem::remove_all(workingFolder(), ec);

	// --- 1. "extraction" into the exhibit store ---------------------------
	std::vector<RawHiveExtraction> reading;
	std::vector<std::wstring> hiveNames;
	for (int i = 2; i < argc; ++i){
		const std::filesystem::path source = argv[i];
		const std::wstring name = source.filename().wstring();
		hiveNames.push_back(name);
		reading.push_back(putInExhibitStore(source, L"C:\\Windows\\system32\\config\\" + name));
		// The transaction logs go along with the hive.
		for (const wchar_t* suffix : { L".LOG1", L".LOG2" }){
			const std::filesystem::path j = source.wstring() + suffix;
			if (std::filesystem::exists(j, ec))
				reading.push_back(putInExhibitStore(
					j, L"C:\\Windows\\system32\\config\\" + name + suffix));
		}
	}
	ExhibitStoreAdd(reading, L"Test: direct copy (raw NTFS reading is not exercised here)");

	// Fingerprints of the exhibit store BEFORE anything else: this must not move.
	std::map<std::wstring, std::wstring> before;
	for (const std::filesystem::directory_entry& e :
	     std::filesystem::recursive_directory_iterator(exhibitStoreFolder(), ec))
		if (e.is_regular_file(ec)) before[e.path().wstring()] = sha256OfFile(e.path().wstring());
	check(!before.empty(), "the exhibit store holds exhibits (" + std::to_string(before.size()) + ")");

	// --- 2. exhibit store -> working copy, verified by fingerprint --------
	size_t copies = 0; unsigned long long bytes = 0;
	const HRESULT hrCopy = ExhibitStoreToWorking(&copies, &bytes);
	check(hrCopy == ERROR_SUCCESS, "copy into the working directory without divergence");
	check(copies == before.size(), "every file copied ("
	         + std::to_string(copies) + "/" + std::to_string(before.size()) + ")");

	// --- 3. replay, which must touch ONLY the working copy ----------------
	for (const std::wstring& name : hiveNames){
		const std::wstring target = pathUnder(workingFolder(),
		                                      L"C:\\Windows\\system32\\config\\" + name);
		const HiveReplayInfo r = ReplayHiveLogs(target, L"00000000000000000000000000000000");
		std::cout << "         " << narrow(name) << " : " << narrow(HiveReplayInfoToString(r)) << "\n";
		check(r.ok, narrow(name) + ": replay without error");
	}

	// --- 4. IS THE EXHIBIT STORE UNTOUCHED? -------------------------------
	int moved = 0;
	for (const auto& kv : before)
		if (sha256OfFile(kv.first) != kv.second){
			++moved;
			std::cout << "         MODIFIED: " << narrow(kv.first) << "\n";
		}
	check(moved == 0, "exhibit store untouched after the replay (" + std::to_string(before.size())
	         + " file(s) checked)");

	// --- 5. the working copy, on the other hand, must have changed --------
	int changes = 0;
	for (const auto& kv : before){
		const std::filesystem::path rel = std::filesystem::relative(
			std::filesystem::path(kv.first), std::filesystem::path(exhibitStoreFolder()), ec);
		const std::filesystem::path t = std::filesystem::path(workingFolder()) / rel;
		if (std::filesystem::exists(t, ec) && sha256OfFile(t.wstring()) != kv.second) ++changes;
	}
	check(changes > 0, "the working copy differs from the exhibit store after the replay ("
	         + std::to_string(changes) + " file(s))");

	// --- 6. manifest and seal ---------------------------------------------
	const HRESULT hrManifest = ExhibitStoreWriteManifest();
	check(hrManifest == ERROR_SUCCESS, "manifest and seal written");
	const std::filesystem::path manifest = std::filesystem::path(exhibitStoreFolder()) / L"MANIFEST.json";
	const std::filesystem::path seal     = std::filesystem::path(exhibitStoreFolder()) / L"MANIFEST.sha256";
	check(std::filesystem::exists(manifest, ec), "MANIFEST.json present");
	check(std::filesystem::exists(seal, ec),     "MANIFEST.sha256 present");

	// The seal must carry the manifest's real fingerprint.
	std::wstring expected = sha256OfFile(manifest.wstring());
	std::ifstream fs(seal);
	std::string line;
	std::getline(fs, line);
	const std::string att = narrow(expected);
	check(line.compare(0, att.size(), att) == 0,
	         "the seal carries the manifest's fingerprint");

	// The manifest must NOT have been copied into the working directory.
	check(!std::filesystem::exists(
	             std::filesystem::path(workingFolder()) / L"MANIFEST.json", ec),
	         "the manifest is not copied into the working directory");

	std::cout << (failures ? "FAILURES: " : "all passed (failures: ") << failures
	          << (failures ? "\n" : ")\n");
	return failures ? 1 : 0;
}
