/*! \file
 *  \brief Checks the table of the artefacts by version of Windows, and dumps
 *  it for the documentation.
 *
 *  WHY THIS TEST. The table decides what a collection does NOT take on a
 *  given Windows: a wrong line loses an exhibit without a word. Checked
 *  here: the table and wac.yml hold exactly the same keys; each artefact's
 *  forms are in order and start with its first build; known cases answer
 *  right (no SRUM before Windows 8, no jump list before 7, Prefetch 23 on
 *  Vista and 30 on 10); a source is "expected" only where the version always
 *  has it, on client editions; a key or a version that is not known never holds a
 *  collection back; and a version NEWER than the table — the next Windows —
 *  is collected as the last one known, and flagged.
 *
 *  Usage: artefact_catalogue_test `<wac.yml>`           the checks
 *         artefact_catalogue_test `<wac.yml>` --dump    the table, tab-separated, for doc/artefact-table.py
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. artefact_catalogue.cpp
 *                        artefact_catalogue_test.cpp -o artefact_catalogue_test
 */
#include "artefact_catalogue.h"
#include <cstdio>
#include <fstream>
#include <set>
#include <string>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! The keys under `artefacts:` in wac.yml, in the file's order.
std::vector<std::string> configurationKeys(const char* path) {
	std::vector<std::string> keys;
	std::ifstream file(path);
	std::string line;
	bool inside = false;
	while (std::getline(file, line)) {
		if (line.compare(0, 10, "artefacts:") == 0) { inside = true; continue; }
		if (!inside || line.compare(0, 2, "  ") != 0 || line.size() < 4 || line[2] == ' ' || line[2] == '#') continue;
		keys.push_back(line.substr(2, line.find(':') - 2));
	}
	return keys;
}

//! A wide string as UTF-8 (the table's texts are short and well formed).
std::string utf8(const wchar_t* text) {
	std::string out;
	for (; *text; ++text) {
		const unsigned c = (unsigned)*text;
		if (c < 0x80) out += (char)c;
		else if (c < 0x800) { out += (char)(0xC0 | (c >> 6)); out += (char)(0x80 | (c & 0x3F)); }
		else { out += (char)(0xE0 | (c >> 12)); out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F)); }
	}
	return out;
}

//! The name of the release a build starts or belongs to, client editions.
std::string clientRelease(unsigned build) {
	bool known = false;
	return utf8(releaseOf(WindowsVersion{ build, false, false }, known).name);
}

//! The table, one line per form: key, first and last release, expected since, form's release, location, format, decoded, note.
void dump() {
	for (const ArtefactEntry& e : artefactCatalogue())
		for (const ArtefactForm& f : e.forms)
			std::printf("%s\t%u\t%u\t%u\t%u\t%s\t%s\t%s\t%s\t%s\n", e.key, e.sinceBuild, e.untilBuild, e.expectedSinceBuild,
			            f.sinceBuild, clientRelease(f.sinceBuild).c_str(), utf8(f.location).c_str(), utf8(f.format).c_str(),
			            f.decoded ? "yes" : "no", utf8(e.note).c_str());
}

} // namespace

int main(int argc, char** argv) {
	if (argc < 2) { std::printf("usage: artefact_catalogue_test <wac.yml> [--dump]\n"); return 2; }
	if (argc > 2 && std::string(argv[2]) == "--dump") { dump(); return 0; }

	// The table and the configuration: the same keys, no more, no less.
	const std::vector<std::string> keys = configurationKeys(argv[1]);
	check(!keys.empty(), "no key read from wac.yml");
	std::set<std::string> listed;
	for (const ArtefactEntry& e : artefactCatalogue()) {
		check(listed.insert(e.key).second, std::string("twice in the table: ") + e.key);
		check(!e.forms.empty(), std::string(e.key) + ": no form");
		if (e.forms.empty()) continue;
		check(e.forms.front().sinceBuild == e.sinceBuild, std::string(e.key) + ": its first form does not start with its first build");
		for (size_t i = 1; i < e.forms.size(); ++i)
			check(e.forms[i].sinceBuild > e.forms[i - 1].sinceBuild, std::string(e.key) + ": forms out of order");
		check(e.untilBuild == 0 || e.untilBuild > e.sinceBuild, std::string(e.key) + ": withdrawn before it existed");
		check(e.expectedSinceBuild == 0 || e.expectedSinceBuild >= e.sinceBuild, std::string(e.key) + ": expected before it existed");
		check(e.note != nullptr, std::string(e.key) + ": no note (\"\" for none)");
	}
	for (const std::string& key : keys) check(listed.count(key) != 0, "key of wac.yml absent from the table: " + key);
	check(listed.size() == keys.size(), "the table holds " + std::to_string(listed.size()) + " artefacts, wac.yml "
	                                    + std::to_string(keys.size()));

	// The releases: each family in order, without overlap.
	for (bool server : { false, true }) {
		const WindowsRelease* previous = nullptr;
		for (const WindowsRelease& r : windowsReleases()) {
			if (r.server != server) continue;
			check(r.lastBuild >= r.firstBuild, "a release ends before it starts");
			check(!previous || r.firstBuild > previous->lastBuild, "releases overlap or out of order");
			previous = &r;
		}
	}

	// Known cases.
	const WindowsVersion xp{ 2600, false, false }, vista{ 6002, false, false }, seven{ 7601, false, false },
	                     eight{ 9200, false, false }, ten{ 19045, false, false }, eleven{ 26200, false, false },
	                     server2019{ 17763, true, false };
	check(availabilityOf("srum", seven) == Availability::AbsentFromThisVersion, "SRUM on Windows 7");
	check(availabilityOf("srum", eight) == Availability::Present, "no SRUM on Windows 8");
	check(availabilityOf("jump_lists", vista) == Availability::AbsentFromThisVersion, "jump lists on Vista");
	check(availabilityOf("jump_lists", seven) == Availability::Present, "no jump list on Windows 7");
	check(availabilityOf("bam", ten) == Availability::Present && availabilityOf("bam", eight) == Availability::AbsentFromThisVersion, "BAM");
	check(availabilityOf("activities_cache", eleven) == Availability::Present, "ActivitiesCache.db withdrawn from Windows 11 (it is still written)");
	check(availabilityOf("mft", xp) == Availability::Present && availabilityOf("events", xp) == Availability::Present, "$MFT or events absent from XP");
	bool known = false;
	check(std::wstring(releaseOf(seven, known).name) == L"Windows 7" && known, "7601 is not Windows 7");
	check(std::wstring(releaseOf(eleven, known).name) == L"Windows 11" && known, "26200 is not Windows 11");
	check(std::wstring(releaseOf(server2019, known).name) == L"Windows Server 2019" && known, "17763 server is not Server 2019");
	const ArtefactEntry* prefetch = artefactEntry("prefetch");
	check(prefetch && std::wstring(formOf(*prefetch, vista).format) == L"SCCA version 23" && !formOf(*prefetch, vista).decoded, "Prefetch on Vista");
	check(prefetch && formOf(*prefetch, eleven).decoded && formOf(*prefetch, eleven).sinceBuild == 10240, "Prefetch on Windows 11");
	const ArtefactEntry* amcache = artefactEntry("amcache");
	check(amcache && formOf(*amcache, ten).decoded && !formOf(*amcache, eight).decoded, "Amcache: Inventory keys decoded, File and Programs keys not");

	/* THE GUARD ON THE MACHINE'S SIDE (expectedOn): a source not found is
	   "expected but missing" only where this version always has one. */
	check(expectedOn("amcache", ten) && !expectedOn("amcache", seven), "Amcache: expected on 10, not certain on 7");
	check(!expectedOn("amcache", server2019), "expected on a server: not measured yet");
	check(expectedOn("hosts", xp) && expectedOn("hosts", eleven) && expectedOn("srum", eight), "hosts or SRUM not expected where it always is");
	check(!expectedOn("srum", seven), "SRUM expected on a version that never had it");
	check(!expectedOn("emails", eleven) && !expectedOn("web_client", eleven), "a source that depends on installed programs is expected");
	check(!expectedOn("usbstor", eleven) && !expectedOn("devices", eleven), "a key that exists only once a device was plugged is expected");
	check(!expectedOn("mft", eleven) && !expectedOn("processes", eleven) && !expectedOn("sessions", eleven),
	      "volume metadata or a live state is expected: not read, it is a failed reading, not a trace");
	check(!expectedOn("an_artefact_of_tomorrow", eleven) && !expectedOn("hosts", WindowsVersion{}), "what is not known is expected");
	check(expectedOn("hosts", WindowsVersion{ 31000, false, false }), "the next Windows no longer expects what the last one known does");

	/* THE GUARD (absentAmong): everything asked for on a Windows 7, on an XP,
	   on a Windows 11 — only what the version lacks is held back, and an
	   artefact switched off in wac.yml (not asked) is never listed. */
	const std::set<std::string> onSeven = [&] { const auto v = absentAmong(keys, seven); return std::set<std::string>(v.begin(), v.end()); }();
	check(onSeven == std::set<std::string>{ "activities_cache", "bam", "defender", "powershell_history", "srum" },
	      "Windows 7: " + std::to_string(onSeven.size()) + " artefacts held back, 5 expected (Timeline, BAM, Defender, PSReadLine, SRUM)");
	const std::vector<std::string> onXp = absentAmong(keys, xp);
	check(onXp.size() == 14, "Windows XP: " + std::to_string(onXp.size()) + " artefacts held back, 14 expected");
	check(absentAmong(keys, eleven).empty(), "Windows 11: an artefact held back");
	check(absentAmong({ "mft", "hosts" }, seven).empty() && absentAmong({}, xp).empty(), "the guard lists what was not asked for");

	// What is not known never holds a collection back.
	check(availabilityOf("an_artefact_of_tomorrow", ten) == Availability::Present, "an unknown key held back");
	check(availabilityOf("srum", WindowsVersion{}) == Availability::Present, "a version without a build held an artefact back");

	/* THE NEXT WINDOWS: a build newer than every release of the table. It is
	   the last release known, flagged as unknown, and every artefact is taken
	   exactly as on that last release. */
	const WindowsVersion next{ 31000, false, false }, nextServer{ 31000, true, false };
	check(std::wstring(releaseOf(next, known).name) == L"Windows 11" && !known, "a newer client build is not treated as the last one known, flagged");
	check(std::wstring(releaseOf(nextServer, known).name) == L"Windows Server 2025" && !known, "a newer server build is not treated as the last one known, flagged");
	for (const ArtefactEntry& e : artefactCatalogue()) {
		check(availabilityOf(e.key, next) == availabilityOf(e.key, eleven), std::string(e.key) + ": differs on the next Windows");
		check(&formOf(e, next) == &formOf(e, eleven), std::string(e.key) + ": another form on the next Windows");
	}
	const WindowsVersion older{ 1381, false, false };   // Windows NT 4
	check(std::wstring(releaseOf(older, known).name) == L"Windows XP" && !known, "an older build not flagged");

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
