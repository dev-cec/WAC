/*! \file
 *  \brief Checks that wac.yml is applied exactly, and refused when it holds
 *  what WAC does not understand.
 *
 *  WHY THIS TEST. The configuration decides what a collection takes. A value
 *  applied wrongly, or a typo accepted, changes the procedure and nothing
 *  shows it. Each setting is applied and checked; each kind of mistake —
 *  unknown key, unknown artefact, value outside the ones allowed, a section
 *  where a value is expected — must refuse the file, naming the line; the
 *  reference file WAC writes (--write-config) must read back as it says.
 *
 *  Usage (runs under wine): config_test.exe `<scratch folder>`
 */
#include "config.h"
#include <cstdio>
#include <filesystem>
#include <fstream>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;
std::filesystem::path g_folder;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! Writes `text` to a file of the scratch folder. @return its path
std::wstring file(const char* name, const std::string& text) {
	const std::filesystem::path path = g_folder / name;
	std::ofstream(path, std::ios::binary) << text;
	return path.wstring();
}

//! The text must be refused, the message naming `line` and containing `expected`.
void refused(const char* name, const std::string& text, int line, const std::string& expected) {
	AppliConf c;
	ConfigurationFile f;
	std::string error;
	const bool read = LoadConfiguration(file(name, text), c, f, error);
	check(!read, std::string(name) + ": accepted");
	check(error.find("line " + std::to_string(line)) == 0 && error.find(expected) != std::string::npos,
	      std::string(name) + ": refused as \"" + error + "\"");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) { std::printf("usage: config_test <scratch folder>\n"); return 2; }
	g_folder = argv[1];
	std::filesystem::create_directories(g_folder);

	// Absent: nothing applied, the defaults kept.
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		check(LoadConfiguration((g_folder / "absent.yml").wstring(), c, f, error) && !f.present, "absent file: refused or applied");
		check(c.mode == RunMode::Full && !c.binary && c.artefacts.registry && !c._events, "absent file: defaults changed");
	}
	// Every setting applied.
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		const std::string text = "convert: false\nbinary: all\nthreads: 3\noutput: case42\nlog_level: 2\ndump: true\n"
		                         "artefacts:\n  registry: false\n  events: true\n  prefetch: false\n  sessions: false\n";
		check(LoadConfiguration(file("all.yml", text), c, f, error), "all settings: refused: " + error);
		check(c.mode == RunMode::Collect && c.binary && c.binaryAll && c.threads == 3 && c._outputDir == L"case42"
		      && c.loglevel == 2 && c._dump, "top-level settings not applied");
		check(!c.artefacts.registry && c._events && !c.artefacts.prefetch && !c.artefacts.sessions
		      && c.artefacts.processes && c.artefacts.jumpLists, "artefact switches not applied, or others changed");
		check(f.present && f.text == text && f.sha256.size() == 64, "file not recorded for the log");
	}
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		check(LoadConfiguration(file("unverified.yml", "binary: unverified\n"), c, f, error) && c.binary && !c.binaryAll,
		      "binary: unverified not applied");
		check(LoadConfiguration(file("none.yml", "binary: none\n"), c, f, error) && !c.binary && !c.binaryAll,
		      "binary: none not applied");
	}
	// The reference file reads back as it says.
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		check(LoadConfiguration(file("reference.yml", DefaultConfiguration()), c, f, error), "reference file refused: " + error);
		check(c.mode == RunMode::Collect && c.binary && !c.binaryAll && c._events && c.artefacts.registry,
		      "reference file not applied as it says");
	}
	refused("unknown.yml", "convert: false\nbinaries: all\n", 2, "unknown setting");
	refused("artefact.yml", "artefacts:\n  registry: true\n  prefetchs: true\n", 3, "unknown artefact");
	refused("bool.yml", "dump: yes\n", 1, "true or false expected");
	refused("binary.yml", "binary: everything\n", 1, "none, unverified or all");
	refused("threads.yml", "threads: 9999\n", 1, "between 0 and 256");
	refused("output.yml", "output: C:\\\\temp\n", 1, "a folder name");
	refused("section.yml", "binary:\n  method: all\n", 1, "takes a value");
	refused("duplicate.yml", "artefacts:\n  events: true\n  events: false\n", 3, "given twice");

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
