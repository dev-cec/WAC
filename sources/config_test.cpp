/*! \file
 *  \brief Checks that wac.yml is applied exactly, and refused when it holds
 *  what WAC does not understand.
 *
 *  WHY THIS TEST. The configuration decides what a collection takes. A value
 *  applied wrongly, or a typo accepted, changes the procedure and nothing
 *  shows it. Each setting is applied and checked; each kind of mistake —
 *  unknown key, unknown artefact, value outside the ones allowed, a section
 *  where a value is expected — must refuse the file, naming the line; the
 *  reference file WAC writes (--write-config) must read back as it says, and
 *  carry the executable's version; a file of another version, or without
 *  one, is refused before any of its settings is read.
 *  The refusals are shown in the console's language: checked in English, and
 *  once in French, with its values placed where the French wording puts them.
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

//! Writes `text` to a file of the scratch folder, as given. @return its path
std::wstring rawFile(const char* name, const std::string& text) {
	const std::filesystem::path path = g_folder / name;
	std::ofstream(path, std::ios::binary) << text;
	return path.wstring();
}

/*! Writes `text` followed by the executable's version — last, so that the
 *  line numbers the refusals name stay those of `text`. @return its path */
std::wstring file(const char* name, const std::string& text) {
	return rawFile(name, text + "wac_version: " + encodeText(WacVersion()) + "\n");
}

/*! The text must be refused, the message naming `line` and containing
 *  `expected` (UTF-8). @param lineWord "line", or "ligne" in French */
void refused(const char* name, const std::string& text, int line, const std::string& expected,
             const std::string& lineWord = "line") {
	AppliConf c;
	ConfigurationFile f;
	std::string error;
	const bool read = LoadConfiguration(file(name, text), c, f, error);
	check(!read, std::string(name) + ": accepted");
	check(error.find(lineWord + " " + std::to_string(line)) == 0 && error.find(expected) != std::string::npos,
	      std::string(name) + ": refused as \"" + error + "\"");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) { std::printf("usage: config_test <scratch folder>\n"); return 2; }
	g_folder = argv[1];
	std::filesystem::create_directories(g_folder);
	setLanguage(Language::English);   // the refusals below are checked in English, one in French at the end

	// Absent: nothing applied, the defaults kept.
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		check(LoadConfiguration((g_folder / "absent.yml").wstring(), c, f, error) && !f.present, "absent file: refused or applied");
		check(c.mode == RunMode::Collect && !c.binary && c.artefacts.events && c.artefacts.amcache && c.artefacts.operatingSystem,
		      "absent file: defaults changed — every artefact is on");
	}
	// Every setting applied.
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		const std::string text = "binary: all\nthreads: 3\noutput: case42\nlog_level: 2\ndump: true\nlanguage: en\n"
		                         "artefacts:\n  amcache: false\n  events: false\n  prefetch: false\n  sessions: false\n"
		                         "  network: false\n";
		check(LoadConfiguration(file("all.yml", text), c, f, error), "all settings: refused: " + error);
		check(c.mode == RunMode::Collect && c.binary && c.binaryAll && c.threads == 3 && c._outputDir == L"case42"
		      && c.loglevel == 2 && c._dump && c.language == Language::English, "top-level settings not applied");
		check(!c.artefacts.amcache && !c.artefacts.events && !c.artefacts.prefetch && !c.artefacts.sessions
		      && !c.artefacts.network && c.artefacts.processes && c.artefacts.jumpLists && c.artefacts.shimcache,
		      "artefact switches not applied, or others changed");
		check(f.present && f.text == text + "wac_version: " + encodeText(WacVersion()) + "\n" && f.sha256.size() == 64,
		      "file not recorded for the log");
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
		check(LoadConfiguration(rawFile("reference.yml", DefaultConfiguration()), c, f, error), "reference file refused: " + error);
		check(c.mode == RunMode::Collect && c.binary && !c.binaryAll && c.artefacts.events && c.artefacts.users
		      && c.language == Language::French, "reference file not applied as it says");
	}
	refused("unknown.yml", "threads: 2\nbinaries: all\n", 2, "unknown setting");
	// Collection OR conversion (B-047): the setting that converted on the examined machine is gone.
	refused("convert.yml", "convert: true\n", 1, "unknown setting");
	// THE VERSION. Read from this executable's resources, as WAC.exe reads its own.
	check(!WacVersion().empty(), "no version in the executable's resources");
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		check(!LoadConfiguration(rawFile("noversion.yml", "binary: none\n"), c, f, error)
		      && error.find("wac_version missing") != std::string::npos, "file without wac_version: " + error);
		// An earlier version's file, with a key gone since: the version is the reason given.
		check(!LoadConfiguration(rawFile("earlier.yml", "artefacts:\n  registry: true\nwac_version: 0.9.9\n"), c, f, error)
		      && error.find("line 3") == 0 && error.find("written for WAC 0.9.9") != std::string::npos,
		      "earlier version's file: " + error);
		const std::string reference = DefaultConfiguration();
		check(reference.find("\nwac_version: " + encodeText(WacVersion()) + "\n") != std::string::npos
		      && reference.find("@WAC_VERSION@") == std::string::npos, "--write-config: the version not written in");
	}
	refused("artefact.yml", "artefacts:\n  events: true\n  prefetchs: true\n", 3, "unknown artefact");
	// `registry` grouped sixteen artefacts and is gone (B-042): one key each now.
	refused("registry.yml", "artefacts:\n  registry: true\n", 2, "unknown artefact");
	refused("bool.yml", "dump: yes\n", 1, "true or false expected");
	refused("binary.yml", "binary: everything\n", 1, "none, unverified or all");
	refused("threads.yml", "threads: 9999\n", 1, "between 0 and 256");
	refused("output.yml", "output: C:\\\\temp\n", 1, "a folder name");
	refused("section.yml", "binary:\n  method: all\n", 1, "takes a value");
	// deleted_files: a switch, or a section of its options (B-036).
	{
		AppliConf c;
		ConfigurationFile f;
		std::string error;
		const AppliConf::DeletedFilesSettings defaults;
		check(LoadConfiguration(file("deleted-switch.yml", "artefacts:\n  deleted_files: false\n"), c, f, error)
		      && !c.artefacts.deletedFiles && c.deletedFilesSettings.maxFileMib == defaults.maxFileMib,
		      "deleted_files: false not applied: " + error);
		AppliConf d;
		const std::string text = "artefacts:\n  deleted_files:\n    enabled: true\n    level: 1\n    max_file_mib: 8\n"
		                         "    max_total_mib: 1048576\n    excluded_folders:\n      - \\Windows\\Temp\n      - \\$Extend\n";
		check(LoadConfiguration(file("deleted-section.yml", text), d, f, error) && d.artefacts.deletedFiles
		      && d.deletedFilesSettings.level == 1 && d.deletedFilesSettings.maxFileMib == 8
		      && d.deletedFilesSettings.maxTotalMib == 1048576 && d.deletedFilesSettings.excludedFolders.size() == 2
		      && d.deletedFilesSettings.excludedFolders[0] == L"\\Windows\\Temp", "deleted_files options not applied: " + error);
		AppliConf e;
		check(LoadConfiguration(file("deleted-partial.yml", "artefacts:\n  deleted_files:\n    max_file_mib: 16\n"), e, f, error)
		      && e.artefacts.deletedFiles && e.deletedFilesSettings.maxFileMib == 16
		      && e.deletedFilesSettings.maxTotalMib == defaults.maxTotalMib
		      && e.deletedFilesSettings.excludedFolders == defaults.excludedFolders, "deleted_files: a missing option lost its default");
		AppliConf g;
		check(LoadConfiguration(rawFile("reference-deleted.yml", DefaultConfiguration()), g, f, error) && g.artefacts.deletedFiles
		      && g.deletedFilesSettings.level == defaults.level && g.deletedFilesSettings.maxFileMib == defaults.maxFileMib
		      && g.deletedFilesSettings.maxTotalMib == defaults.maxTotalMib
		      && g.deletedFilesSettings.excludedFolders == defaults.excludedFolders, "reference file: deleted_files differs from the defaults");
	}
	refused("deleted-level.yml", "artefacts:\n  deleted_files:\n    level: 4\n", 3, "between 1 and 3");
	refused("deleted-unknown.yml", "artefacts:\n  deleted_files:\n    max_size: 8\n", 3, "unknown setting \"artefacts.deleted_files.max_size\"");
	refused("deleted-total.yml", "artefacts:\n  deleted_files:\n    max_total_mib: 99999999\n", 3, "between 1 and 16777216");
	refused("deleted-drive.yml", "artefacts:\n  deleted_files:\n    excluded_folders:\n      - C:\\Windows\n", 3, "a folder from the volume's root");
	refused("deleted-up.yml", "artefacts:\n  deleted_files:\n    excluded_folders:\n      - \\Windows\\..\\Users\n", 3, "a folder from the volume's root");
	refused("deleted-scalar.yml", "artefacts:\n  deleted_files:\n    excluded_folders: \\Windows\n", 3, "a list expected");
	refused("list.yml", "dump:\n  - true\n", 1, "takes a value, not a list");
	refused("deleted-list.yml", "artefacts:\n  deleted_files:\n    - true\n", 2, "takes a value, not a list");
	refused("duplicate.yml", "artefacts:\n  events: true\n  events: false\n", 3, "given twice");
	refused("language.yml", "language: de\n", 1, "fr or en expected");
	// In French: the words, and the values in their places ("entre 0 et 256").
	setLanguage(Language::French);
	refused("threads_fr.yml", "threads: 9999\n", 1, "threads : 9999, entre 0 et 256 attendu", "ligne");
	refused("bool_fr.yml", "dump: oui\n", 1, "true ou false attendu", "ligne");

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
