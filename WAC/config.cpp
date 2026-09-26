/*! \file
 *  \brief The configuration file, wac.yml (see config.h).
 */
#include "config.h"
#include "sha.h"
#include "yaml_light.h"
#include <filesystem>
#include <fstream>

namespace {

const size_t CONFIGURATION_MAX = 64 * 1024;   //!< a configuration is a few hundred bytes

//! "line N: why".
bool refuse(std::string& error, const YamlNode& node, const std::string& why) {
	error = "line " + std::to_string(node.line) + ": " + why;
	return false;
}

//! A scalar setting, not a section. @return false with `error` otherwise
bool scalar(const YamlNode& node, const std::string& key, std::string& error) {
	if (!node.mapping) return true;
	return refuse(error, node, key + " takes a value, not a section");
}

//! true / false, nothing else — "yes", "on", "1" are refused: a value is written one way.
bool readBool(const YamlNode& node, const std::string& key, bool& value, std::string& error) {
	if (!scalar(node, key, error)) return false;
	if (node.scalar == "true") { value = true; return true; }
	if (node.scalar == "false") { value = false; return true; }
	return refuse(error, node, key + ": \"" + node.scalar + "\", true or false expected");
}

//! An integer within bounds.
bool readInt(const YamlNode& node, const std::string& key, int low, int high, int& value, std::string& error) {
	if (!scalar(node, key, error)) return false;
	if (node.scalar.empty() || node.scalar.size() > 4 || node.scalar.find_first_not_of("0123456789") != std::string::npos)
		return refuse(error, node, key + ": \"" + node.scalar + "\", a number expected");
	value = std::stoi(node.scalar);
	if (value < low || value > high)
		return refuse(error, node, key + ": " + node.scalar + ", between " + std::to_string(low) + " and "
		                         + std::to_string(high) + " expected");
	return true;
}

//! The `artefacts:` section: one switch per artefact.
bool readArtefacts(const YamlNode& section, AppliConf& conf, std::string& error) {
	if (!section.mapping) return refuse(error, section, "artefacts is a section: one line per artefact");
	struct Switch { const char* key; bool* value; };
	AppliConf::CollectedArtefacts& a = conf.artefacts;
	const Switch SWITCHES[] = {
		{ "registry", &a.registry }, { "events", &conf._events }, { "scheduled_tasks", &a.scheduledTasks },
		{ "services", &a.services }, { "processes", &a.processes }, { "sessions", &a.sessions },
		{ "prefetch", &a.prefetch }, { "jump_lists", &a.jumpLists }, { "recent_documents", &a.recentDocuments },
	};
	for (const auto& [key, node] : section.children) {
		const Switch* found = nullptr;
		for (const Switch& s : SWITCHES) if (key == s.key) found = &s;
		if (!found) return refuse(error, *node, "unknown artefact \"" + key + "\"");
		if (!readBool(*node, "artefacts." + key, *found->value, error)) return false;
	}
	return true;
}

/*! The top-level settings. `convert` and `binary` map onto the run mode and
 *  the binaries' rule; the command line, applied after, overrides them. */
bool applySettings(const YamlNode& root, AppliConf& conf, std::string& error) {
	for (const auto& [key, node] : root.children) {
		if (key == "convert") {
			bool convert = true;
			if (!readBool(*node, key, convert, error)) return false;
			conf.mode = convert ? RunMode::Full : RunMode::Collect;
		}
		else if (key == "binary") {
			if (!scalar(*node, key, error)) return false;
			if (node->scalar == "none") conf.binary = conf.binaryAll = false;
			else if (node->scalar == "unverified") { conf.binary = true; conf.binaryAll = false; }
			else if (node->scalar == "all") conf.binary = conf.binaryAll = true;
			else return refuse(error, *node, "binary: \"" + node->scalar + "\", none, unverified or all expected");
		}
		else if (key == "threads") {
			int threads = 0;
			if (!readInt(*node, key, 0, 256, threads, error)) return false;
			conf.threads = (unsigned)threads;
		}
		else if (key == "output") {
			if (!scalar(*node, key, error)) return false;
			// As for --output: a folder of the current directory, by its name.
			if (node->scalar.empty() || node->scalar.find_first_of("\\/:") != std::string::npos)
				return refuse(error, *node, "output: a folder name, without \\, / or :");
			conf._outputDir = decodeText(node->scalar, CP_UTF8);
		}
		else if (key == "log_level") {
			if (!readInt(*node, key, 0, 3, conf.loglevel, error)) return false;
		}
		else if (key == "dump") {
			if (!readBool(*node, key, conf._dump, error)) return false;
		}
		else if (key == "artefacts") {
			if (!readArtefacts(*node, conf, error)) return false;
		}
		else return refuse(error, *node, "unknown setting \"" + key + "\"");
	}
	return true;
}

} // namespace

std::wstring DefaultConfigurationPath() {
	wchar_t module[MAX_PATH];
	const DWORD size = GetModuleFileNameW(nullptr, module, MAX_PATH);
	if (size == 0 || size == MAX_PATH) return L"wac.yml";
	return std::filesystem::path(module).parent_path().wstring() + L"\\wac.yml";
}

bool LoadConfiguration(const std::wstring& path, AppliConf& conf, ConfigurationFile& file, std::string& error) {
	file = ConfigurationFile{};
	std::error_code ec;
	if (!std::filesystem::exists(path, ec)) return true;          // no file: the defaults, and the command line
	const uintmax_t size = std::filesystem::file_size(path, ec);
	if (ec || size > CONFIGURATION_MAX) { error = "configuration file unreadable or larger than 64 KiB"; return false; }
	std::ifstream in(std::filesystem::path(path), std::ios::binary);
	file.text.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	if (!in && !in.eof()) { error = "configuration file unreadable"; return false; }
	file.path = path;
	uint8_t digest[32];
	sha256Bytes(reinterpret_cast<const uint8_t*>(file.text.data()), file.text.size(), digest);
	file.sha256 = toHexadecimal(digest, sizeof(digest));
	YamlNode root;
	if (!YamlParse(file.text, root, error) || !applySettings(root, conf, error)) return false;
	file.present = true;
	return true;
}

std::string DefaultConfiguration() {
	return
		"# WAC configuration — read from wac.yml, next to WAC.exe.\n"
		"# The command line overrides it. An unknown key or value refuses the collection.\n"
		"\n"
		"# true: collect and convert on this machine; false: collect only (convert later, elsewhere, with --convert).\n"
		"convert: false\n"
		"\n"
		"# Executables: none; unverified (collect those whose signature does not hold);\n"
		"# all (collect every one, its signature verdict recorded).\n"
		"binary: unverified\n"
		"\n"
		"# Threads analysing the executables; 0: the processor's threads minus one.\n"
		"threads: 0\n"
		"\n"
		"# Output folder, in the current directory.\n"
		"output: output\n"
		"\n"
		"# Detail of WAC.log: 0 (no log) to 3.\n"
		"log_level: 0\n"
		"\n"
		"# Raw hexadecimal values of shellbags and shortcuts, in the JSON.\n"
		"dump: false\n"
		"\n"
		"# The artefacts to collect.\n"
		"artefacts:\n"
		"  registry: true          # the hives, and every artefact read in them\n"
		"  events: true            # the event logs, with their messages\n"
		"  scheduled_tasks: true\n"
		"  services: true          # services and drivers\n"
		"  processes: true         # live\n"
		"  sessions: true          # live\n"
		"  prefetch: true\n"
		"  jump_lists: true\n"
		"  recent_documents: true\n";
}
