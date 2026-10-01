/*! \file
 *  \brief The configuration file, wac.yml (see config.h).
 */
#include "config.h"
#include "sha.h"
#include "yaml_light.h"
#include "resource.h"
#include <filesystem>
#include <fstream>

namespace {

const size_t CONFIGURATION_MAX = 64 * 1024;   //!< a configuration is a few hundred bytes

/*! "line N: why", in the console's language (the refusal is shown to the
 *  operator, before any log exists), as UTF-8 like the YAML reader's. */
bool refuse(std::string& error, const YamlNode& node, const std::wstring& why) {
	error = encodeText(text(Text::ConfigurationLine, { std::to_wstring(node.line), why }));
	return false;
}

//! A key or a value of the file, UTF-8, for a refusal.
std::wstring wide(const std::string& utf8) { return decodeText(utf8, CP_UTF8); }

//! A scalar setting, not a section. @return false with `error` otherwise
bool scalar(const YamlNode& node, const std::string& key, std::string& error) {
	if (!node.mapping) return true;
	return refuse(error, node, text(Text::ConfigurationSectionNotValue, { wide(key) }));
}

//! true / false, nothing else — "yes", "on", "1" are refused: a value is written one way.
bool readBool(const YamlNode& node, const std::string& key, bool& value, std::string& error) {
	if (!scalar(node, key, error)) return false;
	if (node.scalar == "true") { value = true; return true; }
	if (node.scalar == "false") { value = false; return true; }
	return refuse(error, node, text(Text::ConfigurationBooleanExpected, { wide(key), wide(node.scalar) }));
}

//! An integer within bounds.
bool readInt(const YamlNode& node, const std::string& key, int low, int high, int& value, std::string& error) {
	if (!scalar(node, key, error)) return false;
	if (node.scalar.empty() || node.scalar.size() > 4 || node.scalar.find_first_not_of("0123456789") != std::string::npos)
		return refuse(error, node, text(Text::ConfigurationNumberExpected, { wide(key), wide(node.scalar) }));
	value = std::stoi(node.scalar);
	if (value < low || value > high)
		return refuse(error, node, text(Text::ConfigurationOutOfRange,
		                                { wide(key), wide(node.scalar), std::to_wstring(low), std::to_wstring(high) }));
	return true;
}

//! The `artefacts:` section: one switch per artefact.
bool readArtefacts(const YamlNode& section, AppliConf& conf, std::string& error) {
	if (!section.mapping) return refuse(error, section, text(Text::ConfigurationArtefactsSection));
	struct Switch { const char* key; bool* value; };
	AppliConf::CollectedArtefacts& a = conf.artefacts;
	const Switch SWITCHES[] = {
		{ "registry", &a.registry }, { "events", &conf._events }, { "scheduled_tasks", &a.scheduledTasks },
		{ "services", &a.services }, { "processes", &a.processes }, { "sessions", &a.sessions },
		{ "network", &a.network },
		{ "prefetch", &a.prefetch }, { "jump_lists", &a.jumpLists }, { "recent_documents", &a.recentDocuments },
		{ "mft", &a.mft }, { "usn_journal", &a.usnJournal }, { "log_file", &a.logFile },
		{ "powershell_history", &a.powershellHistory }, { "setupapi", &a.setupApi },
		{ "recycle_bin", &a.recycleBin }, { "hosts", &a.hosts }, { "error_reports", &a.errorReports },
		{ "defender", &a.defender }, { "startup_folders", &a.startupFolders },
		{ "shortcuts", &a.shortcuts },
		{ "security_descriptors", &a.securityDescriptors },
		{ "ntfs_volumes", &a.ntfsVolumes },
		{ "dpapi_master_keys", &a.dpapiMasterKeys },
		{ "user_shell_folders", &a.userShellFolders },
		{ "web_client", &a.webClient },
		{ "zone_identifiers", &a.zoneIdentifiers }, { "security", &a.security },
		{ "persistence", &a.persistence },
		{ "office_trust_records", &a.officeTrustRecords }, { "typed_paths", &a.typedPaths }, { "word_wheel_query", &a.wordWheelQuery }, { "root_certificates", &a.rootCertificates }, { "internet_settings", &a.internetSettings }, { "firewall", &a.firewall },
		{ "wmi", &a.wmi }, { "srum", &a.srum }, { "bits", &a.bits },
		{ "fat_volumes", &a.fatVolumes },
		{ "installed_programs", &a.installedPrograms },
		{ "defender_configuration", &a.defenderConfiguration },
		{ "explorer_recent_docs", &a.explorerRecentDocs },
		{ "mount_points", &a.mountPoints },
		{ "known_networks", &a.knownNetworks },
		{ "program_usage", &a.programUsages },
		{ "devices", &a.devices },
		{ "network_shares", &a.networkShares },
		{ "network_configuration", &a.networkConfiguration },
		{ "event_log_configuration", &a.eventLogConfiguration },
	};
	for (const auto& [key, node] : section.children) {
		const Switch* found = nullptr;
		for (const Switch& s : SWITCHES) if (key == s.key) found = &s;
		if (!found) return refuse(error, *node, text(Text::ConfigurationUnknownArtefact, { wide(key) }));
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
			else return refuse(error, *node, text(Text::ConfigurationBinaryValue, { wide(node->scalar) }));
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
				return refuse(error, *node, text(Text::ConfigurationOutputValue));
			conf._outputDir = decodeText(node->scalar, CP_UTF8);
		}
		else if (key == "log_level") {
			if (!readInt(*node, key, 0, 3, conf.loglevel, error)) return false;
		}
		else if (key == "dump") {
			if (!readBool(*node, key, conf._dump, error)) return false;
		}
		else if (key == "language") {
			if (!scalar(*node, key, error)) return false;
			if (!languageFromCode(wide(node->scalar), conf.language))
				return refuse(error, *node, text(Text::ConfigurationLanguageValue, { wide(node->scalar) }));
		}
		else if (key == "artefacts") {
			if (!readArtefacts(*node, conf, error)) return false;
		}
		else return refuse(error, *node, text(Text::ConfigurationUnknownSetting, { wide(key) }));
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
	if (ec || size > CONFIGURATION_MAX) { error = encodeText(text(Text::ConfigurationTooLarge)); return false; }
	std::ifstream in(std::filesystem::path(path), std::ios::binary);
	file.text.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	if (!in && !in.eof()) { error = encodeText(text(Text::ConfigurationUnreadable)); return false; }
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
	// sources/wac.yml, built into the executable (RCDATA): one source for the file WAC writes and the one bin holds.
	HRSRC found = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_DEFAULT_CONFIGURATION), MAKEINTRESOURCEW(10));   // RT_RCDATA
	HGLOBAL loaded = found ? LoadResource(nullptr, found) : nullptr;
	const char* bytes = loaded ? static_cast<const char*>(LockResource(loaded)) : nullptr;
	return bytes ? std::string(bytes, SizeofResource(nullptr, found)) : std::string();
}
