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
const char VERSION_KEY[] = "wac_version";      //!< the version of WAC the file was written for
const char VERSION_PLACEHOLDER[] = "@WAC_VERSION@";   //!< its value in sources/wac.yml, filled when written

/*! "line N: why", in the console's language (the refusal is shown to the
 *  operator, before any log exists), as UTF-8 like the YAML reader's. */
bool refuse(std::string& error, const YamlNode& node, const std::wstring& why) {
	error = encodeText(text(Text::ConfigurationLine, { std::to_wstring(node.line), why }));
	return false;
}

//! A key or a value of the file, UTF-8, for a refusal.
std::wstring wide(const std::string& utf8) { return decodeText(utf8, CP_UTF8); }

//! A scalar setting, not a section nor a list. @return false with `error` otherwise
bool scalar(const YamlNode& node, const std::string& key, std::string& error) {
	if (node.mapping) return refuse(error, node, text(Text::ConfigurationSectionNotValue, { wide(key) }));
	if (node.list) return refuse(error, node, text(Text::ConfigurationListNotValue, { wide(key) }));
	return true;
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
	// Nine digits at most: within an int, whatever the value.
	if (node.scalar.empty() || node.scalar.size() > 9 || node.scalar.find_first_not_of("0123456789") != std::string::npos)
		return refuse(error, node, text(Text::ConfigurationNumberExpected, { wide(key), wide(node.scalar) }));
	value = std::stoi(node.scalar);
	if (value < low || value > high)
		return refuse(error, node, text(Text::ConfigurationOutOfRange,
		                                { wide(key), wide(node.scalar), std::to_wstring(low), std::to_wstring(high) }));
	return true;
}

} // namespace

std::vector<std::pair<std::string, bool*>> artefactSwitches(AppliConf& conf) {
	AppliConf::CollectedArtefacts& a = conf.artefacts;
	return {
		{ "events", &a.events }, { "operating_system", &a.operatingSystem },
		{ "usbstor", &a.usbstor }, { "mounted_devices", &a.mountedDevices }, { "bam", &a.bam },
		{ "muicache", &a.muiCache }, { "amcache", &a.amcache }, { "userassist", &a.userAssist },
		{ "run_keys", &a.runKeys }, { "shimcache", &a.shimcache }, { "shellbags", &a.shellbags },
		{ "mru", &a.mru }, { "mru_apps", &a.mruApps }, { "users", &a.users }, { "local_groups", &a.localGroups },
		{ "registry_backups", &a.registryBackups }, { "scheduled_tasks", &a.scheduledTasks },
		{ "services", &a.services }, { "processes", &a.processes }, { "sessions", &a.sessions },
		{ "network", &a.network },
		{ "prefetch", &a.prefetch }, { "jump_lists", &a.jumpLists }, { "recent_documents", &a.recentDocuments },
		{ "mft", &a.mft }, { "usn_journal", &a.usnJournal }, { "log_file", &a.logFile },
		{ "powershell_history", &a.powershellHistory }, { "powershell_profiles", &a.powershellProfiles },
		{ "setupapi", &a.setupApi },
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
		{ "office_trust_records", &a.officeTrustRecords }, { "typed_paths", &a.typedPaths }, { "word_wheel_query", &a.wordWheelQuery }, { "root_certificates", &a.rootCertificates }, { "internet_settings", &a.internetSettings }, { "intune_logs", &a.intuneLogs }, { "firewall", &a.firewall }, { "firewall_log", &a.firewallLog },
		{ "wmi", &a.wmi }, { "srum", &a.srum }, { "bits", &a.bits },
		{ "boot_records", &a.bootRecords },
		{ "cloud_identity", &a.cloudIdentity },
		{ "defender_endpoint", &a.defenderEndpoint },
		{ "etw_logs", &a.etwLogs },
		{ "onedrive", &a.onedrive },
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
		{ "activities_cache", &a.activitiesCache },
		{ "search_index", &a.searchIndex },
		{ "rdp_client", &a.rdpClient },
		{ "rdp_server", &a.rdpServer },
		{ "thumbcache", &a.thumbcache },
		{ "emails", &a.emails },
		{ "sysmon", &a.sysmon },
		{ "shadow_copies", &a.shadowCopies },
		{ "deleted_files", &a.deletedFiles },
	};
}

namespace {

//! Largest size a deleted file's options accept, in MiB: 1 TiB per file, 16 TiB in all.
const int DELETED_FILE_MAX_MIB = 1 << 20, DELETED_TOTAL_MAX_MIB = 1 << 24;

/*! A folder of `excluded_folders`: a path on each volume, from its root —
 *  "\\Windows\\WinSxS" —, without a drive, a "/", a ".." or a trailing "\\". */
bool volumeFolder(const std::string& folder) {
	if (folder.size() < 2 || folder[0] != '\\' || folder.back() == '\\') return false;
	if (folder.find_first_of(":/*?\"<>|") != std::string::npos) return false;
	return folder.find("\\..") == std::string::npos && folder.find("\\\\") == std::string::npos;
}

/*! The `deleted_files` entry of `artefacts:`: a switch like the others, or a
 *  section of its options — `enabled`, `level`, `max_file_mib`,
 *  `max_total_mib`, `excluded_folders`. A missing option keeps its default;
 *  `excluded_folders` given replaces the default list whole. */
bool readDeletedFiles(const YamlNode& node, AppliConf& conf, std::string& error) {
	const std::string key = "artefacts.deleted_files";
	if (!node.mapping) return readBool(node, key, conf.artefacts.deletedFiles, error);
	AppliConf::DeletedFilesSettings& settings = conf.deletedFilesSettings;
	for (const auto& [option, value] : node.children) {
		const std::string name = key + "." + option;
		if (option == "enabled") {
			if (!readBool(*value, name, conf.artefacts.deletedFiles, error)) return false;
		}
		else if (option == "level") {
			if (!readInt(*value, name, 1, 3, settings.level, error)) return false;
		}
		else if (option == "max_file_mib") {
			if (!readInt(*value, name, 1, DELETED_FILE_MAX_MIB, settings.maxFileMib, error)) return false;
		}
		else if (option == "max_total_mib") {
			if (!readInt(*value, name, 1, DELETED_TOTAL_MAX_MIB, settings.maxTotalMib, error)) return false;
		}
		else if (option == "excluded_folders") {
			if (!value->list) return refuse(error, *value, text(Text::ConfigurationListExpected, { wide(name) }));
			settings.excludedFolders.clear();
			for (const std::string& folder : value->items) {
				if (!volumeFolder(folder)) return refuse(error, *value, text(Text::ConfigurationVolumeFolder, { wide(name), wide(folder) }));
				settings.excludedFolders.push_back(wide(folder));
			}
		}
		else return refuse(error, *value, text(Text::ConfigurationUnknownSetting, { wide(name) }));
	}
	return true;
}

//! The `artefacts:` section: one switch per artefact, a section of options for deleted_files.
bool readArtefacts(const YamlNode& section, AppliConf& conf, std::string& error) {
	if (!section.mapping) return refuse(error, section, text(Text::ConfigurationArtefactsSection));
	const std::vector<std::pair<std::string, bool*>> switches = artefactSwitches(conf);
	for (const auto& [key, node] : section.children) {
		if (key == "deleted_files") {
			if (!readDeletedFiles(*node, conf, error)) return false;
			continue;
		}
		bool* found = nullptr;
		for (const auto& [name, value] : switches) if (key == name) found = value;
		if (!found) return refuse(error, *node, text(Text::ConfigurationUnknownArtefact, { wide(key) }));
		if (!readBool(*node, "artefacts." + key, *found, error)) return false;
	}
	return true;
}

/*! The top-level settings. `convert` and `binary` map onto the run mode and
 *  the binaries' rule; the command line, applied after, overrides them. */
bool applySettings(const YamlNode& root, AppliConf& conf, std::string& error) {
	/* THE VERSION FIRST. A file written for another WAC may lack the settings
	   added since — silently left at their defaults — or carry some that have
	   gone or changed meaning: it is refused, before any of its settings is
	   read, so that the reason given is the version and not a key it misses.
	   The same version is required, bugfix included: --write-config writes it. */
	const YamlNode* version = nullptr;
	for (const auto& [key, node] : root.children) if (key == VERSION_KEY) version = node.get();
	if (!version) {
		error = encodeText(text(Text::ConfigurationVersionMissing, { WacVersion() }));
		return false;
	}
	if (!scalar(*version, VERSION_KEY, error)) return false;
	if (wide(version->scalar) != WacVersion())
		return refuse(error, *version, text(Text::ConfigurationVersionMismatch, { wide(version->scalar), WacVersion() }));
	for (const auto& [key, node] : root.children) {
		if (key == VERSION_KEY) continue;
		if (key == "binary") {
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
	if (!readWholeFile(std::filesystem::path(path), CONFIGURATION_MAX, file.text)) {
		error = encodeText(text(Text::ConfigurationUnreadable));
		return false;
	}
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
	if (!bytes) return std::string();
	std::string reference(bytes, SizeofResource(nullptr, found));
	/* The version is written in WAC.rc only: the file takes the executable's,
	   read in its own resources, in place of the placeholder. */
	const size_t at = reference.find(VERSION_PLACEHOLDER);
	const std::wstring version = WacVersion();
	if (at == std::string::npos || version.empty()) return std::string();
	return reference.replace(at, sizeof(VERSION_PLACEHOLDER) - 1, encodeText(version));
}
