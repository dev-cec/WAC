/*! \file
 *  \brief Sysmon's configuration and archives (see sysmon.h).
 */
#include "sysmon.h"
#include "sha.h"
#include "portable_conversions.h"
#include "tools.h"
#include <algorithm>
#include <filesystem>
#include <set>

namespace {

const std::wstring SERVICES = L"Services";
//! The archive folder when ArchiveDirectory is absent: Sysmon's default.
const wchar_t* const DEFAULT_ARCHIVE_DIRECTORY = L"\\Sysmon\\";

/*! The absolute path of an ArchiveDirectory: a folder at the root of the
 *  system volume, as Sysmon writes it ("\\Sysmon\\", "Sysmon"), or a path
 *  with its letter.
 *  @return without its trailing separator */
std::wstring archiveFolderOf(std::wstring value) {
	while (!value.empty() && (value.back() == L'\\' || value.back() == L'/')) value.pop_back();
	if (value.size() >= 2 && value[1] == L':') return value;
	if (value.empty() || value[0] != L'\\') value = L"\\" + value;
	return conf.systemDrive.substr(0, 2) + value;
}

/*! Reads the driver's Parameters of an installation: every value, Rules'
 *  fingerprint, the archive folder and the configuration file.
 *  @return false if the key holds no Rules: not a Sysmon driver */
bool readDriverParameters(const std::wstring& driverKey, SysmonInstallation& s) {
	ORHKEY key = NULL;
	if (OROpenKey(conf.CurrentControlSet, (driverKey + L"\\Parameters").c_str(), &key) != ERROR_SUCCESS) return false;
	bool rules = false;
	std::wstring archive = DEFAULT_ARCHIVE_DIRECTORY, configFile;
	for (DWORD i = 0;; ++i) {
		std::wstring name;
		DWORD type = 0;
		std::vector<BYTE> data;
		if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
		s.parameters.emplace_back(registryNameToJsonKey(name), registryValueToJson(type, data));
		if (_wcsicmp(name.c_str(), L"Rules") == 0) {
			rules = true;
			uint8_t digest[32];
			sha256Bytes(data.data(), data.size(), digest);
			s.rulesSha256 = toHexadecimal(digest, sizeof digest);
		} else if (_wcsicmp(name.c_str(), L"ArchiveDirectory") == 0) archive = valueText(type, data);
		else if (_wcsicmp(name.c_str(), L"ConfigFile") == 0) configFile = valueText(type, data);
	}
	s.parametersLastWriteUtc = lastWrite(key);
	ORCloseKey(key);
	s.archiveFolder = archiveFolderOf(archive);
	s.configFile = configFile.empty() ? L"" : normalizeFilePath(configFile);
	return rules;
}

} // namespace

std::vector<SysmonInstallation> sysmonInstallations() {
	std::vector<SysmonInstallation> found;
	if (!conf.CurrentControlSet) return found;
	std::set<std::wstring> drivers;
	for (const std::wstring& service : subkeys(conf.CurrentControlSet, SERVICES)) {
		SysmonInstallation s;
		if (getRegSzValue(conf.CurrentControlSet, (SERVICES + L"\\" + service + L"\\Parameters").c_str(), L"DriverName", &s.driver)
		        != ERROR_SUCCESS || s.driver.empty() || !drivers.insert(toLower(s.driver)).second)
			continue;
		const std::wstring driverKey = SERVICES + L"\\" + s.driver;
		if (!readDriverParameters(driverKey, s)) continue;
		s.service = service;
		ORHKEY key = NULL;
		if (OROpenKey(conf.CurrentControlSet, (SERVICES + L"\\" + service).c_str(), &key) == ERROR_SUCCESS) {
			s.serviceLastWriteUtc = lastWrite(key);
			ORCloseKey(key);
		}
		// Absent, the path stays empty and is not emitted.
		if (getRegSzValue(conf.CurrentControlSet, (SERVICES + L"\\" + service).c_str(), L"ImagePath", &s.serviceImagePath) != ERROR_SUCCESS)
			s.serviceImagePath.clear();
		if (getRegSzValue(conf.CurrentControlSet, driverKey.c_str(), L"ImagePath", &s.driverImagePath) != ERROR_SUCCESS)
			s.driverImagePath.clear();
		found.push_back(std::move(s));
	}
	return found;
}

Json SysmonEntry::toJson() const {
	const SysmonInstallation& s = installation;
	Json o = Json::obj();
	o.add(L"Service", Json::str(s.service));
	o.add(L"ServiceImagePath", Json::str(s.serviceImagePath));
	addDate(o, L"ServiceKeyLastWrite", s.serviceLastWriteUtc);
	o.add(L"Driver", Json::str(s.driver));
	o.add(L"DriverImagePath", Json::str(s.driverImagePath));
	addDate(o, L"ParametersKeyLastWrite", s.parametersLastWriteUtc);
	Json parameters = Json::obj();
	for (const auto& [name, value] : s.parameters) parameters.add(name, value);
	o.add(L"Parameters", parameters);
	o.add(L"RulesSha256", Json::str(s.rulesSha256));
	o.add(L"ArchiveFolder", Json::str(s.archiveFolder));
	o.add(L"ConfigFileSha256", Json::str(configFileSha256));
	Json archived = Json::arr();
	for (const SysmonArchivedFile& f : archivedFiles) {
		Json a = Json::obj();
		a.add(L"Path", Json::str(f.path));
		a.add(L"Size", Json::num(f.size));
		a.add(L"Sha256", Json::str(f.sha256));
		archived.push(std::move(a));
	}
	o.add(L"ArchivedFiles", archived);
	return o;
}

HRESULT Sysmon::getData() {
	if (!conf.CurrentControlSet) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	for (SysmonInstallation& s : sysmonInstallations()) {
		SysmonEntry e;
		// The working copy, as the collection took it: the exhibit store is not read again.
		std::error_code ec;
		const std::filesystem::path folder = extractedPath(s.archiveFolder);
		for (std::filesystem::recursive_directory_iterator it(folder, ec), end; !ec && it != end; it.increment(ec)) {
			if (!it->is_regular_file(ec)) continue;
			SysmonArchivedFile f;
			f.path = originalPath(it->path().wstring());
			f.size = it->file_size(ec);
			f.sha256 = sha256OfFile(it->path().wstring());
			e.archivedFiles.push_back(std::move(f));
		}
		std::sort(e.archivedFiles.begin(), e.archivedFiles.end(),
		          [](const SysmonArchivedFile& a, const SysmonArchivedFile& b) { return a.path < b.path; });
		if (!s.configFile.empty()) {
			const std::wstring config = extractedPath(s.configFile);
			if (std::filesystem::is_regular_file(config, ec)) e.configFileSha256 = sha256OfFile(config);
		}
		e.installation = std::move(s);
		entries_.push_back(std::move(e));
	}
	return ERROR_SUCCESS;
}

HRESULT Sysmon::toJson() { return writeList("sysmon.json", entries_); }
void Sysmon::clear() { entries_.clear(); }
