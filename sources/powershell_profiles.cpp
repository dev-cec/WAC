/*! \file
 *  \brief PowerShell profiles (see powershell_profiles.h).
 */
#include "powershell_profiles.h"
#include "consigne.h"
#include "sha.h"
#include "user_shell_folders.h"
#include <set>

namespace {

//! A profile's file is a script of a few lines: beyond this, its content is not given (its hash still is).
const uintmax_t PROFILE_MAX = 16ull * 1024 * 1024;

const wchar_t PROFILE_SUFFIX[] = L"profile.ps1";
const wchar_t HOST_SUFFIX[] = L"_profile.ps1";

} // namespace

bool isPowerShellProfile(const std::wstring& name) {
	const size_t suffix = wcslen(PROFILE_SUFFIX);
	return name.size() >= suffix && toLower(name.substr(name.size() - suffix)) == PROFILE_SUFFIX;
}

std::wstring powerShellProfileHost(const std::wstring& name) {
	const size_t suffix = wcslen(HOST_SUFFIX);
	if (name.size() > suffix && toLower(name.substr(name.size() - suffix)) == HOST_SUFFIX)
		return name.substr(0, name.size() - suffix);
	return L"AllHosts";
}

std::vector<PowerShellProfileFolder> powerShellProfileFolders(
		const std::function<std::vector<std::wstring>(const std::wstring&)>& listFolder) {
	std::vector<PowerShellProfileFolder> folders;
	std::set<std::wstring> seen;   // a folder once, whatever its spelling
	auto add = [&](const std::wstring& path, const std::wstring& sid, const wchar_t* edition) {
		if (seen.insert(toLower(examinedLayout(path))).second) folders.push_back({ path, sid, edition });
	};
	const std::wstring drive = conf.systemDrive.substr(0, 2);
	add(drive + L"\\Windows\\System32\\WindowsPowerShell\\v1.0", L"", L"Windows PowerShell");
	add(drive + L"\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0", L"", L"Windows PowerShell");
	for (const wchar_t* programs : { L"\\Program Files\\PowerShell", L"\\Program Files (x86)\\PowerShell" })
		for (const std::wstring& version : listFolder(drive + programs))
			add(drive + programs + L"\\" + version, L"", L"PowerShell");
	for (const std::tuple<std::wstring, std::wstring>& entry : conf.profiles) {
		const std::wstring& sid = std::get<0>(entry);
		const std::wstring& profile = std::get<1>(entry);
		std::vector<std::wstring> documents = { profile + L"\\Documents" };
		const std::wstring moved = redirectedShellFolder(sid, profile, L"Personal", L"Documents");
		if (!moved.empty()) documents.push_back(moved);
		for (const std::wstring& base : documents) {
			add(base + L"\\WindowsPowerShell", sid, L"Windows PowerShell");
			add(base + L"\\PowerShell", sid, L"PowerShell");
		}
	}
	return folders;
}

Json PowerShellProfile::toJson() const {
	Json o = Json::obj();
	o.add(L"Scope", Json::str(folder.sid.empty() ? L"Machine" : L"User"));
	if (!folder.sid.empty()) addUser(o, folder.sid);
	o.add(L"Edition", Json::str(folder.edition));
	o.add(L"Host", Json::str(host));
	o.add(L"Path", Json::str(path));
	addDate(o, L"SourceCreated", sourceCreatedUtc);
	addDate(o, L"SourceModified", sourceModifiedUtc);
	addDate(o, L"SourceAccessed", sourceAccessedUtc);
	o.add(L"Size", Json::num(size));
	o.add(L"Sha256", Json::str(sha256));
	if (!content.empty()) o.add(L"Content", Json::str(content));
	return o;
}

HRESULT PowerShellProfiles::getData() {
	log(0, L"ℹ️PowerShell profiles :");
	// PowerShell 7's folders as the working copy holds them.
	auto listWorking = [](const std::wstring& absolute) {
		std::vector<std::wstring> names;
		std::error_code ec;
		for (const auto& e : std::filesystem::directory_iterator(extractedPath(absolute), ec))
			if (e.is_directory(ec)) names.push_back(e.path().filename().wstring());
		return names;
	};
	for (const PowerShellProfileFolder& folder : powerShellProfileFolders(listWorking)) {
		for (const std::filesystem::path& file : listFilesByExtension(extractedPath(folder.path), { L".ps1" })) {
			const std::wstring name = file.filename().wstring();
			if (!isPowerShellProfile(name)) continue;
			std::string bytes;
			const bool read = readWholeFile(file, PROFILE_MAX, bytes);
			PowerShellProfile profile;
			profile.folder = folder;
			profile.path = originalPath(file.wstring());
			profile.host = powerShellProfileHost(name);
			ExhibitSourceTimes(file.wstring(), profile.sourceCreatedUtc, profile.sourceModifiedUtc, profile.sourceAccessedUtc);
			std::error_code ec;
			profile.size = std::filesystem::file_size(file, ec);
			if (read) {
				Sha256Stream digest;
				digest.update(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
				profile.sha256 = digest.hexDigest();
				profile.content = decodeTextFile(bytes);
			}
			else {
				profile.sha256 = sha256OfFile(file.wstring());
				log(2, L"🔥PowerShell profile larger than 16 MiB, content not given: " + profile.path);
			}
			log(2, L"❇️PowerShell profile " + profile.path);
			profiles_.push_back(std::move(profile));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT PowerShellProfiles::toJson() {
	Json list = Json::arr();
	for (const PowerShellProfile& p : profiles_) list.push(p.toJson());
	return writeJsonFile("powershell_profiles.json", list);
}

void PowerShellProfiles::clear() {
	profiles_.clear();
}
