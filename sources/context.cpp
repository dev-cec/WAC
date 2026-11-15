/*! \file
 *  \brief The linking context of a record (see context.h).
 */
#include "context.h"
#include <algorithm>
#include <cwctype>
#include "running_machine.h"
#include "tools.h"
#include "account_names.h"
#include "binaires.h"
#include "user_shell_folders.h"

namespace {

/*! A process as JSON; empty members not emitted. */
Json processJson(const ContextProcess& p) {
	Json o = Json::obj();
	o.add(L"Path", Json::str(p.path));
	if (p.pidKnown) o.add(L"Pid", Json::num(p.pid));
	o.add(L"Guid", Json::str(p.guid));
	return o;
}

} // namespace

const wchar_t* contextKindName(ContextKind kind) {
	switch (kind) {
	case ContextKind::None:          return L"";
	case ContextKind::Execution:     return L"Execution";
	case ContextKind::Arrival:       return L"Arrival";
	case ContextKind::Presence:      return L"Presence";
	case ContextKind::Creation:      return L"Creation";
	case ContextKind::Modification:  return L"Modification";
	case ContextKind::Deletion:      return L"Deletion";
	case ContextKind::Access:        return L"Access";
	case ContextKind::Persistence:   return L"Persistence";
	case ContextKind::Installation:  return L"Installation";
	case ContextKind::Account:       return L"Account";
	case ContextKind::Logon:         return L"Logon";
	case ContextKind::Network:       return L"Network";
	case ContextKind::Detection:     return L"Detection";
	case ContextKind::Configuration: return L"Configuration";
	}
	return L"";   // not reached: every kind is named above
}

Json ContextObject::toJson() const {
	Json o = Json::obj();
	o.add(L"Role", Json::str(role));
	o.add(L"Path", Json::str(path));
	o.add(L"Ntfs", Json::str(ntfs));
	o.add(L"Sha1", Json::str(sha1));
	o.add(L"Sha256", Json::str(sha256));
	o.add(L"Md5", Json::str(md5));
	o.add(L"Sid", Json::str(sid));
	o.add(L"User", Json::str(user));
	o.add(L"Software", Json::str(software));
	o.add(L"Device", Json::str(device));
	o.add(L"Serial", Json::str(serial));
	o.add(L"Volume", Json::str(volume));
	o.add(L"Address", Json::str(address));
	o.add(L"Host", Json::str(host));
	o.add(L"Name", Json::str(name));
	return o;
}

Json RecordContext::toJson() const {
	Json o = Json::obj();
	o.add(L"Kind", Json::str(contextKindName(kind)));
	o.add(L"Subject", subject.toJson());
	Json list = Json::arr();
	for (const ContextObject& r : related) {
		Json item = r.toJson();
		if (!item.isEmptyValue()) list.push(std::move(item));
	}
	o.add(L"Related", std::move(list));
	Json who = Json::obj();
	who.add(L"Sid", Json::str(actor.sid));
	who.add(L"User", Json::str(actor.user));
	who.add(L"LogonId", Json::str(actor.logonId));
	who.add(L"Process", processJson(actor.process));
	o.add(L"Actor", std::move(who));
	Json way = Json::obj();
	way.add(L"Parent", processJson(how.parent));
	way.add(L"CommandLine", Json::str(how.commandLine));
	way.add(L"Url", Json::str(how.url));
	way.add(L"Host", Json::str(how.host));
	way.add(L"RemoteAddress", Json::str(how.remoteAddress));
	if (how.remotePortKnown) way.add(L"RemotePort", Json::num(how.remotePort));
	if (how.logonTypeKnown) way.add(L"LogonType", Json::num(how.logonType));
	way.add(L"VolumeSerial", Json::str(how.volumeSerial));
	way.add(L"Device", Json::str(how.device));
	o.add(L"How", std::move(way));
	Json source = Json::obj();
	source.add(L"Path", Json::str(evidence));
	o.add(L"Evidence", std::move(source));
	return o;
}

void addContext(Json& record, const RecordContext& context) {
	record.add(L"Context", context.toJson());   // an empty Context is not emitted (Json::add)
}

std::wstring contextPath(const std::wstring& cited) {
	return normalizeFilePath(onDriveLetter(cited));
}

std::wstring subjectPathIfDifferent(const std::wstring& path) {
	const std::wstring normalised = contextPath(path);
	return normalised == path ? L"" : normalised;
}

std::wstring contextNtfs(const std::wstring& path, unsigned long long entry, unsigned sequence) {
	if (path.size() < 2 || path[1] != L':' || !iswalpha(path[0])) return L"";
	return std::wstring(1, (wchar_t)towupper(path[0])) + L":|" + std::to_wstring(entry) + L"|" + std::to_wstring(sequence);
}

std::wstring rawVolumeEvidence(const std::wstring& volume) { return L"\\\\.\\" + volume; }

void setFileObject(ContextObject& object, const std::wstring& cited, const BinaryFingerprint& fingerprint) {
	object.path = contextPath(cited);
	object.sha1 = fingerprint.sha1;
	object.sha256 = fingerprint.sha256;
	object.md5 = fingerprint.md5;
}

std::wstring systemHiveEvidence(const wchar_t* hive) {
	return contextPath(conf.systemDrive + L"\\Windows\\System32\\config\\" + hive);
}

WindowsBits examinedWindowsBits() {
	static WindowsBits bits = WindowsBits::Unknown;
	if (bits != WindowsBits::Unknown || !conf.CurrentControlSet) return bits;   // read once the hive is open
	std::wstring architecture;
	if (getRegSzValue(conf.CurrentControlSet, L"Control\\Session Manager\\Environment", L"PROCESSOR_ARCHITECTURE",
	                  &architecture) != ERROR_SUCCESS) return bits;
	if (architecture == L"AMD64" || architecture == L"ARM64" || architecture == L"IA64") bits = WindowsBits::Bits64;
	else if (architecture == L"x86" || architecture == L"ARM") bits = WindowsBits::Bits32;
	return bits;
}

std::wstring profileOwner(const std::wstring& path) {
	std::wstring owner;
	size_t longest = 0;
	for (const auto& [sid, folder] : conf.profiles)
		if (folder.size() > longest && path.size() > folder.size() && path[folder.size()] == L'\\'
		    && _wcsnicmp(path.c_str(), folder.c_str(), folder.size()) == 0) {
			owner = sid;
			longest = folder.size();
		}
	return owner;
}

std::wstring examinedComputerName() {
	static std::wstring name;
	if (!name.empty() || !conf.CurrentControlSet) return name;
	if (getRegSzValue(conf.CurrentControlSet, L"Control\\ComputerName\\ComputerName", L"ComputerName", &name) != ERROR_SUCCESS)
		name.clear();
	return name;
}

std::wstring contextAccountSid(const std::wstring& account) {
	return localAccountSid(account, examinedComputerName());
}

std::wstring knownFolderPath(const std::wstring& cited, const std::wstring& sid) {
	return knownFolderPathFor(cited, sid, examinedWindowsBits());
}

std::wstring knownFolderPathFor(const std::wstring& cited, const std::wstring& sid, WindowsBits bits) {
	const size_t close = cited.find(L'}');
	if (cited.empty() || cited[0] != L'{' || close == std::wstring::npos) return L"";
	std::wstring id = cited.substr(0, close + 1);
	for (wchar_t& c : id) c = (wchar_t)towupper(c);
	const std::wstring rest = cited.substr(close + 1);
	const std::wstring windir = conf.systemDrive + L"\\Windows";
	// KNOWNFOLDERID (knownfolders.h): the folders that hold programs, and the user's own.
	/* A user folder by its place in the profile and its value of User Shell
	   Folders, which says where it was moved (OneDrive, another disk). */
	struct Folder { const wchar_t* id; std::wstring base; bool user; const wchar_t* shellFolder = nullptr; };
	const Folder FOLDERS[] = {
		{ L"{F38BF404-1D43-42F2-9305-67DE0B28FC23}", windir, false },                                    // Windows
		{ L"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", windir + L"\\System32", false },                  // System
		// SystemX86: SysWOW64 on a 64-bit Windows, System32 on a 32-bit one; not known: no path.
		{ L"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", bits == WindowsBits::Bits64 ? windir + L"\\SysWOW64"
		                                             : bits == WindowsBits::Bits32 ? windir + L"\\System32" : L"", false },
		{ L"{905E63B6-C1BF-494E-B29C-65B732D3D21A}", conf.systemDrive + L"\\Program Files", false },  // ProgramFiles
		{ L"{6D809377-6AF0-444B-8957-A3773F02200E}", conf.systemDrive + L"\\Program Files", false },  // ProgramFilesX64
		{ L"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", conf.systemDrive + L"\\Program Files (x86)", false },   // ProgramFilesX86
		{ L"{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}", conf.systemDrive + L"\\Program Files\\Common Files", false },
		{ L"{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}", conf.systemDrive + L"\\Program Files\\Common Files", false },
		{ L"{DE974D24-D9C6-4D3E-BF91-F4455120B917}", conf.systemDrive + L"\\Program Files (x86)\\Common Files", false },
		{ L"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", conf.systemDrive + L"\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs", false },
		{ L"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs", true },   // Programs
		{ L"{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", L"\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned", true },
		{ L"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", L"\\Desktop", true, L"Desktop" },
		{ L"{374DE290-123F-4565-9164-39C4925E467B}", L"\\Downloads", true, L"{374DE290-123F-4565-9164-39C4925E467B}" },
		{ L"{5E6C858F-0E22-4760-9AFE-EA3317B67173}", L"", true },                                       // Profile
		{ L"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", L"\\Documents", true, L"Personal" },
		{ L"{33E28130-4E1E-4676-835A-98395C3BC3BB}", L"\\Pictures", true, L"My Pictures" },
		{ L"{4BD8D571-6D19-48D3-BE97-422220080E43}", L"\\Music", true, L"My Music" },
		{ L"{18989B1D-99B5-455B-841C-AB7C74E4DDFC}", L"\\Videos", true, L"My Video" },
		// The same folders as "This PC" names them (shell CLSIDs, Windows 10 on): shellbags' roots.
		{ L"{D3162B92-9365-467A-956B-92703ACA08AF}", L"\\Documents", true, L"Personal" },
		{ L"{24AD3AD4-A569-4530-98E1-AB02F9417AA8}", L"\\Pictures", true, L"My Pictures" },
		{ L"{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}", L"\\Music", true, L"My Music" },
		{ L"{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}", L"\\Videos", true, L"My Video" },
		{ L"{088E3905-0323-4B02-9826-5D99428E115F}", L"\\Downloads", true, L"{374DE290-123F-4565-9164-39C4925E467B}" },
	};
	for (const Folder& f : FOLDERS) {
		if (id != f.id) continue;
		if (f.base.empty() && !f.user) return L"";   // SystemX86 of an unknown bitness; a user's base "" is the profile
		if (!f.user) return contextPath(f.base + rest);
		for (const auto& [profileSid, folder] : conf.profiles) {
			if (_wcsicmp(profileSid.c_str(), sid.c_str()) != 0) continue;
			const std::wstring moved = f.shellFolder ? redirectedShellFolder(sid, folder, f.shellFolder, f.base.substr(1)) : L"";
			return contextPath((moved.empty() ? folder + f.base : moved) + rest);
		}
		return L"";   // a user folder of an account without a known profile
	}
	return L"";
}

std::wstring userHiveEvidence(const std::wstring& sid) {
	for (const auto& [profileSid, folder] : conf.profiles)
		if (_wcsicmp(profileSid.c_str(), sid.c_str()) == 0) return contextPath(folder + L"\\NTUSER.DAT");
	return L"";
}

std::wstring commandProgram(const std::wstring& command) {
	size_t start = 0;
	while (start < command.size() && iswspace(command[start])) ++start;
	if (start < command.size() && command[start] == L'"') {
		const size_t close = command.find(L'"', start + 1);
		return command.substr(start + 1, close == std::wstring::npos ? std::wstring::npos : close - start - 1);
	}
	std::wstring lower = command.substr(start);
	for (wchar_t& c : lower) c = (wchar_t)towlower(c);
	size_t best = std::wstring::npos;
	for (const wchar_t* extension : { L".exe", L".com", L".bat", L".cmd", L".dll", L".sys", L".ps1", L".vbs", L".js", L".scr" }) {
		const std::wstring e(extension);
		for (size_t at = lower.find(e); at != std::wstring::npos; at = lower.find(e, at + 1)) {
			const size_t end = at + e.size();
			if (end == lower.size() || iswspace(lower[end]) || lower[end] == L',') {
				best = std::min(best, end);
				break;
			}
		}
	}
	if (best == std::wstring::npos) best = lower.find(L' ');
	return command.substr(start, best == std::wstring::npos ? std::wstring::npos : best);
}

std::wstring urlHost(const std::wstring& url) {
	const size_t scheme = url.find(L"://");
	if (scheme == std::wstring::npos || scheme == 0) return L"";
	std::wstring authority = url.substr(scheme + 3);
	authority = authority.substr(0, authority.find_first_of(L"/?#"));
	const size_t at = authority.rfind(L'@');
	if (at != std::wstring::npos) authority = authority.substr(at + 1);
	if (!authority.empty() && authority[0] == L'[') authority = authority.substr(0, authority.find(L']') + 1);   // [IPv6]:port
	else authority = authority.substr(0, authority.find(L':'));
	for (wchar_t& c : authority) c = (wchar_t)towlower(c);
	return authority;
}

std::wstring serviceProgram(const std::wstring& imagePath) {
	std::wstring program = commandProgram(imagePath);
	// Relative to the Windows folder, as the service control manager reads it (measured: KslD, 7045).
	if (!program.empty() && program.find(L':') == std::wstring::npos && program[0] != L'\\' && program[0] != L'%')
		program = L"\\SystemRoot\\" + program;
	return contextPath(program);
}

namespace {

//! The profile folder of an account (Host.Profiles), "" when not known.
std::wstring profileOf(const std::wstring& sid) {
	for (const auto& [profileSid, folder] : conf.profiles)
		if (_wcsicmp(profileSid.c_str(), sid.c_str()) == 0) return folder;
	return L"";
}

} // namespace

std::wstring userPath(const std::wstring& cited, const std::wstring& sid) {
	std::wstring program = cited;
	const std::wstring profile = sid.empty() ? L"" : profileOf(sid);
	if (!profile.empty()) {
		const std::pair<const wchar_t*, std::wstring> VARIABLES[] = {
			{ L"%USERPROFILE%", profile }, { L"%APPDATA%", profile + L"\\AppData\\Roaming" },
			{ L"%LOCALAPPDATA%", profile + L"\\AppData\\Local" }, { L"%TEMP%", profile + L"\\AppData\\Local\\Temp" },
			{ L"%TMP%", profile + L"\\AppData\\Local\\Temp" } };
		for (const auto& [variable, value] : VARIABLES) {
			const size_t length = wcslen(variable);
			if (program.size() >= length && _wcsnicmp(program.c_str(), variable, length) == 0) {
				program = value + program.substr(length);
				break;
			}
		}
	}
	return contextPath(program);
}

void setCitedLocation(RecordContext& context, const std::wstring& cited, const std::wstring& sid) {
	std::wstring location = cited;
	while (!location.empty() && iswspace(location.front())) location.erase(0, 1);
	while (!location.empty() && iswspace(location.back())) location.pop_back();
	if (_wcsnicmp(location.c_str(), L"file:", 5) == 0) {
		location.erase(0, 5);
		/* file:///C:/x is a local path, file://server/x a share's, both
		   URL-encoded; file:C:/x, the search indexer's, is written raw —
		   decoded, a "%" of a name would be taken for an escape. */
		if (location.compare(0, 2, L"//") == 0) {
			location = decodeText(decodeURIComponent(encodeText(location)), CP_UTF8);
			if (location.compare(0, 3, L"///") == 0) location.erase(0, 3);
		}
	} else if (location.find(L"://") != std::wstring::npos) {
		context.how.url = location;
		context.how.host = urlHost(location);
		return;
	}
	for (wchar_t& c : location) if (c == L'/') c = L'\\';
	if (location.compare(0, 2, L"\\\\") == 0) {
		const size_t end = location.find(L'\\', 2);
		std::wstring host = location.substr(2, end == std::wstring::npos ? std::wstring::npos : end - 2);
		for (wchar_t& c : host) c = (wchar_t)towlower(c);
		if (host != L"?" && host != L".") {   // \\?\ and \\.\ are local prefixes
			context.how.host = host;
			return;
		}
	}
	context.subject.path = userPath(location, sid);
}

namespace {

//! Whether a text is a dotted IPv4 address: four numbers of at most 255.
bool isIpv4(const std::wstring& text) {
	unsigned parts = 0, value = 0, digits = 0;
	for (size_t i = 0; i <= text.size(); ++i) {
		if (i == text.size() || text[i] == L'.') {
			if (digits == 0 || value > 255) return false;
			++parts;
			value = digits = 0;
		} else if (iswdigit(text[i]) && digits < 3) {
			value = value * 10 + (text[i] - L'0');
			++digits;
		} else {
			return false;
		}
	}
	return parts == 4;
}

} // namespace

void setRemoteObject(ContextObject& object, const std::wstring& cited) {
	std::wstring host = cited;
	while (!host.empty() && iswspace(host.front())) host.erase(0, 1);
	while (!host.empty() && iswspace(host.back())) host.pop_back();
	if (host.empty()) return;
	// An IPv6 address alone: several colons, no brackets — not a host and a port.
	if (std::count(host.begin(), host.end(), L':') > 1 && host.front() != L'[') {
		for (wchar_t& c : host) c = (wchar_t)towlower(c);
		object.address = host;
		return;
	}
	host = urlHost(L"remote://" + host);   // one parser of user@, :port and [IPv6]
	if (host.size() > 2 && host.front() == L'[' && host.back() == L']') object.address = host.substr(1, host.size() - 2);
	else if (isIpv4(host)) object.address = host;
	else object.host = host;
}

std::wstring contextDevice(const std::wstring& cited) {
	std::wstring id = cited;
	// A portable device's name holds the device's own interface path after "_??_".
	const size_t inner = id.find(L"_??_");
	if (inner != std::wstring::npos) id = id.substr(inner + 4);
	for (const wchar_t* prefix : { L"\\\\?\\", L"\\??\\", L"##?#" })
		if (id.compare(0, wcslen(prefix), prefix) == 0) id = id.substr(wcslen(prefix));
	for (wchar_t& c : id) {
		if (c == L'/') c = L'\\';
		c = (wchar_t)towupper(c);
	}
	if (id.find(L'#') != std::wstring::npos) {   // an interface path: its three first parts, its class GUID left
		std::wstring parts[3];
		size_t at = 0;
		for (std::wstring& part : parts) {
			const size_t end = id.find(L'#', at);
			part = id.substr(at, end == std::wstring::npos ? std::wstring::npos : end - at);
			at = end == std::wstring::npos ? id.size() : end + 1;
		}
		if (parts[2].empty() || parts[2][0] == L'{') return L"";
		id = parts[0] + L"\\" + parts[1] + L"\\" + parts[2];
	}
	// enumerator\device\instance: two separators, none at an end; an enumerator
	// has no ":" — "C:\Windows\INF\x.inf", a driver package's path, is no device.
	if (std::count(id.begin(), id.end(), L'\\') < 2 || id.front() == L'\\' || id.back() == L'\\'
	    || id.substr(0, id.find(L'\\')).find(L':') != std::wstring::npos) return L"";
	return id;
}

std::wstring deviceSerial(const std::wstring& device) {
	const size_t slash = device.rfind(L'\\');
	const std::wstring instance = slash == std::wstring::npos ? device : device.substr(slash + 1);
	if (instance.size() < 2 || instance[1] == L'&') return L"";
	const size_t last = instance.rfind(L'&');
	return last == std::wstring::npos ? instance : instance.substr(0, last);
}

std::wstring contextSerial(const std::wstring& cited) {
	std::wstring serial = cited;
	while (!serial.empty() && iswspace(serial.front())) serial.erase(0, 1);
	while (!serial.empty() && iswspace(serial.back())) serial.pop_back();
	for (wchar_t& c : serial) c = (wchar_t)towupper(c);
	return serial;
}

std::wstring contextVolumeGuid(const std::wstring& cited) {
	const size_t open = cited.find(L'{');
	if (open == std::wstring::npos || open + 38 > cited.size() || cited[open + 37] != L'}') return L"";
	std::wstring guid = cited.substr(open, 38);
	for (wchar_t& c : guid) c = (wchar_t)towlower(c);
	return guid;
}

std::wstring userCommandProgram(const std::wstring& command, const std::wstring& sid) {
	return userPath(commandProgram(command), sid);
}

std::wstring hiveEvidence(const std::wstring& hive, const std::wstring& sid) {
	if (_wcsicmp(hive.c_str(), L"NTUSER.DAT") == 0) return userHiveEvidence(sid);
	if (_wcsicmp(hive.c_str(), L"UsrClass.dat") == 0) {
		const std::wstring profile = profileOf(sid);
		return profile.empty() ? L"" : contextPath(profile + L"\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat");
	}
	return hive.empty() ? L"" : systemHiveEvidence(hive.c_str());
}
