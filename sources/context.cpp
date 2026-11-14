/*! \file
 *  \brief The linking context of a record (see context.h).
 */
#include "context.h"
#include <algorithm>
#include <cwctype>
#include "running_machine.h"
#include "tools.h"
#include "binaires.h"

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

std::wstring contextNtfs(const std::wstring& path, unsigned long long entry, unsigned sequence) {
	if (path.size() < 2 || path[1] != L':' || !iswalpha(path[0])) return L"";
	return std::wstring(1, (wchar_t)towupper(path[0])) + L":|" + std::to_wstring(entry) + L"|" + std::to_wstring(sequence);
}

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
	// KNOWNFOLDERID (knownfolders.h): the folders that hold programs.
	struct Folder { const wchar_t* id; std::wstring base; bool user; };
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
		{ L"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", L"\\Desktop", true },
		{ L"{374DE290-123F-4565-9164-39C4925E467B}", L"\\Downloads", true },
	};
	for (const Folder& f : FOLDERS) {
		if (id != f.id) continue;
		if (f.base.empty()) return L"";
		if (!f.user) return contextPath(f.base + rest);
		for (const auto& [profileSid, folder] : conf.profiles)
			if (_wcsicmp(profileSid.c_str(), sid.c_str()) == 0) return contextPath(folder + f.base + rest);
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
