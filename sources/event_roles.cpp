/*! \file
 *  \brief The roles of an event's data (see event_roles.h).
 */
#include "event_roles.h"
#include <cwctype>
#include <initializer_list>

namespace {

const wchar_t SECURITY[] = L"Microsoft-Windows-Security-Auditing";
const wchar_t SYSMON[] = L"Microsoft-Windows-Sysmon";

/*! The values of one event, read by name. */
class Data {
public:
	explicit Data(const EventRoleInput& e) : e_(e) {}
	//! The first value of that name; "" when absent or a placeholder ("-", the null SID).
	std::wstring operator[](const wchar_t* name) const {
		for (const auto& [n, v] : e_.data)
			if (n == name) return v == L"-" || v == L"S-1-0-0" || v == L"NULL SID" ? std::wstring() : v;
		return L"";
	}
	//! "DOMAIN\\name", or the name alone, or "".
	std::wstring account(const wchar_t* domain, const wchar_t* name) const {
		const std::wstring d = (*this)[domain], n = (*this)[name];
		return n.empty() ? L"" : d.empty() ? n : d + L"\\" + n;
	}
private:
	const EventRoleInput& e_;
};

/*! A process identifier as events write it: "0x1c4" (Security) or "452"
 *  (Sysmon); false when it is not one. */
bool processId(const std::wstring& text, unsigned long long& pid) {
	if (text.empty()) return false;
	const bool hex = text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X');
	wchar_t* end = nullptr;
	pid = wcstoull(text.c_str() + (hex ? 2 : 0), &end, hex ? 16 : 10);
	return end && *end == L'\0' && end != text.c_str() + (hex ? 2 : 0);
}

void setProcess(ContextProcess& p, const std::wstring& path, const std::wstring& pid, const std::wstring& guid) {
	p.path = contextPath(path);
	p.pidKnown = processId(pid, p.pid);
	p.guid = guid;
}

/*! Sysmon's Hashes ("SHA1=…,MD5=…,SHA256=…,IMPHASH=…") into a file object. */
void setHashes(ContextObject& o, const std::wstring& hashes) {
	size_t start = 0;
	while (start < hashes.size()) {
		const size_t comma = hashes.find(L',', start);
		const std::wstring pair = hashes.substr(start, comma == std::wstring::npos ? std::wstring::npos : comma - start);
		const size_t equal = pair.find(L'=');
		if (equal != std::wstring::npos) {
			const std::wstring kind = pair.substr(0, equal), value = pair.substr(equal + 1);
			if (kind == L"SHA1") o.sha1 = value;
			else if (kind == L"SHA256") o.sha256 = value;
			else if (kind == L"MD5") o.md5 = value;
		}
		if (comma == std::wstring::npos) break;
		start = comma + 1;
	}
}

bool in(unsigned long long id, std::initializer_list<unsigned long long> ids) {
	for (unsigned long long i : ids) if (i == id) return true;
	return false;
}

/*! The Security log's roles. */
void securityRoles(const EventRoleInput& e, const Data& d, RecordContext& c) {
	auto subjectActor = [&] {
		c.actor.sid = d[L"SubjectUserSid"];
		c.actor.logonId = d[L"SubjectLogonId"];
	};
	if (in(e.id, { 4624, 4625 })) {
		c.kind = ContextKind::Logon;
		c.subject.sid = d[L"TargetUserSid"];
		c.subject.user = d.account(L"TargetDomainName", L"TargetUserName");
		c.actor.logonId = d[L"TargetLogonId"];   // the session opened: what its 4688s name
		setProcess(c.actor.process, d[L"ProcessName"], d[L"ProcessId"], L"");
		c.how.remoteAddress = d[L"IpAddress"];
		c.how.host = d[L"WorkstationName"];
		unsigned long long type = 0;
		if (processId(d[L"LogonType"], type) && type < 100) {
			c.how.logonType = (unsigned)type;
			c.how.logonTypeKnown = true;   // 0 included: SYSTEM's logon at boot
		}
	}
	else if (in(e.id, { 4634, 4647 })) {
		c.kind = ContextKind::Logon;
		c.subject.sid = d[L"TargetUserSid"];
		c.subject.user = d.account(L"TargetDomainName", L"TargetUserName");
		c.actor.logonId = d[L"TargetLogonId"];
	}
	else if (e.id == 4648) {
		c.kind = ContextKind::Logon;
		c.subject.user = d.account(L"TargetDomainName", L"TargetUserName");
		c.subject.host = d[L"TargetServerName"];
		subjectActor();
		setProcess(c.actor.process, d[L"ProcessName"], d[L"ProcessId"], L"");
		c.how.remoteAddress = d[L"IpAddress"];
	}
	else if (e.id == 4672) {
		c.kind = ContextKind::Logon;
		c.subject.sid = d[L"SubjectUserSid"];
		c.actor.logonId = d[L"SubjectLogonId"];
	}
	else if (e.id == 4688) {
		c.kind = ContextKind::Execution;
		c.subject.path = contextPath(d[L"NewProcessName"]);
		subjectActor();
		// A process started in another account's session (runas): that one acted.
		if (!d[L"TargetUserSid"].empty()) c.actor.sid = d[L"TargetUserSid"];
		if (!d[L"TargetLogonId"].empty() && d[L"TargetLogonId"] != L"0x0") c.actor.logonId = d[L"TargetLogonId"];
		setProcess(c.actor.process, d[L"NewProcessName"], d[L"NewProcessId"], L"");
		setProcess(c.how.parent, d[L"ParentProcessName"], d[L"ProcessId"], L"");
		c.how.commandLine = d[L"CommandLine"];
	}
	else if (in(e.id, { 4720, 4722, 4724, 4725, 4726, 4738, 4781, 4731, 4735, 4737, 4717, 4718 })) {
		c.kind = ContextKind::Account;
		c.subject.sid = d[L"TargetSid"];
		c.subject.user = d.account(L"TargetDomainName", L"TargetUserName");
		subjectActor();
	}
	else if (in(e.id, { 4728, 4729, 4732, 4733, 4756, 4757 })) {
		c.kind = ContextKind::Account;
		c.subject.sid = d[L"TargetSid"];                    // the group
		c.subject.user = d.account(L"TargetDomainName", L"TargetUserName");
		ContextObject member;
		member.role = L"Member";
		member.sid = d[L"MemberSid"];
		c.related.push_back(std::move(member));
		subjectActor();
	}
	else if (e.id == 4697) {
		c.kind = ContextKind::Installation;
		c.subject.path = serviceProgram(d[L"ServiceFileName"]);
		c.subject.name = d[L"ServiceName"];
		c.how.commandLine = d[L"ServiceFileName"];
		subjectActor();
	}
	else if (in(e.id, { 4698, 4702 })) {
		c.kind = ContextKind::Persistence;
		c.subject.name = d[L"TaskName"];
		subjectActor();
	}
	else if (e.id == 4719 || e.id == 4616) {
		c.kind = ContextKind::Configuration;
		subjectActor();
		setProcess(c.actor.process, d[L"ProcessName"], d[L"ProcessId"], L"");
	}
}

/*! Sysmon's roles. */
void sysmonRoles(const EventRoleInput& e, const Data& d, RecordContext& c) {
	c.actor.user = d[L"User"];
	if (e.id == 1) {
		c.kind = ContextKind::Execution;
		c.subject.path = contextPath(d[L"Image"]);
		setHashes(c.subject, d[L"Hashes"]);
		c.actor.logonId = d[L"LogonId"];
		setProcess(c.actor.process, d[L"Image"], d[L"ProcessId"], d[L"ProcessGuid"]);
		setProcess(c.how.parent, d[L"ParentImage"], d[L"ParentProcessId"], d[L"ParentProcessGuid"]);
		c.how.commandLine = d[L"CommandLine"];
	}
	else if (e.id == 3) {
		c.kind = ContextKind::Network;
		c.subject.address = d[L"DestinationIp"];
		c.subject.host = d[L"DestinationHostname"];
		setProcess(c.actor.process, d[L"Image"], d[L"ProcessId"], d[L"ProcessGuid"]);
		unsigned long long port = 0;
		if (processId(d[L"DestinationPort"], port) && port < 65536) {
			c.how.remotePort = (unsigned)port;
			c.how.remotePortKnown = true;
		}
	}
	else if (e.id == 5) {
		c.kind = ContextKind::Execution;
		c.subject.path = contextPath(d[L"Image"]);
		setProcess(c.actor.process, d[L"Image"], d[L"ProcessId"], d[L"ProcessGuid"]);
	}
	else if (e.id == 11) {
		c.kind = ContextKind::Creation;
		c.subject.path = contextPath(d[L"TargetFilename"]);
		setProcess(c.actor.process, d[L"Image"], d[L"ProcessId"], d[L"ProcessGuid"]);
	}
	else if (in(e.id, { 23, 26 })) {
		c.kind = ContextKind::Deletion;
		c.subject.path = contextPath(d[L"TargetFilename"]);
		setHashes(c.subject, d[L"Hashes"]);
		setProcess(c.actor.process, d[L"Image"], d[L"ProcessId"], d[L"ProcessGuid"]);
	}
	else c.actor.user.clear();
}

/*! The other providers' roles. */
void otherRoles(const EventRoleInput& e, const Data& d, RecordContext& c) {
	const std::wstring& p = e.provider;
	if (p == L"Service Control Manager" && e.id == 7045) {
		c.kind = ContextKind::Installation;
		c.subject.path = serviceProgram(d[L"ImagePath"]);
		c.subject.name = d[L"ServiceName"];
		c.how.commandLine = d[L"ImagePath"];
	}
	else if (p == L"Microsoft-Windows-Eventlog" && in(e.id, { 1102, 104 })) {
		c.kind = ContextKind::Configuration;
		c.actor.sid = d[L"SubjectUserSid"];
		c.actor.user = d.account(L"SubjectDomainName", L"SubjectUserName");
		c.actor.logonId = d[L"SubjectLogonId"];
	}
	else if (p == L"Microsoft-Windows-Bits-Client" && e.id == 16403) {
		c.kind = ContextKind::Arrival;
		c.subject.path = contextPath(d[L"LocalName"]);
		c.how.url = d[L"RemoteName"];
		c.actor.user = d[L"jobOwner"];
	}
	else if (p == L"Microsoft-Windows-Bits-Client" && in(e.id, { 59, 60 })) {
		c.kind = ContextKind::Arrival;
		c.subject.name = d[L"name"];
		c.how.url = d[L"url"];
	}
	else if (p == L"Microsoft-Windows-PowerShell" && e.id == 4104) {
		c.kind = ContextKind::Execution;
		c.subject.path = contextPath(d[L"Path"]);
		c.actor.sid = e.systemUserId;   // PowerShell writes as the user who ran the script
	}
	else if (p == L"Microsoft-Windows-TaskScheduler" && e.id == 106) {
		c.kind = ContextKind::Persistence;
		c.subject.name = d[L"TaskName"];
		c.actor.user = d[L"UserContext"];
	}
	else if (p == L"Microsoft-Windows-TaskScheduler" && in(e.id, { 200, 201 })) {
		c.kind = ContextKind::Execution;
		c.subject.name = d[L"TaskName"];
		c.how.commandLine = d[L"ActionName"];
	}
	else if (p == L"Microsoft-Windows-TerminalServices-LocalSessionManager" && in(e.id, { 21, 22, 24, 25 })) {
		c.kind = ContextKind::Logon;
		c.subject.user = d[L"User"];
		c.how.remoteAddress = d[L"Address"] == L"LOCAL" ? L"" : d[L"Address"];
	}
	else if (p == L"Microsoft-Windows-TerminalServices-LocalSessionManager" && in(e.id, { 23, 41, 42 })) {
		c.kind = ContextKind::Logon;
		c.subject.user = d[L"User"];
	}
	else if (p == L"Microsoft-Windows-Windows Defender" && in(e.id, { 1116, 1117 })) {
		c.kind = ContextKind::Detection;
		std::wstring path = d[L"Path"];
		if (path.compare(0, 6, L"file:_") == 0) path = path.substr(6);   // "file:_C:\…"
		c.subject.path = contextPath(path.substr(0, path.find(L';')));
		c.subject.name = d[L"Threat Name"];
		c.actor.user = d[L"Detection User"];
		setProcess(c.actor.process, d[L"Process Name"], L"", L"");
	}
	else if (p == L"Microsoft-Windows-Kernel-PnP" && in(e.id, { 400, 410, 430 })) {
		c.kind = ContextKind::Installation;
		c.subject.device = d[L"DeviceInstanceId"];
	}
	else if (p == L"Microsoft-Windows-Partition" && e.id == 1006) {
		c.kind = ContextKind::Access;
		c.subject.serial = d[L"SerialNumber"];
		c.subject.name = d[L"Model"];
	}
	else if (p == L"MsiInstaller" && in(e.id, { 1033, 1040, 1042, 11707 })) {
		c.kind = ContextKind::Installation;   // the product is in the message only
		c.actor.sid = e.systemUserId;        // the installer runs as who installs
	}
}

} // namespace

RecordContext eventContext(const EventRoleInput& event) {
	RecordContext c;
	const Data d(event);
	if (event.provider == SECURITY) securityRoles(event, d, c);
	else if (event.provider == SYSMON) sysmonRoles(event, d, c);
	else otherRoles(event, d, c);
	if (c.kind != ContextKind::None) c.evidence = contextPath(event.evidence);
	return c;
}
