/*! \file
 *  \brief Incoming Remote Desktop connections: see rdp_server.h.
 */
#include "rdp_server.h"
#include "events.h"
#include "evtx.h"
#include "xml_light.h"
#include <cwctype>
#include <filesystem>
#include <map>
#include <memory>
#include <set>

namespace {

//! The logs that hold RDP traces, by their channel in lower case, and the events kept.
const std::map<std::wstring, std::set<unsigned>> RDP_EVENTS = {
	{ L"microsoft-windows-terminalservices-remoteconnectionmanager/operational", { 261, 1149 } },
	{ L"microsoft-windows-remotedesktopservices-rdpcorets/operational", { 131 } },
	{ L"microsoft-windows-terminalservices-localsessionmanager/operational", { 21, 22, 23, 24, 25, 39, 40, 41 } },
	{ L"security", { 4624, 4625, 4634, 4778, 4779 } },
};

/*! Where each log puts the fields an analysis looks for: the first name
 *  present gives the field. */
const std::vector<std::pair<const wchar_t*, std::vector<std::wstring>>> NORMALISED = {
	{ L"User",          { L"TargetUserName", L"AccountName", L"User", L"Param1" } },
	{ L"Domain",        { L"TargetDomainName", L"AccountDomain", L"Param2" } },
	{ L"SourceAddress", { L"IpAddress", L"ClientAddress", L"Address", L"ClientIP", L"Param3" } },
	{ L"SessionId",     { L"SessionID", L"SessionId", L"Session" } },
};

std::wstring lower(std::wstring text) {
	for (wchar_t& c : text) c = (wchar_t)towlower(c);
	return text;
}

} // namespace

bool isIncomingRdpEvent(const std::wstring& channel, unsigned eventId, const std::wstring& logonType) {
	const auto log = RDP_EVENTS.find(lower(channel));
	if (log == RDP_EVENTS.end() || !log->second.count(eventId)) return false;
	// Security's logon events: only those of a remote interactive logon (type 10).
	if (log->first == L"security" && (eventId == 4624 || eventId == 4625 || eventId == 4634)) return logonType == L"10";
	return true;
}

HRESULT RdpServer::getData() {
	log(0, L"ℹ️Incoming RDP connections :");
	// The logs' working copies: the exhibit store is not read (backlog B-040).
	const std::vector<std::filesystem::path> logs =
		listFilesByExtension(extractedPath(L"\\Windows\\System32\\winevt\\Logs"), { L".evtx" });
	for (const std::filesystem::path& file : logs) {
		const std::wstring fileName = file.filename().wstring();
		const std::wstring channel = EvtxChannelFromFileName(fileName);
		if (!RDP_EVENTS.count(lower(channel))) continue;
		size_t kept = 0;
		const HRESULT hr = EvtxReadFile(file.wstring(), [&](const EvtxRecord& e) {
			const std::unique_ptr<XmlNode> root = xmlParse(e.xml, true);
			if (!root) return true;
			Event ev(*root, channel, e.id, fileName);
			std::map<std::wstring, std::wstring> data;
			for (size_t i = 0; i < ev.rawNames.size() && i < ev.rawValues.size(); ++i)
				if (!ev.rawNames[i].empty()) data.emplace(ev.rawNames[i], ev.rawValues[i]);
			const auto type = data.find(L"LogonType");
			if (!isIncomingRdpEvent(channel, ev.messageEventId, type == data.end() ? L"" : type->second)) return true;
			if (e.recovered) ev.evtRecovered = Json::boolean(true);
			Json o = ev.toJson();
			for (const auto& [field, names] : NORMALISED)
				for (const std::wstring& name : names) {
					const auto found = data.find(name);
					if (found != data.end() && !found->second.empty() && found->second != L"-") {
						o.add(field, Json::str(found->second));
						break;
					}
				}
			records_.push_back(std::move(o));
			++kept;
			return true;
		});
		if (FAILED(hr)) log(2, L"🔥Log unreadable: " + fileName, hr);
		else log(2, L"❇️" + channel + L" : " + std::to_wstring(kept) + L" RDP event(s)");
	}
	return ERROR_SUCCESS;
}

HRESULT RdpServer::toJson() {
	Json list = Json::arr();
	for (const Json& r : records_) list.push(r);
	return writeJsonFile("rdp_server.json", list);
}

void RdpServer::clear() {
	records_.clear();
}
