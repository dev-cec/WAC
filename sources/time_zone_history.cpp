/*! \file
 *  \brief The examined machine's time zone over time (see time_zone_history.h).
 */
#include "time_zone_history.h"
#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>
#include "events.h"
#include "tools.h"
#include "xml_light.h"

namespace {

const wchar_t KERNEL_GENERAL[] = L"Microsoft-Windows-Kernel-General";

//! Whether a log is the System log: System.evtx, an archive of it, XP's SysEvent.evt.
bool isSystemLog(const std::wstring& channel) {
	const std::wstring c = toLower(channel);
	return c == L"system" || c.rfind(L"archive-system-", 0) == 0;
}

/*! The field of a Kernel-General event that holds the offset in force:
 *  measured on Windows 11 and Server 2025, 2026-11-09.
 *  @return its name, or nullptr for an event that holds none */
const wchar_t* biasField(const std::wstring& eventId) {
	if (eventId == L"1") return L"TimeZoneBias";   // the clock set: the offset of that moment
	if (eventId == L"22") return L"NewBias";       // the offset changed: the new one
	if (eventId == L"24") return L"CurrentBias";   // the time zone refreshed, at boot among others
	return nullptr;
}

/*! An offset, in minutes, as the event writes it: a signed decimal, nothing
 *  else — a forged value is no offset.
 *  @return false if the text is not one */
bool parseBias(const std::wstring& text, long& bias) {
	if (text.empty() || text.size() > 6) return false;
	size_t i = text[0] == L'-' ? 1 : 0;
	if (i == text.size()) return false;
	long value = 0;
	for (; i < text.size(); ++i) {
		if (!iswdigit(text[i])) return false;
		value = value * 10 + (text[i] - L'0');
	}
	bias = text[0] == L'-' ? -value : value;
	return true;
}

//! The offset an event of the System log holds, if it is one of Kernel-General's that does.
bool loggedBias(const EvtxRecord& record, long& bias) {
	// Most records are not Kernel-General's: not parsed.
	if (record.xml.find(KERNEL_GENERAL) == std::wstring::npos) return false;
	const std::unique_ptr<XmlNode> event = xmlParse(record.xml, true);
	const XmlNode* system = event ? event->child(L"System") : nullptr;
	const XmlNode* provider = system ? system->child(L"Provider") : nullptr;
	if (!provider || provider->attribute(L"Name") != KERNEL_GENERAL) return false;
	const wchar_t* field = biasField(system->textOf(L"EventID"));
	const XmlNode* data = event->child(L"EventData");
	if (!field || !data) return false;
	for (const auto& item : data->children)
		if (item->name == L"Data" && item->attribute(L"Name") == field) return parseBias(item->text, bias);
	return false;
}

} // namespace

HRESULT loadSuspectTimeZoneHistory() {
	conf.timeZone.history = TimeZoneHistory{};
	std::vector<LoggedBias> logged;
	unsigned long long lastId = 0;
	long long endUtc = 0;
	bool found = false;
	HRESULT result = ERROR_SUCCESS;
	for (const EventLogFile& file : workingEventLogs()) {
		if (!isSystemLog(file.channel)) continue;
		found = true;
		const HRESULT hr = readEventLog(file, [&](const EvtxRecord& record) {
			// A record of a cleared log is no live event (evtx.h): its order is not the log's.
			if (record.recovered) return true;
			const long long utc = (long long)ticksFromFiletime(record.writtenUtc);
			// The end of the log: its last record written, whatever its clock said.
			if (record.id >= lastId) { lastId = record.id; endUtc = utc; }
			long bias = 0;
			if (loggedBias(record, bias)) logged.push_back({ record.id, utc, bias });
			return true;
		});
		if (hr != ERROR_SUCCESS) {
			log(2, L"🔥System log partly read for the time zone's history: " + file.path.wstring(), hr);
			result = S_FALSE;
		}
	}
	if (!found) {
		log(2, L"🔥No System log in the collection: local times take the current zone's rules alone");
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}
	conf.timeZone.history = timeZoneHistoryFrom(std::move(logged), endUtc);
	const std::vector<LoggedBias>& changes = conf.timeZone.history.changes;
	log(2, L"❇️Time zone's history (System log): " + std::to_wstring(changes.size()) + L" offset(s) in force, from "
	     + (changes.empty() ? std::wstring(L"-") : timeToIso8601Utc(filetimeFromTicks((uint64_t)changes.front().utc100ns)))
	     + L" to " + timeToIso8601Utc(filetimeFromTicks((uint64_t)endUtc)));
	return result;
}
