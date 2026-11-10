/*! \file
 *  \brief The examined machine's time zone over time (see time_zone_history.h).
 */
#include "time_zone_history.h"
#include <algorithm>
#include <map>
#include <memory>
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

//! The text of a named datum of an event, empty when it has none.
std::wstring datum(const XmlNode* data, const wchar_t* name) {
	if (data)
		for (const auto& item : data->children)
			if (item->name == L"Data" && item->attribute(L"Name") == name) return item->text;
	return L"";
}

/*! The zones the history names, by key name: the current one first, each with
 *  its rules from the examined hives (suspectZoneRules). */
class ObservedZones {
public:
	ObservedZones() { names_.push_back(conf.timeZone.keyName); rules_.push_back(conf.timeZone.rules); }
	/*! The index of a zone, read once for each name met.
	 *  @param name its key name, or its standard name
	 *  @param byStandardName which of the two
	 *  @return its index, -1 for a zone the hives do not hold */
	int indexOf(const std::wstring& name, bool byStandardName) {
		const std::wstring key = (byStandardName ? L"S:" : L"K:") + toLower(name);
		const auto known = byName_.find(key);
		if (known != byName_.end()) return known->second;
		TimeZoneRules rules;
		std::wstring keyName;
		int index = -1;
		if (suspectZoneRules(name, byStandardName, rules, keyName)) {
			const auto same = std::find(names_.begin(), names_.end(), keyName);
			index = (int)(same - names_.begin());
			if (same == names_.end()) { names_.push_back(keyName); rules_.push_back(rules); }
		}
		else log(2, L"🔥Time zone named in the logs not found in the SOFTWARE hive, its observations ignored: " + name);
		byName_[key] = index;
		return index;
	}
	const std::vector<std::wstring>& names() const { return names_; }
	const std::vector<TimeZoneRules>& rules() const { return rules_; }
private:
	std::vector<std::wstring> names_;
	std::vector<TimeZoneRules> rules_;
	std::map<std::wstring, int> byName_;
};

/*! What an event of the System log tells of the time zone.
 *  @param record the event
 *  @param bias receives a Kernel-General offset (Windows 10 and later)
 *  @param observation receives what a Windows before 10 writes (time_zone.h)
 *  @param zones the zones named
 *  @return 1 for an offset, 2 for an observation, 0 for neither */
int systemLogTimeZone(const EvtxRecord& record, long& bias, ZoneObservation& observation, ObservedZones& zones) {
	// Most records are neither: not parsed.
	const bool kernel = record.xml.find(KERNEL_GENERAL) != std::wstring::npos;
	if (!kernel && record.xml.find(L"6013") == std::wstring::npos) return 0;
	const std::unique_ptr<XmlNode> event = xmlParse(record.xml, true);
	const XmlNode* system = event ? event->child(L"System") : nullptr;
	const XmlNode* provider = system ? system->child(L"Provider") : nullptr;
	const XmlNode* data = event ? event->child(L"EventData") : nullptr;
	if (!provider || !data) return 0;
	const std::wstring id = system->textOf(L"EventID");
	observation.utc100ns = (long long)ticksFromFiletime(record.writtenUtc);
	if (provider->attribute(L"Name") == KERNEL_GENERAL) {
		const wchar_t* field = biasField(id);
		const std::wstring value = field ? datum(data, field) : L"";
		if (!value.empty()) return parseBias(value, bias) ? 1 : 0;
		// Before Windows 10, event 1 holds the times only: equal, a zone was set.
		const std::wstring newTime = datum(data, L"NewTime");
		if (id != L"1" || newTime.empty() || newTime != datum(data, L"OldTime")) return 0;
		observation.kind = ZoneObservation::Kind::UnnamedChange;
		return 2;
	}
	long standard = 0;
	std::wstring name;
	if (!zoneInForceOf(*event, standard, name)) return 0;
	observation.kind = ZoneObservation::Kind::InForce;
	observation.zone = zones.indexOf(name, true);
	if (observation.zone < 0) return 0;
	// The offset written must be the zone's standard one at that date: otherwise the name misled.
	SYSTEMTIME st = {};
	const FILETIME ft = record.writtenUtc;
	if (!FileTimeToSystemTime(&ft, &st)) return 0;
	const TimeZoneRule& rule = zones.rules()[(size_t)observation.zone].forYear(st.wYear);
	return rule.biasMinutes + rule.standardBiasMinutes == standard ? 2 : 0;
}

//! Whether a log is TZUtil's own: the zones tzutil set (Windows 7 and later).
bool isTzUtilLog(const std::wstring& channel) {
	const std::wstring c = toLower(channel);
	return c == L"microsoft-windows-tzutil/operational" || c == L"microsoft-windows-tzutil%4operational";
}

} // namespace

bool zoneInForceOf(const XmlNode& event, long& standardBias, std::wstring& standardName) {
	const XmlNode* system = event.child(L"System");
	const XmlNode* provider = system ? system->child(L"Provider") : nullptr;
	const XmlNode* data = event.child(L"EventData");
	if (!provider || !data || provider->attribute(L"Name") != L"EventLog" || system->textOf(L"EventID") != L"6013") return false;
	// Its last datum — the Binary that follows is not one.
	const XmlNode* last = nullptr;
	for (const auto& item : data->children)
		if (item->name == L"Data") last = item.get();
	if (!last) return false;
	const size_t space = last->text.find(L' ');
	if (space == std::wstring::npos || space + 1 == last->text.size()
	    || !parseBias(last->text.substr(0, space), standardBias)) return false;
	standardName = last->text.substr(space + 1);
	return true;
}

HRESULT loadSuspectTimeZoneHistory() {
	conf.timeZone.history = TimeZoneHistory{};
	std::vector<LoggedBias> logged;
	std::vector<ZoneObservation> observations;
	ObservedZones zones;
	unsigned long long lastId = 0;
	long long endUtc = 0;
	bool found = false;
	HRESULT result = ERROR_SUCCESS;
	for (const EventLogFile& file : workingEventLogs()) {
		const bool system = isSystemLog(file.channel), tzUtil = isTzUtilLog(file.channel);
		if (!system && !tzUtil) continue;
		found = found || system;
		const HRESULT hr = readEventLog(file, [&](const EvtxRecord& record) {
			// A record of a cleared log is no live event (evtx.h): its order is not the log's.
			if (record.recovered) return true;
			const long long utc = (long long)ticksFromFiletime(record.writtenUtc);
			if (tzUtil) {
				// 20001: the zone tzutil set, its key name.
				if (record.xml.find(L"20001") == std::wstring::npos) return true;
				const std::unique_ptr<XmlNode> event = xmlParse(record.xml, true);
				const XmlNode* head = event ? event->child(L"System") : nullptr;
				if (!head || head->textOf(L"EventID") != L"20001") return true;
				const int zone = zones.indexOf(datum(event->child(L"EventData"), L"Time Zone"), false);
				if (zone >= 0) observations.push_back({ ZoneObservation::Kind::NamedChange, utc, zone });
				return true;
			}
			// The end of the log: its last record written, whatever its clock said.
			if (record.id >= lastId) { lastId = record.id; endUtc = utc; }
			long bias = 0;
			ZoneObservation observation;
			const int kind = systemLogTimeZone(record, bias, observation, zones);
			if (kind == 1) logged.push_back({ record.id, utc, bias, L"" });
			else if (kind == 2) observations.push_back(observation);
			return true;
		});
		if (hr != ERROR_SUCCESS) {
			log(2, L"🔥Log partly read for the time zone's history: " + file.path.wstring(), hr);
			result = S_FALSE;
		}
	}
	if (!found) {
		log(2, L"🔥No System log in the collection: local times take the current zone's rules alone");
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}
	/* Windows 10 and later log every change of offset (Kernel-General 22): the
	   history is exact. Before, only what is observed (time_zone.h). */
	if (!logged.empty())
		conf.timeZone.history = timeZoneHistoryFrom(std::move(logged), endUtc);
	else
		conf.timeZone.history = timeZoneHistoryFromObservations(zones.rules(), zones.names(), 0,
		                                                        std::move(observations), endUtc);
	const TimeZoneHistory& history = conf.timeZone.history;
	log(2, L"❇️Time zone's history (System log): " + std::to_wstring(history.changes.size()) + L" offset(s) in force, from "
	     + (history.changes.empty() ? std::wstring(L"-") : timeToIso8601Utc(filetimeFromTicks((uint64_t)history.changes.front().utc100ns)))
	     + L" to " + timeToIso8601Utc(filetimeFromTicks((uint64_t)endUtc))
	     + L"; " + std::to_wstring(history.uncertain.size()) + L" change(s) at an unknown instant");
	return result;
}
