/*! \file
 *  \brief Zone.Identifier streams (see zone_identifiers.h).
 */
#include "zone_identifiers.h"

std::wstring zoneName(const std::wstring& zoneId) {
	static const wchar_t* const NAMES[] = { L"Local machine", L"Local intranet", L"Trusted sites",
	                                        L"Internet", L"Restricted sites" };
	if (zoneId.size() != 1 || zoneId[0] < L'0' || zoneId[0] > L'4') return L"";
	return NAMES[zoneId[0] - L'0'];
}

bool parseZoneIdentifier(const std::string& content, ZoneIdentifier& zone) {
	const std::wstring text = decodeTextFile(content);
	for (const std::wstring& line : splitLines(text)) {
		if (line.empty() || line[0] == L'[') continue;           // the [ZoneTransfer] section header
		const size_t equal = line.find(L'=');
		if (equal == std::wstring::npos || equal == 0) continue;
		zone.values.emplace_back(line.substr(0, equal), line.substr(equal + 1));
	}
	return !zone.values.empty();
}

Json ZoneIdentifier::toJson() const {
	Json o = Json::obj();
	o.add(L"Path", Json::str(path));
	if (!pathComplete) o.add(L"PathIncomplete", Json::boolean(true));
	if (deleted) o.add(L"Deleted", Json::boolean(true));
	addDate(o, L"FileCreated", createdUtc);
	std::wstring zoneId;
	for (const auto& [name, value] : values) {
		if (name == L"ZoneId") zoneId = value;
		else if (name == L"ReferrerUrl") o.add(L"ReferrerUrl", Json::str(value));
		else if (name == L"HostUrl") o.add(L"HostUrl", Json::str(value));
	}
	o.add(L"ZoneId", Json::str(zoneId));
	o.add(L"ZoneName", Json::str(zoneName(zoneId)));
	if (!resident) o.add(L"ContentNotResident", Json::boolean(true));
	o.add(L"StreamSize", Json::num(size));
	Json list = Json::arr();
	for (const auto& [name, value] : values) {
		Json pair = Json::obj();
		pair.add(L"Name", Json::str(name));
		pair.add(L"Value", Json::str(value));
		list.push(std::move(pair));
	}
	o.add(L"Values", std::move(list));
	return o;
}

HRESULT ZoneIdentifiers::getData(const Mft& mft) {
	log(0, L"ℹ️Zone.Identifier streams :");
	return mft.forEachFile([this](const MftEntry& e, const std::wstring& path, bool pathComplete) {
		if (!e.zoneIdentifier) return;
		ZoneIdentifier zone;
		zone.path = path.empty() ? e.name : path;
		zone.pathComplete = pathComplete && !path.empty();
		zone.deleted = !e.inUse;
		zone.createdUtc = e.created;
		zone.resident = e.zoneIdentifierResident;
		zone.size = e.zoneIdentifierSize;
		if (zone.resident) parseZoneIdentifier(e.zoneIdentifierContent, zone);
		zones_.push_back(std::move(zone));
	});
}

HRESULT ZoneIdentifiers::toJson() {
	Json list = Json::arr();
	for (const ZoneIdentifier& z : zones_) list.push(z.toJson());
	return writeJsonFile("zone_identifiers.json", list);
}

void ZoneIdentifiers::clear() {
	zones_.clear();
}
