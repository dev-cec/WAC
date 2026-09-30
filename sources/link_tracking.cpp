/*! \file
 *  \brief Output of the link-tracking identifiers (see link_tracking.h).
 */
#include "link_tracking.h"
#include "ip_address.h"
#include "tools.h"

LinkTracking::LinkTracking(const BYTE* at) {
	memcpy(&volume,      at,      sizeof(GUID));
	memcpy(&file,        at + 16, sizeof(GUID));
	memcpy(&birthVolume, at + 32, sizeof(GUID));
	memcpy(&birthFile,   at + 48, sizeof(GUID));
}

namespace {

/*! Instant and hardware address of a version-1 file GUID, under a prefix.
 *  Nothing is added for a GUID of another version: its bits carry no date. */
void addGuidV1(Json& o, const std::wstring& prefix, const GUID& guid) {
	const GuidV1 v = decodeGuidV1(guid);
	if (!v.valid) return;
	o.add(prefix + L"CreatedUtc",      Json::str(timeToIso8601Utc(v.createdUtc)));
	o.add(prefix + L"Created",         Json::str(utcTimeToIso8601Local(v.createdUtc)));
	o.add(prefix + L"HardwareAddress", Json::str(HardwareAddressText(v.node, sizeof v.node)));
}

} // namespace

namespace {

//! A GUID, or nothing for the null GUID: an entry of a file never tracked (a URI) holds zeros, not an identifier.
void addGuid(Json& o, const wchar_t* key, const GUID& guid) {
	static const GUID NONE = { 0 };
	if (memcmp(&guid, &NONE, sizeof(GUID)) != 0) o.add(key, Json::str(guid_to_wstring(guid)));
}

} // namespace

void LinkTracking::addTo(Json& o) const {
	addGuid(o, L"GuidDroidVolume",      volume);
	addGuid(o, L"GuidDroidFile",        file);
	addGuid(o, L"GuidBirthDroidVolume", birthVolume);
	addGuid(o, L"GuidBirthDroidFile",   birthFile);
	addGuidV1(o, L"DroidFile", file);
	// The birth values repeat the current ones for a file never moved: given
	// only when they differ, where they say something.
	if (memcmp(&birthFile, &file, sizeof(GUID)) != 0)
		addGuidV1(o, L"BirthDroidFile", birthFile);
}
