/*! \file
 *  \brief Snapshot of the running examined machine (see running_machine.h).
 */
#include "running_machine.h"
#include "live_snapshot.h"
#include "tools.h"
#include "json.h"
#include <vector>

namespace {

const char SNAPSHOT[] = "running-machine.json";

//! The eight fields of a SYSTEMTIME, in their declaration order.
Json systemTimeToJson(const SYSTEMTIME& t) {
	Json a = Json::arr();
	for (WORD w : { t.wYear, t.wMonth, t.wDayOfWeek, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds })
		a.push(Json::num((unsigned long long)w));
	return a;
}

//! Reverse of systemTimeToJson; false if the array is not eight 16-bit integers.
bool systemTimeFromJson(const Json* a, SYSTEMTIME& t) {
	if (!a || a->kind() != Json::Kind::Arr || a->members().size() != 8) return false;
	WORD fields[8] = {};
	size_t i = 0;
	for (const auto& member : a->members()) {
		long long v = 0;
		if (!snapshotInteger(member.second, v) || v < 0 || v > 0xFFFF) return false;
		fields[i++] = (WORD)v;
	}
	t = SYSTEMTIME{ fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7] };
	return true;
}

/*! Every mounted volume: serial number (%08X, the form prefetchs.cpp builds)
 *  -> first mount point without its backslash ("C:"). A volume without media
 *  (empty card reader, optical drive) fails GetVolumeInformationW and is left
 *  out: a zero serial number would match a Prefetch at random. */
Json observeVolumes() {
	Json volumes = Json::arr();
	WCHAR volume[MAX_PATH + 1] = L"";
	log(3, L"🔈FindFirstVolumeW");
	HANDLE search = FindFirstVolumeW(volume, ARRAYSIZE(volume));
	if (search == INVALID_HANDLE_VALUE) {
		log(2, L"🔥FindFirstVolumeW", GetLastError());
		return volumes;
	}
	do {
		std::vector<wchar_t> paths(MAX_PATH);
		DWORD characters = (DWORD)paths.size();
		BOOL ok = FALSE;
		for (int attempt = 0; attempt < 3; ++attempt) {
			ok = GetVolumePathNamesForVolumeNameW(volume, paths.data(), (DWORD)paths.size(), &characters);
			if (ok || GetLastError() != ERROR_MORE_DATA) break;
			paths.assign(characters ? characters : paths.size() * 2, L'\0');
		}
		if (!ok) {
			log(2, L"🔥GetVolumePathNamesForVolumeNameW " + std::wstring(volume), GetLastError());
			continue;
		}
		const std::wstring mountPoint = replaceAll(std::wstring(paths.data()), L"\\", L"");
		if (mountPoint.empty()) continue;             // volume without a mount point
		DWORD serialNumber = 0;
		wchar_t fileSystem[MAX_PATH + 1] = L"";
		if (!GetVolumeInformationW(volume, nullptr, 0, &serialNumber, nullptr, nullptr, fileSystem, ARRAYSIZE(fileSystem))) {
			log(2, L"🔥GetVolumeInformationW " + std::wstring(volume), GetLastError());
			continue;
		}
		wchar_t hexadecimal[9] = L"";
		swprintf(hexadecimal, 9, L"%08X", serialNumber);
		Json v = Json::obj();
		v.add(L"Serial", Json::str(hexadecimal));
		v.add(L"MountPoint", Json::str(mountPoint));
		// Which volumes hold executables to collect: fixed ones, not the collection medium.
		v.add(L"DriveType", Json::num((unsigned long long)GetDriveTypeW(volume)));
		if (fileSystem[0]) v.add(L"FileSystem", Json::str(fileSystem));
		volumes.push(std::move(v));
	} while (FindNextVolumeW(search, volume, ARRAYSIZE(volume)));
	FindVolumeClose(search);
	return volumes;
}

} // namespace

HRESULT snapshotRunningMachine() {
	Json machine = Json::obj();
	if (!conf.systemDrive.empty()) machine.add(L"SystemDrive", Json::str(conf.systemDrive));
	machine.add(L"AnsiCodePage", Json::num((unsigned long long)GetACP()));
	TIME_ZONE_INFORMATION tz = {};
	const DWORD id = GetTimeZoneInformation(&tz);
	if (id != TIME_ZONE_ID_INVALID) {
		Json zone = Json::obj();
		zone.add(L"TimeZoneId", Json::num((unsigned long long)id));
		zone.add(L"Bias", Json::num((long long)tz.Bias));
		zone.add(L"StandardName", Json::str(tz.StandardName));
		zone.add(L"StandardDate", systemTimeToJson(tz.StandardDate));
		zone.add(L"StandardBias", Json::num((long long)tz.StandardBias));
		zone.add(L"DaylightName", Json::str(tz.DaylightName));
		zone.add(L"DaylightDate", systemTimeToJson(tz.DaylightDate));
		zone.add(L"DaylightBias", Json::num((long long)tz.DaylightBias));
		machine.add(L"TimeZone", std::move(zone));
	}
	else log(2, L"🔥GetTimeZoneInformation", GetLastError());
	machine.add(L"Volumes", observeVolumes());
	return writeLiveSnapshot(SNAPSHOT, machine, L"running machine: system drive, code page, time zone, volumes");
}

const RunningMachine& runningMachine() {
	/* Read once it exists: an absent snapshot is NOT cached — asked before
	   the live phase has written it, the empty answer would have stuck for the
	   whole run. */
	static RunningMachine machine;
	if (machine.read) return machine;
	machine = [] {
		RunningMachine m;
		Json snapshot = Json::null();
		if (readLiveSnapshot(SNAPSHOT, snapshot) != ERROR_SUCCESS || snapshot.kind() != Json::Kind::Obj) {
			log(2, L"🔥Running machine snapshot absent: no fallback on the running machine");
			return m;
		}
		m.read = true;
		if (const Json* d = snapshot.find(L"SystemDrive")) m.systemDrive = d->text();
		long long value = 0;
		if (snapshotInteger(snapshot, L"AnsiCodePage", value) && value > 0 && value <= 0xFFFF) m.ansiCodePage = (UINT)value;
		if (const Json* zone = snapshot.find(L"TimeZone")) {
			long long id = 0, bias = 0, standardBias = 0, daylightBias = 0;
			TIME_ZONE_INFORMATION tz = {};
			const std::wstring standardName = zone->find(L"StandardName") ? zone->find(L"StandardName")->text() : L"";
			const std::wstring daylightName = zone->find(L"DaylightName") ? zone->find(L"DaylightName")->text() : L"";
			// Bounded like the hive's values (see time_zone.h): a forged snapshot changes no date by days.
			auto minutes = [](long long v) { return v >= -24 * 60 && v <= 24 * 60; };
			if (snapshotInteger(*zone, L"TimeZoneId", id) && id >= 0 && id <= 2
			    && snapshotInteger(*zone, L"Bias", bias) && minutes(bias)
			    && snapshotInteger(*zone, L"StandardBias", standardBias) && minutes(standardBias)
			    && snapshotInteger(*zone, L"DaylightBias", daylightBias) && minutes(daylightBias)
			    && systemTimeFromJson(zone->find(L"StandardDate"), tz.StandardDate)
			    && systemTimeFromJson(zone->find(L"DaylightDate"), tz.DaylightDate)
			    && standardName.size() < ARRAYSIZE(tz.StandardName)
			    && daylightName.size() < ARRAYSIZE(tz.DaylightName)) {
				tz.Bias = (LONG)bias;
				tz.StandardBias = (LONG)standardBias;
				tz.DaylightBias = (LONG)daylightBias;
				wcsncpy_s(tz.StandardName, standardName.c_str(), _TRUNCATE);
				wcsncpy_s(tz.DaylightName, daylightName.c_str(), _TRUNCATE);
				m.timeZone = tz;
				m.timeZoneId = (DWORD)id;
			}
			else log(2, L"🔥Running machine snapshot: time zone unreadable");
		}
		if (const Json* volumes = snapshot.find(L"Volumes"))
			for (const auto& member : volumes->members()) {
				const Json* serial = member.second.find(L"Serial");
				const Json* mountPoint = member.second.find(L"MountPoint");
				if (serial && mountPoint) m.volumeBySerial.emplace(serial->text(), mountPoint->text());
				if (!mountPoint) continue;
				RunningMachine::Volume v;
				v.mountPoint = mountPoint->text();
				long long type = 0;
				if (snapshotInteger(member.second, L"DriveType", type) && type >= 0 && type <= 6) v.driveType = (UINT)type;
				if (const Json* fs = member.second.find(L"FileSystem")) v.fileSystem = fs->text();
				m.volumes.push_back(std::move(v));
			}
		return m;
	}();
	return machine;
}
