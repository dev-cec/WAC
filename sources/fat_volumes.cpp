/*! \file
 *  \brief The FAT and exFAT volumes of the machine, read raw (see fat_volumes.h).
 */
#include "fat_volumes.h"
#include "audit.h"
#include "consigne.h"
#include "idList.h"
#include "running_machine.h"
#include <filesystem>

namespace {

//! The copy's name on its volume, as the manifest records it.
const wchar_t METADATA[] = L"\\$FatMetadata";

//! True for the file systems this reader handles, as Windows names them.
bool isFat(const std::wstring& fileSystem) {
	return fileSystem == L"FAT" || fileSystem == L"FAT32" || fileSystem == L"exFAT";
}

//! Minutes east of UTC as "+02:00".
std::wstring offsetText(int minutes) {
	wchar_t text[8];
	swprintf(text, 8, L"%c%02d:%02d", minutes < 0 ? L'-' : L'+', std::abs(minutes) / 60, std::abs(minutes) % 60);
	return text;
}

/*! A date as the entry stores it: local (FAT, exFAT without offset) — as
 *  stored with the examined machine's offset, and in UTC by its time zone —,
 *  or UTC (exFAT with its offset) — exact, and the offset given. */
void addFatDate(Json& o, const wchar_t* name, const FILETIME& date, bool utc, int offset, Precision precision) {
	if (date.dwLowDateTime == 0 && date.dwHighDateTime == 0) return;
	const std::wstring key = name;
	if (utc) {
		o.add(key + L"Utc", Json::str(timeToIso8601Utc(date, precision)));
		o.add(key, Json::str(utcTimeToIso8601Local(date, precision)));
		o.add(key + L"Offset", Json::str(offsetText(offset)));
	}
	else {
		o.add(key + L"Utc", Json::str(timeToIso8601Utc(suspectLocalToUtc(date), precision)));
		o.add(key, Json::str(timeToIso8601Local(date, precision)));
	}
}

} // namespace

HRESULT ExtractFatVolumesRaw() {
	std::error_code ec;
	const std::wstring medium = std::filesystem::absolute(exhibitStoreFolder(), ec).root_name().wstring();
	HRESULT global = ERROR_EMPTY;
	for (const RunningMachine::Volume& v : runningMachine().volumes) {
		if (!isFat(v.fileSystem) || (v.driveType != DRIVE_FIXED && v.driveType != DRIVE_REMOVABLE)
		    || v.mountPoint.size() != 2 || _wcsicmp(v.mountPoint.c_str(), medium.c_str()) == 0)
			continue;
		const std::wstring device = L"\\\\.\\" + v.mountPoint;
		FileVolumeSource source(device);
		FatVolume volume;
		// Walked once: every byte it reads — the metadata — is what is copied.
		const bool read = source.isOpen() && volume.open(source);
		if (read) volume.entries();
		const HRESULT result = read ? ExhibitStoreProduce(pathUnder(exhibitStoreFolder(), v.mountPoint + METADATA),
		                                                 volumeCopyBytes(source), v.mountPoint + METADATA,
		                                                 L"Raw reading of " + device + L" (" + volume.type()
		                                                 + L"): boot sector, FAT and directories copied, no file opened")
		                            : HRESULT_FROM_WIN32(ERROR_UNRECOGNIZED_VOLUME);
		auditRecord(L"Raw reading of the FAT/exFAT metadata", device, result, Footprint::VOLUME_BRUT);
		if (FAILED(result)) log(2, L"🔥FAT/exFAT volume not read: " + device, result);
		global = FAILED(result) ? S_FALSE : (global == ERROR_EMPTY ? S_OK : global);
	}
	return global;
}

Json FatVolumeEntry::toJson() const {
	const FatEntry& e = entry;
	Json o = Json::obj();
	o.add(L"Volume", Json::str(volume));
	o.add(L"FileSystem", Json::str(fileSystem));
	o.add(L"Label", Json::str(label));
	o.add(L"Path", Json::str(volume + e.path));
	o.add(L"ShortName", Json::str(e.shortName));
	if (e.deleted) o.add(L"Deleted", Json::boolean(true));
	if (e.nameIncomplete) o.add(L"NameIncomplete", Json::boolean(true));
	if (e.directory) o.add(L"Directory", Json::boolean(true));
	else o.add(L"Size", Json::num(e.size));
	o.add(L"Attributes", Json::str(FileAttributes(e.attributes).to_wstring()));
	if (e.firstCluster) o.add(L"FirstCluster", Json::num(e.firstCluster));
	if (e.contiguous) o.add(L"Contiguous", Json::boolean(true));
	// FAT: creation to the hundredth, modification to two seconds, access to the day.
	addFatDate(o, L"Created", e.created, e.createdUtc, e.createdOffset, Precision::HundredNanoseconds);
	addFatDate(o, L"Modified", e.modified, e.modifiedUtc, e.modifiedOffset,
	           fileSystem == L"exFAT" ? Precision::HundredNanoseconds : Precision::Second);
	addFatDate(o, L"Accessed", e.accessed, e.accessedUtc, e.accessedOffset, Precision::Second);
	return o;
}

HRESULT FatVolumes::getData() {
	log(0, L"ℹ️FAT and exFAT volumes :");
	const std::wstring suffix = toLower(METADATA);
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		if (exhibit.file.empty() || key.size() != 2 + suffix.size() || key.compare(2, suffix.size(), suffix) != 0) continue;
		CopiedVolumeSource source;
		FatVolume volume;
		if (!source.load(exhibit.file) || !volume.open(source)) {
			log(2, L"🔥FAT/exFAT metadata not read: " + exhibit.sourcePath);
			continue;
		}
		const std::vector<FatEntry> found = volume.entries();   // the label is in the root: read first
		const std::wstring letter = exhibit.sourcePath.substr(0, 2);
		for (const FatEntry& e : found) entries_.push_back({ letter, volume.type(), volume.label(), e });
	}
	return ERROR_SUCCESS;
}

HRESULT FatVolumes::toJson() {
	JsonArrayWriter out("fat_volumes.json");
	for (const FatVolumeEntry& e : entries_) out.add(e.toJson());
	return out.close();
}

void FatVolumes::clear() {
	entries_.clear();
}
