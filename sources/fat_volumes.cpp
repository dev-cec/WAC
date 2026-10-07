/*! \file
 *  \brief The FAT and exFAT volumes of the machine, read raw (see fat_volumes.h).
 */
#include "fat_volumes.h"
#include "audit.h"
#include "consigne.h"
#include "idList.h"
#include "quickdigest5.h"
#include "running_machine.h"
#include "sha.h"
#include <fstream>
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

//! Two seconds, FAT's resolution for a modification, in 100 ns.
const int64_t FAT_RESOLUTION = 2LL * 10000000;

/*! A date as the entry stores it: local (FAT, exFAT without offset) or UTC
 *  (exFAT with its offset, exact, the offset given). Either way the local
 *  date written is derived from the UTC one by the examined machine's time
 *  zone, with the offset in force at THAT instant — the same rule as every
 *  other artefact, so that one instant reads the same everywhere.
 *  A local date is converted with the offset of the moment it was WRITTEN:
 *  `writtenAt`, the date itself unless told otherwise (a copy). */
void addFatDate(Json& o, const wchar_t* name, const FILETIME& date, bool utc, int offset, Precision precision,
                const FILETIME* writtenAt = nullptr) {
	if (date.dwLowDateTime == 0 && date.dwHighDateTime == 0) return;
	const std::wstring key = name;
	FILETIME instant = date;
	if (utc) o.add(key + L"Offset", Json::str(offsetText(offset)));
	else if (!writtenAt) instant = suspectLocalToUtc(date);
	else {
		// The offset in force when the entry was written, applied to the date kept.
		const int64_t bias = (int64_t)ticksFromFiletime(*writtenAt) - (int64_t)ticksFromFiletime(suspectLocalToUtc(*writtenAt));
		instant = filetimeFromTicks((uint64_t)((int64_t)ticksFromFiletime(date) - bias));
		o.add(key + L"WrittenAt", Json::str(L"Copy"));
		o.add(key + L"OffsetApplied", Json::str(offsetText((int)(bias / 600000000))));
		o.add(key + L"AsStored", Json::str(timeToIso8601Utc(date, precision).substr(0, 19)));
	}
	o.add(key + L"Utc", Json::str(timeToIso8601Utc(instant, precision)));
	o.add(key, Json::str(utcTimeToIso8601Local(instant, precision)));
}

} // namespace

std::vector<std::wstring> fatVolumesToRead() {
	std::error_code ec;
	const std::wstring medium = std::filesystem::absolute(exhibitStoreFolder(), ec).root_name().wstring();
	std::vector<std::wstring> out;
	for (const RunningMachine::Volume& v : runningMachine().volumes)
		if (isFat(v.fileSystem) && (v.driveType == DRIVE_FIXED || v.driveType == DRIVE_REMOVABLE)
		    && v.mountPoint.size() == 2 && _wcsicmp(v.mountPoint.c_str(), medium.c_str()) != 0)
			out.push_back(v.mountPoint);
	return out;
}

bool onFatVolume(const std::wstring& path) {
	if (path.size() < 3 || path[1] != L':') return false;
	for (const std::wstring& v : fatVolumesToRead())
		if (towupper(v[0]) == towupper(path[0])) return true;
	return false;
}

HRESULT ExtractFatVolumesRaw() {
	HRESULT global = ERROR_EMPTY;
	for (const std::wstring& mountPoint : fatVolumesToRead()) {
		const std::wstring device = L"\\\\.\\" + mountPoint;
		FileVolumeSource source(device);
		FatVolume volume;
		// Walked once: every byte it reads — the metadata — is what is copied.
		const bool read = source.isOpen() && volume.open(source);
		if (read) volume.entries();
		const HRESULT result = read ? ExhibitStoreProduce(pathUnder(exhibitStoreFolder(), mountPoint + METADATA),
		                                                 volumeCopyBytes(source), mountPoint + METADATA,
		                                                 L"Raw reading of " + device + L" (" + volume.type()
		                                                 + L"): boot sector, FAT and directories copied, no file opened")
		                            : HRESULT_FROM_WIN32(ERROR_UNRECOGNIZED_VOLUME);
		auditRecord(L"Raw reading of the FAT/exFAT metadata", device, result, Footprint::VOLUME_BRUT);
		if (FAILED(result)) log(2, L"🔥FAT/exFAT volume not read: " + device, result);
		global = FAILED(result) ? S_FALSE : (global == ERROR_EMPTY ? S_OK : global);
	}
	return global;
}

// ------------------------------------------------------------ files on FAT volumes

namespace {

//! A FILETIME as the manifest's 64-bit UTC value, a local one converted.
uint64_t manifestTime(const FILETIME& date, bool utc) {
	if (date.dwLowDateTime == 0 && date.dwHighDateTime == 0) return 0;
	const FILETIME u = utc ? date : suspectLocalToUtc(date);
	return ticksFromFiletime(u);
}

} // namespace

FatAwareReader::Volume* FatAwareReader::fatVolume(const std::wstring& path) {
	if (path.size() < 3 || path[1] != L':' || path[2] != L'\\') return nullptr;
	const wchar_t letter = (wchar_t)towupper(path[0]);
	const auto known = volumes_.find(letter);
	if (known != volumes_.end()) return known->second.get();
	std::unique_ptr<Volume> v;
	if (onFatVolume(path)) {
		v = std::make_unique<Volume>();
		// Contents are read without being kept: only a collection's metadata copy keeps its bytes.
		v->source = std::make_unique<FileVolumeSource>(L"\\\\.\\" + path.substr(0, 2), 0, false);
		if (!v->source->isOpen() || !v->volume.open(*v->source)) v.reset();
		else
			for (const FatEntry& e : v->volume.entries())
				if (!e.deleted && v->byPath.emplace(toLower(e.path), e).second) v->ids.emplace(toLower(e.path), v->ids.size() + 1);
	}
	return (volumes_[letter] = std::move(v)).get();
}

HRESULT FatAwareReader::read(const std::wstring& absolutePath, const std::wstring& output,
                             RawHiveExtraction& line, std::streambuf* observer) {
	Volume* v = fatVolume(absolutePath);
	if (!v) return ntfs_.read(absolutePath, output, line, observer);
	line.volumePath = absolutePath;
	line.outputPath = output;
	const auto found = v->byPath.find(toLower(absolutePath.substr(2)));
	if (found == v->byPath.end() || found->second.directory) return line.result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const FatEntry& e = found->second;
	std::ofstream file;
	if (!output.empty()) file.open(std::filesystem::path(output), std::ios::binary);
	Md5Stream md5;
	Sha1Stream sha1;
	Sha256Stream sha256;
	const bool hashes = line.fingerprints.computeHashes;
	uint64_t bytes = 0;
	const bool whole = v->volume.readContent(e, [&](const uint8_t* data, size_t size) {
		if (hashes) { md5.update(data, size); sha1.update(data, size); sha256.update(data, size); }
		if (observer) observer->sputn(reinterpret_cast<const char*>(data), (std::streamsize)size);
		if (file.is_open()) file.write(reinterpret_cast<const char*>(data), (std::streamsize)size);
		bytes += size;
		return !file.is_open() || (bool)file;
	});
	if (!whole || (file.is_open() && !file)) return line.result = HRESULT_FROM_WIN32(ERROR_READ_FAULT);
	RawHiveFingerprints& f = line.fingerprints;
	if (hashes) { f.md5 = md5.hexDigest(); f.sha1 = sha1.hexDigest(); f.sha256 = sha256.hexDigest(); }
	f.bytes = bytes;
	f.declaredSize = f.validDataLength = e.size;
	f.creeUtc = manifestTime(e.created, e.createdUtc);
	f.modifiedUtc = manifestTime(e.modified, e.modifiedUtc);
	f.accedeUtc = manifestTime(e.accessed, e.accessedUtc);
	FILETIME now = { 0, 0 };
	GetSystemTimeAsFileTime(&now);
	f.extractedUtc = ticksFromFiletime(now);
	return line.result = ERROR_SUCCESS;
}

HRESULT FatAwareReader::list(const std::wstring& absoluteFolder, std::vector<RawDirEntry>& entries) {
	Volume* v = fatVolume(absoluteFolder);
	if (!v) return ntfs_.list(absoluteFolder, entries);
	entries.clear();
	std::wstring folder = toLower(absoluteFolder.substr(2));
	if (!folder.empty() && folder.back() != L'\\') folder += L'\\';
	for (const auto& [path, e] : v->byPath) {
		if (path.size() <= folder.size() || path.compare(0, folder.size(), folder) != 0
		    || path.find(L'\\', folder.size()) != std::wstring::npos)
			continue;
		RawDirEntry d;
		d.name = e.path.substr(e.path.find_last_of(L'\\') + 1);
		d.mftIndex = v->ids[path];
		d.size = e.directory ? 0 : e.size;
		d.isDirectory = e.directory;
		entries.push_back(std::move(d));
	}
	return S_OK;
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
	/* A modification earlier than the creation — beyond FAT's two seconds — is
	   a date KEPT by a copy onto the volume (Explorer, robocopy, Copy-Item
	   keep it): Windows wrote it with the offset in force at the copy, which
	   the creation dates, not with that of the date kept. Converted with the
	   offset of the date kept, a winter file copied in summer would be an
	   hour off — the case of an exfiltration onto a key. */
	const bool copied = !e.modifiedUtc && !e.createdUtc && (int64_t)ticksFromFiletime(e.created) != 0 && (int64_t)ticksFromFiletime(e.modified) != 0
	                    && (int64_t)ticksFromFiletime(e.modified) < (int64_t)ticksFromFiletime(e.created) - FAT_RESOLUTION;
	addFatDate(o, L"Modified", e.modified, e.modifiedUtc, e.modifiedOffset,
	           fileSystem == L"exFAT" ? Precision::HundredNanoseconds : Precision::Second, copied ? &e.created : nullptr);
	addFatDate(o, L"Accessed", e.accessed, e.accessedUtc, e.accessedOffset, Precision::Second);
	return o;
}

HRESULT FatVolumes::getData() {
	log(0, L"ℹ️FAT and exFAT volumes :");
	const std::wstring suffix = toLower(METADATA);
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		if (exhibit.workingFile.empty() || key.size() != 2 + suffix.size() || key.compare(2, suffix.size(), suffix) != 0) continue;
		CopiedVolumeSource source;
		FatVolume volume;
		if (!source.load(exhibit.workingFile) || !volume.open(source)) {
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
