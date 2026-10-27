/*! \file
 *  \brief NTFS volumes (see ntfs_volumes.h).
 */
#include "ntfs_volumes.h"
#include "consigne.h"
#include "running_machine.h"
#include <cstring>
#include <cwctype>
#include <fstream>

namespace {

const size_t USN_MAX_SIZE = 32;               //!< four uint64
const uintmax_t EXHIBIT_MAX = 1024 * 1024;    //!< $Boot is 8 KiB, $UsnJrnl:$Max 32 bytes

/*! The bytes of a file of the exhibit store, by its path on the examined machine.
 *  @param key the path, as the store's index holds it
 *  @param bytes receives the content
 *  @return false if the store has no such file, or it is unreadable or too large */
bool readExhibit(const std::wstring& key, std::vector<uint8_t>& bytes) {
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(key));
	if (found == index.end() || found->second.workingFile.empty()) return false;
	return readWholeFile(std::filesystem::path(found->second.workingFile), EXHIBIT_MAX, bytes);
}

} // namespace

bool parseUsnJournalHeader(const uint8_t* data, size_t size, UsnJournalHeader& header) {
	if (size < USN_MAX_SIZE) return false;
	header.maximumSize = readLittleEndian<uint64_t>(data);
	header.allocationDelta = readLittleEndian<uint64_t>(data + 8);
	header.journalId = readLittleEndian<uint64_t>(data + 16);
	header.lowestValidUsn = readLittleEndian<uint64_t>(data + 24);
	return true;
}

Json NtfsVolumeInfo::toJson() const {
	Json o = Json::obj();
	o.add(L"Volume", Json::str(volume));
	if (boot) {
		o.add(L"VolumeSerial", Json::str(to_hex(boot->serialNumber & 0xFFFFFFFFULL, 8, HexLetters::Upper)));   // as shortcuts and Prefetch files record it
		o.add(L"VolumeSerial64", Json::str(to_hex(boot->serialNumber, 16, HexLetters::Upper)));
		o.add(L"BytesPerSector", Json::num((unsigned long long)boot->bytesPerSector));
		o.add(L"BytesPerCluster", Json::num((unsigned long long)boot->bytesPerCluster));
		o.add(L"TotalSectors", Json::num((unsigned long long)boot->totalSectors));
		o.add(L"MftCluster", Json::num((unsigned long long)boot->mftCluster));
		o.add(L"MftMirrorCluster", Json::num((unsigned long long)boot->mftMirrorCluster));
		o.add(L"BytesPerRecord", Json::num((unsigned long long)boot->bytesPerRecord));
		o.add(L"BytesPerIndexBlock", Json::num((unsigned long long)boot->bytesPerIndexBlock));
	}
	if (journal) {
		Json j = Json::obj();
		j.add(L"MaximumSize", Json::num((unsigned long long)journal->maximumSize));
		j.add(L"AllocationDelta", Json::num((unsigned long long)journal->allocationDelta));
		j.add(L"UsnJournalId", Json::str(to_hex(journal->journalId, 16, HexLetters::Upper)));
		// The journal's identifier is the FILETIME of its creation.
		const FILETIME created = filetimeFromTicks(journal->journalId);
		addDate(j, L"Created", created);
		j.add(L"LowestValidUsn", Json::num((unsigned long long)journal->lowestValidUsn));
		o.add(L"UsnJournal", std::move(j));
	}
	return o;
}

HRESULT NtfsVolumes::getData() {
	log(0, L"ℹ️NTFS volumes ($Boot, $UsnJrnl:$Max) :");
	HRESULT result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	for (const std::wstring& drive : fixedNtfsVolumes()) {
		NtfsVolumeInfo info;
		info.volume = drive.substr(0, 2);
		std::vector<uint8_t> bytes;
		NtfsBootSector boot;
		if (!readExhibit(info.volume + L"\\$Boot", bytes)) log(2, L"🔥$Boot not collected for " + info.volume);
		else if (!parseNtfsBootSector(bytes.data(), bytes.size(), boot)) log(2, L"🔥$Boot of " + info.volume + L" is no NTFS boot sector");
		else info.boot = boot;
		UsnJournalHeader header;
		if (readExhibit(info.volume + L"\\$Extend\\$UsnJrnl:$Max", bytes)
		    && parseUsnJournalHeader(bytes.data(), bytes.size(), header)) info.journal = header;
		if (!info.boot && !info.journal) continue;
		volumes_.push_back(std::move(info));
		result = ERROR_SUCCESS;
	}
	return result;
}

HRESULT NtfsVolumes::toJson() {
	Json list = Json::arr();
	for (const NtfsVolumeInfo& v : volumes_) list.push(v.toJson());
	return writeJsonFile("ntfs_volumes.json", list);
}

void NtfsVolumes::clear() {
	volumes_.clear();
}
