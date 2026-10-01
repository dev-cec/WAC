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

// Layout of the NTFS boot sector (the Linux-NTFS project's documentation).
const size_t BOOT_OEM = 0x03;                 //!< "NTFS    "
const size_t BOOT_BYTES_PER_SECTOR = 0x0B;    //!< uint16
const size_t BOOT_SECTORS_PER_CLUSTER = 0x0D; //!< uint8; above 0x80, the cluster is 2^(256 - value) bytes
const size_t BOOT_TOTAL_SECTORS = 0x28;       //!< uint64
const size_t BOOT_MFT_CLUSTER = 0x30;         //!< uint64
const size_t BOOT_MFT_MIRROR_CLUSTER = 0x38;  //!< uint64
const size_t BOOT_CLUSTERS_PER_RECORD = 0x40; //!< int8; negative, the record is 2^-value bytes
const size_t BOOT_CLUSTERS_PER_INDEX = 0x44;  //!< int8; same rule
const size_t BOOT_SERIAL = 0x48;              //!< uint64
const size_t BOOT_SIGNATURE = 0x1FE;          //!< 0x55, 0xAA
const size_t BOOT_SECTOR_SIZE = 512;
const size_t USN_MAX_SIZE = 32;               //!< four uint64

/*! A size the boot sector gives in clusters, or as a power of two when negative.
 *  @return the size in bytes, 0 if impossible */
uint32_t clustersOrPower(uint8_t raw, uint32_t bytesPerCluster) {
	const int8_t value = (int8_t)raw;
	if (value < 0) return -value < 32 ? 1u << -value : 0;
	return (uint32_t)value * bytesPerCluster;
}

/*! The bytes of a file of the exhibit store, by its path on the examined machine.
 *  @param key the path, as the store's index holds it
 *  @param bytes receives the content
 *  @return false if the store has no such file */
bool readExhibit(const std::wstring& key, std::vector<uint8_t>& bytes) {
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(key));
	if (found == index.end() || found->second.file.empty()) return false;
	std::ifstream in(std::filesystem::path(found->second.file), std::ios::binary);
	bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	return true;
}

/*! An integer in upper-case hexadecimal, zero-padded: the form Windows shows serials in.
 *  @param value the integer
 *  @param digits the number of digits
 *  @return the digits */
std::wstring upperHex(uint64_t value, int digits) {
	std::wstring text = to_hex(value, digits);
	for (wchar_t& c : text) c = (wchar_t)towupper(c);
	return text;
}

} // namespace

bool parseNtfsBootSector(const uint8_t* data, size_t size, NtfsBootSector& boot) {
	if (size < BOOT_SECTOR_SIZE || std::memcmp(data + BOOT_OEM, "NTFS    ", 8) != 0
	    || data[BOOT_SIGNATURE] != 0x55 || data[BOOT_SIGNATURE + 1] != 0xAA) return false;
	boot.bytesPerSector = readLittleEndian<uint16_t>(data + BOOT_BYTES_PER_SECTOR);
	const uint8_t sectorsPerCluster = data[BOOT_SECTORS_PER_CLUSTER];
	const uint32_t sectors = sectorsPerCluster <= 0x80 ? sectorsPerCluster
	                       : (256u - sectorsPerCluster < 32 ? 1u << (256u - sectorsPerCluster) : 0);
	boot.bytesPerCluster = boot.bytesPerSector * sectors;
	// Sectors of 256 to 4096 bytes, a power of two; a cluster of at least one sector.
	if (boot.bytesPerSector < 256 || boot.bytesPerSector > 4096
	    || (boot.bytesPerSector & (boot.bytesPerSector - 1)) || !boot.bytesPerCluster) return false;
	boot.totalSectors = readLittleEndian<uint64_t>(data + BOOT_TOTAL_SECTORS);
	boot.mftCluster = readLittleEndian<uint64_t>(data + BOOT_MFT_CLUSTER);
	boot.mftMirrorCluster = readLittleEndian<uint64_t>(data + BOOT_MFT_MIRROR_CLUSTER);
	boot.bytesPerRecord = clustersOrPower(data[BOOT_CLUSTERS_PER_RECORD], boot.bytesPerCluster);
	boot.bytesPerIndexBlock = clustersOrPower(data[BOOT_CLUSTERS_PER_INDEX], boot.bytesPerCluster);
	boot.serialNumber = readLittleEndian<uint64_t>(data + BOOT_SERIAL);
	return true;
}

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
		o.add(L"VolumeSerial", Json::str(upperHex(boot->serialNumber & 0xFFFFFFFFULL, 8)));   // as shortcuts and Prefetch files record it
		o.add(L"VolumeSerial64", Json::str(upperHex(boot->serialNumber, 16)));
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
		j.add(L"UsnJournalId", Json::str(upperHex(journal->journalId, 16)));
		// The journal's identifier is the FILETIME of its creation.
		const FILETIME created = { (DWORD)(journal->journalId & 0xFFFFFFFFULL), (DWORD)(journal->journalId >> 32) };
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
