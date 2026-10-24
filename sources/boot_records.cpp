/*! \file
 *  \brief The boot records of the disks (see boot_records.h).
 */
#include "boot_records.h"
#include "audit.h"
#include "consigne.h"
#include "conversions.h"
#include "fat_volume.h"
#include "portable_conversions.h"
#include "sha.h"
#include <cstring>
#include <filesystem>
#include <map>
#include <winioctl.h>

namespace {

//! The type GUID of an EFI system partition, as a GPT entry stores it (mixed endianness).
const uint8_t EFI_SYSTEM_TYPE[16] = { 0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                                      0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B };
const uint8_t MBR_EFI_SYSTEM = 0xEF, MBR_GPT_PROTECTIVE = 0xEE;
const size_t MBR_BOOT_CODE = 440, MBR_SIGNATURE = 440, MBR_TABLE = 446, MBR_ENTRY = 16;
//! Sectors copied from the start of each partition: the boot sector and NTFS's loader (8 KiB at 512 bytes).
const uint64_t BOOT_SECTORS = 16;
//! Physical disks tried: their numbers may skip one (a disk removed).
const unsigned MAX_DISKS = 32;
//! A GPT holds at most this many entries in practice (128 by default).
const uint32_t MAX_GPT_ENTRIES = 1024;
const wchar_t STORE_FOLDER[] = L"\\$BootRecords\\PhysicalDrive";
const wchar_t SOURCE_PREFIX[] = L"\\\\.\\PhysicalDrive";

/*! Whether a sector is a volume's boot sector — NTFS, exFAT, FAT12/16/32 —
 *  by the names its BPB writes: a disk without a partition table starts so.
 *  @param sector 512 bytes */
bool isVolumeBootSector(const uint8_t* sector) {
	return memcmp(sector + 3, "NTFS    ", 8) == 0 || memcmp(sector + 3, "EXFAT   ", 8) == 0
	       || memcmp(sector + 54, "FAT", 3) == 0 || memcmp(sector + 82, "FAT32   ", 8) == 0;
}

//! The OEM name of a boot sector ("NTFS", "MSDOS5.0"), printable characters only.
std::wstring oemName(const uint8_t* sector, size_t length) {
	std::wstring oem;
	for (size_t i = 3; i < 11 && i < length && sector[i] >= 0x20 && sector[i] < 0x7F; ++i) oem += (wchar_t)sector[i];
	while (!oem.empty() && oem.back() == L' ') oem.pop_back();
	return oem;
}

/*! A partition of a disk, as a volume of its own: the FAT reader reads
 *  from the partition's first byte, never past its end. */
class PartitionSource : public VolumeSource {
public:
	PartitionSource(VolumeSource& disk, uint64_t offset, uint64_t size) : disk_(disk), offset_(offset), size_(size) {}
	bool read(uint64_t offset, size_t size, std::vector<uint8_t>& out) override {
		if (offset > size_ || size > size_ - offset) return false;
		return disk_.read(offset_ + offset, size, out);
	}
	uint64_t size() const override { return size_; }
private:
	VolumeSource& disk_;
	uint64_t offset_, size_;
};

/*! The number of the disk holding a volume (IOCTL_STORAGE_GET_DEVICE_NUMBER).
 *  @param volume "E:"
 *  @return its number, or -1 if unknown */
long diskOfVolume(const std::wstring& volume) {
	const HANDLE h = CreateFileW((L"\\\\.\\" + volume).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (h == INVALID_HANDLE_VALUE) return -1;
	STORAGE_DEVICE_NUMBER number = {};
	DWORD returned = 0;
	const BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &number, sizeof number, &returned, nullptr);
	CloseHandle(h);
	return ok ? (long)number.DeviceNumber : -1;
}

/*! A disk's bytes per sector (IOCTL_DISK_GET_DRIVE_GEOMETRY_EX).
 *  @return them, or 512 if the disk does not say */
uint32_t sectorSizeOf(const std::wstring& device) {
	const HANDLE h = CreateFileW(device.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (h == INVALID_HANDLE_VALUE) return 512;
	DISK_GEOMETRY_EX geometry = {};
	DWORD returned = 0;
	const BOOL ok = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &geometry, sizeof geometry, &returned, nullptr);
	CloseHandle(h);
	const uint32_t size = ok ? geometry.Geometry.BytesPerSector : 0;
	return size >= 512 && size <= 4096 && (size & (size - 1)) == 0 ? size : 512;
}

//! Bytes as the exhibit store writes them.
std::string asString(const std::vector<uint8_t>& bytes) { return std::string(bytes.begin(), bytes.end()); }

/*! Copies every present file of an EFI system partition.
 *  @param disk the disk, read raw
 *  @param offset,size the partition, in bytes
 *  @param store,source the partition's folder in the exhibit store, and its source name
 *  @return S_OK, S_FALSE if a file was not read, or why the partition was not */
HRESULT copyEfiFiles(VolumeSource& disk, uint64_t offset, uint64_t size, const std::wstring& store, const std::wstring& source) {
	PartitionSource partition(disk, offset, size);
	FatVolume volume;
	if (!volume.open(partition)) return HRESULT_FROM_WIN32(ERROR_UNRECOGNIZED_VOLUME);
	HRESULT result = S_OK;
	for (const FatEntry& e : volume.entries()) {
		if (e.deleted || e.directory) continue;
		std::string bytes;
		const bool read = volume.readContent(e, [&](const uint8_t* p, size_t n) { bytes.append((const char*)p, n); return true; });
		if (!read || FAILED(ExhibitStoreProduce(store + e.path, bytes, source + e.path,
		                                        L"Raw reading of the EFI system partition (WAC's FAT reader), no file opened")))
			result = S_FALSE;
	}
	return result;
}

/*! Copies one disk's boot records.
 *  @return S_OK, S_FALSE if a part was not read, or why the disk was not */
HRESULT copyDisk(unsigned number) {
	const std::wstring device = SOURCE_PREFIX + std::to_wstring(number);
	FileVolumeSource disk(device, 0, false);
	if (!disk.isOpen()) return HRESULT_FROM_WIN32(GetLastError());
	const std::wstring store = exhibitStoreFolder() + STORE_FOLDER + std::to_wstring(number);
	std::vector<uint8_t> head;
	const size_t headSize = (size_t)std::min<uint64_t>(BOOT_HEAD_BYTES, disk.size());
	if (!disk.read(0, headSize, head)) return HRESULT_FROM_WIN32(ERROR_READ_FAULT);
	HRESULT result = ExhibitStoreProduce(store + L"\\head.bin", asString(head), device + L"\\$Head",
	                                     L"Raw reading of the disk's first mebibyte (" + device + L"), nothing written");
	const PartitionTable table = parsePartitionTable(head.data(), head.size());
	// The GPT says its sector size; an MBR does not, the disk does.
	const uint32_t sectorSize = table.sectorSize ? table.sectorSize : sectorSizeOf(device);
	for (const BootPartition& p : table.partitions) {
		const uint64_t offset = p.firstSector * sectorSize, size = p.sectors * sectorSize;
		if (p.firstSector > disk.size() / sectorSize || offset > disk.size() || size > disk.size() - offset) { result = S_FALSE; continue; }
		const std::wstring part = L"\\partition" + std::to_wstring(p.index), sourcePart = L"\\$Partition" + std::to_wstring(p.index);
		std::vector<uint8_t> boot;
		if (!disk.read(offset, (size_t)std::min<uint64_t>(BOOT_SECTORS * sectorSize, size), boot)
		    || FAILED(ExhibitStoreProduce(store + part + L".bin", asString(boot), device + sourcePart,
		                                  L"Raw reading of the partition's first sectors, nothing written")))
			result = S_FALSE;
		if (p.efiSystem && copyEfiFiles(disk, offset, size, store + part, device + sourcePart) != S_OK) result = S_FALSE;
	}
	return result;
}

} // namespace

PartitionTable parsePartitionTable(const uint8_t* head, size_t length) {
	PartitionTable t;
	if (length < 512 || head[510] != 0x55 || head[511] != 0xAA) return t;
	bool protective = false;
	for (unsigned i = 0; i < 4; ++i)
		if (head[MBR_TABLE + i * MBR_ENTRY + 4] == MBR_GPT_PROTECTIVE) protective = true;
	if (protective)
		for (const uint32_t sectorSize : { 512u, 4096u }) {
			if (length < sectorSize + 92 || memcmp(head + sectorSize, "EFI PART", 8) != 0) continue;
			const uint8_t* h = head + sectorSize;
			const uint64_t entriesLba = readLittleEndian<uint64_t>(h + 72);
			const uint32_t count = readLittleEndian<uint32_t>(h + 80), entrySize = readLittleEndian<uint32_t>(h + 84);
			if (entrySize < 128 || entrySize > 4096 || entrySize % 8 || count > MAX_GPT_ENTRIES || entriesLba > length / sectorSize)
				return t;
			t.style = L"GPT";
			t.sectorSize = sectorSize;
			t.diskId = guid_to_wstring(h + 56);
			const uint64_t base = entriesLba * sectorSize;
			for (uint32_t i = 0; i < count; ++i) {
				const uint64_t at = base + (uint64_t)i * entrySize;
				if (at > length || 128 > length - at) break;   // entries past the bytes copied: not read
				const uint8_t* e = head + at;
				static const uint8_t ZERO[16] = {};
				if (memcmp(e, ZERO, 16) == 0) continue;          // an unused entry
				BootPartition p;
				p.index = i + 1;
				p.type = guid_to_wstring(e);
				p.guid = guid_to_wstring(e + 16);
				p.firstSector = readLittleEndian<uint64_t>(e + 32);
				const uint64_t last = readLittleEndian<uint64_t>(e + 40);
				p.sectors = last >= p.firstSector ? last - p.firstSector + 1 : 0;
				p.name = readWideZ(e, 128, 56);
				p.efiSystem = memcmp(e, EFI_SYSTEM_TYPE, 16) == 0;
				t.partitions.push_back(std::move(p));
			}
			return t;
		}
	/* A partition table's entries say 0x00 or 0x80 in their boot flag. A
	   disk formatted whole, without a table (a USB key, a memory card), starts
	   with a volume's boot sector, which ends in 0x55AA too: its BPB, read as
	   entries, gave partitions at random — measured on the harness's keys. */
	for (unsigned i = 0; i < 4; ++i) {
		const uint8_t flag = head[MBR_TABLE + i * MBR_ENTRY];
		if (flag != 0x00 && flag != 0x80) {
			if (isVolumeBootSector(head)) t.style = L"Volume";
			return t;
		}
	}
	t.style = L"MBR";
	t.diskId = to_hex(readLittleEndian<uint32_t>(head + MBR_SIGNATURE), 8, HexLetters::Upper);
	for (unsigned i = 0; i < 4; ++i) {
		const uint8_t* e = head + MBR_TABLE + i * MBR_ENTRY;
		if (e[4] == 0) continue;
		BootPartition p;
		p.index = i + 1;
		p.type = L"0x" + to_hex(e[4], 2, HexLetters::Upper);
		p.firstSector = readLittleEndian<uint32_t>(e + 8);
		p.sectors = readLittleEndian<uint32_t>(e + 12);
		p.active = e[0] == 0x80;
		p.efiSystem = e[4] == MBR_EFI_SYSTEM;
		t.partitions.push_back(std::move(p));
	}
	return t;
}

HRESULT ExtractBootRecordsRaw() {
	std::error_code ec;
	const std::wstring medium = std::filesystem::absolute(exhibitStoreFolder(), ec).root_name().wstring();
	/* The medium's disk is left out — unless it is the system's: a collection
	   written to the examined disk itself (the test harness does) would
	   otherwise lose the very disk it examines. */
	long mediumDisk = medium.size() == 2 ? diskOfVolume(medium) : -1;
	if (mediumDisk >= 0 && mediumDisk == diskOfVolume(conf.systemDrive.substr(0, 2))) mediumDisk = -1;
	HRESULT global = ERROR_EMPTY;
	for (unsigned n = 0; n < MAX_DISKS; ++n) {
		if ((long)n == mediumDisk) continue;   // the collection's own disk
		const HRESULT result = copyDisk(n);
		if (result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) continue;   // no such disk
		auditRecord(L"Raw reading of the boot records (first mebibyte, partitions' boot sectors, EFI system partition)",
		            SOURCE_PREFIX + std::to_wstring(n), result, Footprint::VOLUME_BRUT);
		if (FAILED(result)) log(2, L"🔥Boot records not read: PhysicalDrive" + std::to_wstring(n), result);
		global = result != S_OK ? S_FALSE : (global == ERROR_EMPTY ? S_OK : global);
	}
	return global;
}

// ------------------------------------------------------------ conversion

namespace {

//! The SHA-256 of bytes, uppercase hexadecimal.
std::wstring sha256Of(const uint8_t* data, size_t length) {
	uint8_t digest[32];
	sha256Bytes(data, length, digest);
	return toHexadecimal(digest, sizeof digest);
}

//! A working copy's bytes, at most `limit`.
std::vector<uint8_t> readCopy(const std::wstring& path, uintmax_t limit) {
	std::string bytes;
	if (!readWholeFile(path, limit, bytes)) return {};
	return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

/*! One disk's entry, from its copies.
 *  @param disk "\\\\.\\PhysicalDrive0"
 *  @param parts its exhibits, by what follows the disk ("\\$Head", "\\$Partition1", "\\$Partition1\\EFI\\…") */
Json diskJson(const std::wstring& disk, const std::map<std::wstring, const StoredExhibit*>& parts) {
	Json o = Json::obj();
	o.add(L"Disk", Json::str(disk));
	const auto head = parts.find(L"\\$head");
	if (head == parts.end()) return o;
	const std::vector<uint8_t> bytes = readCopy(head->second->workingFile, BOOT_HEAD_BYTES);
	o.add(L"HeadSha256", Json::str(head->second->sha256));
	if (bytes.size() >= MBR_BOOT_CODE) o.add(L"MbrBootCodeSha256", Json::str(sha256Of(bytes.data(), MBR_BOOT_CODE)));
	const PartitionTable table = parsePartitionTable(bytes.data(), bytes.size());
	o.add(L"PartitionStyle", Json::str(table.style));
	if (table.sectorSize) o.add(L"SectorSize", Json::num((unsigned long long)table.sectorSize));
	o.add(L"DiskId", Json::str(table.diskId));
	// A disk formatted whole: its first sector is the volume's boot sector.
	if (table.style == L"Volume") o.add(L"BootSectorOemId", Json::str(oemName(bytes.data(), bytes.size())));
	Json partitions = Json::arr();
	for (const BootPartition& p : table.partitions) {
		Json j = Json::obj();
		j.add(L"Index", Json::num((unsigned long long)p.index));
		j.add(L"Type", Json::str(p.type));
		j.add(L"Guid", Json::str(p.guid));
		j.add(L"Name", Json::str(p.name));
		j.add(L"FirstSector", Json::num(p.firstSector));
		j.add(L"Sectors", Json::num(p.sectors));
		if (table.style == L"MBR") j.add(L"Active", Json::boolean(p.active));
		if (p.efiSystem) j.add(L"EfiSystem", Json::boolean(true));
		const std::wstring key = L"\\$partition" + std::to_wstring(p.index);
		const auto boot = parts.find(key);
		if (boot != parts.end()) {
			j.add(L"BootSectorsSha256", Json::str(boot->second->sha256));
			const std::vector<uint8_t> b = readCopy(boot->second->workingFile, BOOT_SECTORS * 4096);
			j.add(L"BootSectorOemId", Json::str(oemName(b.data(), b.size())));
		}
		Json files = Json::arr();
		for (auto it = parts.lower_bound(key + L"\\"); it != parts.end() && it->first.compare(0, key.size() + 1, key + L"\\") == 0; ++it) {
			Json f = Json::obj();
			f.add(L"Path", Json::str(it->second->sourcePath.substr(disk.size() + key.size())));
			std::error_code ec;
			const uintmax_t size = std::filesystem::file_size(it->second->workingFile, ec);
			if (!ec) f.add(L"Size", Json::num((unsigned long long)size));
			f.add(L"Sha256", Json::str(it->second->sha256));
			files.push(std::move(f));
		}
		j.add(L"EfiFiles", files);
		partitions.push(std::move(j));
	}
	o.add(L"Partitions", partitions);
	return o;
}

} // namespace

HRESULT BootRecords::getData() {
	// The disks' copies, grouped by disk: their source is "\\.\PhysicalDriveN\…".
	std::map<std::wstring, std::map<std::wstring, const StoredExhibit*>> byDisk;
	const std::wstring prefix = toLower(SOURCE_PREFIX);
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		if (exhibit.workingFile.empty() || key.compare(0, prefix.size(), prefix) != 0) continue;
		const size_t end = key.find(L'\\', prefix.size());
		if (end == std::wstring::npos) continue;
		byDisk[exhibit.sourcePath.substr(0, end)][key.substr(end)] = &exhibit;
	}
	for (const auto& [disk, parts] : byDisk) disks_.push_back(diskJson(disk, parts));
	return ERROR_SUCCESS;
}

HRESULT BootRecords::toJson() {
	Json list = Json::arr();
	for (const Json& d : disks_) list.push(d);
	return writeJsonFile("boot_records.json", list);
}

void BootRecords::clear() { disks_.clear(); }
