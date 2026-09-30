/*! \file
 *  \brief Raw reader of FAT12, FAT16, FAT32 and exFAT volumes (see fat_volume.h).
 */
#include "fat_volume.h"
#include <winioctl.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>

namespace {

const uint32_t ALIGNMENT = 4096;                      //!< reads of a device: whole sectors, 512 or 4096 bytes
const size_t FAT_MAX = 256 * 1024 * 1024;             //!< a larger FAT is not loaded
const size_t DIRECTORY_MAX = 64 * 1024 * 1024;        //!< a larger directory is not read
const size_t ENTRIES_MAX = 10 * 1000 * 1000;
const size_t DIRECTORIES_MAX = 1000 * 1000;
const unsigned DEPTH_MAX = 64;
const uint8_t ATTR_DIRECTORY = 0x10, ATTR_VOLUME = 0x08, ATTR_LONG_NAME = 0x0F;
const uint8_t DELETED = 0xE5;
const char COPY_MAGIC[8] = { 'W', 'A', 'C', 'F', 'A', 'T', 'M', '1' };

uint16_t rd16(const uint8_t* p) { uint16_t v; memcpy(&v, p, 2); return v; }
uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
uint64_t rd64(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }

//! A page-aligned buffer, as a device opened without cache requires.
struct AlignedBuffer {
	void* data = nullptr;
	explicit AlignedBuffer(size_t size) { data = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }
	~AlignedBuffer() { if (data) VirtualFree(data, 0, MEM_RELEASE); }
	AlignedBuffer(const AlignedBuffer&) = delete;
	AlignedBuffer& operator=(const AlignedBuffer&) = delete;
};

//! A FAT date and time (two 16-bit words) plus hundredths, in local time.
FILETIME dosTime(uint16_t date, uint16_t time, unsigned hundredths) {
	FILETIME f = FatDateTime((uint32_t)date | ((uint32_t)time << 16)).toFileTime();
	if (f.dwLowDateTime == 0 && f.dwHighDateTime == 0) return f;
	ULARGE_INTEGER v;
	v.LowPart = f.dwLowDateTime;
	v.HighPart = f.dwHighDateTime;
	v.QuadPart += (uint64_t)std::min(hundredths, 199u) * 100000;   // 10 ms in 100 ns
	f.dwLowDateTime = v.LowPart;
	f.dwHighDateTime = v.HighPart;
	return f;
}

/*! An exFAT timestamp: the time in the low word, the date in the high one,
 *  hundredths apart, and an offset byte — bit 7 set, the low 7 bits are
 *  signed quarter hours east of UTC. With an offset, the instant is UTC. */
void exfatTime(uint32_t stamp, unsigned hundredths, uint8_t offset, FILETIME& out, bool& utc, int& minutes) {
	out = dosTime((uint16_t)(stamp >> 16), (uint16_t)(stamp & 0xFFFF), hundredths);
	utc = false;
	minutes = 0;
	if (!(offset & 0x80) || (out.dwLowDateTime == 0 && out.dwHighDateTime == 0)) return;
	minutes = ((int8_t)(uint8_t)(offset << 1) >> 1) * 15;
	ULARGE_INTEGER v;
	v.LowPart = out.dwLowDateTime;
	v.HighPart = out.dwHighDateTime;
	v.QuadPart -= (int64_t)minutes * 60 * 10000000;
	out.dwLowDateTime = v.LowPart;
	out.dwHighDateTime = v.HighPart;
	utc = true;
}

//! UTF-16 characters of a name entry, up to its terminator or its padding.
void appendName(std::wstring& name, const uint8_t* p, size_t chars) {
	for (size_t i = 0; i < chars; ++i) {
		const wchar_t c = (wchar_t)rd16(p + 2 * i);
		if (c == 0 || c == 0xFFFF) return;
		name.push_back(c);
	}
}

/*! A part of a long name: its checksum, up to 13 characters, and whether
 *  it ends the name — a terminator or padding before its thirteenth
 *  character, or the "last part" flag of a present entry. */
struct LongNamePart {
	uint8_t checksum = 0;
	std::wstring text;
	bool ends = false;
};

//! The part a long-name entry holds.
LongNamePart longNamePart(const uint8_t* e) {
	LongNamePart part;
	part.checksum = e[13];
	std::wstring pieces[3];
	appendName(pieces[0], e + 1, 5);
	appendName(pieces[1], e + 14, 6);
	appendName(pieces[2], e + 28, 2);
	part.text = pieces[0];
	if (pieces[0].size() == 5) { part.text += pieces[1]; if (pieces[1].size() == 6) part.text += pieces[2]; }
	part.ends = part.text.size() < 13 || (e[0] != DELETED && (e[0] & 0x40));
	return part;
}

//! An 8.3 name, its case flags applied (bit 3: lower-case base, bit 4: lower-case extension).
std::wstring shortName(const uint8_t name[11], uint8_t caseFlags) {
	std::string base(reinterpret_cast<const char*>(name), 8), ext(reinterpret_cast<const char*>(name + 8), 3);
	while (!base.empty() && base.back() == ' ') base.pop_back();
	while (!ext.empty() && ext.back() == ' ') ext.pop_back();
	auto lower = [](std::string& s) { for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32); };
	if (caseFlags & 0x08) lower(base);
	if (caseFlags & 0x10) lower(ext);
	return decodeText(ext.empty() ? base : base + "." + ext, CP_OEMCP);
}

} // namespace

uint8_t fatShortNameChecksum(const uint8_t name[11]) {
	uint8_t sum = 0;
	for (int i = 0; i < 11; ++i) sum = (uint8_t)(((sum & 1) << 7) + (sum >> 1) + name[i]);
	return sum;
}

// ------------------------------------------------------------ sources

FileVolumeSource::FileVolumeSource(const std::wstring& path, uint64_t size) {
	handle_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (handle_ == INVALID_HANDLE_VALUE) return;
	size_ = size;
	LARGE_INTEGER fileSize;
	if (!size_ && GetFileSizeEx(handle_, &fileSize) && fileSize.QuadPart > 0) size_ = (uint64_t)fileSize.QuadPart;
	GET_LENGTH_INFORMATION length;
	DWORD returned = 0;
	if (!size_ && DeviceIoControl(handle_, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &length, sizeof length, &returned, nullptr))
		size_ = (uint64_t)length.Length.QuadPart;
}

FileVolumeSource::~FileVolumeSource() {
	if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
}

bool FileVolumeSource::read(uint64_t offset, size_t size, std::vector<uint8_t>& out) {
	if (handle_ == INVALID_HANDLE_VALUE || offset > size_ || size > size_ - offset) return false;
	// Whole aligned blocks, within the volume.
	const uint64_t begin = offset / ALIGNMENT * ALIGNMENT;
	const uint64_t end = std::min<uint64_t>((offset + size + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT, size_);
	AlignedBuffer buffer((size_t)(end - begin + ALIGNMENT));
	if (!buffer.data) return false;
	LARGE_INTEGER at;
	at.QuadPart = (LONGLONG)begin;
	DWORD read = 0;
	if (!SetFilePointerEx(handle_, at, nullptr, FILE_BEGIN)
	    || !ReadFile(handle_, buffer.data, (DWORD)(end - begin), &read, nullptr) || read != end - begin)
		return false;
	const uint8_t* bytes = static_cast<const uint8_t*>(buffer.data);
	out.assign(bytes + (offset - begin), bytes + (offset - begin) + size);
	// Kept, merged with its neighbours: the copy a collection writes.
	std::vector<uint8_t> block(bytes, bytes + (end - begin));
	uint64_t blockBegin = begin;
	auto it = ranges_.upper_bound(blockBegin);
	if (it != ranges_.begin()) --it;
	while (it != ranges_.end() && it->first <= blockBegin + block.size()) {
		const uint64_t itEnd = it->first + it->second.size();
		if (itEnd < blockBegin) { ++it; continue; }
		const uint64_t mergedBegin = std::min(it->first, blockBegin);
		const uint64_t mergedEnd = std::max(itEnd, blockBegin + block.size());
		std::vector<uint8_t> merged((size_t)(mergedEnd - mergedBegin));
		std::copy(it->second.begin(), it->second.end(), merged.begin() + (it->first - mergedBegin));
		std::copy(block.begin(), block.end(), merged.begin() + (blockBegin - mergedBegin));
		block = std::move(merged);
		blockBegin = mergedBegin;
		it = ranges_.erase(it);
	}
	ranges_[blockBegin] = std::move(block);
	return true;
}

bool CopiedVolumeSource::load(const std::wstring& path) {
	std::ifstream in(std::filesystem::path(path), std::ios::binary);
	char magic[8];
	uint64_t size = 0;
	uint32_t count = 0;
	if (!in.read(magic, 8) || memcmp(magic, COPY_MAGIC, 8) != 0 || !in.read(reinterpret_cast<char*>(&size), 8)
	    || !in.read(reinterpret_cast<char*>(&count), 4))
		return false;
	size_ = size;
	for (uint32_t i = 0; i < count; ++i) {
		uint64_t offset = 0;
		uint32_t length = 0;
		if (!in.read(reinterpret_cast<char*>(&offset), 8) || !in.read(reinterpret_cast<char*>(&length), 4)
		    || offset > size_ || length > size_ - offset || length > FAT_MAX + DIRECTORY_MAX)
			return false;
		std::vector<uint8_t> bytes(length);
		if (!in.read(reinterpret_cast<char*>(bytes.data()), length)) return false;
		ranges_[offset] = std::move(bytes);
	}
	return true;
}

bool CopiedVolumeSource::read(uint64_t offset, size_t size, std::vector<uint8_t>& out) {
	auto it = ranges_.upper_bound(offset);
	if (it == ranges_.begin()) return false;
	--it;
	if (offset - it->first > it->second.size() || size > it->second.size() - (offset - it->first)) return false;
	out.assign(it->second.begin() + (offset - it->first), it->second.begin() + (offset - it->first) + size);
	return true;
}

std::string volumeCopyBytes(const FileVolumeSource& source) {
	std::string out(COPY_MAGIC, COPY_MAGIC + 8);
	auto put = [&](const void* p, size_t n) { out.append(static_cast<const char*>(p), n); };
	const uint64_t size = source.size();
	const uint32_t count = (uint32_t)source.ranges().size();
	put(&size, 8);
	put(&count, 4);
	for (const auto& [offset, bytes] : source.ranges()) {
		const uint32_t length = (uint32_t)bytes.size();
		put(&offset, 8);
		put(&length, 4);
		put(bytes.data(), length);
	}
	return out;
}

// ------------------------------------------------------------ volume

bool FatVolume::open(VolumeSource& source) {
	source_ = &source;
	std::vector<uint8_t> b;
	if (!source.read(0, 512, b) || b[510] != 0x55 || b[511] != 0xAA) return false;
	uint64_t fatOffset = 0, fatLength = 0;
	if (memcmp(b.data() + 3, "EXFAT   ", 8) == 0) {
		const unsigned sectorShift = b[108], clusterShift = b[109];
		if (sectorShift < 9 || sectorShift > 12 || clusterShift > 25 - sectorShift) return false;
		const uint32_t bps = 1u << sectorShift;
		fatOffset = (uint64_t)rd32(b.data() + 80) * bps;
		fatLength = (uint64_t)rd32(b.data() + 84) * bps;
		dataOffset_ = (uint64_t)rd32(b.data() + 88) * bps;
		clusterCount_ = rd32(b.data() + 92);
		rootCluster_ = rd32(b.data() + 96);
		clusterSize_ = bps << clusterShift;
		fatBits_ = 32;
		type_ = L"exFAT";
	}
	else {
		const uint32_t bps = rd16(b.data() + 11), spc = b[13], reserved = rd16(b.data() + 14), fats = b[16];
		const uint32_t rootEntries = rd16(b.data() + 17);
		const uint32_t total = rd16(b.data() + 19) ? rd16(b.data() + 19) : rd32(b.data() + 32);
		const uint32_t fatSectors = rd16(b.data() + 22) ? rd16(b.data() + 22) : rd32(b.data() + 36);
		if ((bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) || spc == 0 || (spc & (spc - 1))
		    || reserved == 0 || fats == 0 || fatSectors == 0)
			return false;
		const uint64_t rootSectors = ((uint64_t)rootEntries * 32 + bps - 1) / bps;
		const uint64_t metaSectors = reserved + (uint64_t)fats * fatSectors + rootSectors;
		if (metaSectors >= total) return false;
		clusterCount_ = (uint32_t)((total - metaSectors) / spc);
		clusterSize_ = bps * spc;
		fatOffset = (uint64_t)reserved * bps;
		fatLength = (uint64_t)fatSectors * bps;
		rootOffset_ = (reserved + (uint64_t)fats * fatSectors) * bps;
		rootSize_ = rootSectors * bps;
		dataOffset_ = metaSectors * bps;
		// The type by the count of clusters, as the specification says.
		fatBits_ = clusterCount_ < 4085 ? 12 : clusterCount_ < 65525 ? 16 : 32;
		type_ = fatBits_ == 12 ? L"FAT12" : fatBits_ == 16 ? L"FAT16" : L"FAT32";
		if (fatBits_ == 32) rootCluster_ = rd32(b.data() + 44);
	}
	if (clusterSize_ == 0 || clusterCount_ == 0 || fatLength > FAT_MAX) return false;
	return source.read(fatOffset, (size_t)fatLength, fat_);
}

uint32_t FatVolume::next(uint32_t cluster) {
	uint32_t value = 0;
	if (fatBits_ == 12) {
		const size_t at = cluster + cluster / 2;
		if (!fits(fat_.size(), at, 2)) return 0;
		value = rd16(fat_.data() + at);
		value = (cluster & 1) ? value >> 4 : value & 0x0FFF;
		if (value >= 0xFF7) return 0;
	}
	else if (fatBits_ == 16) {
		if (!fits(fat_.size(), (size_t)cluster * 2, 2)) return 0;
		value = rd16(fat_.data() + (size_t)cluster * 2);
		if (value >= 0xFFF7) return 0;
	}
	else {
		if (!fits(fat_.size(), (size_t)cluster * 4, 4)) return 0;
		value = rd32(fat_.data() + (size_t)cluster * 4);
		if (type_ != L"exFAT") value &= 0x0FFFFFFF;
		if (value >= (type_ == L"exFAT" ? 0xFFFFFFF7u : 0x0FFFFFF7u)) return 0;
	}
	return value >= 2 && value < clusterCount_ + 2 ? value : 0;
}

/*! The clusters of a directory: following its FAT chain, or contiguous
 *  (exFAT's NoFatChain) for `knownSize` bytes; each cluster once. */
std::vector<uint8_t> FatVolume::chain(uint32_t first, uint64_t knownSize, bool contiguous) {
	std::vector<uint8_t> data, cluster;
	std::set<uint32_t> seen;
	const uint64_t count = contiguous ? (knownSize + clusterSize_ - 1) / clusterSize_ : clusterCount_;
	for (uint32_t c = first, i = 0; c >= 2 && c < clusterCount_ + 2 && i < count; ++i) {
		if (data.size() + clusterSize_ > DIRECTORY_MAX || !seen.insert(c).second) break;
		if (!source_->read(dataOffset_ + (uint64_t)(c - 2) * clusterSize_, clusterSize_, cluster)) break;
		data.insert(data.end(), cluster.begin(), cluster.end());
		c = contiguous ? c + 1 : next(c);
	}
	return data;
}

std::vector<FatEntry> FatVolume::entries() {
	std::vector<FatEntry> out;
	visited_ = 0;
	std::vector<uint8_t> root;
	if (fatBits_ == 32) root = chain(rootCluster_, 0, false);
	else if (!source_->read(rootOffset_, (size_t)rootSize_, root)) return out;
	if (type_ == L"exFAT") exfatDirectory(root, L"", false, 0, out);
	else fatDirectory(root, L"", false, 0, out);
	return out;
}

void FatVolume::descend(const FatEntry& e, unsigned depth, std::vector<FatEntry>& out) {
	if (!e.directory || e.firstCluster < 2 || depth >= DEPTH_MAX || ++visited_ > DIRECTORIES_MAX || out.size() > ENTRIES_MAX) return;
	const std::vector<uint8_t> data = chain(e.firstCluster, e.size, e.contiguous);
	if (data.size() < 32) return;
	if (type_ == L"exFAT") { exfatDirectory(data, e.path, e.deleted, depth + 1, out); return; }
	// A deleted folder's first cluster may hold something else since: "." first, or nothing.
	if (e.deleted && !(data[0] == '.' && (data[11] & ATTR_DIRECTORY))) return;
	fatDirectory(data, e.path, e.deleted, depth + 1, out);
}

/*! A FAT directory: long-name entries gathered, then bound to the 8.3 entry
 *  that follows by its checksum — for a deleted entry, the checksum of each
 *  possible first byte also gives back the first letter. */
void FatVolume::fatDirectory(const std::vector<uint8_t>& data, const std::wstring& path, bool deletedParent,
                             unsigned depth, std::vector<FatEntry>& out) {
	std::vector<LongNamePart> parts;   // in the order met: the name's last part first
	for (size_t o = 0; o + 32 <= data.size() && out.size() < ENTRIES_MAX; o += 32) {
		const uint8_t* e = data.data() + o;
		if (e[0] == 0x00) break;                                        // the end of the directory
		if ((e[11] & 0x3F) == ATTR_LONG_NAME) {
			if (e[0] != DELETED && (e[0] & 0x40)) parts.clear();          // the last part of a new name
			parts.push_back(longNamePart(e));
			continue;
		}
		uint8_t name[11];
		memcpy(name, e, 11);
		const bool deleted = name[0] == DELETED || deletedParent;
		if (name[0] == 0x05) name[0] = DELETED;                         // a real 0xE5 first character
		if ((e[11] & ATTR_VOLUME) && !(e[11] & ATTR_DIRECTORY)) {
			if (path.empty() && name[0] != DELETED) label_ = shortName(name, 0);
			parts.clear();
			continue;
		}
		if (name[0] == '.' && (e[11] & ATTR_DIRECTORY)) { parts.clear(); continue; }
		FatEntry entry;
		entry.deleted = deleted;
		// The long name, if its parts carry this entry's checksum.
		std::wstring longName;
		const uint8_t sum = parts.empty() ? 0 : parts.front().checksum;
		bool bound = !parts.empty() && std::all_of(parts.begin(), parts.end(), [&](const LongNamePart& p) { return p.checksum == sum; });
		if (bound && name[0] == DELETED && e[0] == DELETED) {
			bound = false;
			for (unsigned c = 0x20; c < 0x100 && !bound; ++c) {
				name[0] = (uint8_t)c;
				bound = fatShortNameChecksum(name) == sum;
			}
			if (!bound) name[0] = DELETED;
		}
		else if (bound) bound = fatShortNameChecksum(name) == sum;
		if (bound) for (auto it = parts.rbegin(); it != parts.rend(); ++it) longName += it->text;
		// A deleted name whose last part found does not end it lost its next parts to a newer entry.
		const bool truncated = bound && !parts.front().ends;
		parts.clear();
		if (name[0] == DELETED) { name[0] = '_'; entry.nameIncomplete = longName.empty(); }
		if (truncated) entry.nameIncomplete = true;
		entry.shortName = shortName(name, e[12]);
		entry.path = path + L"\\" + (longName.empty() ? entry.shortName : longName);
		entry.attributes = e[11];
		entry.directory = (e[11] & ATTR_DIRECTORY) != 0;
		entry.firstCluster = ((fatBits_ == 32 ? (uint32_t)rd16(e + 20) : 0) << 16) | rd16(e + 26);
		entry.size = rd32(e + 28);
		entry.created = dosTime(rd16(e + 16), rd16(e + 14), e[13]);
		entry.modified = dosTime(rd16(e + 24), rd16(e + 22), 0);
		entry.accessed = dosTime(rd16(e + 18), 0, 0);
		out.push_back(entry);
		descend(entry, depth, out);
	}
}

/*! An exFAT directory: entry sets of a file entry (0x85), its stream
 *  extension (0xC0) and its name entries (0xC1); the same types, high bit
 *  cleared, for a deleted set. */
void FatVolume::exfatDirectory(const std::vector<uint8_t>& data, const std::wstring& path, bool deletedParent,
                               unsigned depth, std::vector<FatEntry>& out) {
	for (size_t o = 0; o + 32 <= data.size() && out.size() < ENTRIES_MAX; o += 32) {
		const uint8_t* e = data.data() + o;
		const uint8_t type = e[0];
		if (type == 0x00) break;
		if (type == 0x83) {                                             // volume label
			if (path.empty()) { label_.clear(); appendName(label_, e + 2, std::min<size_t>(e[1], 11)); }
			continue;
		}
		if ((type | 0x80) != 0x85) continue;
		const bool deleted = !(type & 0x80) || deletedParent;
		const size_t secondaries = e[1];
		if (secondaries < 2 || !fits(data.size(), o, 32 * (secondaries + 1))) continue;
		const uint8_t* stream = e + 32;
		if ((stream[0] | 0x80) != 0xC0 || ((stream[0] & 0x80) != (type & 0x80))) continue;
		FatEntry entry;
		entry.deleted = deleted;
		std::wstring name;
		const size_t length = stream[3];
		for (size_t i = 2; i <= secondaries && name.size() < length; ++i) {
			const uint8_t* n = e + 32 * i;
			if ((n[0] | 0x80) != 0xC1) break;
			appendName(name, n + 2, std::min<size_t>(15, length - name.size()));
		}
		entry.path = path + L"\\" + name;
		entry.attributes = rd16(e + 4);
		entry.directory = (entry.attributes & ATTR_DIRECTORY) != 0;
		entry.contiguous = (stream[1] & 0x02) != 0;
		entry.firstCluster = rd32(stream + 20);
		entry.size = rd64(stream + 24);
		exfatTime(rd32(e + 8), e[20], e[22], entry.created, entry.createdUtc, entry.createdOffset);
		exfatTime(rd32(e + 12), e[21], e[23], entry.modified, entry.modifiedUtc, entry.modifiedOffset);
		exfatTime(rd32(e + 16), 0, e[24], entry.accessed, entry.accessedUtc, entry.accessedOffset);
		out.push_back(entry);
		descend(entry, depth, out);
		o += 32 * secondaries;
	}
}
