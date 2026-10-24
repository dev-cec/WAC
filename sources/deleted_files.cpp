/*! \file
 *  \brief Deleted files recovered by raw reading (see deleted_files.h).
 */
#include "deleted_files.h"
#include "fat_volume.h"
#include "fat_volumes.h"
#include "audit.h"
#include "binaires.h"
#include "consigne.h"
#include "live_snapshot.h"
#include "mft.h"
#include "usn_journal.h"
#include "quickdigest5.h"
#include "running_machine.h"
#include "sha.h"
#include "tools.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <winioctl.h>

namespace {

// Layout of a FILE record and of its attributes (the NTFS documentation of the Linux-NTFS project).
const size_t RECORD_SEQUENCE = 0x10, RECORD_ATTRIBUTES = 0x14, RECORD_FLAGS = 0x16, RECORD_USED_SIZE = 0x18, RECORD_BASE = 0x20;
const uint16_t RECORD_IN_USE = 0x01, RECORD_DIRECTORY = 0x02;
const uint32_t ATTRIBUTE_LIST = 0x20, DATA = 0x80, ATTRIBUTE_END = 0xFFFFFFFF;
const uint16_t DATA_COMPRESSED = 0x0001, DATA_ENCRYPTED = 0x4000;
const size_t NON_RESIDENT_HEADER = 0x40;   //!< a non-resident attribute's header, up to its initialized size

//! Bytes read at a time: clusters of one run, checked in $Bitmap before and after.
const uint64_t CHUNK_BYTES = 1u << 20;

//! Adds a hole, merged with the previous one when they touch.
void addMissing(std::vector<MissingRange>& missing, uint64_t offset, uint64_t length) {
	if (length == 0) return;
	if (!missing.empty() && missing.back().offset + missing.back().length == offset) missing.back().length += length;
	else missing.push_back({ offset, length });
}

} // namespace

DeletedRecord parseDeletedRecord(const uint8_t* record, size_t size) {
	DeletedRecord r;
	if (!record || size < 0x30 || std::memcmp(record, "FILE", 4) != 0) return r;
	r.fileRecord = true;
	r.sequence = readLittleEndian<uint16_t>(record + RECORD_SEQUENCE);
	const uint16_t flags = readLittleEndian<uint16_t>(record + RECORD_FLAGS);
	r.inUse = (flags & RECORD_IN_USE) != 0;
	r.directory = (flags & RECORD_DIRECTORY) != 0;
	r.baseRecord = readLittleEndian<uint64_t>(record + RECORD_BASE) == 0;
	const size_t used = std::min<size_t>(readLittleEndian<uint32_t>(record + RECORD_USED_SIZE), size);
	for (size_t p = readLittleEndian<uint16_t>(record + RECORD_ATTRIBUTES); p + 16 <= used;) {
		const uint32_t type = readLittleEndian<uint32_t>(record + p);
		const uint32_t length = readLittleEndian<uint32_t>(record + p + 4);
		if (type == ATTRIBUTE_END || length < 16 || length > used - p) break;
		const uint8_t* a = record + p;
		p += length;
		if (type == ATTRIBUTE_LIST) { r.data.attributeList = true; continue; }
		if (type != DATA || a[9] != 0 || r.data.found) continue;   // the unnamed $DATA, the first one
		DeletedData& d = r.data;
		if (a[8] == 0) {
			if (length < 0x18) continue;
			const uint32_t valueLength = readLittleEndian<uint32_t>(a + 0x10);
			const uint16_t valueOffset = readLittleEndian<uint16_t>(a + 0x14);
			if ((uint64_t)valueOffset + valueLength > length) continue;
			d.found = d.resident = true;
			d.residentBytes.assign(a + valueOffset, a + valueOffset + valueLength);
			d.size = d.initializedSize = valueLength;
			continue;
		}
		// The fragment starting at cluster 0 carries the sizes; another lies in an extension record.
		if (length < NON_RESIDENT_HEADER || readLittleEndian<uint64_t>(a + 0x10) != 0) continue;
		d.found = true;
		d.lastVcn = readLittleEndian<uint64_t>(a + 0x18);
		d.flags = readLittleEndian<uint16_t>(a + 0x0C);
		d.allocatedSize = readLittleEndian<uint64_t>(a + 0x28);
		d.size = readLittleEndian<uint64_t>(a + 0x30);
		d.initializedSize = readLittleEndian<uint64_t>(a + 0x38);
		const uint16_t runsOffset = readLittleEndian<uint16_t>(a + 0x20);
		if (runsOffset >= NON_RESIDENT_HEADER && runsOffset < length) d.runs = decodeNtfsRuns(a + runsOffset, a + length);
		d.runsDecoded = !d.runs.empty();
	}
	return r;
}

std::string checkRuns(const DeletedData& data, uint32_t clusterSize, uint64_t clusters) {
	if (!data.runsDecoded) return "data runs malformed";
	if (clusterSize == 0) return "cluster size unknown";
	uint64_t total = 0;
	std::vector<NtfsRun> placed;
	for (const NtfsRun& run : data.runs) {
		if (run.count > UINT64_MAX - total) return "data runs longer than any volume";
		total += run.count;
		if (run.lcn < 0) continue;                       // sparse: no cluster
		if ((uint64_t)run.lcn >= clusters || run.count > clusters - (uint64_t)run.lcn) return "a data run past the volume's end";
		placed.push_back(run);
	}
	if (data.lastVcn == UINT64_MAX || total != data.lastVcn + 1) {
		return data.attributeList ? "data runs partly in extension records ($ATTRIBUTE_LIST)"
		                          : "data runs do not end at the attribute's last cluster";
	}
	if (total > UINT64_MAX / clusterSize || data.allocatedSize != total * clusterSize) {
		return data.attributeList ? "data runs partly in extension records ($ATTRIBUTE_LIST)"
		                          : "allocated size differs from the data runs";
	}
	if (data.size > data.allocatedSize || data.initializedSize > data.size) return "sizes inconsistent";
	std::sort(placed.begin(), placed.end(), [](const NtfsRun& a, const NtfsRun& b) { return a.lcn < b.lcn; });
	for (size_t k = 1; k < placed.size(); ++k)
		if ((uint64_t)placed[k].lcn < (uint64_t)placed[k - 1].lcn + placed[k - 1].count) return "two data runs on the same clusters";
	return std::string();
}

const wchar_t* recoveryStateName(RecoveryState state) {
	switch (state) {
	case RecoveryState::Recovered: return L"Recovered";
	case RecoveryState::Partial: return L"Partial";
	case RecoveryState::Overwritten: return L"Overwritten";
	case RecoveryState::Zeroed: return L"Zeroed";
	case RecoveryState::NotRecoverable: return L"NotRecoverable";
	}
	return L"NotRecoverable";
}

void ClusterClaims::add(uint64_t lcn, uint64_t count, uint64_t date) {
	if (count && lcn <= UINT64_MAX - count) runs_.push_back({ lcn, lcn + count, date });
}

void ClusterClaims::finish() {
	// A sweep over the runs' bounds, keeping the latest date of those open.
	std::vector<std::pair<uint64_t, int64_t>> bounds;     // (cluster, +index+1 opening / -index-1 closing)
	bounds.reserve(runs_.size() * 2);
	for (size_t k = 0; k < runs_.size(); ++k) {
		bounds.emplace_back(runs_[k].start, (int64_t)k + 1);
		bounds.emplace_back(runs_[k].end, -(int64_t)k - 1);
	}
	std::sort(bounds.begin(), bounds.end());
	std::multiset<uint64_t> open;
	latest_.clear();
	for (size_t k = 0; k < bounds.size();) {
		const uint64_t at = bounds[k].first;
		for (; k < bounds.size() && bounds[k].first == at; ++k) {
			if (bounds[k].second > 0) open.insert(runs_[(size_t)bounds[k].second - 1].date);
			else open.erase(open.find(runs_[(size_t)(-bounds[k].second) - 1].date));
		}
		if (k == bounds.size() || open.empty()) continue;
		const uint64_t date = *open.rbegin(), next = bounds[k].first;
		if (!latest_.empty() && latest_.back().end == at && latest_.back().date == date) latest_.back().end = next;
		else latest_.push_back({ at, next, date });
	}
	runs_.clear();
	runs_.shrink_to_fit();
}

void ClusterClaims::laterThan(uint64_t lcn, uint64_t count, uint64_t date, std::vector<bool>& claimed) const {
	claimed.assign((size_t)count, false);
	const uint64_t end = lcn + count;
	auto span = std::upper_bound(latest_.begin(), latest_.end(), lcn, [](uint64_t at, const Span& s) { return at < s.end; });
	for (; span != latest_.end() && span->start < end; ++span) {
		if (span->date <= date) continue;
		for (uint64_t c = std::max(lcn, span->start); c < std::min(end, span->end); ++c) claimed[(size_t)(c - lcn)] = true;
	}
}

Recovery recoverContent(const DeletedData& data, const ClusterSource& volume,
                        const std::function<void(const uint8_t*, size_t)>& sink) {
	Recovery recovery;
	if (!data.found) { recovery.reason = "no unnamed $DATA attribute"; return recovery; }
	if (data.resident) {
		// In the record itself: what the record holds is the content, whatever the clusters.
		if (!data.residentBytes.empty()) sink(data.residentBytes.data(), data.residentBytes.size());
		recovery.state = RecoveryState::Recovered;
		recovery.recoveredBytes = data.residentBytes.size();
		return recovery;
	}
	if (data.flags & DATA_COMPRESSED) { recovery.reason = "compressed by NTFS"; return recovery; }
	if (data.flags & DATA_ENCRYPTED) { recovery.reason = "encrypted (EFS)"; return recovery; }
	recovery.reason = checkRuns(data, volume.clusterSize, volume.clusters);
	if (!recovery.reason.empty()) return recovery;

	const uint64_t clusterSize = volume.clusterSize;
	const uint64_t validEnd = data.initializedSize;     // beyond it, zeros by definition: nothing read
	const uint64_t needed = (validEnd + clusterSize - 1) / clusterSize;
	const uint64_t chunkClusters = std::max<uint64_t>(1, CHUNK_BYTES / clusterSize);
	std::vector<uint8_t> buffer;
	std::vector<bool> before, after, claimed;
	bool nonZero = false;
	uint64_t vcn = 0;
	for (const NtfsRun& run : data.runs) {
		for (uint64_t c = 0; c < run.count && vcn + c < needed;) {
			const uint64_t n = std::min({ chunkClusters, run.count - c, needed - (vcn + c) });
			const uint64_t start = (vcn + c) * clusterSize;
			const uint64_t bytes = std::min<uint64_t>(n * clusterSize, validEnd - start);
			buffer.assign((size_t)(n * clusterSize), 0);
			if (run.lcn >= 0) {
				const uint64_t lcn = (uint64_t)run.lcn + c;
				// Unreadable allocation: every cluster counts as taken, a hole.
				if (!volume.allocation(lcn, n, before)) before.assign((size_t)n, true);
				// Claimed since by a later deleted file: taken too, not read.
				if (volume.claimedSince) {
					volume.claimedSince(lcn, n, claimed);
					for (uint64_t k = 0; k < n; ++k)
						if (claimed[(size_t)k] && !before[(size_t)k]) { before[(size_t)k] = true; ++recovery.claimedClusters; }
				}
				std::vector<bool> unread((size_t)n, false);
				for (uint64_t k = 0; k < n;) {                 // the free clusters, by contiguous stretch
					if (before[(size_t)k]) { ++k; continue; }
					uint64_t end = k;
					while (end < n && !before[(size_t)end]) ++end;
					if (!volume.read(lcn + k, end - k, buffer.data() + k * clusterSize))
						for (uint64_t u = k; u < end; ++u) unread[(size_t)u] = true;
					k = end;
				}
				if (!volume.allocation(lcn, n, after)) after.assign((size_t)n, true);
				for (uint64_t k = 0; k < n; ++k) {
					const uint64_t offset = start + k * clusterSize;
					if (offset >= validEnd) break;
					const uint64_t length = std::min<uint64_t>(clusterSize, validEnd - offset);
					uint8_t* cluster = buffer.data() + k * clusterSize;
					if (before[(size_t)k] || after[(size_t)k] || unread[(size_t)k]) {
						std::memset(cluster, 0, (size_t)clusterSize);
						addMissing(recovery.missing, offset, length);
						continue;
					}
					recovery.recoveredBytes += length;
					if (!nonZero) nonZero = std::any_of(cluster, cluster + length, [](uint8_t b) { return b != 0; });
				}
			}
			sink(buffer.data(), (size_t)bytes);
			c += n;
		}
		vcn += run.count;
	}
	// From the valid data length to the size: zeros, as NTFS returns them.
	std::vector<uint8_t> zeros((size_t)std::min<uint64_t>(CHUNK_BYTES, std::max<uint64_t>(1, data.size - validEnd)), 0);
	for (uint64_t at = validEnd; at < data.size;) {
		const size_t n = (size_t)std::min<uint64_t>(zeros.size(), data.size - at);
		sink(zeros.data(), n);
		at += n;
	}
	if (recovery.claimedClusters) recovery.reason = "clusters claimed since by a later deleted file";
	if (recovery.recoveredBytes == 0 && !recovery.missing.empty()) recovery.state = RecoveryState::Overwritten;
	else if (recovery.recoveredBytes > 0 && !nonZero) recovery.state = RecoveryState::Zeroed;
	else if (!recovery.missing.empty()) recovery.state = RecoveryState::Partial;
	else recovery.state = RecoveryState::Recovered;
	return recovery;
}

namespace {

//! Clusters looked at a time: their allocation and claims read once.
const uint64_t CARVE_WINDOW = 256;

/*! Whether every cluster of a range is free and unclaimed now.
 *  @return false as soon as one is not, or the allocation is unreadable */
bool freeAndUnclaimed(const ClusterSource& volume, uint64_t lcn, uint64_t count) {
	if (count == 0 || lcn >= volume.clusters || count > volume.clusters - lcn) return false;
	std::vector<bool> used, claimed;
	for (uint64_t done = 0; done < count;) {
		const uint64_t n = std::min<uint64_t>(CARVE_WINDOW * 16, count - done);
		if (!volume.allocation(lcn + done, n, used)) return false;
		if (volume.claimedSince) volume.claimedSince(lcn + done, n, claimed);
		for (uint64_t k = 0; k < n; ++k)
			if (used[(size_t)k] || (volume.claimedSince && claimed[(size_t)k])) return false;
		done += n;
	}
	return true;
}

/*! The bytes of a run of free, unclaimed clusters from `lcn`, up to `bytes`
 *  or to the first cluster that is not — read, then checked again.
 *  @return what was read, a whole number of clusters; empty on a read error */
std::vector<uint8_t> readFreeRun(const ClusterSource& volume, uint64_t lcn, uint64_t bytes) {
	const uint64_t size = volume.clusterSize;
	const uint64_t wanted = std::min((bytes + size - 1) / size, volume.clusters - std::min(lcn, volume.clusters));
	uint64_t clusters = 0;
	std::vector<bool> used, claimed;
	while (clusters < wanted) {                        // a window at a time, up to the first cluster taken
		const uint64_t n = std::min(CARVE_WINDOW, wanted - clusters);
		if (!volume.allocation(lcn + clusters, n, used)) break;
		if (volume.claimedSince) volume.claimedSince(lcn + clusters, n, claimed);
		uint64_t k = 0;
		while (k < n && !used[(size_t)k] && !(volume.claimedSince && claimed[(size_t)k])) ++k;
		clusters += k;
		if (k < n) break;
	}
	std::vector<uint8_t> data((size_t)(clusters * size));
	if (clusters && !volume.read(lcn, clusters, data.data())) data.clear();
	return data;
}

/*! The file a cluster starts, cut at its end and checked free all along.
 *  @return its format None when nothing valid starts there */
CarvedFile carveAt(const ClusterSource& volume, uint64_t lcn, const uint8_t* head, uint64_t maxFile) {
	CarvedFile file;
	const CarvedStart start = carvedStart(head, volume.clusterSize);
	if (start.format == CarvedFormat::None) return file;
	const uint64_t cluster = volume.clusterSize;
	uint64_t size = start.size;
	std::vector<uint8_t> data;
	if (!size) {
		// The end lies further: as far as free clusters go, within the bound.
		const uint64_t reach = start.needed ? std::min(start.needed, maxFile) : maxFile;
		if (start.needed > maxFile) {                      // a PE larger than the bound: its size unread
			file.lcn = lcn;
			file.format = start.format;
			return file;
		}
		data = readFreeRun(volume, lcn, reach);
		if (start.needed && data.size() < start.needed) return CarvedFile();
		size = carvedEnd(start.format, data.data(), data.size());
		if (!size) return CarvedFile();
	}
	file.lcn = lcn;
	file.format = start.format;
	file.size = size;
	if (size > maxFile) return file;                       // listed with its size, not read
	const uint64_t clusters = (size + cluster - 1) / cluster;
	if (data.size() < size) {
		if (!freeAndUnclaimed(volume, lcn, clusters)) return CarvedFile();
		data.assign((size_t)(clusters * cluster), 0);
		if (!volume.read(lcn, clusters, data.data())) return CarvedFile();
	}
	// Read so, still so: a cluster taken while it was read is another file's.
	if (!freeAndUnclaimed(volume, lcn, clusters)) return CarvedFile();
	data.resize((size_t)size);
	file.content = std::move(data);
	return file;
}

} // namespace

uint64_t carveClusters(const ClusterSource& volume, uint64_t maxFile, const std::function<void(const CarvedFile&)>& found) {
	const uint64_t cluster = volume.clusterSize;
	uint64_t looked = 0;
	std::vector<bool> used, claimed;
	std::vector<uint8_t> buffer;
	for (uint64_t lcn = 0; lcn < volume.clusters;) {
		const uint64_t n = std::min(CARVE_WINDOW, volume.clusters - lcn);
		if (!volume.allocation(lcn, n, used)) { lcn += n; continue; }
		if (volume.claimedSince) volume.claimedSince(lcn, n, claimed);
		uint64_t next = lcn + n;
		for (uint64_t k = 0; k < n;) {
			if (used[(size_t)k] || (volume.claimedSince && claimed[(size_t)k])) { ++k; continue; }
			uint64_t end = k;
			while (end < n && !used[(size_t)end] && !(volume.claimedSince && claimed[(size_t)end])) ++end;
			buffer.assign((size_t)((end - k) * cluster), 0);
			if (!volume.read(lcn + k, end - k, buffer.data())) { k = end; continue; }
			bool jumped = false;
			for (uint64_t c = k; c < end; ++c) {
				++looked;
				const CarvedFile file = carveAt(volume, lcn + c, buffer.data() + (c - k) * cluster, maxFile);
				if (file.format == CarvedFormat::None) continue;
				found(file);
				// Past the file: what it holds (a PE inside an archive) is not another file.
				const uint64_t past = lcn + c + std::max<uint64_t>(1, (file.size + cluster - 1) / cluster);
				if (past > lcn + c + 1) { next = past; jumped = true; break; }
			}
			if (jumped) break;
			k = end;
		}
		lcn = next;
	}
	return looked;
}

std::wstring safeFileName(const std::wstring& name) {
	const size_t NAME_MAX = 120;   // the store's folders add their own length: well under MAX_PATH
	std::wstring safe = name.substr(0, NAME_MAX);
	for (wchar_t& c : safe)
		if (c < 0x20 || wcschr(L"<>:\"/\\|?*", c)) c = L'_';
	// Windows drops a trailing dot or space: the name written would not be the one recorded.
	while (!safe.empty() && (safe.back() == L'.' || safe.back() == L' ')) safe.back() = L'_';
	return safe.empty() ? std::wstring(L"_") : safe;
}

namespace {

// An index entry and the $FILE_NAME it carries as its key.
const size_t ENTRY_KEY = 0x10;           //!< the key after the entry's header: file reference, lengths, flags
const size_t NAME_LENGTH = 0x40, NAME_SPACE = 0x41, NAME = 0x42;   //!< in $FILE_NAME
const size_t NODE_HEADER = 0x18;         //!< the node header in an INDX block
const uint8_t DOS_NAME_SPACE = 2;
const uint64_t DATE_MIN = 119600064000000000ull;   //!< 1980-01-01 as FILETIME
const uint64_t DATE_MAX = 157469184000000000ull;   //!< 2100-01-01

//! A plausible $FILE_NAME date: an entry of the slack whose dates are not is no entry.
bool plausibleDate(uint64_t ticks) { return ticks >= DATE_MIN && ticks < DATE_MAX; }

//! A name Windows could have given: no control character, none of the separators of a path.
bool plausibleName(const std::wstring& name, uint8_t nameSpace) {
	for (wchar_t c : name) {
		if (c < 0x20 || c == L'/') return false;
		if (nameSpace != 0 && wcschr(L"\\:*?\"<>|", c)) return false;   // POSIX names allow them
	}
	return !name.empty();
}

} // namespace

std::vector<IndexSlackEntry> indexSlackEntries(const uint8_t* block, size_t size, bool inUse, uint64_t directory) {
	std::vector<IndexSlackEntry> found;
	if (!block || size < NODE_HEADER + 0x10 || std::memcmp(block, "INDX", 4) != 0) return found;
	const uint8_t* node = block + NODE_HEADER;
	const size_t nodeRoom = size - NODE_HEADER;
	const size_t first = readLittleEndian<uint32_t>(node), used = readLittleEndian<uint32_t>(node + 4);
	const size_t allocated = std::min<size_t>(readLittleEndian<uint32_t>(node + 8), nodeRoom);
	/* In use: what lies beyond the used size. Released: the whole node, its
	   former live entries included — none of them is live any more. */
	size_t from = inUse ? used : first;
	if (from >= allocated) return found;
	from = (from + 7) & ~(size_t)7;                 // entries start on 8 bytes, from the node
	for (size_t at = from; at + ENTRY_KEY + NAME <= allocated; at += 8) {
		const uint8_t* e = node + at;
		const uint16_t keyLength = readLittleEndian<uint16_t>(e + 10);
		const uint8_t* key = e + ENTRY_KEY;
		const uint8_t characters = key[NAME_LENGTH], nameSpace = key[NAME_SPACE];
		if (characters == 0 || nameSpace > 3 || nameSpace == DOS_NAME_SPACE) continue;
		if (keyLength != NAME + 2u * characters || at + ENTRY_KEY + keyLength > allocated) continue;
		if (readLittleEndian<uint16_t>(e + 8) < ENTRY_KEY + keyLength) continue;    // the entry holds its key
		if (splitNtfsReference(readLittleEndian<uint64_t>(key)).entry != directory) continue;
		IndexSlackEntry slack;
		const uint64_t times[4] = { readLittleEndian<uint64_t>(key + 0x08), readLittleEndian<uint64_t>(key + 0x10),
		                            readLittleEndian<uint64_t>(key + 0x18), readLittleEndian<uint64_t>(key + 0x20) };
		if (!std::all_of(times, times + 4, plausibleDate)) continue;
		slack.name.assign(characters, L'\0');
		for (size_t k = 0; k < characters; ++k) slack.name[k] = (wchar_t)readLittleEndian<uint16_t>(key + NAME + 2 * k);
		if (!plausibleName(slack.name, nameSpace)) continue;
		const NtfsReference file = splitNtfsReference(readLittleEndian<uint64_t>(e));
		slack.entry = file.entry;
		slack.sequence = file.sequence;
		slack.nameSpace = nameSpace;
		slack.created = filetimeFromTicks(times[0]);
		slack.modified = filetimeFromTicks(times[1]);
		slack.mftModified = filetimeFromTicks(times[2]);
		slack.accessed = filetimeFromTicks(times[3]);
		slack.size = readLittleEndian<uint64_t>(key + 0x30);
		slack.attributes = readLittleEndian<uint32_t>(key + 0x38);
		found.push_back(std::move(slack));
	}
	return found;
}

namespace {

/*! A deleted file the $MFT copy lists, before its record is read again. */
struct Candidate {
	std::wstring volume;        //!< "C:"
	uint64_t entry = 0;
	uint16_t sequence = 0;
	std::wstring path;
	bool pathComplete = true;
	std::wstring name;
	uint64_t size = 0;
	FILETIME created = { 0 }, modified = { 0 }, mftModified = { 0 }, accessed = { 0 };
	uint64_t latest = 0;        //!< the latest date the record carries: the order of the recovery
};

//! A FILETIME as a number, to compare.
uint64_t ticks(const FILETIME& f) { return ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime; }

//! Whether a path lies in a folder (case ignored), or is it.
bool under(const std::wstring& path, const std::wstring& folder) {
	if (folder.empty() || path.size() < folder.size()) return false;
	if (toLower(path.substr(0, folder.size())) != toLower(folder)) return false;
	return path.size() == folder.size() || path[folder.size()] == L'\\';
}

/*! The folders of a volume never read: those of `excluded_folders`, and the
 *  collection's own output when it lies on that volume.
 *  @param volume "C:"…
 *  @return absolute paths */
std::vector<std::wstring> excludedFolders(const std::wstring& volume) {
	std::vector<std::wstring> excluded;
	for (const std::wstring& folder : conf.deletedFilesSettings.excludedFolders) excluded.push_back(volume + folder);
	std::error_code ec;
	excluded.push_back(std::filesystem::absolute(conf._outputDir, ec).wstring());
	return excluded;
}

/*! The latest date a record carries — its file's last change, the deletion's
 *  being in no record: the order of the recovery, and of the claims. */
uint64_t latestDate(const MftEntry& e) {
	return std::max({ ticks(e.created), ticks(e.modified), ticks(e.mftModified), ticks(e.fileNameMftModified) });
}

/*! The runs every deleted record of a $MFT copy claims, dated (ClusterClaims):
 *  those of the folders left out too — what they overwrote is as lost.
 *  @param mft the copy, loaded
 *  @param volume "C:"…
 *  @param claims receives the runs, finished */
void claimDeletedRuns(const Mft& mft, const std::wstring& volume, ClusterClaims& claims) {
	RawVolumeLayout layout;
	if (FAILED(RawVolumeLayoutOf(volume.substr(0, 1), layout))) return;
	mft.forEachRawRecord([&](const uint8_t* bytes, size_t size, uint64_t number) {
		const DeletedRecord record = parseDeletedRecord(bytes, size);
		if (!record.fileRecord || record.inUse || !record.baseRecord || record.data.resident
		    || !checkRuns(record.data, layout.clusterSize, layout.clusters).empty()) return;
		MftEntry entry;
		if (!entry.parse(bytes, size, number)) return;
		const uint64_t date = latestDate(entry);
		for (const NtfsRun& run : record.data.runs)
			if (run.lcn >= 0) claims.add((uint64_t)run.lcn, run.count, date);
	});
	claims.finish();
}

/*! The deleted files the $MFT copies list, minus the folders left out, and
 *  the clusters their records claim.
 *  @param candidates receives them
 *  @param claims receives, by volume, the runs of every deleted record
 *  @return S_FALSE if a volume's $MFT could not be read */
HRESULT listCandidates(std::vector<Candidate>& candidates, std::map<std::wstring, ClusterClaims>& claims) {
	HRESULT global = S_OK;
	for (const std::wstring& volume : fixedNtfsVolumes()) {
		Mft mft;
		const HRESULT loaded = mft.load(volume, extractedPath(volume + L"\\$MFT"));
		if (loaded != ERROR_SUCCESS) {
			log(2, L"🔥Deleted files: no $MFT of " + volume, loaded);
			global = S_FALSE;
			continue;
		}
		const std::vector<std::wstring> excluded = excludedFolders(volume);
		const HRESULT walked = mft.forEachFile([&](const MftEntry& e, const std::wstring& path, bool complete) {
			if (e.inUse || e.directory || !e.sizeKnown || e.size == 0) return;
			// An incomplete path ("?\…") cannot be placed in a folder: kept.
			if (complete && std::any_of(excluded.begin(), excluded.end(), [&](const std::wstring& f) { return under(path, f); })) return;
			Candidate c;
			c.volume = volume;
			c.entry = e.entry;
			c.sequence = e.sequence;
			c.path = path;
			c.pathComplete = complete;
			c.name = e.name;
			c.size = e.size;
			c.created = e.created;
			c.modified = e.modified;
			c.mftModified = e.mftModified;
			c.accessed = e.accessed;
			c.latest = latestDate(e);
			candidates.push_back(std::move(c));
		});
		if (walked != ERROR_SUCCESS) global = S_FALSE;
		claimDeletedRuns(mft, volume, claims[volume]);
		mft.clear();
	}
	return global;
}

/*! The volume as recoverContent reads it: raw, as it is now, the clusters
 *  claimed since by a deleted file later than `date` left out.
 *  @param claims the volume's claims, or nullptr */
ClusterSource rawClusters(const std::wstring& letter, const RawVolumeLayout& layout, const ClusterClaims* claims, uint64_t date) {
	ClusterSource source;
	source.clusterSize = layout.clusterSize;
	source.clusters = layout.clusters;
	source.allocation = [letter](uint64_t lcn, uint64_t count, std::vector<bool>& inUse) {
		return SUCCEEDED(ReadClusterAllocationRaw(letter, lcn, count, inUse));
	};
	source.read = [letter](uint64_t lcn, uint64_t count, uint8_t* out) {
		return SUCCEEDED(ReadClustersRaw(letter, lcn, count, out));
	};
	if (claims)
		source.claimedSince = [claims, date](uint64_t lcn, uint64_t count, std::vector<bool>& claimed) {
			claims->laterThan(lcn, count, date, claimed);
		};
	return source;
}

//! The file's description, before its recovery.
Json describe(const Candidate& c) {
	Json o = Json::obj();
	o.add(L"Volume", Json::str(c.volume));
	o.add(L"Source", Json::str(L"MftRecord"));
	o.add(L"Entry", Json::num(c.entry));
	o.add(L"Sequence", Json::num(c.sequence));
	o.add(L"Path", Json::str(c.path));
	if (!c.pathComplete) o.add(L"PathIncomplete", Json::boolean(true));
	o.add(L"Size", Json::num(c.size));
	addUtcDate(o, L"CreatedUtc", c.created);
	addUtcDate(o, L"ModifiedUtc", c.modified);
	addUtcDate(o, L"MftModifiedUtc", c.mftModified);
	addUtcDate(o, L"AccessedUtc", c.accessed);
	return o;
}

//! The outcome of a recovery into the file's object.
void describeRecovery(Json& o, const Recovery& r) {
	o.add(L"State", Json::str(recoveryStateName(r.state)));
	if (!r.reason.empty()) o.add(L"Reason", Json::str(decodeText(r.reason, CP_UTF8)));
	if (r.state == RecoveryState::NotRecoverable) return;
	o.add(L"RecoveredBytes", Json::num(r.recoveredBytes));
	if (r.missing.empty()) return;
	Json holes = Json::arr();
	for (const MissingRange& m : r.missing) {
		Json hole = Json::obj();
		hole.add(L"Offset", Json::num(m.offset));
		hole.add(L"Length", Json::num(m.length));
		holes.push(std::move(hole));
	}
	o.add(L"MissingRanges", std::move(holes));
}

//! The three digests of a content, under the keys that say it is the recovered one, holes included.
void addRecoveredDigests(Json& o, const std::wstring& md5, const std::wstring& sha1, const std::wstring& sha256) {
	o.add(L"RecoveredMD5", Json::str(md5));
	o.add(L"RecoveredSHA1", Json::str(sha1));
	o.add(L"RecoveredSHA256", Json::str(sha256));
}

/*! The counts of a collection, for the investigation log. */
struct Tally {
	size_t listed = 0, copied = 0, partial = 0, lost = 0, notRead = 0;
	uint64_t copiedBytes = 0;
	/*! By volume, the clusters level 1 gave as a file's content (Recovered
	 *  or Partial): carving leaves them, not the clusters of every deleted
	 *  record — the stale records of files gone long ago, on the same
	 *  clusters, hid the content written since (Windows 11, measured). */
	std::map<std::wstring, ClusterClaims> recovered;
};

/*! Recovers one deleted file: its record read again, its content read, then
 *  stored, or fingerprinted only.
 *  @param c the file
 *  @param claims the clusters its volume's deleted records claim, or nullptr
 *  @param tally the counts, the bytes copied among them
 *  @return its object for the snapshot */
Json recoverOne(const Candidate& c, const ClusterClaims* claims, Tally& tally) {
	Json o = describe(c);
	const std::wstring letter = c.volume.substr(0, 1);
	std::vector<uint8_t> bytes;
	DeletedRecord record;
	if (SUCCEEDED(ReadMftRecordRaw(letter, c.entry, bytes))) record = parseDeletedRecord(bytes.data(), bytes.size());
	/* Read again on the volume: freed records are the first NTFS gives out,
	   and the copy of the $MFT is minutes old. */
	if (!record.fileRecord || record.inUse || !record.baseRecord || record.directory || record.sequence != c.sequence) {
		o.add(L"State", Json::str(L"RecordReused"));
		++tally.lost;
		return o;
	}
	RawVolumeLayout layout;
	if (FAILED(RawVolumeLayoutOf(letter, layout))) {
		o.add(L"State", Json::str(recoveryStateName(RecoveryState::NotRecoverable)));
		o.add(L"Reason", Json::str(L"volume unreadable"));
		++tally.lost;
		return o;
	}
	const ClusterSource source = rawClusters(letter, layout, claims, c.latest);
	const uint64_t maxFile = (uint64_t)conf.deletedFilesSettings.maxFileMib << 20;
	Md5Stream md5;
	Sha1Stream sha1;
	Sha256Stream sha256;
	std::vector<uint8_t> content;
	const bool copy = record.data.size <= maxFile;
	if (copy) content.reserve((size_t)record.data.size);
	const Recovery recovery = recoverContent(record.data, source, [&](const uint8_t* data, size_t length) {
		if (copy) content.insert(content.end(), data, data + length);
		else { md5.update(data, length); sha1.update(data, length); sha256.update(data, length); }
	});
	describeRecovery(o, recovery);
	if (recovery.state != RecoveryState::Recovered && recovery.state != RecoveryState::Partial) {
		++tally.lost;
		return o;
	}
	for (const NtfsRun& run : record.data.runs)
		if (run.lcn >= 0) tally.recovered[c.volume].add((uint64_t)run.lcn, run.count, 1);
	if (recovery.state == RecoveryState::Partial) ++tally.partial;
	if (!copy) {
		addRecoveredDigests(o, md5.hexDigest(), sha1.hexDigest(), sha256.hexDigest());
		o.add(L"Copied", Json::boolean(false));
		o.add(L"NotCopied", Json::str(L"larger than max_file_mib"));
		return o;
	}
	const std::wstring exhibitPath = c.volume + L"\\$DeletedFiles\\" + std::to_wstring(c.entry) + L"-"
	                               + std::to_wstring(c.sequence) + L"_" + safeFileName(c.name);
	const std::wstring method = L"Raw NTFS reading (\\\\.\\" + c.volume + L" — deleted $MFT record "
	                          + std::to_wstring(c.entry) + L", sequence " + std::to_wstring(c.sequence)
	                          + L", clusters checked free in $Bitmap before and after reading); deleted file "
	                          + recoveryStateName(recovery.state) + L", formerly " + c.path;
	RawHiveExtraction line;
	const RecoveredStorage stored = BinariesStoreRecovered(exhibitPath, c.path, content, method, line);
	addRecoveredDigests(o, line.fingerprints.md5, line.fingerprints.sha1, line.fingerprints.sha256);
	o.add(L"Copied", Json::boolean(stored.copied));
	if (stored.copied) {
		o.add(L"Exhibit", Json::str(exhibitPath));
		++tally.copied;
		tally.copiedBytes += content.size();
	}
	if (!stored.signature.empty()) o.add(L"Signature", Json::str(stored.signature));
	if (!stored.notCopied.empty()) o.add(L"NotCopied", Json::str(stored.notCopied));
	return o;
}

/*! Level 3: the files carved from the free clusters of a volume that no
 *  deleted record claims. Copied within what max_total_mib leaves.
 *  @param volume "C:"…
 *  @param source its clusters, the claims of its deleted files among them
 *  @param firstCluster the number of the source's cluster 0 on the volume
 *         (0 for NTFS; 2 for FAT, whose data region starts at cluster 2)
 *  @param reading how the clusters are read, for the manifest
 *  @param files receives one object per file
 *  @param tally the counts, the bytes copied among them
 *  @return the files found */
size_t carveSource(const std::wstring& volume, const ClusterSource& source, uint64_t firstCluster,
                   const std::wstring& reading, Json& files, Tally& tally) {
	const uint64_t maxFile = (uint64_t)conf.deletedFilesSettings.maxFileMib << 20;
	const uint64_t maxTotal = (uint64_t)conf.deletedFilesSettings.maxTotalMib << 20;
	size_t count = 0;
	const uint64_t looked = carveClusters(source, maxFile, [&](const CarvedFile& f) {
		if ((++count & 63) == 1) printProgressStep(L"$Carved " + volume, (unsigned)count, 0);
		Json o = Json::obj();
		o.add(L"Volume", Json::str(volume));
		o.add(L"Source", Json::str(L"Carved"));
		o.add(L"Format", Json::str(carvedFormatName(f.format)));
		o.add(L"Lcn", Json::num(f.lcn + firstCluster));
		if (f.size) o.add(L"Size", Json::num(f.size));
		if (f.content.empty()) {
			o.add(L"State", Json::str(L"NotRead"));
			o.add(L"Reason", Json::str(L"larger than max_file_mib"));
			files.push(std::move(o));
			return;
		}
		o.add(L"State", Json::str(L"Carved"));
		const std::wstring exhibitPath = volume + L"\\$CarvedFiles\\" + std::to_wstring(f.lcn + firstCluster) + carvedFormatExtension(f.format);
		if (f.content.size() > maxTotal - std::min(maxTotal, tally.copiedBytes)) {
			// Beyond the total: its fingerprints, from the bytes already read.
			Md5Stream md5;
			Sha1Stream sha1;
			Sha256Stream sha256;
			md5.update(f.content.data(), f.content.size());
			sha1.update(f.content.data(), f.content.size());
			sha256.update(f.content.data(), f.content.size());
			addRecoveredDigests(o, md5.hexDigest(), sha1.hexDigest(), sha256.hexDigest());
			o.add(L"Copied", Json::boolean(false));
			o.add(L"NotCopied", Json::str(L"max_total_mib reached"));
			files.push(std::move(o));
			return;
		}
		const std::wstring method = reading + L"; " + carvedFormatName(f.format) + L" carved from cluster "
		                          + std::to_wstring(f.lcn + firstCluster) + L", cut at the end its structure gives";
		RawHiveExtraction line;
		const RecoveredStorage stored = BinariesStoreRecovered(exhibitPath, std::wstring(L"carved") + carvedFormatExtension(f.format),
		                                                       f.content, method, line);
		addRecoveredDigests(o, line.fingerprints.md5, line.fingerprints.sha1, line.fingerprints.sha256);
		o.add(L"Copied", Json::boolean(stored.copied));
		if (stored.copied) {
			o.add(L"Exhibit", Json::str(exhibitPath));
			tally.copiedBytes += f.content.size();
		}
		if (!stored.signature.empty()) o.add(L"Signature", Json::str(stored.signature));
		if (!stored.notCopied.empty()) o.add(L"NotCopied", Json::str(stored.notCopied));
		files.push(std::move(o));
	});
	printProgressEnd();
	log(1, L"ℹ️Deleted files, level 3: " + std::to_wstring(count) + L" file(s) carved from " + std::to_wstring(looked)
	       + L" free cluster(s) of " + volume);
	return count;
}

//! Level 3 on an NTFS volume: its free clusters but those level 1 gave as a file's content.
size_t carveVolume(const std::wstring& volume, Json& files, Tally& tally) {
	const std::wstring letter = volume.substr(0, 1);
	RawVolumeLayout layout;
	if (FAILED(RawVolumeLayoutOf(letter, layout))) return 0;
	ClusterClaims& recovered = tally.recovered[volume];
	recovered.finish();
	const ClusterSource source = rawClusters(letter, layout, &recovered, 0);
	return carveSource(volume, source, 0, L"Raw NTFS reading (\\\\.\\" + volume
	                   + L" — free clusters level 1 did not give as a file's content, checked free in $Bitmap before and after reading)",
	                   files, tally);
}

/*! The clusters of a FAT or exFAT volume as recoverContent and carveClusters
 *  read them: cluster n of the data region is the source's n - 2.
 *  @param claims the claims of the volume's deleted entries, or nullptr
 *  @param date claims later than it only; 0 for any */
ClusterSource fatClusters(FatVolume& volume, const ClusterClaims* claims, uint64_t date) {
	ClusterSource source;
	source.clusterSize = volume.clusterSize();
	source.clusters = volume.clusterCount();
	source.allocation = [&volume](uint64_t lcn, uint64_t count, std::vector<bool>& used) {
		return lcn + count <= UINT32_MAX && volume.allocation((uint32_t)lcn + 2, (uint32_t)count, used);
	};
	source.read = [&volume](uint64_t lcn, uint64_t count, uint8_t* out) {
		return lcn + count <= UINT32_MAX && volume.readClusters((uint32_t)lcn + 2, (uint32_t)count, out);
	};
	if (claims)
		source.claimedSince = [claims, date](uint64_t lcn, uint64_t count, std::vector<bool>& claimed) {
			claims->laterThan(lcn, count, date, claimed);
		};
	return source;
}

//! A FAT date as stored — local time of the machine that wrote it, unless exFAT gave its offset.
void addStoredDate(Json& o, const std::wstring& key, const FILETIME& date, bool utc) {
	if (!date.dwLowDateTime && !date.dwHighDateTime) return;
	if (utc) addUtcDate(o, key + L"Utc", date);
	else o.add(key + L"AsStored", Json::str(timeToIso8601Utc(date, Precision::Second).substr(0, 19)));
}

/*! The deleted files of the FAT and exFAT volumes — a suspect's keys among
 *  them. Level 1: a deleted entry keeps its first cluster and its size, its
 *  chain is erased: the content is read as the clusters that follow, each
 *  checked free, and not claimed since by a later deleted entry. Level 3:
 *  their free clusters carved.
 *  @param files receives one object per file
 *  @param tally the counts, the bytes copied among them
 *  @return the files read */
size_t collectFatDeleted(Json& files, Tally& tally) {
	const uint64_t maxFile = (uint64_t)conf.deletedFilesSettings.maxFileMib << 20;
	const uint64_t maxTotal = (uint64_t)conf.deletedFilesSettings.maxTotalMib << 20;
	size_t read = 0;
	for (const std::wstring& mountPoint : fatVolumesToRead()) {
		FileVolumeSource device(L"\\\\.\\" + mountPoint, 0, false);   // nothing kept: contents, not metadata
		FatVolume volume;
		if (!device.isOpen() || !volume.open(device)) {
			log(2, L"🔥Deleted files: FAT volume " + mountPoint + L" unreadable");
			continue;
		}
		const uint64_t cluster = volume.clusterSize();
		std::vector<FatEntry> deleted;
		ClusterClaims claims;
		for (const FatEntry& e : volume.entries()) {
			if (!e.deleted || e.directory || e.size == 0 || e.firstCluster < 2) continue;
			deleted.push_back(e);
			claims.add(e.firstCluster - 2, (e.size + cluster - 1) / cluster, ticks(e.modified));
		}
		claims.finish();
		std::stable_sort(deleted.begin(), deleted.end(), [](const FatEntry& a, const FatEntry& b) { return ticks(a.modified) > ticks(b.modified); });
		const std::wstring reading = L"Raw " + volume.type() + L" reading (\\\\.\\" + mountPoint + L")";
		for (const FatEntry& e : deleted) {
			Json o = Json::obj();
			o.add(L"Volume", Json::str(mountPoint));
			o.add(L"Source", Json::str(L"FatEntry"));
			o.add(L"Path", Json::str(mountPoint + e.path));
			if (e.nameIncomplete) o.add(L"NameIncomplete", Json::boolean(true));
			o.add(L"FirstCluster", Json::num(e.firstCluster));
			o.add(L"Size", Json::num(e.size));
			addStoredDate(o, L"Created", e.created, e.createdUtc);
			addStoredDate(o, L"Modified", e.modified, e.modifiedUtc);
			if (e.size <= maxFile && e.size > maxTotal - std::min(maxTotal, tally.copiedBytes)) {
				o.add(L"State", Json::str(L"NotRead"));
				o.add(L"Reason", Json::str(L"max_total_mib reached"));
				files.push(std::move(o));
				continue;
			}
			// The chain erased: the clusters that follow the first, contiguous —
			// exFAT says so (NoFatChain) of a file it never fragmented.
			const uint64_t clusters = (e.size + cluster - 1) / cluster;
			DeletedData data;
			data.found = true;
			data.runs = { { (int64_t)e.firstCluster - 2, clusters } };
			data.runsDecoded = true;
			data.lastVcn = clusters - 1;
			data.allocatedSize = clusters * cluster;
			data.size = data.initializedSize = e.size;
			const ClusterSource source = fatClusters(volume, &claims, ticks(e.modified));
			std::vector<uint8_t> content;
			Md5Stream md5;
			Sha1Stream sha1;
			Sha256Stream sha256;
			const bool copy = e.size <= maxFile;
			const Recovery recovery = recoverContent(data, source, [&](const uint8_t* d, size_t n) {
				if (copy) content.insert(content.end(), d, d + n);
				else { md5.update(d, n); sha1.update(d, n); sha256.update(d, n); }
			});
			/* Contiguity assumed — FAT, and exFAT without NoFatChain: a file
			   fragmented once read on, the clusters that follow are another's,
			   and nothing tells. Not "Recovered" then, but what it is. */
			Json state = Json::obj();
			describeRecovery(state, recovery);
			for (const auto& field : state.members()) {
				if (field.first == L"State" && recovery.state == RecoveryState::Recovered && !e.contiguous)
					o.add(L"State", Json::str(L"RecoveredIfContiguous"));
				else o.add(field.first, field.second);
			}
			if (!e.contiguous && recovery.state != RecoveryState::NotRecoverable) o.add(L"ContiguityAssumed", Json::boolean(true));
			++read;
			if (recovery.state != RecoveryState::Recovered && recovery.state != RecoveryState::Partial) {
				++tally.lost;
				files.push(std::move(o));
				continue;
			}
			if (recovery.state == RecoveryState::Partial) ++tally.partial;
			tally.recovered[mountPoint].add(e.firstCluster - 2, clusters, 1);
			if (!copy) {
				addRecoveredDigests(o, md5.hexDigest(), sha1.hexDigest(), sha256.hexDigest());
				o.add(L"Copied", Json::boolean(false));
				o.add(L"NotCopied", Json::str(L"larger than max_file_mib"));
				files.push(std::move(o));
				continue;
			}
			const std::wstring name = e.path.substr(e.path.find_last_of(L'\\') + 1);
			const std::wstring exhibitPath = mountPoint + L"\\$DeletedFiles\\" + std::to_wstring(e.firstCluster) + L"_" + safeFileName(name);
			RawHiveExtraction line;
			const RecoveredStorage stored = BinariesStoreRecovered(exhibitPath, mountPoint + e.path, content,
			        reading + L"; deleted entry, first cluster " + std::to_wstring(e.firstCluster)
			        + L", the clusters that follow checked free; deleted file " + recoveryStateName(recovery.state)
			        + L", formerly " + mountPoint + e.path, line);
			addRecoveredDigests(o, line.fingerprints.md5, line.fingerprints.sha1, line.fingerprints.sha256);
			o.add(L"Copied", Json::boolean(stored.copied));
			if (stored.copied) {
				o.add(L"Exhibit", Json::str(exhibitPath));
				++tally.copied;
				tally.copiedBytes += content.size();
			}
			if (!stored.signature.empty()) o.add(L"Signature", Json::str(stored.signature));
			if (!stored.notCopied.empty()) o.add(L"NotCopied", Json::str(stored.notCopied));
			files.push(std::move(o));
		}
		ClusterClaims& recovered = tally.recovered[mountPoint];
		recovered.finish();
		if (conf.deletedFilesSettings.level >= 3)
			carveSource(mountPoint, fatClusters(volume, &recovered, 0), 2,
			            reading + L" — free clusters level 1 did not give as a file's content, checked free in the "
			            + std::wstring(volume.type() == L"exFAT" ? L"allocation bitmap" : L"FAT") + L" before and after reading",
			            files, tally);
	}
	return read;
}

//! A key for a name in a directory, case ignored: the directory's record and the name's hash.
uint64_t nameKey(uint64_t directory, const std::wstring& name) {
	uint64_t h = std::hash<std::wstring>()(toLower(name)) ^ (directory * 0x9E3779B97F4A7C15ull);
	h ^= h >> 31;
	return h * 0xBF58476D1CE4E5B9ull;
}

/*! Level 2: the names the slack of every directory index of a volume keeps,
 *  that no directory holds any more and no deleted record of level 1 names.
 *  @param volume "C:"…
 *  @param files receives one object per name
 *  @return how many names were added; the directories unreadable are logged */
size_t collectIndexSlack(const std::wstring& volume, Json& files) {
	Mft mft;
	if (mft.load(volume, extractedPath(volume + L"\\$MFT")) != ERROR_SUCCESS) return 0;
	const std::vector<std::wstring> excluded = excludedFolders(volume);
	std::vector<std::pair<uint64_t, std::wstring>> directories;
	std::unordered_set<uint64_t> live;                 // every name a directory holds now
	std::unordered_map<uint64_t, std::wstring> deleted;   // the names of the deleted records: level 1's
	mft.forEachFile([&](const MftEntry& e, const std::wstring& path, bool complete) {
		if (!e.inUse) {
			if (!e.name.empty()) deleted.emplace(e.entry, toLower(e.name));
			return;
		}
		for (const MftEntry::Link& link : e.links) live.insert(nameKey(link.parentEntry, link.name));
		if (e.directory && complete
		    && !std::any_of(excluded.begin(), excluded.end(), [&](const std::wstring& f) { return under(path, f); }))
			directories.emplace_back(e.entry, path);
	});
	const std::wstring letter = volume.substr(0, 1);
	std::unordered_set<uint64_t> seen;                 // an entry repeated in the slack, once
	size_t added = 0, unreadable = 0;
	for (size_t k = 0; k < directories.size(); ++k) {
		const uint64_t directory = directories[k].first;
		const std::wstring& folder = directories[k].second;
		printProgressStep(L"$I30 " + volume, (unsigned)k + 1, (unsigned)directories.size());
		const HRESULT read = ForEachIndexBlockRaw(letter, directory, [&](const uint8_t* block, size_t size, bool inUse) {
			for (const IndexSlackEntry& e : indexSlackEntries(block, size, inUse, directory)) {
				if (live.count(nameKey(directory, e.name))) continue;
				const auto former = deleted.find(e.entry);
				if (former != deleted.end() && former->second == toLower(e.name)) continue;   // level 1 has it
				if (!seen.insert(nameKey(directory, e.name) ^ (e.entry << 1)).second) continue;
				Json o = Json::obj();
				o.add(L"Volume", Json::str(volume));
				o.add(L"Source", Json::str(L"IndexSlack"));
				o.add(L"Entry", Json::num(e.entry));
				o.add(L"Sequence", Json::num(e.sequence));
				o.add(L"Path", Json::str((folder.size() > 3 ? folder : folder.substr(0, 2)) + L"\\" + e.name));
				o.add(L"ParentEntry", Json::num(directory));
				o.add(L"Size", Json::num(e.size));
				addUtcDate(o, L"FileNameCreatedUtc", e.created);
				addUtcDate(o, L"FileNameModifiedUtc", e.modified);
				addUtcDate(o, L"FileNameMftModifiedUtc", e.mftModified);
				addUtcDate(o, L"FileNameAccessedUtc", e.accessed);
				// The same file under another name now — moved or renamed, not deleted.
				bool complete = true;
				const std::wstring now = mft.pathOf(e.entry, e.sequence, complete);
				if (!now.empty() && complete) o.add(L"CurrentPath", Json::str(now));
				o.add(L"State", Json::str(L"NameOnly"));
				files.push(std::move(o));
				++added;
			}
		});
		if (FAILED(read)) ++unreadable;
	}
	printProgressEnd();
	if (unreadable) log(2, L"🔥Deleted files, level 2: " + std::to_wstring(unreadable) + L" index(es) of " + volume + L" unreadable");
	return added;
}

} // namespace

HRESULT DeletedFilesCollect() {
	std::vector<Candidate> candidates;
	std::map<std::wstring, ClusterClaims> claims;
	const HRESULT listed = listCandidates(candidates, claims);
	// The most recent first: the total's bound leaves out the oldest.
	std::stable_sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) { return a.latest > b.latest; });
	const uint64_t maxFile = (uint64_t)conf.deletedFilesSettings.maxFileMib << 20;
	const uint64_t maxTotal = (uint64_t)conf.deletedFilesSettings.maxTotalMib << 20;
	Json files = Json::arr();
	Tally tally;
	/* The FAT and exFAT volumes first: a suspect's keys, small, and what the
	   total's bound should not leave out behind the system volume's files. */
	const size_t fatRead = collectFatDeleted(files, tally);
	for (size_t k = 0; k < candidates.size(); ++k) {
		const Candidate& c = candidates[k];
		/* A file to copy that the bound no longer allows is not read, and
		   listed so: absent, it would read as a file never looked at. A
		   larger one than max_file_mib is read for its fingerprints only, and
		   costs nothing. */
		if (c.size <= maxFile && c.size > maxTotal - std::min(maxTotal, tally.copiedBytes)) {
			Json o = describe(c);
			o.add(L"State", Json::str(L"NotRead"));
			o.add(L"Reason", Json::str(L"max_total_mib reached"));
			files.push(std::move(o));
			++tally.notRead;
			continue;
		}
		printProgressStep(L"$DeletedFiles", (unsigned)k + 1, (unsigned)candidates.size());
		const auto volumeClaims = claims.find(c.volume);
		files.push(recoverOne(c, volumeClaims == claims.end() ? nullptr : &volumeClaims->second, tally));
		++tally.listed;
	}
	printProgressEnd();
	size_t names = 0, carved = 0;
	if (conf.deletedFilesSettings.level >= 2)
		for (const std::wstring& volume : fixedNtfsVolumes()) names += collectIndexSlack(volume, files);
	if (conf.deletedFilesSettings.level >= 3)
		for (const std::wstring& volume : fixedNtfsVolumes()) carved += carveVolume(volume, files, tally);
	const HRESULT written = writeLiveSnapshot("deleted_files.json", files, L"deleted files of the fixed NTFS volumes, recovered by raw reading");
	auditRecord(L"Raw recovery of the deleted files (" + std::to_wstring(tally.listed) + L" read, "
	            + std::to_wstring(tally.copied) + L" copied (" + std::to_wstring(tally.copiedBytes / 1024 / 1024) + L" MiB), "
	            + std::to_wstring(tally.partial) + L" partial, " + std::to_wstring(tally.lost) + L" lost or not recoverable, "
	            + std::to_wstring(tally.notRead) + L" not read beyond max_total_mib"
	            + (conf.deletedFilesSettings.level >= 2 ? L"; " + std::to_wstring(names) + L" former name(s) in the slack of the directory indexes" : L"")
	            + (conf.deletedFilesSettings.level >= 3 ? L"; " + std::to_wstring(carved) + L" file(s) carved from the free clusters of NTFS" : L"")
	            + L"; " + std::to_wstring(fatRead) + L" deleted file(s) of FAT and exFAT volumes read"
	            + L")",
	            L"$MFT copy of every fixed NTFS volume; each record read again raw, its clusters checked free in $Bitmap "
	            L"before and after reading; nothing written to the volume",
	            written, Footprint::VOLUME_BRUT);
	if (FAILED(written)) return written;
	return listed;
}

namespace {

/*! What the change journal says of a record's last life: when it was
 *  deleted, and the name it had before Windows moved it to $Extend\$Deleted. */
struct JournalTrace {
	FILETIME deletedUtc = { 0 };
	std::wstring formerPath;
};

/*! The traces of the change journal of a volume, by record and sequence
 *  number of the deleted life ((entry << 16) | sequence of the record when
 *  it held the file — one less than the deleted record's own).
 *  @param volume "C:"…
 *  @return the traces; empty without a journal or a $MFT */
std::map<uint64_t, JournalTrace> journalTraces(const std::wstring& volume) {
	std::map<uint64_t, JournalTrace> traces;
	Mft mft;
	UsnJournal usn;
	if (mft.getData(volume) != ERROR_SUCCESS || usn.getData(volume) != ERROR_SUCCESS) return traces;
	for (const UsnRecord& r : usn.records) {
		const uint64_t key = (r.fileEntry << 16) | r.fileSequence;
		if (r.reason & USN_REASON_FILE_DELETE) traces[key].deletedUtc = r.timestamp;
		/* POSIX deletion (Windows 10 and later): a file still open when
		   deleted is renamed into $Extend\$Deleted, and freed at its last
		   close. Its record then names it there; the name it had is the old
		   name of its LAST rename — the records are in the journal's order,
		   each later one replacing the earlier. */
		if (r.reason & USN_REASON_RENAME_OLD_NAME) {
			bool complete = true;
			const std::wstring folder = mft.pathOf(r.parentEntry, r.parentSequence, complete);
			traces[key].formerPath = (folder.empty() ? std::wstring(L"?") : folder) + L"\\" + r.name;
		}
	}
	return traces;
}

} // namespace

HRESULT DeletedFiles::getData() {
	log(3, L"🔈deleted files getData");
	Json snapshot = Json::null();
	const HRESULT hresult = readLiveSnapshot("deleted_files.json", snapshot);
	if (hresult != ERROR_SUCCESS) return hresult;
	if (snapshot.kind() != Json::Kind::Arr) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	/* The deletion's time is in no record: the change journal has it, and
	   the former name of a file moved to $Extend\$Deleted. Both added from
	   the journal of the collection, when it holds them. */
	std::map<std::wstring, std::map<uint64_t, JournalTrace>> byVolume;
	files_ = Json::arr();
	for (const auto& member : snapshot.members()) {
		Json file = Json::obj();
		for (const auto& field : member.second.members()) file.add(field.first, field.second);
		long long entry = 0, sequence = 0;
		const Json* volume = member.second.find(L"Volume");
		if (volume && snapshotInteger(member.second, L"Entry", entry) && snapshotInteger(member.second, L"Sequence", sequence)) {
			auto traces = byVolume.find(volume->text());
			if (traces == byVolume.end()) traces = byVolume.emplace(volume->text(), journalTraces(volume->text())).first;
			/* A deleted record's sequence number is one more than the file's
			   (NTFS raises it on freeing); an entry of the index slack carries
			   the file's own. */
			const Json* source = member.second.find(L"Source");
			const bool record = !source || source->text() != L"IndexSlack";
			const auto trace = traces->second.find(((uint64_t)entry << 16) | (uint16_t)(record ? sequence - 1 : sequence));
			if (trace != traces->second.end()) {
				addUtcDate(file, L"DeletedUtc", trace->second.deletedUtc);
				const Json* path = member.second.find(L"Path");
				if (!trace->second.formerPath.empty() && path && path->text().find(L"\\$Extend\\$Deleted\\") != std::wstring::npos)
					file.add(L"FormerPath", Json::str(trace->second.formerPath));
			}
		}
		files_.push(std::move(file));
	}
	return ERROR_SUCCESS;
}

HRESULT DeletedFiles::toJson() {
	return writeJsonFile("deleted_files.json", files_);
}

void DeletedFiles::clear() {
	files_ = Json::arr();
}
