/*! \file
 *  \brief Deleted files recovered by raw reading (see deleted_files.h).
 */
#include "deleted_files.h"
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
	std::vector<bool> before, after;
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
	if (recovery.recoveredBytes == 0 && !recovery.missing.empty()) recovery.state = RecoveryState::Overwritten;
	else if (recovery.recoveredBytes > 0 && !nonZero) recovery.state = RecoveryState::Zeroed;
	else if (!recovery.missing.empty()) recovery.state = RecoveryState::Partial;
	else recovery.state = RecoveryState::Recovered;
	return recovery;
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

/*! The deleted files the $MFT copies list, minus the folders left out.
 *  @param candidates receives them
 *  @return S_FALSE if a volume's $MFT could not be read */
HRESULT listCandidates(std::vector<Candidate>& candidates) {
	HRESULT global = S_OK;
	std::error_code ec;
	const std::wstring output = std::filesystem::absolute(conf._outputDir, ec).wstring();
	for (const std::wstring& volume : fixedNtfsVolumes()) {
		Mft mft;
		const HRESULT loaded = mft.load(volume, extractedPath(volume + L"\\$MFT"));
		if (loaded != ERROR_SUCCESS) {
			log(2, L"🔥Deleted files: no $MFT of " + volume, loaded);
			global = S_FALSE;
			continue;
		}
		std::vector<std::wstring> excluded;
		for (const std::wstring& folder : conf.deletedFilesSettings.excludedFolders) excluded.push_back(volume + folder);
		excluded.push_back(output);   // the collection's own files, on a fixed volume
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
			c.latest = std::max({ ticks(e.created), ticks(e.modified), ticks(e.mftModified), ticks(e.fileNameMftModified) });
			candidates.push_back(std::move(c));
		});
		if (walked != ERROR_SUCCESS) global = S_FALSE;
		mft.clear();
	}
	return global;
}

//! The volume as recoverContent reads it: raw, as it is now.
ClusterSource rawClusters(const std::wstring& letter, const RawVolumeLayout& layout) {
	ClusterSource source;
	source.clusterSize = layout.clusterSize;
	source.clusters = layout.clusters;
	source.allocation = [letter](uint64_t lcn, uint64_t count, std::vector<bool>& inUse) {
		return SUCCEEDED(ReadClusterAllocationRaw(letter, lcn, count, inUse));
	};
	source.read = [letter](uint64_t lcn, uint64_t count, uint8_t* out) {
		return SUCCEEDED(ReadClustersRaw(letter, lcn, count, out));
	};
	return source;
}

//! The file's description, before its recovery.
Json describe(const Candidate& c) {
	Json o = Json::obj();
	o.add(L"Volume", Json::str(c.volume));
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
};

/*! Recovers one deleted file: its record read again, its content read, then
 *  stored, or fingerprinted only.
 *  @param c the file
 *  @param tally the counts, the bytes copied among them
 *  @return its object for the snapshot */
Json recoverOne(const Candidate& c, Tally& tally) {
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
	const ClusterSource source = rawClusters(letter, layout);
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

} // namespace

HRESULT DeletedFilesCollect() {
	std::vector<Candidate> candidates;
	const HRESULT listed = listCandidates(candidates);
	// The most recent first: the total's bound leaves out the oldest.
	std::stable_sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) { return a.latest > b.latest; });
	const uint64_t maxFile = (uint64_t)conf.deletedFilesSettings.maxFileMib << 20;
	const uint64_t maxTotal = (uint64_t)conf.deletedFilesSettings.maxTotalMib << 20;
	Json files = Json::arr();
	Tally tally;
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
		files.push(recoverOne(c, tally));
		++tally.listed;
	}
	printProgressEnd();
	const HRESULT written = writeLiveSnapshot("deleted_files.json", files, L"deleted files of the fixed NTFS volumes, recovered by raw reading");
	auditRecord(L"Raw recovery of the deleted files (" + std::to_wstring(tally.listed) + L" read, "
	            + std::to_wstring(tally.copied) + L" copied (" + std::to_wstring(tally.copiedBytes / 1024 / 1024) + L" MiB), "
	            + std::to_wstring(tally.partial) + L" partial, " + std::to_wstring(tally.lost) + L" lost or not recoverable, "
	            + std::to_wstring(tally.notRead) + L" not read beyond max_total_mib)",
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
			const auto trace = traces->second.find(((uint64_t)entry << 16) | (uint16_t)(sequence - 1));
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
