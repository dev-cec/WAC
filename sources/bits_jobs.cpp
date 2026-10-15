/*! \file
 *  \brief Background Intelligent Transfer Service jobs (see bits_jobs.h).
 */
#include "conversions.h"
#include "bits_jobs.h"
#include "ese_recovery.h"
#include "consigne.h"
#include "ese_database.h"
#include <algorithm>
#include <filesystem>
#include <cstring>

namespace {

//! qmgr.db, relative to the system volume, in lower case as the manifest index is.
const wchar_t DATABASE[] = L"\\programdata\\microsoft\\network\\downloader\\qmgr.db";
//! The queue files before Windows 10, in the same folder.
const wchar_t* const QUEUE_FILES[] = { L"\\programdata\\microsoft\\network\\downloader\\qmgr0.dat",
                                       L"\\programdata\\microsoft\\network\\downloader\\qmgr1.dat" };
//! A queue file is read whole; BITS keeps it at 4 MiB.
const uintmax_t QUEUE_MAX = 64ULL * 1024 * 1024;
//! The delimiters that frame each job of a queue file, one per version of BITS (bits_parser, ANSSI).
const uint8_t JOB_DELIMITERS[][16] = {
	{ 0x93, 0x36, 0x20, 0x35, 0xA0, 0x0C, 0x10, 0x4A, 0x84, 0xF3, 0xB1, 0x7E, 0x7B, 0x49, 0x9C, 0xD7 },
	{ 0x10, 0x13, 0x70, 0xC8, 0x36, 0x53, 0xB3, 0x41, 0x83, 0xE5, 0x81, 0x55, 0x7F, 0x36, 0x1B, 0x87 },
	{ 0x8C, 0x93, 0xEA, 0x64, 0x03, 0x0F, 0x68, 0x40, 0xB4, 0x6F, 0xF9, 0x7F, 0xE5, 0x1D, 0x4D, 0xCD },
	{ 0xB3, 0x46, 0xED, 0x3D, 0x3B, 0x10, 0xF9, 0x44, 0xBC, 0x2F, 0xE8, 0x37, 0x8B, 0xD3, 0x19, 0x86 },
};
const size_t BLOB_HEADER = 16;                 //!< a type GUID heads every blob
//! The delimiter around a job's list of files (BitsParser's XFER_HEADER).
const uint8_t XFER[16] = { 0x36, 0xDA, 0x56, 0x77, 0x6F, 0x51, 0x5A, 0x43, 0xAC, 0xAC, 0x44, 0xA2, 0x48, 0xFF, 0xF3, 0x4D };
const size_t ERROR_RECORD = 25;                //!< code (8), four 32-bit statuses, a byte
const uint32_t ID_COLUMN = 1, BLOB_COLUMN = 256;

//! A UTF-16 string preceded by its length in characters, terminator included.
bool pascalString(const std::vector<uint8_t>& b, size_t& o, std::wstring& out) {
	if (!fits(b.size(), o, 4)) return false;
	const size_t chars = readLittleEndian<uint32_t>(b.data() + o);
	o += 4;
	if (chars > b.size() / 2 || !fits(b.size(), o, chars * 2)) return false;
	out = readWideZ(b.data(), o + chars * 2, o);
	o += chars * 2;
	return true;
}

//! The position of the next XFER delimiter from `from`, or npos.
size_t findXfer(const std::vector<uint8_t>& b, size_t from) {
	if (from > b.size()) return std::string::npos;
	const auto it = std::search(b.begin() + from, b.end(), std::begin(XFER), std::end(XFER));
	return it == b.end() ? std::string::npos : (size_t)(it - b.begin());
}

//! A value of an enumeration by its name, or its number when unknown.
Json named(uint32_t value, std::initializer_list<const wchar_t*> names) {
	if (value < names.size()) return Json::str(*(names.begin() + value));
	return Json::num(value);
}

//! The notification flags (BG_NOTIFY_*), by name.
std::wstring notifyFlagNames(uint32_t flags) {
	static const std::pair<uint32_t, const wchar_t*> FLAGS[] = {
		{ 0x01, L"JobTransferred" }, { 0x02, L"JobError" }, { 0x04, L"Disable" },
		{ 0x08, L"JobModification" }, { 0x10, L"FileTransferred" },
	};
	std::wstring out;
	for (const auto& [bit, name] : FLAGS)
		if (flags & bit) { out += (out.empty() ? L"" : L", "); out += name; flags &= ~bit; }
	if (flags) out += (out.empty() ? L"0x" : L", 0x") + to_hex(flags);
	return out;
}

/*! The metadata after the files' list: errors, retry delay, timeout, dates. */
bool parseMetadata(const std::vector<uint8_t>& b, size_t o, BitsJob& job) {
	if (!fits(b.size(), o, 4)) return false;
	job.errorCount = readLittleEndian<uint32_t>(b.data() + o);
	o += 4;
	if (job.errorCount > (b.size() - o) / ERROR_RECORD) return false;
	o += job.errorCount * ERROR_RECORD;
	// transient errors, retry delay, timeout (3 × 4), creation, modification (2 × 8)
	if (!fits(b.size(), o, 12 + 16)) return false;
	job.transientErrorCount = readLittleEndian<uint32_t>(b.data() + o);
	job.retryDelay = readLittleEndian<uint32_t>(b.data() + o + 4);
	job.noProgressTimeout = readLittleEndian<uint32_t>(b.data() + o + 8);
	job.createdUtc = filetimeFromTicks(readLittleEndian<uint64_t>(b.data() + o + 12));
	job.modifiedUtc = filetimeFromTicks(readLittleEndian<uint64_t>(b.data() + o + 20));
	return true;
}

} // namespace

namespace {

/*! The job's control part, from `o`: type, priority, state, a 32-bit field,
 *  the job's GUID, five strings, the notification flags.
 *  @return the offset after it, or npos if it does not fit */
size_t parseJobControl(const std::vector<uint8_t>& b, size_t o, BitsJob& job) {
	if (!fits(b.size(), o, 16 + 16)) return std::string::npos;
	job.type = readLittleEndian<uint32_t>(b.data() + o);
	job.priority = readLittleEndian<uint32_t>(b.data() + o + 4);
	job.state = readLittleEndian<uint32_t>(b.data() + o + 8);
	job.id = guid_to_wstring(b.data() + o + 16);
	o += 32;
	if (!pascalString(b, o, job.name) || !pascalString(b, o, job.description) || !pascalString(b, o, job.notifyProgram)
	    || !pascalString(b, o, job.notifyArguments) || !pascalString(b, o, job.ownerSid) || !fits(b.size(), o, 4))
		return std::string::npos;
	job.notifyFlags = readLittleEndian<uint32_t>(b.data() + o);
	job.parsed = true;
	return o + 4;
}

/*! A file's fields from `o`: destination, source, temporary file, sizes,
 *  drive, volume.
 *  @return the offset after them, or npos if a length does not fit */
size_t parseFileFields(const std::vector<uint8_t>& b, size_t o, BitsFile& file) {
	if (!pascalString(b, o, file.destination) || !pascalString(b, o, file.source) || !pascalString(b, o, file.temporary)
	    || !fits(b.size(), o, 8 + 8 + 1))
		return std::string::npos;
	file.downloadedBytes = readLittleEndian<uint64_t>(b.data() + o);
	file.totalBytes = readLittleEndian<uint64_t>(b.data() + o + 8);
	o += 17;
	if (!pascalString(b, o, file.drive) || !pascalString(b, o, file.volume)) return std::string::npos;
	file.parsed = true;
	return o;
}

/*! The start of the next file of a queue file's job, from `from` to `end`:
 *  a string whose first characters are a drive ("X:\"). Between two files
 *  BITS writes a trailer not described (73 bytes after the witness's file
 *  on Windows 8.1, starting with 3 and the volume's serial number): the next
 *  file is found as bits_parser (ANSSI) finds it, by the drive of its
 *  destination.
 *  @return its offset, or npos */
size_t nextFileStart(const std::vector<uint8_t>& b, size_t from, size_t end) {
	for (size_t o = from; o + 10 <= end; ++o)
		if (b[o + 5] == 0 && b[o + 6] == ':' && b[o + 7] == 0 && b[o + 8] == '\\' && b[o + 9] == 0 && iswalpha(b[o + 4])
		    && readLittleEndian<uint32_t>(b.data() + o) > 3 && readLittleEndian<uint32_t>(b.data() + o) < 32768)
			return o;
	return std::string::npos;
}

/*! One job of a queue file (Windows 8.1 and earlier): the control part from
 *  the first byte (no blob header), its files written in it after the first
 *  delimiter — their count, then each one —, the metadata after the second.
 *  Measured on the witness job of the Windows 8.1 VM against bits_parser. */
void parseQueueJob(const std::vector<uint8_t>& b, BitsJob& job) {
	job.blob = b;
	const size_t afterControl = parseJobControl(b, 0, job);
	if (afterControl == std::string::npos) return;
	const size_t first = findXfer(b, afterControl);
	if (first == std::string::npos || !fits(b.size(), first + sizeof XFER, 4)) return;
	const size_t second = findXfer(b, first + sizeof XFER + 4);
	const size_t filesEnd = second == std::string::npos ? b.size() : second;
	const size_t count = readLittleEndian<uint32_t>(b.data() + first + sizeof XFER);
	size_t o = first + sizeof XFER + 4;
	for (size_t i = 0; i < count && o != std::string::npos && o < filesEnd; ++i) {
		BitsFile file;
		const size_t end = parseFileFields(b, o, file);
		if (end == std::string::npos || end > filesEnd) break;
		file.blob.assign(b.begin() + o, b.begin() + end);
		job.inlineFiles.push_back(std::move(file));
		o = i + 1 < count ? nextFileStart(b, end, filesEnd) : end;
	}
	if (second != std::string::npos) job.metadataParsed = parseMetadata(b, second + sizeof XFER, job);
}

} // namespace

bool parseBitsQueue(const std::vector<uint8_t>& queue, const std::wstring& queueFile, std::vector<BitsJob>& jobs) {
	// The delimiter of this version of BITS: the one the queue holds.
	for (const auto& delimiter : JOB_DELIMITERS) {
		std::vector<size_t> at;
		for (auto it = queue.begin(); (it = std::search(it, queue.end(), std::begin(delimiter), std::end(delimiter))) != queue.end(); it += 16)
			at.push_back((size_t)(it - queue.begin()));
		if (at.empty()) continue;
		// Each job lies between two delimiters.
		for (size_t i = 0; i + 1 < at.size(); ++i) {
			const size_t start = at[i] + 16, end = at[i + 1];
			if (end <= start + 32) continue;
			BitsJob job;
			job.queueFile = queueFile;
			parseQueueJob(std::vector<uint8_t>(queue.begin() + start, queue.begin() + end), job);
			if (job.parsed) jobs.push_back(std::move(job));
		}
		return true;
	}
	return false;
}

bool parseBitsJob(const std::vector<uint8_t>& b, BitsJob& job) {
	job.blob = b;
	// After the blob's header, the control part.
	const size_t o = parseJobControl(b, BLOB_HEADER, job);
	if (o == std::string::npos) return false;
	// The files: between two delimiters, a count then their GUIDs.
	const size_t first = findXfer(b, o);
	if (first == std::string::npos) return true;
	const size_t list = first + sizeof XFER;
	if (!fits(b.size(), list, 4)) return true;
	const size_t count = readLittleEndian<uint32_t>(b.data() + list);
	if (count > (b.size() - list - 4) / 16) return true;
	for (size_t i = 0; i < count; ++i) job.fileIds.push_back(guid_to_wstring(b.data() + list + 4 + 16 * i));
	const size_t second = findXfer(b, list + 4 + 16 * count);
	if (second != std::string::npos) job.metadataParsed = parseMetadata(b, second + sizeof XFER, job);
	return true;
}

bool parseBitsFile(const std::vector<uint8_t>& b, BitsFile& file) {
	file.blob = b;
	return parseFileFields(b, BLOB_HEADER, file) != std::string::npos;
}

Json BitsFile::toJson() const {
	Json o = Json::obj();
	o.add(L"FileId", Json::str(id));
	if (parsed) {
		o.add(L"Source", Json::str(source));
		o.add(L"Destination", Json::str(destination));
		o.add(L"Temporary", Json::str(temporary));
		o.add(L"DownloadedBytes", Json::num(downloadedBytes));
		if (totalBytes != UINT64_MAX) o.add(L"TotalBytes", Json::num(totalBytes));
		o.add(L"Drive", Json::str(drive));
		o.add(L"Volume", Json::str(volume));
	}
	o.add(L"Blob", Json::str(toHexadecimal(blob.data(), blob.size())));
	return o;
}

Json BitsJob::toJson(const std::vector<BitsFile>& files) const {
	Json o = Json::obj();
	o.add(L"JobId", Json::str(id));
	o.add(L"QueueFile", Json::str(queueFile));
	if (parsed) {
		o.add(L"Name", Json::str(name));
		o.add(L"Description", Json::str(description));
		o.add(L"Type", named(type, { L"Download", L"Upload", L"UploadReply" }));
		o.add(L"Priority", named(priority, { L"Foreground", L"High", L"Normal", L"Low" }));
		o.add(L"State", named(state, { L"Queued", L"Connecting", L"Transferring", L"Suspended", L"Error",
		                               L"TransientError", L"Transferred", L"Acknowledged", L"Cancelled" }));
		o.add(L"NotifyProgram", Json::str(notifyProgram));
		o.add(L"NotifyArguments", Json::str(notifyArguments));
		o.add(L"NotifyFlags", Json::str(notifyFlagNames(notifyFlags)));
		o.add(L"OwnerSID", Json::str(ownerSid));
		if (!ownerSid.empty()) o.add(L"OwnerName", Json::str(getNameFromSid(ownerSid)));
	}
	if (metadataParsed) {
		o.add(L"ErrorCount", Json::num(errorCount));
		o.add(L"TransientErrorCount", Json::num(transientErrorCount));
		o.add(L"RetryDelaySeconds", Json::num(retryDelay));
		o.add(L"NoProgressTimeoutSeconds", Json::num(noProgressTimeout));
		addDate(o, L"Created", createdUtc);
		addDate(o, L"Modified", modifiedUtc);
	}
	Json list = Json::arr();
	for (const std::wstring& fileId : fileIds) {
		const auto file = std::find_if(files.begin(), files.end(), [&](const BitsFile& f) { return f.id == fileId; });
		if (file != files.end()) list.push(file->toJson());
		else {
			Json missing = Json::obj();
			missing.add(L"FileId", Json::str(fileId));
			missing.add(L"NotInFilesTable", Json::boolean(true));
			list.push(std::move(missing));
		}
	}
	for (const BitsFile& f : inlineFiles) list.push(f.toJson());
	if (!list.empty()) o.add(L"Files", std::move(list));
	o.add(L"Blob", Json::str(toHexadecimal(blob.data(), blob.size())));
	return o;
}

HRESULT BitsJobs::getData() {
	log(0, L"ℹ️BITS jobs :");
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(conf.systemDrive.substr(0, 2)) + DATABASE);
	if (found == index.end() || found->second.workingFile.empty()) return readQueueFiles();
	// Its latest changes are in its edb*.log, collected with it: replayed into the copy first (B-046).
	const EseReplay replayed = ReplayEseLogsOnce(found->second.workingFile, found->second.sourcePath);
	if (replayed.attempted && !replayed.applied) log(1, L"⚠️BITS database logs not replayed: " + replayed.detail);
	EseDatabase database;
	const HRESULT opened = database.open(found->second.workingFile);
	if (opened != ERROR_SUCCESS) return opened;
	// Each row: its GUID (column 1) and its blob (column 256).
	auto rows = [&](const wchar_t* name, auto&& visit) {
		const EseTable* table = database.table(name);
		if (!table) return;
		for (const EseRecord& r : database.records(*table)) {
			std::wstring id;
			const std::vector<uint8_t>* blob = nullptr;
			for (const EseCell& c : r) {
				if (c.values.empty() || c.compressionScheme >= 0 || c.longValueMissing) continue;
				if (c.columnId == ID_COLUMN && c.values.front().size() == 16) id = guid_to_wstring(c.values.front().data());
				else if (c.columnId == BLOB_COLUMN) blob = &c.values.front();
			}
			if (blob) visit(id, *blob);
		}
	};
	rows(L"Files", [&](const std::wstring& id, const std::vector<uint8_t>& blob) {
		BitsFile f;
		f.id = id;
		parseBitsFile(blob, f);
		files_.push_back(std::move(f));
	});
	rows(L"Jobs", [&](const std::wstring& id, const std::vector<uint8_t>& blob) {
		BitsJob j;
		if (!parseBitsJob(blob, j)) j.id = id;
		jobs_.push_back(std::move(j));
	});
	return ERROR_SUCCESS;
}

HRESULT BitsJobs::readQueueFiles() {
	const auto& index = ExhibitStoreIndex();
	bool any = false;
	for (const wchar_t* name : QUEUE_FILES) {
		const auto found = index.find(toLower(conf.systemDrive.substr(0, 2)) + name);
		if (found == index.end() || found->second.workingFile.empty()) continue;
		any = true;
		std::vector<uint8_t> bytes;
		if (!readWholeFile(std::filesystem::path(found->second.workingFile), QUEUE_MAX, bytes)) {
			log(2, L"🔥BITS queue unreadable: " + found->second.sourcePath);
			continue;
		}
		const size_t before = jobs_.size();
		if (!parseBitsQueue(bytes, found->second.sourcePath, jobs_))
			log(2, L"❇️BITS queue without a known job delimiter (empty, or another version): " + found->second.sourcePath);
		log(2, L"❇️" + found->second.sourcePath + L": " + std::to_wstring(jobs_.size() - before) + L" job(s)");
	}
	return any ? ERROR_SUCCESS : HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}

HRESULT BitsJobs::toJson() {
	Json list = Json::arr();
	for (const BitsJob& j : jobs_) list.push(j.toJson(files_));
	return writeJsonFile("bits_jobs.json", list);
}

void BitsJobs::clear() {
	jobs_.clear();
	files_.clear();
}
