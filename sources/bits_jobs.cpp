/*! \file
 *  \brief Background Intelligent Transfer Service jobs (see bits_jobs.h).
 */
#include "bits_jobs.h"
#include "consigne.h"
#include "ese_database.h"
#include "sha.h"
#include <algorithm>
#include <cstring>

namespace {

//! qmgr.db, relative to the system volume, in lower case as the manifest index is.
const wchar_t DATABASE[] = L"\\programdata\\microsoft\\network\\downloader\\qmgr.db";
const size_t BLOB_HEADER = 16;                 //!< a type GUID heads every blob
//! The delimiter around a job's list of files (BitsParser's XFER_HEADER).
const uint8_t XFER[16] = { 0x36, 0xDA, 0x56, 0x77, 0x6F, 0x51, 0x5A, 0x43, 0xAC, 0xAC, 0x44, 0xA2, 0x48, 0xFF, 0xF3, 0x4D };
const size_t ERROR_RECORD = 25;                //!< code (8), four 32-bit statuses, a byte
const uint32_t ID_COLUMN = 1, BLOB_COLUMN = 256;

uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
uint64_t rd64(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }

FILETIME filetime(uint64_t v) {
	FILETIME f;
	f.dwLowDateTime = (DWORD)v;
	f.dwHighDateTime = (DWORD)(v >> 32);
	return f;
}

//! A UTF-16 string preceded by its length in characters, terminator included.
bool pascalString(const std::vector<uint8_t>& b, size_t& o, std::wstring& out) {
	if (!fits(b.size(), o, 4)) return false;
	const size_t chars = rd32(b.data() + o);
	o += 4;
	if (chars > b.size() / 2 || !fits(b.size(), o, chars * 2)) return false;
	out = readWideZ(b.data(), o + chars * 2, o);
	o += chars * 2;
	return true;
}

//! A GUID at an offset, in braces.
std::wstring guidAt(const uint8_t* p) {
	GUID g;
	memcpy(&g, p, sizeof g);
	return guid_to_wstring(g);
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
	job.errorCount = rd32(b.data() + o);
	o += 4;
	if (job.errorCount > (b.size() - o) / ERROR_RECORD) return false;
	o += job.errorCount * ERROR_RECORD;
	// transient errors, retry delay, timeout (3 × 4), creation, modification (2 × 8)
	if (!fits(b.size(), o, 12 + 16)) return false;
	job.transientErrorCount = rd32(b.data() + o);
	job.retryDelay = rd32(b.data() + o + 4);
	job.noProgressTimeout = rd32(b.data() + o + 8);
	job.createdUtc = filetime(rd64(b.data() + o + 12));
	job.modifiedUtc = filetime(rd64(b.data() + o + 20));
	return true;
}

} // namespace

bool parseBitsJob(const std::vector<uint8_t>& b, BitsJob& job) {
	job.blob = b;
	// Header, type, priority, state, a 32-bit field, the job's GUID.
	size_t o = BLOB_HEADER;
	if (!fits(b.size(), o, 16 + 16)) return false;
	job.type = rd32(b.data() + o);
	job.priority = rd32(b.data() + o + 4);
	job.state = rd32(b.data() + o + 8);
	job.id = guidAt(b.data() + o + 16);
	o += 32;
	if (!pascalString(b, o, job.name) || !pascalString(b, o, job.description) || !pascalString(b, o, job.notifyProgram)
	    || !pascalString(b, o, job.notifyArguments) || !pascalString(b, o, job.ownerSid) || !fits(b.size(), o, 4))
		return false;
	job.notifyFlags = rd32(b.data() + o);
	o += 4;
	job.parsed = true;
	// The files: between two delimiters, a count then their GUIDs.
	const size_t first = findXfer(b, o);
	if (first == std::string::npos) return true;
	const size_t list = first + sizeof XFER;
	if (!fits(b.size(), list, 4)) return true;
	const size_t count = rd32(b.data() + list);
	if (count > (b.size() - list - 4) / 16) return true;
	for (size_t i = 0; i < count; ++i) job.fileIds.push_back(guidAt(b.data() + list + 4 + 16 * i));
	const size_t second = findXfer(b, list + 4 + 16 * count);
	if (second != std::string::npos) job.metadataParsed = parseMetadata(b, second + sizeof XFER, job);
	return true;
}

bool parseBitsFile(const std::vector<uint8_t>& b, BitsFile& file) {
	file.blob = b;
	size_t o = BLOB_HEADER;
	if (!pascalString(b, o, file.destination) || !pascalString(b, o, file.source) || !pascalString(b, o, file.temporary)
	    || !fits(b.size(), o, 8 + 8 + 1))
		return false;
	file.downloadedBytes = rd64(b.data() + o);
	file.totalBytes = rd64(b.data() + o + 8);
	o += 17;
	if (!pascalString(b, o, file.drive) || !pascalString(b, o, file.volume)) return false;
	file.parsed = true;
	return true;
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
	if (!list.empty()) o.add(L"Files", std::move(list));
	o.add(L"Blob", Json::str(toHexadecimal(blob.data(), blob.size())));
	return o;
}

HRESULT BitsJobs::getData() {
	log(0, L"ℹ️BITS jobs :");
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(conf.systemDrive.substr(0, 2)) + DATABASE);
	if (found == index.end() || found->second.workingFile.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
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
				if (c.columnId == ID_COLUMN && c.values.front().size() == 16) id = guidAt(c.values.front().data());
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

HRESULT BitsJobs::toJson() {
	Json list = Json::arr();
	for (const BitsJob& j : jobs_) list.push(j.toJson(files_));
	return writeJsonFile("bits_jobs.json", list);
}

void BitsJobs::clear() {
	jobs_.clear();
	files_.clear();
}
