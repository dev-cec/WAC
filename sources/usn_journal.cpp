/*! \file
 *  \brief The change journal of an NTFS volume, read from its exhibit (see usn_journal.h).
 */
#include "usn_journal.h"
#include "mft.h"
#include "conversions.h"
#include "consigne.h"
#include "idList.h"
#include <cstring>
#include <filesystem>
#include <fstream>

namespace {

// USN_RECORD_V2 and V3 (winioctl.h): same fields, the references on 8 or 16 bytes.
const size_t RECORD_LENGTH = 0x00;        //!< uint32 length of the record, name included
const size_t RECORD_MAJOR = 0x04;         //!< uint16 version: 2, 3 or 4
const size_t V2_MINIMUM = 0x3C, V3_MINIMUM = 0x4C;   //!< length of the fixed part
const size_t ALIGNMENT = 8;               //!< every record starts on an 8-byte boundary

/*! USN_REASON_*: a FIELD OF BITS — a record gathers every change made to the
 *  file since it was opened, until it is closed (CLOSE). Each bit is named;
 *  a bit Windows adds later is written in hexadecimal, not dropped. */
std::wstring reasonNames(uint32_t reason) {
	static const struct { uint32_t bit; const wchar_t* name; } NAMES[] = {
		{ 0x00000001, L"DATA_OVERWRITE" }, { 0x00000002, L"DATA_EXTEND" }, { 0x00000004, L"DATA_TRUNCATION" },
		{ 0x00000010, L"NAMED_DATA_OVERWRITE" }, { 0x00000020, L"NAMED_DATA_EXTEND" },
		{ 0x00000040, L"NAMED_DATA_TRUNCATION" }, { 0x00000100, L"FILE_CREATE" }, { 0x00000200, L"FILE_DELETE" },
		{ 0x00000400, L"EA_CHANGE" }, { 0x00000800, L"SECURITY_CHANGE" }, { 0x00001000, L"RENAME_OLD_NAME" },
		{ 0x00002000, L"RENAME_NEW_NAME" }, { 0x00004000, L"INDEXABLE_CHANGE" }, { 0x00008000, L"BASIC_INFO_CHANGE" },
		{ 0x00010000, L"HARD_LINK_CHANGE" }, { 0x00020000, L"COMPRESSION_CHANGE" }, { 0x00040000, L"ENCRYPTION_CHANGE" },
		{ 0x00080000, L"OBJECT_ID_CHANGE" }, { 0x00100000, L"REPARSE_POINT_CHANGE" }, { 0x00200000, L"STREAM_CHANGE" },
		{ 0x00400000, L"TRANSACTED_CHANGE" }, { 0x00800000, L"INTEGRITY_CHANGE" },
		{ 0x01000000, L"DESIRED_STORAGE_CLASS_CHANGE" }, { 0x80000000, L"CLOSE" },
	};
	std::wstring text;
	uint32_t left = reason;
	for (const auto& n : NAMES)
		if (reason & n.bit) {
			text += (text.empty() ? L"" : L", ") + std::wstring(n.name);
			left &= ~n.bit;
		}
	if (left) {
		wchar_t hex[16];
		swprintf(hex, 16, L"0x%08X", left);
		text += (text.empty() ? L"" : L", ") + std::wstring(hex);
	}
	return text;
}

/*! USN_SOURCE_*: a field of bits too. A change made by the system (data
 *  management, replication) rather than by a program the user runs. */
std::wstring sourceNames(uint32_t source) {
	std::wstring text;
	if (source & 0x1) text += L"DATA_MANAGEMENT";
	if (source & 0x2) text += (text.empty() ? L"" : L", ") + std::wstring(L"AUXILIARY_DATA");
	if (source & 0x4) text += (text.empty() ? L"" : L", ") + std::wstring(L"REPLICATION_MANAGEMENT");
	if (source & 0x8) text += (text.empty() ? L"" : L", ") + std::wstring(L"CLIENT_REPLICATION_MANAGEMENT");
	return text;
}

} // namespace

bool UsnRecord::parse(const uint8_t* record, size_t size, uint64_t usnBase) {
	if (size < V2_MINIMUM) return false;
	const uint32_t length = readLittleEndian<uint32_t>(record + RECORD_LENGTH);
	const uint16_t major = readLittleEndian<uint16_t>(record + RECORD_MAJOR);
	if (length > size || (major != 2 && major != 3) || length < (major == 2 ? V2_MINIMUM : V3_MINIMUM)) return false;
	// Version 3 carries 128-bit references (ReFS); on NTFS their low 64 bits are the NTFS reference.
	const size_t referenceSize = major == 2 ? 8 : 16;
	const uint8_t* p = record + 8;
	const uint64_t file = readLittleEndian<uint64_t>(p);
	const uint64_t parent = readLittleEndian<uint64_t>(p + referenceSize);
	p += 2 * referenceSize;
	const NtfsReference fileReference = splitNtfsReference(file);
	const NtfsReference parentReference = splitNtfsReference(parent);
	fileEntry = fileReference.entry;
	fileSequence = fileReference.sequence;
	parentEntry = parentReference.entry;
	parentSequence = parentReference.sequence;
	usn = readLittleEndian<uint64_t>(p);
	const uint64_t ticks = readLittleEndian<uint64_t>(p + 8);
	timestamp = { (DWORD)(ticks & 0xFFFFFFFFULL), (DWORD)(ticks >> 32) };
	reason = readLittleEndian<uint32_t>(p + 16);
	sourceInfo = readLittleEndian<uint32_t>(p + 20);
	securityId = readLittleEndian<uint32_t>(p + 24);
	attributes = readLittleEndian<uint32_t>(p + 28);
	const uint16_t nameLength = readLittleEndian<uint16_t>(p + 32);
	const uint16_t nameOffset = readLittleEndian<uint16_t>(p + 34);
	if ((size_t)nameOffset + nameLength > length || (nameLength & 1)) return false;
	name.assign(nameLength / 2, L'\0');
	for (size_t k = 0; k < name.size(); ++k) name[k] = (wchar_t)readLittleEndian<uint16_t>(record + nameOffset + 2 * k);
	/* The record's number is its offset in the stream: the value written in
	   it is checked against the place it was read from, which catches a
	   misplaced offset (LeadingSparseBytes) or a record read out of step. */
	return usn == usnBase;
}

Json UsnRecord::toJson(const Mft& mft) const {
	Json o = Json::obj();
	o.add(L"Volume", Json::str(mft.volume()));
	o.add(L"Usn", Json::num(usn));
	o.add(L"TimestampUtc", Json::str(timeToIso8601Utc(timestamp)));
	o.add(L"Name", Json::str(name));
	bool complete = true;
	const std::wstring folder = mft.pathOf(parentEntry, parentSequence, complete);
	o.add(L"Path", Json::str(folder.empty() ? std::wstring() : folder + (folder.back() == L'\\' ? L"" : L"\\") + name));
	if (folder.empty() || !complete) o.add(L"PathIncomplete", Json::boolean(true));
	o.add(L"Reasons", Json::str(reasonNames(reason)));
	o.add(L"Sources", Json::str(sourceNames(sourceInfo)));
	o.add(L"Attributes", Json::str(FileAttributes(attributes).to_wstring()));
	o.add(L"FileEntry", Json::num(fileEntry));
	o.add(L"FileSequence", Json::num(fileSequence));
	o.add(L"ParentEntry", Json::num(parentEntry));
	o.add(L"ParentSequence", Json::num(parentSequence));
	/* Current NTFS versions leave the field at 0 (the identifier stays in
	   $STANDARD_INFORMATION): 0 names no descriptor — $Secure numbers them from
	   0x100 — and is not emitted. */
	if (securityId) o.add(L"SecurityId", Json::num(securityId));
	return o;
}

HRESULT UsnJournal::getData(const std::wstring& volume) {
	log(3, L"🔈usn journal getData " + volume);
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(volume.substr(0, 2) + L"\\$Extend\\$UsnJrnl:$J"));
	if (found == index.end() || found->second.workingFile.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	/* Read in one block, at the file's size: the journal's allocated part
	   weighs tens to hundreds of megabytes on a busy machine, which a byte-wise
	   stream iterator reads slowly. */
	std::error_code ec;
	const uintmax_t size = std::filesystem::file_size(std::filesystem::path(found->second.workingFile), ec);
	if (ec) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	std::ifstream in(std::filesystem::path(found->second.workingFile), std::ios::binary);
	if (!in) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	std::vector<uint8_t> data((size_t)size);
	if (!in.read(reinterpret_cast<char*>(data.data()), (std::streamsize)data.size()))
		return HRESULT_FROM_WIN32(ERROR_READ_FAULT);
	const uint64_t base = found->second.leadingSparseBytes;
	for (size_t pos = 0; pos + V2_MINIMUM <= data.size();) {
		const uint32_t length = readLittleEndian<uint32_t>(data.data() + pos + RECORD_LENGTH);
		const uint16_t major = readLittleEndian<uint16_t>(data.data() + pos + RECORD_MAJOR);
		// Zeros between records (the end of a page, a region freed): the next boundary.
		if (length < V2_MINIMUM || length % ALIGNMENT || length > data.size() - pos) { pos += ALIGNMENT; continue; }
		if (major == 4) ++rangeRecords;
		else {
			UsnRecord record;
			if (record.parse(data.data() + pos, data.size() - pos, base + pos)) records.push_back(std::move(record));
			else { pos += ALIGNMENT; continue; }
		}
		pos += length;
	}
	return ERROR_SUCCESS;
}

HRESULT UsnJournal::toJson(JsonArrayWriter& out, const Mft& mft) const {
	log(3, L"🔈usn journal toJson " + mft.volume());
	for (const UsnRecord& r : records) out.add(r.toJson(mft));
	return ERROR_SUCCESS;
}

void UsnJournal::clear() {
	log(3, L"🔈usn journal clear");
	records.clear();
	records.shrink_to_fit();
	rangeRecords = 0;
}
