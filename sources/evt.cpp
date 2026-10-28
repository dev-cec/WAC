/*! \file
 *  \brief Classic event logs (.evt): see evt.h.
 */
#include "evt.h"
#include "conversions.h"
#include "registry_common.h"
#include "tools.h"
#include <cstring>
#include <filesystem>

namespace {

const size_t HEADER_SIZE = 0x30;           //!< the file header, before the circular area
const size_t RECORD_FIXED = 0x38;          //!< a record's fixed part, up to the source name
const uint32_t EOF_RECORD_SIZE = 0x28;     //!< the end-of-file record, as its first DWORD
const uint32_t EOF_MARK = 0x11111111;      //!< its second DWORD
const uintmax_t LOG_MAX = 1ull << 30;      //!< a classic log is a few MiB at most

// Event types (winnt.h EVENTLOG_*), and the Level and Keywords Windows
// gives them when it renders a classic record as XML.
const uint16_t TYPE_ERROR = 0x1, TYPE_WARNING = 0x2, TYPE_AUDIT_SUCCESS = 0x8, TYPE_AUDIT_FAILURE = 0x10;
const wchar_t KEYWORDS_CLASSIC[] = L"0x80000000000000";
const wchar_t KEYWORDS_AUDIT_SUCCESS[] = L"0x8020000000000000";
const wchar_t KEYWORDS_AUDIT_FAILURE[] = L"0x8010000000000000";

/*! The circular area of the file: offsets from HEADER_SIZE to the end, a
 *  read reaching the end going on right after the header. */
struct Circle {
	const std::vector<uint8_t>& file;
	//! The next offset after `at` moved by `count` bytes, within the area.
	size_t advance(size_t at, size_t count) const {
		const size_t area = file.size() - HEADER_SIZE;
		return HEADER_SIZE + (at - HEADER_SIZE + count) % area;
	}
	//! `count` bytes from `at`, the area's end crossed if need be.
	std::vector<uint8_t> read(size_t at, size_t count) const {
		std::vector<uint8_t> out(count);
		for (size_t i = 0; i < count; ++i) out[i] = file[advance(at, i)];
		return out;
	}
	uint32_t dword(size_t at) const {
		const std::vector<uint8_t> b = read(at, 4);
		return readLittleEndian<uint32_t>(b.data());
	}
};

//! A null-terminated UTF-16 string from `at`, never past `end`; `at` moves past its null.
std::wstring readString(const std::vector<uint8_t>& r, size_t& at, size_t end) {
	std::wstring text;
	while (at + 2 <= end) {
		const wchar_t c = (wchar_t)readLittleEndian<uint16_t>(r.data() + at);
		at += 2;
		if (c == 0) break;
		text += c;
	}
	return text;
}

/*! One record as the XML of a classic source in an .evtx (see evt.h).
 *  @param r the record, whole, its length its size
 *  @param channel the log's name
 *  @param record receives its number, its time written and its XML */
void renderRecord(const std::vector<uint8_t>& r, const std::wstring& channel, EvtxRecord& record) {
	const size_t end = r.size() - 4;   // the trailing length
	const uint32_t number = readLittleEndian<uint32_t>(r.data() + 8);
	const uint32_t generated = readLittleEndian<uint32_t>(r.data() + 12);
	const uint32_t written = readLittleEndian<uint32_t>(r.data() + 16);
	const uint32_t eventId = readLittleEndian<uint32_t>(r.data() + 20);
	const uint16_t type = readLittleEndian<uint16_t>(r.data() + 24);
	const uint16_t strings = readLittleEndian<uint16_t>(r.data() + 26);
	const uint16_t category = readLittleEndian<uint16_t>(r.data() + 28);
	const size_t stringOffset = readLittleEndian<uint32_t>(r.data() + 36);
	const size_t sidLength = readLittleEndian<uint32_t>(r.data() + 40);
	const size_t sidOffset = readLittleEndian<uint32_t>(r.data() + 44);
	const size_t dataLength = readLittleEndian<uint32_t>(r.data() + 48);
	const size_t dataOffset = readLittleEndian<uint32_t>(r.data() + 52);

	size_t at = RECORD_FIXED;
	const std::wstring source = readString(r, at, end);
	const std::wstring computer = readString(r, at, end);

	const wchar_t* level = L"4";
	const wchar_t* keywords = KEYWORDS_CLASSIC;
	if (type == TYPE_ERROR) level = L"2";
	else if (type == TYPE_WARNING) level = L"3";
	else if (type == TYPE_AUDIT_SUCCESS) { level = L"0"; keywords = KEYWORDS_AUDIT_SUCCESS; }
	else if (type == TYPE_AUDIT_FAILURE) { level = L"0"; keywords = KEYWORDS_AUDIT_FAILURE; }

	std::wstring xml = L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>";
	xml += L"<Provider Name='" + EvtxXmlEscape(source) + L"'/>";
	xml += L"<EventID Qualifiers='" + std::to_wstring(eventId >> 16) + L"'>" + std::to_wstring(eventId & 0xFFFF) + L"</EventID>";
	xml += L"<Level>" + std::wstring(level) + L"</Level><Task>" + std::to_wstring(category) + L"</Task>";
	xml += L"<Keywords>" + std::wstring(keywords) + L"</Keywords>";
	xml += L"<TimeCreated SystemTime='" + timeToIso8601Utc(unixToFiletime(generated)) + L"'/>";
	xml += L"<EventRecordID>" + std::to_wstring(number) + L"</EventRecordID>";
	xml += L"<Channel>" + EvtxXmlEscape(channel) + L"</Channel><Computer>" + EvtxXmlEscape(computer) + L"</Computer>";
	if (sidLength && fits(end, sidOffset, sidLength))
		xml += L"<Security UserID='" + EvtxXmlEscape(sidToText(r.data() + sidOffset, sidLength)) + L"'/>";
	else xml += L"<Security/>";
	xml += L"</System><EventData>";
	at = stringOffset;
	for (uint16_t i = 0; i < strings && at < end; ++i) xml += L"<Data>" + EvtxXmlEscape(readString(r, at, end)) + L"</Data>";
	if (dataLength && fits(end, dataOffset, dataLength))
		xml += L"<Binary>" + toHexadecimal(r.data() + dataOffset, dataLength) + L"</Binary>";
	xml += L"</EventData></Event>";

	record.id = number;
	record.writtenUtc = unixToFiletime(written);
	record.xml = std::move(xml);
}

} // namespace

HRESULT EvtReadFile(const std::wstring& path, const std::wstring& channel,
                    const std::function<bool(const EvtxRecord&)>& onRecord, EvtxSummary* summary) {
	EvtxSummary local;
	EvtxSummary& s = summary ? *summary : local;
	std::vector<uint8_t> file;
	if (!readWholeFile(path, LOG_MAX, file)) {
		s.diagnostic = L"unreadable";
		return HRESULT_FROM_WIN32(ERROR_READ_FAULT);
	}
	if (file.size() < HEADER_SIZE + RECORD_FIXED || readLittleEndian<uint32_t>(file.data()) != HEADER_SIZE
	    || std::memcmp(file.data() + 4, "LfLe", 4) != 0) {
		s.diagnostic = L"not a classic event log (no LfLe header)";
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	s.headerValid = true;
	const uint32_t flags = readLittleEndian<uint32_t>(file.data() + 0x24);
	s.dirty = (flags & 0x1) != 0;   // ELF_LOGFILE_HEADER_DIRTY: written while the log was open
	const Circle circle{ file };
	size_t at = readLittleEndian<uint32_t>(file.data() + 0x10);
	if (at < HEADER_SIZE || at >= file.size()) {
		s.diagnostic = L"oldest record outside the file";
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	/* One pass round the area at most: a record is at least RECORD_FIXED
	   bytes, and a chain of lengths that loops ends there. */
	const size_t area = file.size() - HEADER_SIZE;
	std::wstring stop = L"end-of-file record reached";
	for (size_t walked = 0; walked < area;) {
		const uint32_t length = circle.dword(at);
		if (length == EOF_RECORD_SIZE && circle.dword(circle.advance(at, 4)) == EOF_MARK) break;
		if (length < RECORD_FIXED + 4 || length % 4 != 0 || length > area - walked) {
			stop = L"record of length " + std::to_wstring(length) + L" at " + std::to_wstring(at) + L": walk stopped";
			++s.unreadable;
			break;
		}
		const std::vector<uint8_t> record = circle.read(at, length);
		if (std::memcmp(record.data() + 4, "LfLe", 4) != 0 || readLittleEndian<uint32_t>(record.data() + length - 4) != length) {
			stop = L"record without its signature or trailing length at " + std::to_wstring(at) + L": walk stopped";
			++s.unreadable;
			break;
		}
		EvtxRecord e;
		renderRecord(record, channel, e);
		++s.read;
		if (!onRecord(e)) { stop = L"reading stopped by the caller"; break; }
		at = circle.advance(at, length);
		walked += length;
	}
	s.diagnostic = std::to_wstring(s.read) + L" record(s)" + (s.dirty ? L", log dirty" : L"") + L"; " + stop;
	return s.unreadable ? S_FALSE : ERROR_SUCCESS;
}

std::wstring EvtChannelFromFile(ORHKEY controlSet, const std::wstring& fileName) {
	if (controlSet) {
		const std::wstring EVENTLOG = L"Services\\Eventlog";
		for (const std::wstring& log : subkeys(controlSet, EVENTLOG)) {
			std::wstring file;
			if (getRegSzValue(controlSet, (EVENTLOG + L"\\" + log).c_str(), L"File", &file) != ERROR_SUCCESS) continue;
			const size_t slash = file.find_last_of(L'\\');
			if (_wcsicmp(file.substr(slash == std::wstring::npos ? 0 : slash + 1).c_str(), fileName.c_str()) == 0) return log;
		}
	}
	static const wchar_t* const KNOWN[][2] = { { L"AppEvent.Evt", L"Application" }, { L"SecEvent.Evt", L"Security" },
	                                           { L"SysEvent.Evt", L"System" } };
	for (const auto& k : KNOWN) if (_wcsicmp(fileName.c_str(), k[0]) == 0) return k[1];
	return std::filesystem::path(fileName).stem().wstring();
}
