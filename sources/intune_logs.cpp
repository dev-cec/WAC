/*! \file
 *  \brief The Intune Management Extension's logs (see intune_logs.h).
 */
#include "intune_logs.h"
#include "conversions.h"
#include "registry_common.h"
#include <algorithm>
#include <filesystem>

const wchar_t INTUNE_LOGS_FOLDER[] = L"\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs";

namespace {

//! Largest log read: the extension rotates its logs at a few MiB.
const uintmax_t LOG_MAX = 256ULL * 1024 * 1024;
const std::wstring OPEN = L"<![LOG[", CLOSE = L"]LOG]!>";

/*! The value of an attribute name="value" in a CMTrace header.
 *  @return it, or "" if the attribute is absent */
std::wstring attribute(const std::wstring& header, const wchar_t* name) {
	const std::wstring key = std::wstring(name) + L"=\"";
	size_t at = 0;
	// The attribute's name begins the header or follows a space: "time" is not "datetime".
	while ((at = header.find(key, at)) != std::wstring::npos && at > 0 && header[at - 1] != L' ' && header[at - 1] != L'<') ++at;
	if (at == std::wstring::npos) return L"";
	const size_t start = at + key.size(), end = header.find(L'"', start);
	return end == std::wstring::npos ? L"" : header.substr(start, end - start);
}

//! A number of 1 to 4 decimal digits, or -1.
int number(const std::wstring& text) {
	if (text.empty() || text.size() > 4 || text.find_first_not_of(L"0123456789") != std::wstring::npos) return -1;
	return std::stoi(text);
}

/*! Reads the date "10-24-2026" and the time "15:01:02.1234567[+300]".
 *  @param e receives timeLocal, and the bias when one is written
 *  @return false if either is not such a text */
bool readTime(const std::wstring& date, std::wstring time, IntuneLogEntry& e) {
	const size_t sign = time.find_first_of(L"+-");
	if (sign != std::wstring::npos) {
		const int bias = number(time.substr(sign + 1));
		if (bias < 0) return false;
		e.hasBias = true;
		e.biasMinutes = time[sign] == L'-' ? -bias : bias;
		time.resize(sign);
	}
	const size_t first = date.find(L'-'), second = date.find(L'-', first == std::wstring::npos ? 0 : first + 1);
	if (first == std::wstring::npos || second == std::wstring::npos) return false;
	const int month = number(date.substr(0, first)), day = number(date.substr(first + 1, second - first - 1)),
	          year = number(date.substr(second + 1));
	if (month < 1 || day < 1 || year < 1601) return false;
	wchar_t iso[16];
	swprintf(iso, 16, L"%04d-%02d-%02dT", year, month, day);
	// Read as ISO 8601, which checks each field: the instant is the local one, as written.
	return iso8601UtcToFiletime(iso + time + L"Z", e.timeLocal);
}

} // namespace

std::vector<IntuneLogEntry> parseCmTraceLog(const std::wstring& text, const std::wstring& file) {
	std::vector<IntuneLogEntry> entries;
	size_t at = 0;
	unsigned long long line = 1;
	size_t counted = 0;   // the line ends counted up to here
	while ((at = text.find(OPEN, at)) != std::wstring::npos) {
		line += std::count(text.begin() + counted, text.begin() + at, L'\n');
		counted = at;
		const size_t start = at + OPEN.size(), end = text.find(CLOSE, start);
		if (end == std::wstring::npos) break;                      // cut short: not a message
		const size_t headerEnd = text.find(L'>', end + CLOSE.size());
		if (headerEnd == std::wstring::npos) break;
		IntuneLogEntry e;
		e.file = file;
		e.line = line;
		e.message = text.substr(start, end - start);
		const std::wstring header = text.substr(end + CLOSE.size(), headerEnd - end - CLOSE.size());
		if (!readTime(attribute(header, L"date"), attribute(header, L"time"), e)) e.timeLocal = FILETIME{ 0, 0 };
		e.component = attribute(header, L"component");
		e.context = attribute(header, L"context");
		e.type = attribute(header, L"type");
		e.thread = attribute(header, L"thread");
		e.sourceFile = attribute(header, L"file");
		entries.push_back(std::move(e));
		at = headerEnd + 1;
	}
	return entries;
}

Json IntuneLogEntry::toJson() const {
	Json o = Json::obj();
	if (timeLocal.dwLowDateTime || timeLocal.dwHighDateTime) {
		if (hasBias) {
			// UTC = local + bias: the writer's own offset, exact.
			const long long ticks = (long long)ticksFromFiletime(timeLocal) + (long long)biasMinutes * 600000000LL;
			addUtcDate(o, L"Time", filetimeFromTicks((uint64_t)ticks));
			o.add(L"BiasMinutes", Json::num((long long)biasMinutes));
		}
		else addDate(o, L"Time", suspectLocalToUtc(timeLocal));
	}
	o.add(L"Message", Json::str(message));
	o.add(L"Component", Json::str(component));
	o.add(L"Context", Json::str(context));
	o.add(L"Type", Json::str(type));
	o.add(L"Thread", Json::str(thread));
	o.add(L"SourceFile", Json::str(sourceFile));
	o.add(L"File", Json::str(file));
	o.add(L"Line", Json::num(line));
	return o;
}

HRESULT IntuneLogs::getData() {
	// The working copy, as the collection took it.
	for (const std::filesystem::path& path : listFilesByExtension(extractedPath(conf.systemDrive + INTUNE_LOGS_FOLDER), { L".log" })) {
		std::string bytes;
		if (!readWholeFile(path, LOG_MAX, bytes)) {
			log(2, L"🔥Intune log not read (unreadable or larger than 256 MiB): " + path.wstring());
			continue;
		}
		std::vector<IntuneLogEntry> read = parseCmTraceLog(decodeTextFile(bytes), originalPath(path.wstring()));
		log(2, L"❇️" + path.wstring() + L" : " + std::to_wstring(read.size()) + L" message(s)");
		for (IntuneLogEntry& e : read) entries_.push_back(std::move(e));
	}
	return ERROR_SUCCESS;
}

HRESULT IntuneLogs::toJson() { return writeList("intune_logs.json", entries_); }
void IntuneLogs::clear() { entries_.clear(); }
