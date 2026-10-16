/*! \file
 *  \brief Device installation log (see setupapi_log.h).
 */
#include "setupapi_log.h"
#include <filesystem>
#include <fstream>

namespace {

const wchar_t HEADER[] = L">>>  [";               //!< first line of a section
const wchar_t START[] = L">>>  Section start ";   //!< its start date
const wchar_t END[] = L"<<<  Section end ";       //!< its end date
const wchar_t STATUS[] = L"<<<  [Exit status: ";  //!< its outcome
const wchar_t XP_LOG[] = L"[SetupAPI Log]";        //!< first line of Windows XP's setupapi.log
const wchar_t XP_INSTALLED[] = L"Device install of \"";   //!< #I121: a device installed, its instance quoted
const wchar_t XP_FINISHED[] = L"\" finished successfully";

/*! The logs reach tens of megabytes on a machine that installs a lot; beyond
 *  this, the file is not read — its exhibit stays in the store. */
const uintmax_t LOG_MAX = 256ULL * 1024 * 1024;

//! true if `line` starts with `prefix`.
bool startsWith(const std::wstring& line, const wchar_t* prefix) {
	return line.compare(0, wcslen(prefix), prefix) == 0;
}

//! A two- or four-digit field of a date, or -1.
int number(const std::wstring& text, size_t at, size_t digits) {
	if (at + digits > text.size()) return -1;
	int value = 0;
	for (size_t i = at; i < at + digits; ++i) {
		if (text[i] < L'0' || text[i] > L'9') return -1;
		value = value * 10 + (text[i] - L'0');
	}
	return value;
}

} // namespace

bool parseSetupApiDate(const std::wstring& text, FILETIME& local) {
	// "YYYY/MM/DD HH:MM:SS.mmm", the milliseconds optional.
	if (text.size() < 19 || text[4] != L'/' || text[7] != L'/' || text[10] != L' '
	    || text[13] != L':' || text[16] != L':') return false;
	SYSTEMTIME t = {};
	const int year = number(text, 0, 4), month = number(text, 5, 2), day = number(text, 8, 2);
	const int hour = number(text, 11, 2), minute = number(text, 14, 2), second = number(text, 17, 2);
	if (year < 1601 || month < 1 || day < 1 || hour < 0 || minute < 0 || second < 0) return false;
	t.wYear = (WORD)year; t.wMonth = (WORD)month; t.wDay = (WORD)day;
	t.wHour = (WORD)hour; t.wMinute = (WORD)minute; t.wSecond = (WORD)second;
	if (text.size() >= 23 && text[19] == L'.') {
		const int milliseconds = number(text, 20, 3);
		if (milliseconds >= 0) t.wMilliseconds = (WORD)milliseconds;
	}
	// SystemTimeToFileTime refuses an impossible date (31 February): not a date then.
	return SystemTimeToFileTime(&t, &local) != 0;
}

namespace {

/*! Windows XP's setupapi.log (see setupapi_log.h): a section per
 *  "[YYYY/MM/DD HH:MM:SS pid.n]" line, its lines "#<code> <message>". */
std::vector<SetupApiSection> parseXpLog(const std::vector<std::wstring>& lines, const std::wstring& file) {
	std::vector<SetupApiSection> sections;
	size_t current = SIZE_MAX;
	for (size_t i = 0; i < lines.size(); ++i) {
		const std::wstring& line = lines[i];
		FILETIME start;
		if (line.size() > 21 && line[0] == L'[' && parseSetupApiDate(line.substr(1), start)) {
			SetupApiSection section;
			section.file = file;
			section.line = i + 1;
			section.startLocal = start;
			sections.push_back(std::move(section));
			current = sections.size() - 1;
			continue;
		}
		if (current == SIZE_MAX || line.size() < 6 || line[0] != L'#') continue;
		// "#-199 Executing …", "#I121 Device install of …", "#E361 …": the message after the code.
		const size_t space = line.find(L' ');
		if (space == std::wstring::npos) continue;
		const std::wstring message = line.substr(space + 1);
		SetupApiSection& s = sections[current];
		if (s.operation.empty()) s.operation = message;
		const size_t installed = message.find(XP_INSTALLED);
		if (installed != std::wstring::npos) {
			const size_t from = installed + wcslen(XP_INSTALLED);
			const size_t quote = message.find(L'"', from);
			if (quote != std::wstring::npos) {
				s.subject = message.substr(from, quote - from);
				if (message.compare(quote, wcslen(XP_FINISHED), XP_FINISHED) == 0) s.exitStatus = L"SUCCESS";
			}
		}
		// An error line (#E…): the outcome, when none was given yet.
		if (line[1] == L'E' && s.exitStatus.empty()) s.exitStatus = message;
	}
	return sections;
}

} // namespace

std::vector<SetupApiSection> parseSetupApiLog(const std::wstring& text, const std::wstring& file) {
	const std::vector<std::wstring> all = splitLines(text);
	if (!all.empty() && startsWith(all.front(), XP_LOG)) return parseXpLog(all, file);
	std::vector<SetupApiSection> sections;
	// The section being read, by its index: a pointer would not survive the vector growing.
	size_t current = SIZE_MAX;
	unsigned long long lineNumber = 0;
	for (const std::wstring& line : all) {
		++lineNumber;

		if (startsWith(line, HEADER)) {
			const size_t close = line.rfind(L']');
			if (close == std::wstring::npos || close < wcslen(HEADER)) continue;
			SetupApiSection section;
			section.file = file;
			section.line = lineNumber;
			const std::wstring title = line.substr(wcslen(HEADER), close - wcslen(HEADER));
			// "<operation> - <subject>"; a title without a subject is the operation alone.
			const size_t dash = title.find(L" - ");
			section.operation = dash == std::wstring::npos ? title : title.substr(0, dash);
			if (dash != std::wstring::npos) section.subject = title.substr(dash + 3);
			sections.push_back(std::move(section));
			current = sections.size() - 1;
		}
		else if (current != SIZE_MAX && startsWith(line, START))
			parseSetupApiDate(line.substr(wcslen(START)), sections[current].startLocal);
		else if (current != SIZE_MAX && startsWith(line, END))
			parseSetupApiDate(line.substr(wcslen(END)), sections[current].endLocal);
		else if (current != SIZE_MAX && startsWith(line, STATUS)) {
			const size_t close = line.rfind(L']');
			if (close != std::wstring::npos && close > wcslen(STATUS))
				sections[current].exitStatus = line.substr(wcslen(STATUS), close - wcslen(STATUS));
			current = SIZE_MAX;   // the section is over
		}
	}
	return sections;
}

Json SetupApiSection::toJson() const {
	Json o = Json::obj();
	o.add(L"Operation", Json::str(operation));
	o.add(L"Subject", Json::str(subject));
	addDate(o, L"Start", suspectLocalToUtc(startLocal));
	addDate(o, L"End", suspectLocalToUtc(endLocal));
	o.add(L"ExitStatus", Json::str(exitStatus));
	o.add(L"File", Json::str(file));
	o.add(L"Line", Json::num(line));
	return o;
}

HRESULT SetupApiLogs::getData() {
	log(0, L"ℹ️setupapi.dev.log :");
	std::vector<std::filesystem::path> logs = listFilesByExtension(extractedPath(conf.systemDrive + L"\\Windows\\INF"), { L".log" });
	for (const std::filesystem::path& p : listFilesByExtension(extractedPath(conf.systemDrive + L"\\Windows"), { L".log" })) logs.push_back(p);
	for (const std::filesystem::path& path : logs) {
		/* setupapi.dev.log and its rotations setupapi.dev.<date>.log (INF), or
		   Windows XP's setupapi.log (Windows); the other logs are not device installs. */
		const std::wstring name = toLower(path.filename().wstring());
		if (name.compare(0, 13, L"setupapi.dev.") != 0 && name != L"setupapi.log") continue;
		std::string bytes;
		if (!readWholeFile(path, LOG_MAX, bytes)) {
			log(2, L"🔥setupapi log not read (unreadable or larger than 256 MiB): " + path.wstring());
			continue;
		}
		/* Written in the machine's ANSI code page; the identifiers are ASCII,
		   a device's friendly name may not be. */
		std::vector<SetupApiSection> read = parseSetupApiLog(decodeText(bytes), originalPath(path.wstring()));
		log(2, L"❇️" + path.wstring() + L" : " + std::to_wstring(read.size()) + L" section(s)");
		for (SetupApiSection& s : read) sections_.push_back(std::move(s));
	}
	return ERROR_SUCCESS;
}

HRESULT SetupApiLogs::toJson() {
	Json list = Json::arr();
	for (const SetupApiSection& s : sections_) list.push(s.toJson());
	return writeJsonFile("setupapi.json", list);
}

void SetupApiLogs::clear() {
	sections_.clear();
}
