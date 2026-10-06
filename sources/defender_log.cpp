/*! \file
 *  \brief Microsoft Defender's support logs (see defender_log.h).
 */
#include "defender_log.h"
#include "consigne.h"
#include <filesystem>
#include <fstream>

namespace {

//! Folder of the logs, relative to the system volume, in lower case as the manifest index is.
const wchar_t SUPPORT_FOLDER[] = L"\\programdata\\microsoft\\windows defender\\support\\";

//! An MPLog is capped by Defender at a few tens of megabytes; beyond this, the file is not read.
const uintmax_t LOG_MAX = 256ULL * 1024 * 1024;

} // namespace

bool parseDefenderDate(const std::wstring& text, FILETIME& utc) {
	// The date is the line's first word: "2023-05-12T10:11:12.345Z …".
	const size_t space = text.find(L' ');
	return iso8601UtcToFiletime(text.substr(0, space), utc);
}

std::vector<DefenderLogLine> parseDefenderLog(const std::wstring& text) {
	std::vector<DefenderLogLine> lines;
	unsigned long long lineNumber = 0;
	for (std::wstring line : splitLines(text)) {
		++lineNumber;
		while (!line.empty() && line.back() == L' ') line.pop_back();
		if (line.empty()) continue;
		DefenderLogLine entry;
		entry.line = lineNumber;
		parseDefenderDate(line, entry.timeUtc);
		entry.text = std::move(line);
		lines.push_back(std::move(entry));
	}
	return lines;
}

Json DefenderLogLine::toJson() const {
	Json o = Json::obj();
	o.add(L"Line", Json::num(line));
	addDate(o, L"Time", timeUtc);
	o.add(L"Text", Json::str(text));
	return o;
}

Json DefenderLog::toJson() const {
	Json o = Json::obj();
	o.add(L"Path", Json::str(path));
	addDate(o, L"SourceModified", sourceModifiedUtc);
	o.add(L"LineCount", Json::num((unsigned long long)lines.size()));
	Json list = Json::arr();
	for (const DefenderLogLine& l : lines) list.push(l.toJson());
	o.add(L"Lines", std::move(list));
	return o;
}

HRESULT DefenderLogs::getData() {
	log(0, L"ℹ️Defender support logs :");
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		if (exhibit.workingFile.empty() || key.size() < 3 || key.compare(2, wcslen(SUPPORT_FOLDER), SUPPORT_FOLDER) != 0) continue;
		const std::wstring name = std::filesystem::path(key).filename().wstring();
		if (name.compare(0, 6, L"mplog-") != 0) continue;
		std::error_code ec;
		const uintmax_t size = std::filesystem::file_size(exhibit.workingFile, ec);
		if (ec || size > LOG_MAX) {
			log(2, L"🔥Defender log not read (unreadable or larger than 256 MiB): " + exhibit.sourcePath);
			continue;
		}
		std::ifstream in(std::filesystem::path(exhibit.workingFile), std::ios::binary);
		const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		DefenderLog logFile;
		logFile.path = exhibit.sourcePath;
		FILETIME created = { 0 }, accessed = { 0 };
		ExhibitSourceTimes(exhibit.workingFile, created, logFile.sourceModifiedUtc, accessed);
		// UTF-16LE with its byte-order mark, as Defender writes it; UTF-8 otherwise.
		const bool utf16 = bytes.size() >= 2 && (uint8_t)bytes[0] == 0xFF && (uint8_t)bytes[1] == 0xFE;
		logFile.lines = parseDefenderLog(utf16 ? readWideZ(reinterpret_cast<const BYTE*>(bytes.data()), bytes.size(), 2)
		                                       : decodeText(bytes, CP_UTF8));
		logs_.push_back(std::move(logFile));
	}
	return ERROR_SUCCESS;
}

HRESULT DefenderLogs::toJson() {
	Json list = Json::arr();
	for (const DefenderLog& l : logs_) list.push(l.toJson());
	return writeJsonFile("defender_log.json", list);
}

void DefenderLogs::clear() {
	logs_.clear();
}
