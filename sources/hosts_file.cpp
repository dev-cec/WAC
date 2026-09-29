/*! \file
 *  \brief The hosts file (see hosts_file.h).
 */
#include "hosts_file.h"
#include "consigne.h"
#include <filesystem>
#include <fstream>

namespace {

//! The file, relative to the system volume.
const wchar_t HOSTS_PATH[] = L"\\Windows\\System32\\drivers\\etc\\hosts";

//! A hosts file is a few kilobytes; one of several megabytes is read up to this.
const size_t HOSTS_MAX = 16 * 1024 * 1024;

bool blank(wchar_t c) { return c == L' ' || c == L'\t'; }

} // namespace

std::vector<HostsEntry> parseHostsFile(const std::wstring& text) {
	std::vector<HostsEntry> entries;
	unsigned long long lineNumber = 0;
	for (std::wstring line : splitLines(text)) {
		++lineNumber;
		const size_t comment = line.find(L'#');
		if (comment != std::wstring::npos) line.erase(comment);
		std::vector<std::wstring> words;
		size_t i = 0;
		while (i < line.size()) {
			while (i < line.size() && blank(line[i])) ++i;
			size_t j = i;
			while (j < line.size() && !blank(line[j])) ++j;
			if (j > i) words.push_back(line.substr(i, j - i));
			i = j;
		}
		if (words.empty()) continue;
		HostsEntry entry;
		entry.line = lineNumber;
		entry.address = words[0];
		entry.names.assign(words.begin() + 1, words.end());
		entries.push_back(std::move(entry));
	}
	return entries;
}

Json HostsEntry::toJson() const {
	Json o = Json::obj();
	o.add(L"Address", Json::str(address));
	Json list = Json::arr();
	for (const std::wstring& n : names) list.push(Json::str(n));
	o.add(L"Names", std::move(list));
	o.add(L"Line", Json::num(line));
	return o;
}

HRESULT HostsFile::getData() {
	const std::filesystem::path file = extractedPath(conf.systemDrive + HOSTS_PATH);
	std::error_code ec;
	if (!std::filesystem::exists(file, ec)) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	std::ifstream in(file, std::ios::binary);
	std::string bytes(HOSTS_MAX, '\0');
	in.read(&bytes[0], (std::streamsize)bytes.size());
	bytes.resize((size_t)in.gcount());
	path_ = conf.systemDrive + HOSTS_PATH;
	ExhibitSourceTimes(file.wstring(), createdUtc_, modifiedUtc_, accessedUtc_);
	// Windows reads it as ANSI; a UTF-8 byte-order mark is skipped, as its resolver does.
	const bool bom = bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") == 0;
	entries_ = parseHostsFile(bom ? decodeText(bytes.substr(3), CP_UTF8) : decodeText(bytes));
	return ERROR_SUCCESS;
}

HRESULT HostsFile::toJson() {
	Json o = Json::obj();
	o.add(L"Path", Json::str(path_));
	addDate(o, L"SourceCreated", createdUtc_);
	addDate(o, L"SourceModified", modifiedUtc_);
	addDate(o, L"SourceAccessed", accessedUtc_);
	o.add(L"EntryCount", Json::num((unsigned long long)entries_.size()));
	Json list = Json::arr();
	for (const HostsEntry& e : entries_) list.push(e.toJson());
	o.add(L"Entries", std::move(list));
	return writeJsonFile("hosts.json", o);
}

void HostsFile::clear() {
	entries_.clear();
}
