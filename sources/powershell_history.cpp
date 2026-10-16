/*! \file
 *  \brief PowerShell command history (see powershell_history.h).
 */
#include "powershell_history.h"
#include "consigne.h"
#include <filesystem>
#include <fstream>

const wchar_t PSREADLINE_FOLDER[] = L"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine";

namespace {

//! Suffix of a history file: `<host>_history.txt`.
const wchar_t HISTORY_SUFFIX[] = L"_history.txt";

/*! A history file is a few hundred kilobytes (PSReadLine keeps 4,096
 *  commands by default); beyond this, the file is not a history and is not
 *  read — its exhibit stays in the store. */
const uintmax_t HISTORY_MAX = 64ULL * 1024 * 1024;

} // namespace

std::vector<PowerShellCommand> parsePowerShellHistory(const std::wstring& text) {
	std::vector<PowerShellCommand> commands;
	PowerShellCommand current;
	bool continued = false;          // the previous line ended with a backtick
	unsigned long long lineNumber = 0;
	for (std::wstring line : splitLines(text)) {
		++lineNumber;

		if (continued) current.command += L"\n" + line;
		else {
			if (line.empty()) continue;
			current = PowerShellCommand{};
			current.line = lineNumber;
			current.command = line;
		}
		continued = !line.empty() && line.back() == L'`';
		if (!continued) {
			current.number = commands.size() + 1;
			commands.push_back(current);
		}
	}
	// A last command left open by a backtick is still a command.
	if (continued) {
		current.number = commands.size() + 1;
		commands.push_back(current);
	}
	return commands;
}

Json PowerShellCommand::toJson() const {
	Json o = Json::obj();
	o.add(L"Number", Json::num(number));
	o.add(L"Line", Json::num(line));
	o.add(L"Command", Json::str(command));
	return o;
}

Json PowerShellHistory::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	o.add(L"Path", Json::str(path));
	o.add(L"Host", Json::str(host));
	addDate(o, L"SourceCreated", sourceCreatedUtc);
	addDate(o, L"SourceModified", sourceModifiedUtc);
	addDate(o, L"SourceAccessed", sourceAccessedUtc);
	o.add(L"CommandCount", Json::num((unsigned long long)commands.size()));
	Json list = Json::arr();
	for (const PowerShellCommand& c : commands) list.push(c.toJson());
	o.add(L"Commands", std::move(list));
	return o;
}

HRESULT PowerShellHistories::getData() {
	log(0, L"ℹ️PowerShell history :");
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::filesystem::path folder = extractedPath(std::get<1>(profileEntry) + PSREADLINE_FOLDER);
		for (const std::filesystem::path& file : listFilesByExtension(folder, { L".txt" })) {
			const std::wstring name = file.filename().wstring();
			const size_t suffix = name.size() >= wcslen(HISTORY_SUFFIX) ? name.size() - wcslen(HISTORY_SUFFIX) : std::wstring::npos;
			if (suffix == std::wstring::npos || toLower(name.substr(suffix)) != HISTORY_SUFFIX) continue;
			std::string bytes;
			if (!readWholeFile(file, HISTORY_MAX, bytes)) {
				log(2, L"🔥PowerShell history not read (unreadable or larger than 64 MiB): " + file.wstring());
				continue;
			}
			PowerShellHistory history;
			history.sid = std::get<0>(profileEntry);
			history.path = originalPath(file.wstring());
			history.host = name.substr(0, suffix);
			ExhibitSourceTimes(file.wstring(), history.sourceCreatedUtc, history.sourceModifiedUtc,
			                   history.sourceAccessedUtc);
			// PSReadLine writes UTF-8; a byte-order mark, when present, is not text.
			const bool bom = bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") == 0;
			history.commands = parsePowerShellHistory(decodeText(bom ? bytes.substr(3) : bytes, CP_UTF8));
			log(2, L"❇️" + history.path + L" : " + std::to_wstring(history.commands.size()) + L" command(s)");
			histories_.push_back(std::move(history));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT PowerShellHistories::toJson() {
	Json list = Json::arr();
	for (const PowerShellHistory& h : histories_) list.push(h.toJson());
	return writeJsonFile("powershell_history.json", list);
}

void PowerShellHistories::clear() {
	histories_.clear();
}
