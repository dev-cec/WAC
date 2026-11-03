/*! \file
 *  \brief The group policies of a domain controller (see group_policies.h).
 */
#include "group_policies.h"
#include "long_path.h"
#include "whole_file.h"
#include "xml_light.h"
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <set>

namespace {

const wchar_t NETLOGON_PARAMETERS[] = L"Services\\Netlogon\\Parameters";
const uintmax_t POLICY_FILE_MAX = 64ull * 1024 * 1024;   //!< far above any policy file: larger, it is not one
const unsigned TREE_DEPTH_MAX = 32;                      //!< the bound of a walk, against a forged tree

//! A text without the spaces and tabs at its edges.
std::wstring trimmed(const std::wstring& text) {
	const size_t first = text.find_first_not_of(L" \t\r");
	return first == std::wstring::npos ? L"" : text.substr(first, text.find_last_not_of(L" \t\r") - first + 1);
}

//! The file's text, whatever its encoding; empty if absent or too large.
std::wstring textOfFile(const std::filesystem::path& file) {
	std::string bytes;
	return readWholeFile(file, POLICY_FILE_MAX, bytes) ? decodeTextFile(bytes) : L"";
}

/*! The files under a folder, relative to it, walked by hand: an iterator
 *  stops at the first folder it cannot enter.
 *  @param folder the folder
 *  @param relative its path so far
 *  @param depth levels left
 *  @param out receives the relative paths */
void listFiles(const std::filesystem::path& folder, const std::wstring& relative, unsigned depth, std::vector<std::wstring>& out) {
	if (depth == 0) return;
	std::error_code ec;
	for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(std::filesystem::path(extendedPath(folder.wstring())), ec)) {
		const std::wstring name = e.path().filename().wstring(), path = relative.empty() ? name : relative + L"\\" + name;
		if (e.is_directory(ec)) listFiles(folder / name, path, depth - 1, out);
		else out.push_back(path);
	}
}

//! A list of strings in JSON.
Json stringArray(const std::vector<std::wstring>& items) {
	Json list = Json::arr();
	for (const std::wstring& item : items) list.push(Json::str(item));
	return list;
}

//! A list of objects in JSON.
Json objectArray(const std::vector<Json>& items) {
	Json list = Json::arr();
	for (const Json& item : items) list.push(item);
	return list;
}

/*! Reads the UTF-16 text of an entry up to a delimiter.
 *  @param data the file
 *  @param size its size
 *  @param at the offset, moved past the delimiter
 *  @param delimiter the UTF-16 code it ends on
 *  @param text receives the text, its terminating zero left out
 *  @return false if the file ends before it */
bool readUntil(const uint8_t* data, size_t size, size_t& at, uint16_t delimiter, std::wstring& text) {
	text.clear();
	for (; at + 2 <= size; at += 2) {
		const uint16_t c = readLittleEndian<uint16_t>(data + at);
		if (c == delimiter) { at += 2; return true; }
		if (c) text.push_back((wchar_t)c);
	}
	return false;
}

//! The same for a number of 4 bytes followed by its delimiter.
bool readNumber(const uint8_t* data, size_t size, size_t& at, uint32_t& number) {
	if (size - at < 6 || at > size) return false;
	number = readLittleEndian<uint32_t>(data + at);
	if (readLittleEndian<uint16_t>(data + at + 4) != L';') return false;
	at += 6;
	return true;
}

//! The files starting and ending so, whatever their case: a policy writes MACHINE or Machine.
std::vector<std::wstring> filesNamed(const std::vector<std::wstring>& files, const std::wstring& prefix, const std::wstring& suffix) {
	std::vector<std::wstring> found;
	const std::wstring wantedPrefix = toLower(prefix), wantedSuffix = toLower(suffix);
	for (const std::wstring& f : files) {
		const std::wstring lower = toLower(f);
		if (lower.compare(0, wantedPrefix.size(), wantedPrefix) == 0 && lower.size() >= wantedSuffix.size()
		    && lower.compare(lower.size() - wantedSuffix.size(), wantedSuffix.size(), wantedSuffix) == 0)
			found.push_back(f);
	}
	return found;
}

/*! One policy's folder, as its element.
 *  @param folder its working copy
 *  @param source the same on the examined machine
 *  @param id its name, {GUID} */
Json readPolicy(const std::filesystem::path& folder, const std::wstring& source, const std::wstring& id) {
	Json row = Json::obj();
	row.add(L"Id", Json::str(id));
	row.add(L"Path", Json::str(source));
	std::vector<std::wstring> files;
	listFiles(folder, L"", TREE_DEPTH_MAX, files);
	row.add(L"Files", stringArray(files));
	const IniSections gpt = parseIniText(textOfFile(folder / L"GPT.INI"));
	const auto general = gpt.find(L"General");
	if (general != gpt.end())
		for (const auto& [key, value] : general->second) {
			if (_wcsicmp(key.c_str(), L"Version") == 0) row.add(L"Version", Json::str(value));
			else if (_wcsicmp(key.c_str(), L"displayName") == 0) row.add(L"DisplayName", Json::str(value));
		}
	std::vector<Json> registry, scripts, tasks, templates, stored;
	for (const wchar_t* scope : { L"Machine", L"User" }) {
		for (const std::wstring& f : filesNamed(files, std::wstring(scope) + L"\\", L"\\Registry.pol")) {
			std::vector<uint8_t> bytes;
			if (!readWholeFile(folder / f, POLICY_FILE_MAX, bytes)) continue;
			for (const PolicyRegistryEntry& e : parseRegistryPol(bytes.data(), bytes.size())) {
				Json entry = e.toJson();
				entry.add(L"Scope", Json::str(scope));
				registry.push_back(std::move(entry));
			}
		}
		for (const auto& [name, engine] : { std::pair<const wchar_t*, const wchar_t*>{ L"\\Scripts\\scripts.ini", L"Script" }, { L"\\Scripts\\psscripts.ini", L"PowerShell" } })
			for (const std::wstring& f : filesNamed(files, scope, name))
				for (Json& s : parsePolicyScripts(textOfFile(folder / f), scope, engine)) scripts.push_back(std::move(s));
		for (const std::wstring& f : filesNamed(files, scope, L"\\ScheduledTasks.xml"))
			for (Json& t : parsePolicyTasks(textOfFile(folder / f), scope)) tasks.push_back(std::move(t));
	}
	for (const std::wstring& f : filesNamed(files, L"Machine\\", L"\\GptTmpl.inf"))
		for (const auto& [section, lines] : parseIniText(textOfFile(folder / f))) {
			if (section == L"Unicode" || section == L"Version") continue;
			for (const auto& [key, value] : lines) {
				Json entry = Json::obj();
				entry.add(L"Section", Json::str(section));
				entry.add(L"Key", Json::str(key));
				entry.add(L"Value", Json::str(value));
				templates.push_back(std::move(entry));
			}
		}
	for (const std::wstring& f : files) {
		const std::wstring lower = toLower(f);
		if (lower.find(L"\\preferences\\") == std::wstring::npos || lower.size() < 4 || lower.compare(lower.size() - 4, 4, L".xml") != 0) continue;
		for (const std::wstring& name : storedPasswordElements(textOfFile(folder / f))) {
			Json entry = Json::obj();
			entry.add(L"File", Json::str(f));
			entry.add(L"Element", Json::str(name));
			stored.push_back(std::move(entry));
		}
	}
	if (!registry.empty()) row.add(L"RegistryValues", objectArray(registry));
	if (!scripts.empty()) row.add(L"Scripts", objectArray(scripts));
	if (!tasks.empty()) row.add(L"ScheduledTasks", objectArray(tasks));
	if (!templates.empty()) row.add(L"SecurityTemplate", objectArray(templates));
	if (!stored.empty()) row.add(L"StoredPasswords", objectArray(stored));
	return row;
}

} // namespace

Json PolicyRegistryEntry::toJson() const {
	Json o = Json::obj();
	o.add(L"Key", Json::str(key));
	o.add(L"Value", Json::str(value));
	o.add(L"Type", Json::num((unsigned long long)type));
	if (data.empty()) return o;
	if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) o.add(L"Data", Json::str(readWideZ(data.data(), data.size() & ~(size_t)1, 0)));
	else if (type == REG_DWORD && data.size() == 4) o.add(L"Data", Json::num((unsigned long long)readLittleEndian<uint32_t>(data.data())));
	else if (type == REG_QWORD && data.size() == 8) o.add(L"Data", Json::num((unsigned long long)readLittleEndian<uint64_t>(data.data())));
	else {
		std::wstring hex;
		for (uint8_t b : data) hex += to_hex(b);
		o.add(L"Data", Json::str(hex));
	}
	return o;
}

std::vector<PolicyRegistryEntry> parseRegistryPol(const uint8_t* data, size_t size) {
	std::vector<PolicyRegistryEntry> entries;
	const size_t HEADER = 8;
	if (size < HEADER || memcmp(data, "PReg", 4) != 0 || readLittleEndian<uint32_t>(data + 4) != 1) return entries;
	size_t at = HEADER;
	while (at + 2 <= size && readLittleEndian<uint16_t>(data + at) == L'[') {
		at += 2;
		PolicyRegistryEntry e;
		uint32_t length = 0;
		if (!readUntil(data, size, at, L';', e.key) || !readUntil(data, size, at, L';', e.value)
		    || !readNumber(data, size, at, e.type) || !readNumber(data, size, at, length)) break;
		if (length > size - at || size - at - length < 2 || readLittleEndian<uint16_t>(data + at + length) != L']') break;
		e.data.assign(data + at, data + at + length);
		at += (size_t)length + 2;
		entries.push_back(std::move(e));
	}
	return entries;
}

IniSections parseIniText(const std::wstring& text) {
	IniSections sections;
	std::wstring section;
	for (std::wstring line : splitLines(text)) {
		line = trimmed(line);
		if (line.empty() || line[0] == L';') continue;
		if (line.front() == L'[' && line.back() == L']') {
			section = line.substr(1, line.size() - 2);
			sections[section];
			continue;
		}
		const size_t equals = line.find(L'=');
		if (equals == std::wstring::npos) sections[section].emplace_back(line, L"");
		else sections[section].emplace_back(trimmed(line.substr(0, equals)), trimmed(line.substr(equals + 1)));
	}
	return sections;
}

std::vector<Json> parsePolicyScripts(const std::wstring& text, const std::wstring& scope, const std::wstring& engine) {
	std::vector<Json> scripts;
	for (const auto& [section, lines] : parseIniText(text)) {
		std::map<unsigned, std::pair<std::wstring, std::wstring>> numbered;
		for (const auto& [key, value] : lines) {
			size_t digits = 0;
			while (digits < key.size() && std::iswdigit(key[digits])) ++digits;
			if (digits == 0 || digits > 6) continue;
			const unsigned order = (unsigned)std::stoul(key.substr(0, digits));
			const std::wstring name = toLower(key.substr(digits));
			if (name == L"cmdline") numbered[order].first = value;
			else if (name == L"parameters") numbered[order].second = value;
		}
		for (const auto& [order, script] : numbered) {
			if (script.first.empty()) continue;
			Json o = Json::obj();
			o.add(L"Scope", Json::str(scope));
			o.add(L"Engine", Json::str(engine));
			o.add(L"Event", Json::str(section));
			o.add(L"Order", Json::num((unsigned long long)order));
			o.add(L"CommandLine", Json::str(script.first));
			o.add(L"Parameters", Json::str(script.second));
			scripts.push_back(std::move(o));
		}
	}
	return scripts;
}

std::vector<Json> parsePolicyTasks(const std::wstring& text, const std::wstring& scope) {
	std::vector<Json> tasks;
	const std::unique_ptr<XmlNode> root = xmlParse(text);
	if (!root) return tasks;
	for (const wchar_t* kind : { L"Task", L"TaskV2", L"ImmediateTask", L"ImmediateTaskV2" })
		for (const XmlNode* node : root->descendants(kind)) {
			// A TaskV2's definition nests a <Task> of the scheduler, without a clsid: not an entry.
			if (node->attribute(L"clsid").empty()) continue;
			Json o = Json::obj();
			o.add(L"Scope", Json::str(scope));
			o.add(L"Kind", Json::str(kind));
			o.add(L"Name", Json::str(node->attribute(L"name")));
			o.add(L"Changed", Json::str(node->attribute(L"changed")));
			if (const XmlNode* properties = node->child(L"Properties")) {
				o.add(L"Action", Json::str(properties->attribute(L"action")));
				o.add(L"RunAs", Json::str(properties->attribute(L"runAs")));
				// The older Task: its command in attributes; the V2: in an Exec element, as a task's own XML.
				std::wstring command = properties->attribute(L"appName"), arguments = properties->attribute(L"args");
				const std::vector<const XmlNode*> exec = properties->descendants(L"Exec");
				if (!exec.empty()) { command = exec.front()->textOf(L"Command"); arguments = exec.front()->textOf(L"Arguments"); }
				o.add(L"Command", Json::str(command));
				o.add(L"Arguments", Json::str(arguments));
			}
			tasks.push_back(std::move(o));
		}
	return tasks;
}

std::vector<std::wstring> storedPasswordElements(const std::wstring& text) {
	std::vector<std::wstring> names;
	const std::unique_ptr<XmlNode> root = xmlParse(text);
	if (!root) return names;
	for (const XmlNode* properties : root->descendants(L"Properties")) {
		if (properties->attribute(L"cpassword").empty()) continue;
		const std::wstring account = properties->attribute(L"userName");
		names.push_back(account.empty() ? properties->name : account);
	}
	return names;
}

bool sysvolDomainFolder(std::wstring& folder) {
	if (!conf.CurrentControlSet) return false;
	std::wstring sysvol;
	if (getRegSzValue(conf.CurrentControlSet, NETLOGON_PARAMETERS, L"SysVol", &sysvol) != ERROR_SUCCESS || sysvol.empty()) return false;
	while (!sysvol.empty() && sysvol.back() == L'\\') sysvol.pop_back();
	const size_t slash = sysvol.rfind(L'\\');
	if (slash == std::wstring::npos) return false;
	folder = sysvol.substr(0, slash) + L"\\domain";
	return true;
}

HRESULT GroupPolicies::getData() {
	log(0, L"ℹ️Group policies :");
	std::wstring source;
	if (!sysvolDomainFolder(source)) {
		log(2, L"❇️no SysVol in Services\\Netlogon\\Parameters: not a domain controller");
		return ERROR_SUCCESS;
	}
	const std::filesystem::path folder(extractedPath(source));
	if (!pathExists(folder.wstring())) return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
	std::error_code ec;
	for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(std::filesystem::path(extendedPath(folder.wstring())), ec)) {
		if (!e.is_directory(ec)) continue;
		const std::wstring name = e.path().filename().wstring();
		if (_wcsicmp(name.c_str(), L"Policies") == 0) {
			for (const std::filesystem::directory_entry& p : std::filesystem::directory_iterator(e.path(), ec))
				if (p.is_directory(ec)) rows_.push_back(readPolicy(folder / name / p.path().filename(), source + L"\\" + name + L"\\" + p.path().filename().wstring(), p.path().filename().wstring()));
			continue;
		}
		Json row = Json::obj();
		row.add(L"Path", Json::str(source + L"\\" + name));
		std::vector<std::wstring> files;
		listFiles(folder / name, L"", TREE_DEPTH_MAX, files);
		row.add(L"Files", stringArray(files));
		rows_.push_back(std::move(row));
	}
	log(2, L"❇️" + std::to_wstring(rows_.size()) + L" folder(s) of SYSVOL");
	return ERROR_SUCCESS;
}

HRESULT GroupPolicies::toJson() {
	JsonArrayWriter out("group_policies.json");
	for (const Json& row : rows_) out.add(row);
	return out.close();
}

void GroupPolicies::clear() {
	rows_.clear();
}
