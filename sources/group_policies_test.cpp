/*! \file
 *  \brief Checks the readers of a policy's files (group_policies.cpp) on contents
 *         of known meaning: a Registry.pol built here entry by entry, in the
 *         format Microsoft documents; scripts, tasks and a preference file.
 *
 *  The real files of a policy are confronted with Get-GPRegistryValue in the VM
 *  cycle (check-json.py, check_group_policies).
 *
 *  Usage: group_policies_test — built by `build-windows.sh --test`, runs under Wine.
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include "group_policies.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned g_checks = 0, g_failures = 0;

//! Records one check, printing a failure.
void check(bool ok, const char* what) {
	++g_checks;
	if (ok) return;
	++g_failures;
	printf("FAILED: %s\n", what);
}

//! Appends a UTF-16 text, its terminator if asked.
void addText(std::vector<uint8_t>& out, const std::wstring& text, bool terminated) {
	for (wchar_t c : text) { out.push_back((uint8_t)c); out.push_back((uint8_t)(c >> 8)); }
	if (terminated) { out.push_back(0); out.push_back(0); }
}

//! Appends a number of 4 bytes.
void addNumber(std::vector<uint8_t>& out, uint32_t number) {
	for (int i = 0; i < 4; ++i) out.push_back((uint8_t)(number >> (8 * i)));
}

/*! One entry `[key;value;type;size;data]`.
 *  @param announced the size it says, which may lie */
void addEntry(std::vector<uint8_t>& out, const std::wstring& key, const std::wstring& value, uint32_t type,
              const std::vector<uint8_t>& data, uint32_t announced) {
	addText(out, L"[", false);
	addText(out, key, true);
	addText(out, L";", false);
	addText(out, value, true);
	addText(out, L";", false);
	addNumber(out, type);
	addText(out, L";", false);
	addNumber(out, announced);
	addText(out, L";", false);
	out.insert(out.end(), data.begin(), data.end());
	addText(out, L"]", false);
}

//! The header of a Registry.pol.
std::vector<uint8_t> polHeader() {
	std::vector<uint8_t> out = { 'P', 'R', 'e', 'g' };
	addNumber(out, 1);
	return out;
}

/*! Registry.pol: values and types read, a lying size refused. */
void registryPol() {
	std::vector<uint8_t> file = polHeader(), number;
	addNumber(number, 7);
	std::vector<uint8_t> text;
	addText(text, L"wac", true);
	addEntry(file, L"Software\\Wac", L"Number", REG_DWORD, number, 4);
	addEntry(file, L"Software\\Wac", L"Text", REG_SZ, text, (uint32_t)text.size());
	const std::vector<PolicyRegistryEntry> entries = parseRegistryPol(file.data(), file.size());
	check(entries.size() == 2, "two entries");
	if (entries.size() == 2) {
		check(entries[0].key == L"Software\\Wac" && entries[0].value == L"Number" && entries[0].type == REG_DWORD, "key, value and type");
		check(entries[0].data == number, "a number's data");
		check(entries[1].toJson().dump().find(L"wac") != std::wstring::npos, "a text's data");
	}
	std::vector<uint8_t> lying = polHeader();
	addEntry(lying, L"Software\\Wac", L"Number", REG_DWORD, number, 0x7FFFFFFF);
	check(parseRegistryPol(lying.data(), lying.size()).empty(), "a size beyond the file ends the reading");
	check(parseRegistryPol(file.data(), 7).empty(), "a truncated header gives nothing");
	std::vector<uint8_t> truncated(file.begin(), file.end() - 3);
	check(parseRegistryPol(truncated.data(), truncated.size()).size() == 1, "a truncated entry is not read");
	std::vector<uint8_t> other = file;
	other[0] = 'X';
	check(parseRegistryPol(other.data(), other.size()).empty(), "another signature gives nothing");
}

/*! scripts.ini: by event and number, CmdLine with its Parameters. */
void scripts() {
	const std::vector<Json> found = parsePolicyScripts(L"[Startup]\r\n0CmdLine=a.cmd\r\n0Parameters=-x\r\n1CmdLine=b.cmd\r\n[Logon]\r\n0CmdLine=c.cmd\r\n", L"Machine", L"Script");
	check(found.size() == 3, "three scripts");
	std::wstring all;
	for (const Json& s : found) all += s.dump();
	check(all.find(L"a.cmd") != std::wstring::npos && all.find(L"-x") != std::wstring::npos && all.find(L"Logon") != std::wstring::npos, "their commands, parameters and events");
	check(parsePolicyScripts(L"[Startup]\r\nCmdLine=no-number\r\n", L"Machine", L"Script").empty(), "a line without its number is no script");
}

/*! A preferences' task: immediate, its command in an Exec. */
void tasks() {
	const std::wstring xml = L"<ScheduledTasks clsid=\"{1}\"><ImmediateTaskV2 clsid=\"{2}\" name=\"w\" changed=\"2026-11-03\"><Properties action=\"C\" runAs=\"NT AUTHORITY\\System\"><Task version=\"1.2\"><Actions><Exec><Command>cmd.exe</Command><Arguments>/c rem</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2></ScheduledTasks>";
	const std::vector<Json> found = parsePolicyTasks(xml, L"Machine");
	check(found.size() == 1, "one task, the scheduler's nested Task not counted");
	if (found.size() == 1) {
		const std::wstring text = found[0].dump();
		check(text.find(L"ImmediateTaskV2") != std::wstring::npos && text.find(L"cmd.exe") != std::wstring::npos && text.find(L"/c rem") != std::wstring::npos, "its kind and command");
	}
}

/*! A stored password: named by its element, its value nowhere. */
void storedPasswords() {
	const std::vector<std::wstring> names = storedPasswordElements(L"<Groups><User><Properties userName=\"witness\" cpassword=\"VALUE\"/></User><User><Properties userName=\"none\" cpassword=\"\"/></User></Groups>");
	check(names.size() == 1 && names[0] == L"witness", "the element holding one, by its account");
}

} // namespace

int wmain() {
	registryPol();
	scripts();
	tasks();
	storedPasswords();
	printf("%u checks, %u failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
