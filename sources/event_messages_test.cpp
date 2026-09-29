/*! \file
 *  \brief Walks, STEP BY STEP, the chain that produces an event's plain-text
 *  message.
 *
 *  WHY THIS HARNESS. The chain has five links, and a mass failure does not say
 *  which one gave way: the collection stays valid, the field disappears, and
 *  until now each hypothesis needed a full collection of several minutes to be
 *  ruled out. This program takes the same route and prints every step.
 *
 *  It runs ON THE EXAMINED MACHINE (or a test VM), the SOFTWARE hive and the
 *  provider binaries being readable only there.
 *
 *  Usage: event_messages_test `<SOFTWARE hive>` `<guid>` [id[:version] ...]
 *  Excluded from WAC's build by the "_test.cpp" pattern.
 */
#include "tools.h"
#include "pe_resource.h"
#include "wevt.h"
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

void line(const wchar_t* step, bool ok, const std::wstring& detail) {
	wprintf(L"  %ls  %-42ls %ls\n", ok ? L"ok   " : L"FAILED", step, detail.c_str());
}

} // namespace

/*! Runs the test.
 * @param argc,argv `<SOFTWARE hive>` `<guid>` [id[:version] ...]
 * @return 0 if every check passed */
int wmain(int argc, wchar_t** argv) {
	if (argc < 3) {
		wprintf(L"usage: event_messages_test <SOFTWARE hive> <guid> [id[:version] ...]\n");
		return 2;
	}
	conf.systemDrive = L"C:";

	// 1. The hive, and the provider's key.
	ORHKEY software = NULL;
	HRESULT hr = OROpenHive(argv[1], &software);
	line(L"opening of the SOFTWARE hive", hr == ERROR_SUCCESS,
	      hr == ERROR_SUCCESS ? argv[1] : L"code " + std::to_wstring(hr));
	if (hr != ERROR_SUCCESS) return 1;
	conf.Software = software;

	std::wstring guid = argv[2];
	const std::wstring key =
		L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + guid;
	std::wstring declare;
	HRESULT hrv = getRegSzValue(software, key.c_str(), L"ResourceFileName", &declare);
	if (hrv != ERROR_SUCCESS || declare.empty())
		hrv = getRegSzValue(software, key.c_str(), L"MessageFileName", &declare);
	line(L"ResourceFileName / MessageFileName", hrv == ERROR_SUCCESS && !declare.empty(),
	      declare.empty() ? L"(absent)" : declare);
	if (declare.empty()) return 1;

	// 2. Resolving the path.
	const std::wstring resolved = binaryPath(declare);
	std::vector<std::wstring> candidates;
	if (!resolved.empty()) candidates.push_back(resolved);
	{
		const std::wstring nameOnly = std::filesystem::path(
			resolved.empty() ? declare : resolved).filename().wstring();
		if (!nameOnly.empty())
			candidates.push_back(conf.systemDrive + L"\\Windows\\System32\\" + nameOnly);
	}
	std::wstring found;
	for (const std::wstring& c : candidates) {
		std::error_code ec;
		const bool exists = std::filesystem::exists(c, ec);
		line(L"path candidate", exists, c);
		if (exists && found.empty()) found = c;
	}
	if (found.empty()) return 1;

	// 3. The two resources.
	PeResource pe;
	const bool open = pe.open(found);
	line(L"PE reading", open, open ? found : pe.error());
	if (!open) return 1;

	std::wstring types;
	for (const std::wstring& t : pe.typesPresent()) types += t + L" ";
	line(L"resource types present", !types.empty(), types);

	const std::vector<uint8_t> wevtResource = pe.namedResource(L"WEVT_TEMPLATE");
	line(L"WEVT_TEMPLATE", !wevtResource.empty(),
	      std::to_wstring(wevtResource.size()) + L" bytes");

	std::vector<uint8_t> messageTable = pe.resource(PE_RT_MESSAGETABLE);
	std::wstring messageSource = L"in the binary";
	if (messageTable.empty()) {
		// Localised satellite: on a localised system the table is not in the
		// DLL itself, but in <language>\<name>.mui.
		const std::filesystem::path p = found;
		for (PCWSTR l : { L"fr-FR", L"en-US", L"de-DE", L"es-ES" }) {
			const std::wstring mui = p.parent_path().wstring() + L"\\" + l + L"\\"
			                       + p.filename().wstring() + L".mui";
			std::error_code ec;
			if (!std::filesystem::exists(mui, ec)) continue;
			PeResource peMui;
			if (!peMui.open(mui)) continue;
			messageTable = peMui.resource(PE_RT_MESSAGETABLE);
			if (!messageTable.empty()) { messageSource = mui; break; }
		}
	}
	line(L"MESSAGETABLE", !messageTable.empty(),
	      std::to_wstring(messageTable.size()) + L" bytes, " + messageSource);

	// 4. The parsing, then the resolution of the requested identifiers.
	WevtMetadata meta;
	const size_t eventCount = meta.analyse(wevtResource, guid);
	line(L"events described", eventCount > 0, std::to_wstring(eventCount));
	TableMessages table;
	const size_t messageCount = table.analyse(messageTable);
	line(L"messages read", messageCount > 0, std::to_wstring(messageCount));

	for (int i = 3; i < argc; ++i) {
		std::wstring a = argv[i];
		const size_t sep = a.find(L':');
		const uint16_t id = (uint16_t)wcstoul(a.substr(0, sep).c_str(), nullptr, 10);
		const uint8_t ver = (uint8_t)(sep == std::wstring::npos ? 0
		                              : wcstoul(a.substr(sep + 1).c_str(), nullptr, 10));
		const uint32_t m = meta.messageId(id, ver);
		const std::wstring messageTemplate = m ? table.text(m) : std::wstring();
		line(L"event -> message", !messageTemplate.empty(),
		      std::to_wstring(id) + L" v" + std::to_wstring(ver) + L" -> "
		      + std::to_wstring(m));
		if (!messageTemplate.empty()) wprintf(L"         %ls\n", messageTemplate.substr(0, 160).c_str());
	}

	ORCloseHive(software);
	return 0;
}
