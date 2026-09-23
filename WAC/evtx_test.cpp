/*! \file
 *  \brief Validation harness for the EVTX parser, outside WAC.
 *
 *  The same intent as raw_hive_test: a parsing defect produces JSON that is
 *  valid and wrong, which the VM harness does not see. This test confronts the
 *  decoder with real logs, among them logs deliberately damaged (a chunk with a
 *  wrong signature, a log not closed, null sizes).
 *
 *  Usage: evtx_test.exe <file.evtx> [number of records to print]
 *         evtx_test.exe --collect `<root>` `<output>`   (the COMPLETE chain: reads
 *         `<root>\Windows\System32\winevt\Logs\*.evtx` as the collection does, and
 *         writes `<output>\events.json`. Exercises the XML -> Event mapping and
 *         the streaming write, which decoding alone does not cover.)
 *         evtx_test.exe <file.evtx> --dump   (one record per line,
 *         "identifier<TAB>xml" in UTF-8, line breaks escaped, for automatic
 *         comparison with an independent implementation)
 *  Excluded from WAC's build by the "_test.cpp" pattern of build-windows.sh.
 */
#include "evtx.h"
#include "tools.h"
#include "events.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <map>
#include <vector>
#include <fcntl.h>
#include <io.h>

/*  `conf` is WAC's global configuration, defined by main.cpp. This harness does
 *  not embed main.cpp: it provides an empty instance of it. evtx.cpp does not
 *  read it — tools.cpp is what references it — but the linker asks for it. A
 *  default instance is enough and keeps the test isolated.
 */
AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

//! Writes a wide string to stdout in UTF-8, without going through the console's
//! code page: the automatic comparison requires stable bytes.
static void writeUtf8(const std::wstring& s) {
	if (s.empty()) return;
	const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
	if (n <= 0) return;
	std::vector<char> buffer(n);
	WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), buffer.data(), n, nullptr, nullptr);
	fwrite(buffer.data(), 1, n, stdout);
}

/*! Runs the test.
 * @param argc,argv see the file header for the modes
 * @return 0 if every check passed */
int wmain(int argc, wchar_t** argv) {
	if (argc < 2) {
		wprintf(L"usage: evtx_test <file.evtx> [count|--dump]\n");
		wprintf(L"       evtx_test --collect <root> <output>\n");
		return 2;
	}

	/*  The OLD WRITING STRATEGY, on the same data: every event built in memory,
	 *  then serialised in one go, as the collection through the API did. The
	 *  decoding is identical — only the writing changes — which isolates the cost
	 *  of the strategy from that of the source, and allows a memory comparison
	 *  that the examined machine, for its part, does not allow to be redone
	 *  identically.
	 */
	if (wcscmp(argv[1], L"--collect-memory") == 0) {
		if (argc < 4) { wprintf(L"usage: evtx_test --collect-memory <root> <output>\n"); return 2; }
		conf.mountpoint = argv[2];
		int n = WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, nullptr, 0, nullptr, nullptr);
		std::vector<char> tmp(n > 0 ? n : 1);
		WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, tmp.data(), n, nullptr, nullptr);
		conf._outputDir = tmp.data();

		const std::wstring directory = extractedPath(L"\\Windows\\System32\\winevt\\Logs");
		std::vector<Json> all;
		unsigned long long read = 0;
		for (const std::filesystem::path& j : listFilesByExtension(directory, { L".evtx" })) {
			const std::wstring channel = EvtxChannelFromFileName(j.filename().wstring());
			EvtxReadFile(j.wstring(), [&](const EvtxRecord& e) {
				const std::unique_ptr<XmlNode> root = xmlParse(e.xml);
				if (root) { all.push_back(Event(*root, channel, e.id,
				                     j.filename().wstring()).toJson()); ++read; }
				return true;
			}, nullptr);
		}
		Json arr = Json::arr();
		for (Json& o : all) arr.push(std::move(o));
		const HRESULT hr = writeJsonFile("events.json", arr);
		wprintf(L"hresult      : 0x%08lx\n", (unsigned long)hr);
		wprintf(L"events       : %llu\n", read);
		return 0;
	}

	// The complete chain: the same as the one WAC runs, without the rest of the
	// collection. `mountpoint` is the root of the extracted copies (see tools.h).
	if (wcscmp(argv[1], L"--collect") == 0) {
		if (argc < 4) { wprintf(L"usage: evtx_test --collect <root> <output>\n"); return 2; }
		conf.mountpoint = argv[2];
		int n = WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, nullptr, 0, nullptr, nullptr);
		std::vector<char> tmp(n > 0 ? n : 1);
		WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, tmp.data(), n, nullptr, nullptr);
		conf._outputDir = tmp.data();
		Events ev;
		const HRESULT hr = ev.getData();
		wprintf(L"hresult      : 0x%08lx\n", (unsigned long)hr);
		wprintf(L"logs         : %llu\n", ev.files);
		wprintf(L"events       : %llu\n", ev.read);
		wprintf(L"discarded    : %llu\n", ev.unreadable);
		return 0;
	}
	const bool dump = (argc > 2) && (wcscmp(argv[2], L"--dump") == 0);
	const long toDisplay = (!dump && argc > 2) ? wcstol(argv[2], nullptr, 10) : 0;
	if (dump) _setmode(_fileno(stdout), _O_BINARY);

	long displayed = 0;
	unsigned long long empties = 0, withSystem = 0, withEventData = 0;
	std::map<std::wstring, unsigned long long> providers;

	EvtxSummary summary;
	const HRESULT hr = EvtxReadFile(argv[1], [&](const EvtxRecord& e) {
		if (e.xml.empty()) ++empties;
		if (e.xml.find(L"<System") != std::wstring::npos) ++withSystem;
		if (e.xml.find(L"<EventData") != std::wstring::npos
		    || e.xml.find(L"<UserData") != std::wstring::npos) ++withEventData;
		// Provider: the first Name attribute of the first Provider.
		const size_t p = e.xml.find(L"<Provider Name=\"");
		if (p != std::wstring::npos) {
			const size_t d = p + 16, f = e.xml.find(L'"', d);
			if (f != std::wstring::npos) ++providers[e.xml.substr(d, f - d)];
		}
		if (dump) {
			std::wstring line = std::to_wstring(e.id) + L"\t";
			for (wchar_t ch : e.xml) {
				if (ch == L'\n') line += L"\\n";
				else if (ch == L'\r') line += L"\\r";
				else if (ch == L'\\') line += L"\\\\";
				else line += ch;
			}
			line += L"\n";
			writeUtf8(line);
			return true;
		}
		if (displayed < toDisplay) {
			++displayed;
			wprintf(L"--- record %llu\n%ls\n", e.id, e.xml.c_str());
		}
		return true;
	}, &summary);

	if (dump) return 0;
	wprintf(L"file         : %ls\n", argv[1]);
	wprintf(L"hresult      : 0x%08lx\n", (unsigned long)hr);
	wprintf(L"diagnostic   : %ls\n", summary.diagnostic.c_str());
	wprintf(L"read         : %llu\n", summary.read);
	wprintf(L"unreadable   : %llu\n", summary.unreadable);
	wprintf(L"empty xml    : %llu\n", empties);
	wprintf(L"with System  : %llu\n", withSystem);
	wprintf(L"with Data    : %llu\n", withEventData);
	wprintf(L"providers    : %llu\n", (unsigned long long)providers.size());
	for (const auto& kv : providers)
		if (kv.second > summary.read / 20) wprintf(L"   %-60ls %llu\n", kv.first.c_str(), kv.second);
	return 0;
}
