/*! \file
 *  \brief Proves that the jump list and Prefetch parsers never read outside
 *         their buffer, and always end.
 *
 *  WHY THIS TEST. lnk_test.cpp covers the shortcut parser. The automatic jump
 *  lists add an OLE container (sector chains, allocation tables, directory
 *  entries) and the DestList; the custom jump lists a scan for shortcut
 *  headers; the Prefetch files the SCCA structure. Every one of them reads at
 *  offsets and follows chains the file itself declares.
 *
 *  Each input is placed against a PAGE_NOACCESS page, at its end then at its
 *  start (see guard_page.h): one byte read outside it raises an access
 *  violation. A WATCHDOG also stops the test if one parse does not end — a
 *  cyclic sector chain looping for ever is a defect too, on a forged file.
 *
 *  Inputs, for each file given:
 *    - the file itself;
 *    - its truncations: every length up to 2048 bytes, then about 1000 more,
 *      spread over the rest of the file;
 *    - 1000 copies with 1 to 8 random bytes overwritten (fixed seed).
 *  A compressed Prefetch ("MAM") is decompressed first: the test aims at WAC's
 *  SCCA parser, not at ntdll's decompressor. Its compressed form is still
 *  given whole and in its truncations, for WAC's checks around the call.
 *
 *  Registry hives ("hive") go through WAC's own reader (offline_registry.cpp):
 *  the whole tree is walked — subkeys, values, ORQueryInfoKey.
 *
 *  Usage: `parsers_test jumplist-auto|jumplist-custom|prefetch|hive <file> [file ...]`
 *  Built by `build-windows.sh --test`; runs on Windows (real ntdll and propsys)
 *  or under Wine for the jump lists.
 */
#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include "guard_page.h"
#include "jumplist_automatic.h"
#include "jumplist_custom.h"
#include "prefetchs.h"
#include "offline_registry.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

std::atomic<unsigned long long> g_done{ 0 };  //!< parses finished, watched by the watchdog
std::mutex g_labelMutex;                     //!< guards g_label
std::string g_label;                         //!< the input being parsed, for the watchdog's report

/*! Stops the process if no parse finishes for 60 seconds, naming the input. */
void watchdog() {
	unsigned long long last = g_done.load();
	for (;;) {
		std::this_thread::sleep_for(std::chrono::seconds(60));
		const unsigned long long now = g_done.load();
		if (now == last) {
			std::lock_guard<std::mutex> lock(g_labelMutex);
			std::printf("  FAILED  no end after 60 s: %s\n", g_label.c_str());
			std::fflush(stdout);
			ExitProcess(3);
		}
		last = now;
	}
}

/*! Reports the input being parsed when the process faults, then lets it end.
 *  Without it, a read outside the buffer ends the test with a bare exit code
 *  on Windows: the input and the faulting instruction are what make it
 *  reproducible. The address is given relative to the executable, for
 *  addr2line / nm. */
LONG WINAPI reportFault(EXCEPTION_POINTERS* info) {
	const EXCEPTION_RECORD* r = info->ExceptionRecord;
	const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(GetModuleHandleW(nullptr));
	const ULONG_PTR at = reinterpret_cast<ULONG_PTR>(r->ExceptionAddress);
	std::string label;
	{
		std::lock_guard<std::mutex> lock(g_labelMutex);
		label = g_label;
	}
	std::printf("  FAILED  exception 0x%08lX at exe+0x%llx, address read 0x%llx: %s\n",
	            (unsigned long)r->ExceptionCode, (unsigned long long)(at - base),
	            (unsigned long long)(r->NumberParameters > 1 ? r->ExceptionInformation[1] : 0),
	            label.c_str());
	std::fflush(stdout);
	return EXCEPTION_EXECUTE_HANDLER;
}

/*! Walks a key and its subtree through every function WAC uses.
 *  @return the number of keys walked */
size_t walkHive(ORHKEY key, int depth) {
	size_t keys = 1;
	DWORD subkeys = 0, values = 0, maxName = 0, maxValueName = 0, maxValue = 0;
	FILETIME lastWrite;
	if (ORQueryInfoKey(key, nullptr, nullptr, &subkeys, &maxName, nullptr, &values,
	                   &maxValueName, &maxValue, nullptr, &lastWrite) != ERROR_SUCCESS) return keys;
	std::vector<wchar_t> name(16384);
	std::vector<BYTE> data;
	for (DWORD i = 0; i < values; ++i) {
		DWORD cchName = (DWORD)name.size(), type = 0, size = 0;
		if (OREnumValue(key, i, name.data(), &cchName, &type, nullptr, &size) != ERROR_MORE_DATA && size == 0) continue;
		data.assign(size + 1, 0);
		DWORD got = size;
		cchName = (DWORD)name.size();
		OREnumValue(key, i, name.data(), &cchName, &type, data.data(), &got);
		got = size;
		ORGetValue(key, nullptr, name.data(), &type, data.data(), &got);
	}
	if (depth > 512) return keys;
	for (DWORD i = 0; i < subkeys; ++i) {
		DWORD cchName = (DWORD)name.size();
		if (OREnumKey(key, i, name.data(), &cchName, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;
		ORHKEY child = nullptr;
		if (OROpenKey(key, name.data(), &child) == ERROR_SUCCESS) {
			keys += walkHive(child, depth + 1);
			ORCloseKey(child);
		}
	}
	return keys;
}

/*! Parses one input of the given kind, placed against a guard page.
 *  @param kind "jumplist-auto", "jumplist-custom" or "prefetch"
 *  @param input the bytes
 *  @param side which end touches the guard page
 *  @param label description of the input, for the watchdog
 *  @return what was decoded: DestList entries, shortcuts, or files loaded by
 *          the Prefetch — to show the whole file is parsed to its end */
size_t parseGuarded(const std::string& kind, const std::vector<BYTE>& input,
                    GuardSide side, const std::string& label) {
	{
		std::lock_guard<std::mutex> lock(g_labelMutex);
		g_label = label + (side == GuardSide::After ? " (guard after)" : " (guard before)");
	}
	GuardedCopy copy(input, side);
	if (copy.data() == nullptr) return 0;
	size_t decoded = 0;
	if (kind == "jumplist-auto") {
		AutomaticDestination list(L"test.automaticDestinations-ms", L"S-1-0-0");
		list.parse(copy.data(), copy.size());
		decoded = list.entries.size();
	}
	else if (kind == "jumplist-custom") {
		CustomDestinationCategory category(copy.data(), copy.size(), L"test.customDestinations-ms", L"S-1-0-0");
		decoded = category.recentDocs.size();
	}
	else if (kind == "hive") {
		ORHKEY root = nullptr;
		if (openHiveBuffer(copy.data(), copy.size(), &root) == ERROR_SUCCESS) {
			decoded = walkHive(root, 0);
			ORCloseHive(root);
		}
	}
	else {
		Prefetch prefetch(L"test.pf");
		prefetch.parse(copy.data(), copy.size());
		decoded = prefetch.filenames.size();
	}
	++g_done;
	return decoded;
}

/*! Parses an input with the guard page on each side in turn.
 *  @return what the first parse decoded (see parseGuarded) */
size_t parseBothSides(const std::string& kind, const std::vector<BYTE>& input, const std::string& label) {
	const size_t decoded = parseGuarded(kind, input, GuardSide::After, label);
	parseGuarded(kind, input, GuardSide::Before, label);
	return decoded;
}

/*! Runs every input derived from `data`.
 *  @param whole receives what the whole file decoded
 *  @return the number of inputs parsed (each on both sides) */
unsigned long long exercise(const std::string& kind, const std::vector<BYTE>& data,
                            const std::string& name, std::mt19937& rng, size_t& whole) {
	unsigned long long runs = 0;
	whole = parseBothSides(kind, data, name + " whole");
	++runs;
	// Truncations: all of the first 2048 lengths, then about 1000 more.
	const size_t stride = data.size() > 2048 ? std::max<size_t>(1, (data.size() - 2048) / 1000) : 1;
	for (size_t n = 0; n < data.size(); n += (n < 2048 ? 1 : stride)) {
		parseBothSides(kind, std::vector<BYTE>(data.begin(), data.begin() + n),
		               name + " truncated at " + std::to_string(n));
		++runs;
	}
	if (data.empty()) return runs;
	std::uniform_int_distribution<size_t> where(0, data.size() - 1);
	std::uniform_int_distribution<int> value(0, 255), count(1, 8);
	for (int k = 0; k < 1000; ++k) {
		std::vector<BYTE> bad = data;
		for (int c = count(rng); c > 0; --c) bad[where(rng)] = (BYTE)value(rng);
		parseBothSides(kind, bad, name + " corruption " + std::to_string(k));
		++runs;
	}
	return runs;
}

} // namespace

/*! Runs the test.
 * @param argc,argv `<kind> <file> [file ...]`
 * @return 0 if no input made a parser read outside its buffer or loop */
int main(int argc, char** argv) {
	if (argc < 3) {
		std::printf("usage: parsers_test jumplist-auto|jumplist-custom|prefetch|hive <file> [file ...]\n");
		return 2;
	}
	const std::string kind = argv[1];
	if (kind != "jumplist-auto" && kind != "jumplist-custom" && kind != "prefetch" && kind != "hive") {
		std::printf("unknown kind: %s\n", kind.c_str());
		return 2;
	}
	SetUnhandledExceptionFilter(reportFault);
	std::thread(watchdog).detach();
	std::mt19937 rng(20260924);
	unsigned long long runs = 0;
	for (int a = 2; a < argc; ++a) {
		std::ifstream f(argv[a], std::ios::binary);
		std::vector<BYTE> file((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		if (file.empty()) { std::printf("  FAILED  unreadable: %s\n", argv[a]); return 1; }

		std::vector<BYTE> data = file;
		if (kind == "prefetch" && file.size() >= 3 && file[0] == 'M' && file[1] == 'A' && file[2] == 'M') {
			// The compressed form, whole and truncated: WAC's checks around ntdll.
			parseBothSides(kind, file, std::string(argv[a]) + " compressed");
			for (size_t n = 0; n < file.size(); n += std::max<size_t>(1, file.size() / 200))
				parseBothSides(kind, std::vector<BYTE>(file.begin(), file.begin() + n),
				               std::string(argv[a]) + " compressed, truncated at " + std::to_string(n));
			if (decompressPrefetch(file.data(), file.size(), data) != ERROR_SUCCESS) {
				std::printf("  FAILED  not decompressed: %s\n", argv[a]);
				return 1;
			}
		}
		size_t whole = 0;
		runs += exercise(kind, data, argv[a], rng, whole);
		std::printf("  ok     %s: %zu bytes, %zu %s\n", argv[a], data.size(), whole,
		            kind == "prefetch" ? "file(s) loaded" : kind == "jumplist-auto" ? "DestList entries"
		            : kind == "hive" ? "key(s)" : "shortcut(s)");
		std::fflush(stdout);
	}
	std::printf("all passed: %llu inputs, each with the guard page after then before it: "
	            "no read outside the buffer, every parse ended\n", runs);
	return 0;
}
