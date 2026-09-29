/*! \file
 *  \brief Proves that the shortcut parser never reads outside its buffer.
 *
 *  WHY THIS TEST. A shortcut is read at offsets the file itself declares; a
 *  truncated or forged .lnk used to make WAC read past its buffer — and publish
 *  what it found there, in a perfectly valid JSON. Such an over-read does not
 *  crash on its own: it has to be made to crash. Each input is therefore placed
 *  against a page mapped PAGE_NOACCESS, at its end then at its start (see
 *  guard_page.h). A single byte read outside the input raises an access
 *  violation, and the test stops there.
 *
 *  Inputs, for each shortcut given on the command line:
 *    - the file itself, and every one of its truncations (1 byte to size - 1);
 *    - 2,000 copies with random bytes overwritten (fixed seed: reproducible).
 *
 *  Usage: `lnk_test <file.lnk> [file.lnk ...]`
 *  Excluded from WAC's build by the "_test.cpp" pattern. Built by
 *  `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <cstdio>
#include <fstream>
#include <random>
#include <vector>
#include "guard_page.h"
#include "recent_docs.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

/*! Parses `data` placed against a PAGE_NOACCESS page, after it then before it.
 *  @param data the bytes of the shortcut
 *  @return the number of shell items decoded */
size_t parseGuarded(const std::vector<BYTE>& data) {
	size_t items = 0;
	for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
		GuardedCopy copy(data, side);
		if (copy.data() == nullptr) return 0;
		RecentDoc doc(copy.data(), copy.size(), L"test.lnk", L"S-1-0-0");
		items = doc.idLists.size();
	}
	return items;
}

} // namespace

/*! Runs the test.
 * @param argc,argv `<file.lnk> [file.lnk ...]`
 * @return 0 if no input made the parser read outside its buffer */
int main(int argc, char** argv) {
	if (argc < 2) {
		std::printf("usage: lnk_test <file.lnk> [file.lnk ...]\n");
		return 2;
	}
	std::mt19937 rng(20260924);
	unsigned long long runs = 0;
	for (int a = 1; a < argc; ++a) {
		std::ifstream f(argv[a], std::ios::binary);
		std::vector<BYTE> lnk((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		if (lnk.empty()) { std::printf("  FAILED  unreadable: %s\n", argv[a]); return 1; }

		const size_t full = parseGuarded(lnk);
		std::printf("  ok     %s: %zu bytes, %zu shell item(s)\n", argv[a], lnk.size(), full);

		for (size_t n = 1; n < lnk.size(); ++n) {                  // every truncation
			parseGuarded(std::vector<BYTE>(lnk.begin(), lnk.begin() + n));
			++runs;
		}
		std::uniform_int_distribution<size_t> where(0, lnk.size() - 1);
		std::uniform_int_distribution<int> value(0, 255), count(1, 8);
		for (int k = 0; k < 2000; ++k) {                           // random corruptions
			std::vector<BYTE> bad = lnk;
			for (int c = count(rng); c > 0; --c) bad[where(rng)] = (BYTE)value(rng);
			parseGuarded(bad);
			++runs;
		}
	}
	std::printf("all passed: %llu truncated or corrupted input(s), each with the guard page after "
	            "then before it: no read outside the buffer\n", runs);
	return 0;
}
