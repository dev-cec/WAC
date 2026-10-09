/*! \file
 *  \brief Checks the decoding of the browsers' sessions: LZ4 blocks against
 *  an independent compressor, SNSS files built field by field, and both
 *  damaged at random.
 *
 *  WHY THIS TEST. A session file says which pages were open, and when: a
 *  field read one place off gives another URL or another instant, in valid
 *  JSON. The LZ4 vectors are made by Python's lz4 module (lz4.block.compress,
 *  store_size=False), an implementation independent of WAC's: each must
 *  decompress byte for byte. The SNSS files are written here as Chromium's
 *  base::Pickle lays them out (32-bit sizes, fields aligned to 32 bits): a
 *  navigation replaced by a later one, an older navigation without the
 *  fields after its title, a closed tab and its instant, a truncated command.
 *  Then every input, damaged and truncated at random (fixed seed), must never
 *  make the decoders read or write out of bounds — built with
 *  AddressSanitizer and UBSan.
 *
 *  Usage: browser_sessions_test [`<original>` `<lz4-block>`] ...
 *  Vectors: python3 -c "import lz4.block,sys; d=open(sys.argv[1],'rb').read();
 *           open(sys.argv[2],'wb').write(lz4.block.compress(d, store_size=False))" in out
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. browser_sessions.cpp
 *                        browser_sessions_test.cpp -o browser_sessions_test
 */
#include "browser_sessions.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! A file's bytes.
std::vector<uint8_t> readFile(const char* path) {
	std::ifstream f(path, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

//! Appends a little-endian integer.
template <class T>
void put(std::vector<uint8_t>& b, T value) {
	for (size_t i = 0; i < sizeof(T); ++i) b.push_back((uint8_t)((uint64_t)value >> (8 * i)));
}

//! A base::Pickle being written: fields aligned to 32 bits, the payload size in front.
class Pickle {
public:
	Pickle& integer(int32_t v) { put(payload_, (uint32_t)v); return *this; }
	Pickle& integer64(int64_t v) { put(payload_, (uint64_t)v); return *this; }
	Pickle& string(const std::string& s) {
		integer((int32_t)s.size());
		payload_.insert(payload_.end(), s.begin(), s.end());
		align();
		return *this;
	}
	Pickle& string16(const std::u16string& s) {
		integer((int32_t)s.size());
		for (char16_t c : s) put(payload_, (uint16_t)c);
		align();
		return *this;
	}
	std::vector<uint8_t> bytes() const {
		std::vector<uint8_t> b;
		put(b, (uint32_t)payload_.size());
		b.insert(b.end(), payload_.begin(), payload_.end());
		return b;
	}
private:
	void align() { while (payload_.size() % 4) payload_.push_back(0); }
	std::vector<uint8_t> payload_;
};

//! A navigation pickle with every field up to the HTTP status.
Pickle navigation(int32_t tab, int32_t index, const std::string& url, const std::u16string& title, int64_t time,
                  int32_t status) {
	Pickle p;
	p.integer(tab).integer(index).string(url).string16(title).string("state").integer(0x08000001).integer(0)
	 .string("https://referrer.invalid/").integer(1).string(url + "?original").integer(0).integer64(time)
	 .string16(u"").integer(status);
	return p;
}

//! Appends one command: its 16-bit size (identifier included), its identifier, its payload.
void command(std::vector<uint8_t>& file, uint8_t id, const std::vector<uint8_t>& payload) {
	put(file, (uint16_t)(payload.size() + 1));
	file.push_back(id);
	file.insert(file.end(), payload.begin(), payload.end());
}

//! An SNSS file's header.
std::vector<uint8_t> header() {
	std::vector<uint8_t> file = { 'S', 'N', 'S', 'S' };
	put(file, (uint32_t)3);
	return file;
}

//! A Session file: a navigation replaced, a second tab, an older navigation, a truncated end.
void checkSession() {
	std::vector<uint8_t> file = header();
	command(file, 6, navigation(7, 0, "https://first.invalid/", u"First", 13436012780545319, 200).bytes());
	command(file, 0, { 1, 2, 3, 4 });                                    // another command: skipped
	command(file, 6, navigation(7, 0, "https://replaced.invalid/", u"Replacé \U0001F600", 13436012780672533, 404).bytes());
	command(file, 6, navigation(8, 1, "https://second.invalid/", u"Second", 13436012781633592, 200).bytes());
	Pickle older;
	older.integer(9).integer(0).string("https://older.invalid/").string16(u"Older");
	command(file, 6, older.bytes());
	file.push_back(0x40);                                                // a size without its command
	SnssContents c;
	check(decodeSnss(file.data(), file.size(), SnssKind::Session, c), "session: refused");
	check(c.version == 3, "session: version");
	check(c.navigations.size() == 3, "session: " + std::to_string(c.navigations.size()) + " navigations, 3 expected");
	if (c.navigations.size() != 3) return;
	const SnssNavigation& a = c.navigations[0];
	check(a.tab == 7 && a.index == 0 && a.url == "https://replaced.invalid/", "session: the later navigation replaces the earlier");
	check(a.title == std::wstring(L"Replacé ") + (sizeof(wchar_t) == 4 ? std::wstring(1, (wchar_t)0x1F600)
	                                                                         : std::wstring{ (wchar_t)0xD83D, (wchar_t)0xDE00 }),
	      "session: UTF-16 title, surrogate pair");
	check(a.time == 13436012780672533 && a.httpStatus == 404 && a.transition == 0x08000001, "session: time, status, transition");
	check(a.referrer == "https://referrer.invalid/" && a.originalUrl == "https://replaced.invalid/?original", "session: referrer, original URL");
	check(c.navigations[1].tab == 8 && c.navigations[1].index == 1 && c.navigations[1].time == 13436012781633592, "session: second tab");
	const SnssNavigation& o = c.navigations[2];
	check(o.url == "https://older.invalid/" && o.title == L"Older" && o.time == 0 && o.httpStatus == 0,
	      "session: an older navigation, its absent fields left empty");
}

//! A Tabs file: a closed tab's navigation and its closing instant.
void checkTabRestore() {
	std::vector<uint8_t> file = header();
	command(file, 1, navigation(42, 1, "https://closed.invalid/", u"Closed", 13435924744424349, 200).bytes());
	std::vector<uint8_t> selected;
	put(selected, (uint32_t)42); put(selected, (uint32_t)1); put(selected, (uint64_t)13435924744733708);
	command(file, 4, selected);
	command(file, 6, navigation(43, 0, "https://not-a-navigation-here.invalid/", u"", 1, 200).bytes());   // 6 is no navigation in Tabs
	SnssContents c;
	check(decodeSnss(file.data(), file.size(), SnssKind::TabRestore, c), "tabs: refused");
	check(c.navigations.size() == 1 && c.navigations[0].url == "https://closed.invalid/", "tabs: the closed tab's navigation alone");
	check(c.closedTimes.count(42) && c.closedTimes[42] == 13435924744733708 && c.selectedIndex[42] == 1, "tabs: closing instant");
	const char notSnss[] = "SNSX\3\0\0\0";
	check(!decodeSnss(reinterpret_cast<const uint8_t*>(notSnss), 8, SnssKind::Session, c), "a wrong magic accepted");
}

//! A pickle whose string states more bytes than it holds: the navigation is skipped, never read past.
void checkLyingLength() {
	std::vector<uint8_t> file = header();
	Pickle p;
	p.integer(1).integer(0).integer(0x7FFFFFF0);   // a URL "of" 2 GiB
	command(file, 6, p.bytes());
	SnssContents c;
	check(decodeSnss(file.data(), file.size(), SnssKind::Session, c) && c.navigations.empty(), "a lying string length read");
}

//! Damaged copies of `input`, given to `decode`: within bounds, whatever the verdict.
template <class Decode>
void damage(const std::vector<uint8_t>& input, unsigned rounds, std::mt19937_64& rng, Decode decode) {
	if (input.empty()) return;
	for (unsigned round = 0; round < rounds; ++round) {
		std::vector<uint8_t> d = input;
		const int edits = 1 + (int)(rng() % 6);
		for (int k = 0; k < edits; ++k) d[rng() % d.size()] = (uint8_t)rng();
		if (rng() % 3 == 0) d.resize(rng() % d.size());
		decode(d);
		++g_checks;
	}
}

} // namespace

int main(int argc, char** argv) {
	checkSession();
	checkTabRestore();
	checkLyingLength();

	std::mt19937_64 rng(20261009);
	for (int i = 1; i + 1 < argc; i += 2) {
		const std::vector<uint8_t> original = readFile(argv[i]), block = readFile(argv[i + 1]);
		std::vector<uint8_t> out;
		check(decompressLz4Block(block.data(), block.size(), original.size(), out) && out == original,
		      std::string("LZ4 ") + argv[i + 1] + " not decompressed byte for byte");
		check(!decompressLz4Block(block.data(), block.size(), original.size() + 1, out), "LZ4: a wrong size accepted");
		std::vector<uint8_t> moz = { 'm', 'o', 'z', 'L', 'z', '4', '0', 0 };
		put(moz, (uint32_t)original.size());
		moz.insert(moz.end(), block.begin(), block.end());
		check(decompressMozLz4(moz.data(), moz.size(), 1u << 28, out) && out == original, "mozLz4 not decompressed");
		check(!decompressMozLz4(moz.data(), moz.size(), original.size() - 1, out), "mozLz4: the maximum not enforced");
		damage(block, 2000, rng, [&](const std::vector<uint8_t>& d) { decompressLz4Block(d.data(), d.size(), original.size(), out); });
		damage(moz, 500, rng, [&](const std::vector<uint8_t>& d) { decompressMozLz4(d.data(), d.size(), 1u << 20, out); });
	}

	// The SNSS files of the checks above, damaged.
	std::vector<uint8_t> session = header();
	command(session, 6, navigation(7, 0, "https://first.invalid/", u"First", 13436012780545319, 200).bytes());
	command(session, 1, navigation(8, 1, "https://second.invalid/", u"Second", 13436012781633592, 200).bytes());
	std::vector<uint8_t> selected;
	put(selected, (uint32_t)8); put(selected, (uint32_t)1); put(selected, (uint64_t)1);
	command(session, 4, selected);
	SnssContents c;
	damage(session, 5000, rng, [&](const std::vector<uint8_t>& d) {
		decodeSnss(d.data(), d.size(), SnssKind::Session, c);
		decodeSnss(d.data(), d.size(), SnssKind::TabRestore, c);
	});

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
