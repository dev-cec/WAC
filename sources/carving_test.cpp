/*! \file
 *  \brief Checks the carving's structure checks (carving.h): a PE, a ZIP and
 *         a PDF cut at their exact end, forged ones refused, nothing read
 *         outside the bytes given.
 *
 *  WHY THIS TEST. A carved file has nothing but its bytes: cut one byte
 *  short or long, it looks like the file and is not. Files built here, whose
 *  size is known, must come out at that size; their forged variants (a
 *  section past the end, an unknown machine, a central directory that is not
 *  where the end record says, a startxref pointing at nothing) must not come
 *  out at all. Then damaged heads against a PAGE_NOACCESS page
 *  (guard_page.h), and real files given on the command line — each must
 *  come out at exactly its size.
 *
 *  Usage: carving_test [file ...]
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>
#include "carving.h"
#include "guard_page.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned long long g_checks = 0, g_failures = 0;

/*! Records one check, printing the first failures. */
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

void put16(std::vector<uint8_t>& b, size_t at, uint16_t v) { b[at] = (uint8_t)v; b[at + 1] = (uint8_t)(v >> 8); }
void put32(std::vector<uint8_t>& b, size_t at, uint32_t v) { for (int k = 0; k < 4; ++k) b[at + k] = (uint8_t)(v >> (8 * k)); }

/*! A PE32+ of two sections, file alignment 512, a signature after them:
 *  its exact size is 0x1200 + 0x80 (the signature at 0x1200). */
std::vector<uint8_t> pe(bool signature = true) {
	std::vector<uint8_t> b(signature ? 0x1280 : 0x1200, 0);
	b[0] = 'M'; b[1] = 'Z';
	put32(b, 0x3C, 0x80);
	std::memcpy(b.data() + 0x80, "PE\0\0", 4);
	const size_t coff = 0x84, optional = coff + 20, size = 240;
	put16(b, coff, 0x8664);
	put16(b, coff + 2, 2);
	put16(b, coff + 16, (uint16_t)size);
	put16(b, optional, 0x20B);
	put32(b, optional + 36, 512);
	put32(b, optional + 60, 0x400);
	put32(b, optional + 108, 16);                    // NumberOfRvaAndSizes
	if (signature) { put32(b, optional + 112 + 4 * 8, 0x1200); put32(b, optional + 112 + 4 * 8 + 4, 0x80); }
	const size_t table = optional + size;
	put32(b, table + 16, 0x800); put32(b, table + 20, 0x400);              // .text: 0x400..0xC00
	put32(b, table + 40 + 16, 0x600); put32(b, table + 40 + 20, 0xC00);    // .data: 0xC00..0x1200
	return b;
}

/*! A ZIP of one stored file, and a comment: its exact size. */
std::vector<uint8_t> zip(const std::string& comment = "c") {
	const std::string name = "a.txt", data = "WAC carving witness";
	std::vector<uint8_t> b;
	auto bytes = [&](const void* p, size_t n) { b.insert(b.end(), (const uint8_t*)p, (const uint8_t*)p + n); };
	auto le = [&](uint32_t v, int n) { for (int k = 0; k < n; ++k) b.push_back((uint8_t)(v >> (8 * k))); };
	bytes("PK\3\4", 4); le(20, 2); le(0, 2); le(0, 2); le(0, 4); le(0, 4);
	le((uint32_t)data.size(), 4); le((uint32_t)data.size(), 4); le((uint32_t)name.size(), 2); le(0, 2);
	bytes(name.data(), name.size()); bytes(data.data(), data.size());
	const uint32_t cd = (uint32_t)b.size();
	bytes("PK\1\2", 4); le(20, 2); le(20, 2); le(0, 2); le(0, 2); le(0, 4); le(0, 4);
	le((uint32_t)data.size(), 4); le((uint32_t)data.size(), 4); le((uint32_t)name.size(), 2); le(0, 2); le(0, 2);
	le(0, 2); le(0, 2); le(0, 4); le(0, 4); bytes(name.data(), name.size());
	const uint32_t cdSize = (uint32_t)b.size() - cd;
	bytes("PK\5\6", 4); le(0, 2); le(0, 2); le(1, 2); le(1, 2); le(cdSize, 4); le(cd, 4);
	le((uint32_t)comment.size(), 2); bytes(comment.data(), comment.size());
	return b;
}

//! A PDF with a cross-reference table, then CR LF after %%EOF: its exact size.
std::vector<uint8_t> pdf() {
	std::string body = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
	const size_t xref = body.size();
	body += "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n"
	      + std::to_string(xref) + "\n%%EOF\r\n";
	return std::vector<uint8_t>(body.begin(), body.end());
}

//! A buffer with the file, then bytes that follow it on the disk.
std::vector<uint8_t> followed(std::vector<uint8_t> file, size_t more = 4096) {
	file.resize(file.size() + more, 0xA5);
	return file;
}

void known() {
	const std::vector<uint8_t> p = pe(), q = pe(false);
	CarvedStart s = carvedStart(p.data(), p.size());
	check(s.format == CarvedFormat::Pe && s.size == p.size(), "PE with a signature: size " + std::to_string(s.size));
	s = carvedStart(q.data(), q.size());
	check(s.format == CarvedFormat::Pe && s.size == q.size(), "PE without a signature: size " + std::to_string(s.size));
	const std::vector<uint8_t> z = zip(), zf = followed(z);
	s = carvedStart(zf.data(), zf.size());
	check(s.format == CarvedFormat::Zip && s.size == 0 && carvedEnd(CarvedFormat::Zip, zf.data(), zf.size()) == z.size(),
	      "ZIP: not cut at the end of its end record and comment");
	const std::vector<uint8_t> d = pdf(), df = followed(d);
	s = carvedStart(df.data(), df.size());
	check(s.format == CarvedFormat::Pdf && carvedEnd(CarvedFormat::Pdf, df.data(), df.size()) == d.size(),
	      "PDF: not cut after its %%EOF and line end");
	const std::vector<uint8_t> text = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!' };
	check(carvedStart(text.data(), text.size()).format == CarvedFormat::None, "a text taken for a carved format");
}

void forged() {
	std::vector<uint8_t> p = pe();
	put16(p, 0x84, 0x1234);
	check(carvedStart(p.data(), p.size()).format == CarvedFormat::None, "PE of an unknown machine accepted");
	p = pe();
	put16(p, 0x86, 200);
	check(carvedStart(p.data(), p.size()).format == CarvedFormat::None, "PE of 200 sections accepted");
	p = pe();
	put32(p, 0x84 + 20 + 240 + 20, 0x401);
	check(carvedStart(p.data(), p.size()).format == CarvedFormat::None, "PE section off its file alignment accepted");
	p = pe();
	put32(p, 0x84 + 20 + 112 + 4 * 8, 0x800);
	check(carvedStart(p.data(), p.size()).format == CarvedFormat::None, "PE signature inside its sections accepted");
	p = pe();
	put32(p, 0x3C, 0x7FFFFFF0);
	check(carvedStart(p.data(), p.size()).format == CarvedFormat::None, "PE header past the bytes accepted");
	std::vector<uint8_t> z = zip();
	put32(z, z.size() - 1 - 2 - 4, 3);               // the end record's central directory offset
	check(carvedEnd(CarvedFormat::Zip, z.data(), z.size()) == 0, "ZIP whose central directory is elsewhere accepted");
	z = zip("a long comment the bytes do not hold");
	z.resize(z.size() - 10);
	check(carvedEnd(CarvedFormat::Zip, z.data(), z.size()) == 0, "ZIP whose comment runs past the bytes accepted");
	std::string bad = "%PDF-1.4\n1 0 obj\nendobj\nstartxref\n3\n%%EOF\n";
	check(carvedEnd(CarvedFormat::Pdf, (const uint8_t*)bad.data(), bad.size()) == 0, "PDF whose startxref points at nothing accepted");
	bad = "%PDF-1.4\nno end here at all";
	check(carvedEnd(CarvedFormat::Pdf, (const uint8_t*)bad.data(), bad.size()) == 0, "PDF without %%EOF given an end");
}

/*! Damaged files against a guard page: nothing read outside, every size within the bytes. */
void guarded(std::mt19937_64& rng) {
	const std::vector<std::vector<uint8_t>> sound = { pe(), followed(zip(), 64), followed(pdf(), 64) };
	for (int n = 0; n < 30000; ++n) {
		std::vector<uint8_t> b = sound[(size_t)(rng() % sound.size())];
		for (int k = 1 + (int)(rng() % 6); k > 0; --k) b[rng() % b.size()] = (uint8_t)rng();
		if (rng() % 4 == 0) b.resize(1 + rng() % b.size());
		for (GuardSide side : { GuardSide::After, GuardSide::Before }) {
			GuardedCopy copy(b, side);
			const CarvedStart s = carvedStart(copy.data(), copy.size());
			check(s.format != CarvedFormat::Pe || s.size >= 0x200 || s.needed, "damaged PE: an absurd size");
			if (s.format == CarvedFormat::Pe && !s.size)
				check(carvedEnd(s.format, copy.data(), copy.size()) <= copy.size() || s.needed > copy.size(), "damaged PE: an end past its bytes");
			if (s.format == CarvedFormat::Zip || s.format == CarvedFormat::Pdf)
				check(carvedEnd(s.format, copy.data(), copy.size()) <= copy.size(), "damaged file: an end past its bytes");
		}
	}
}

/*! A real file: it must be recognised and cut at exactly its size. */
void real(const wchar_t* path) {
	std::ifstream in(path, std::ios::binary);
	std::vector<uint8_t> b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	const size_t size = b.size();
	b.resize(size + 8192, 0x5A);                     // what follows it on the disk
	// The head first, as the carving reads it: a cluster; then the rest when needed.
	const CarvedStart s = carvedStart(b.data(), std::min<size_t>(b.size(), 4096));
	const uint64_t end = s.size ? s.size : carvedEnd(s.format, b.data(), b.size());
	std::printf("  %ls: %ls, %llu of %zu bytes\n", path, carvedFormatName(s.format), (unsigned long long)end, size);
	check(s.format != CarvedFormat::None && end == size && (s.format != CarvedFormat::Pe || s.size || s.needed),
	      "real file not cut at its size: " + encodeText(path));
}

} // namespace

/*! Runs every check, then each file given.
 * @return 0 if all passed */
int wmain(int argc, wchar_t** argv) {
	std::mt19937_64 rng(20261024);
	known();
	forged();
	guarded(rng);
	for (int k = 1; k < argc; ++k) real(argv[k]);
	std::printf("%s: %llu check(s), %llu failure(s)\n", g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
