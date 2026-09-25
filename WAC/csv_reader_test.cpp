/*! \file
 *  \brief Confronts the CSV reading with Python's csv module, then with
 *  malformed texts.
 *
 *  WHY THIS TEST. A field read one column off hands a certificate authority
 *  the revocation list of another, and the output stays valid. The reference
 *  is Python's csv module, an independent implementation: it writes, for the
 *  same file, one line per record, `<number of fields>` then the SHA-256 of
 *  each field; every record must match. Then texts that must be refused, or
 *  read exactly, test the edges: quotes doubled, line breaks within a field,
 *  CRLF, a quote left open, a short record.
 *
 *  Usage: csv_reader_test `<file.csv>` `<reference written by Python>`
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. csv_reader.cpp sha.cpp csv_reader_test.cpp -o csv_reader_test
 */
#include "csv_reader.h"
#include "sha.h"
#include <cstdio>
#include <fstream>
#include <sstream>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

//! SHA-256 in lowercase hexadecimal, Python's hexdigest.
std::string sha256Hex(const std::string& s) {
	uint8_t d[32];
	sha256Bytes((const uint8_t*)s.data(), s.size(), d);
	static const char HEX[] = "0123456789abcdef";
	std::string r;
	for (uint8_t b : d) { r += HEX[b >> 4]; r += HEX[b & 15]; }
	return r;
}

//! Reads `text`, which must succeed with `expected`.
void expectRead(const std::string& text, const std::vector<std::vector<std::string>>& expected, const std::string& what) {
	std::vector<std::vector<std::string>> records;
	std::string reason;
	check(CsvRead(text, records, reason) && records == expected, what + (reason.empty() ? "" : ": " + reason));
}

//! Reads `text`, which must be refused.
void expectRefused(const std::string& text, const std::string& what) {
	std::vector<std::vector<std::string>> records;
	std::string reason;
	check(!CsvRead(text, records, reason), what + ": accepted");
}

} // namespace

int main(int argc, char** argv) {
	if (argc != 3) { std::printf("usage: csv_reader_test <file.csv> <python reference>\n"); return 2; }
	std::ifstream file(argv[1], std::ios::binary);
	const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	std::vector<std::vector<std::string>> records;
	std::string reason;
	check(CsvRead(text, records, reason), std::string("refused: ") + reason);
	std::ifstream reference(argv[2]);
	size_t line = 0;
	for (std::string expected; std::getline(reference, expected); ++line) {
		if (line >= records.size()) { check(false, "fewer records than the reference"); break; }
		std::string mine = std::to_string(records[line].size());
		for (const std::string& f : records[line]) mine += " " + sha256Hex(f);
		check(mine == expected, "record " + std::to_string(line) + " differs from Python's");
	}
	check(line == records.size(), std::to_string(records.size()) + " records, " + std::to_string(line) + " by Python");
	std::printf("  %zu records compared with Python's\n", line);

	expectRead("a,b\r\n1,2\r\n", { { "a", "b" }, { "1", "2" } }, "CRLF");
	expectRead("a,b\n\"x,\"\"y\"\"\nz\",\n", { { "a", "b" }, { "x,\"y\"\nz", "" } }, "quotes, comma and line break in a field");
	expectRead("a,b\n1,2", { { "a", "b" }, { "1", "2" } }, "no line break at the end");
	expectRead("\xEF\xBB\xBFh\n", { { "h" } }, "byte order mark");
	expectRefused("a,b\n\"open,2\n", "quote left open");
	expectRefused("a,b\n1\n", "short record");
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
