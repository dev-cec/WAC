/*! \file
 *  \brief Confronts the DEFLATE decompression with zlib, then with damaged
 *  input.
 *
 *  WHY THIS TEST. --update-trust decompresses what it downloads: Microsoft's
 *  CAB lists (MSZIP) and a ZIP list of vulnerable drivers. A wrong
 *  decompressor would give a wrong list of trusted roots — without an error.
 *  The test vectors are made by zlib, an independent implementation
 *  (compressobj with raw DEFLATE, levels 0 to 9, fixed and dynamic codes, a
 *  preset dictionary as MSZIP uses one): every one must decompress byte for
 *  byte; every one truncated and damaged at random (fixed seed) must never
 *  make the decoder read or write out of bounds — built with AddressSanitizer
 *  and UBSan — nor exceed the output limit.
 *
 *  Usage: inflate_test `<original>` `<raw-deflate>` [`<dictionary>`] ...
 *         (triples or pairs, a "-" dictionary meaning none)
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. inflate.cpp inflate_test.cpp -o inflate_test
 */
#include "inflate.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

std::vector<uint8_t> readAll(const char* path) {
	std::ifstream f(path, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

//! Decompresses from an exact-size heap copy: a byte read past it is caught.
bool inflateExact(const uint8_t* data, size_t size, std::vector<uint8_t>& out, size_t limit,
                  const std::vector<uint8_t>& dictionary) {
	std::unique_ptr<uint8_t[]> exact(new uint8_t[size ? size : 1]);
	if (size) std::memcpy(exact.get(), data, size);
	return Inflate(exact.get(), size, out, limit, dictionary);
}

} // namespace

/*! Runs every check.
 * @param argc,argv the vectors, as `<original> <raw-deflate> <dictionary or ->`
 * @return 0 if all passed */
int main(int argc, char** argv) {
	if (argc < 4 || (argc - 1) % 3 != 0) {
		std::printf("usage: inflate_test <original> <raw-deflate> <dictionary|-> ...\n");
		return 2;
	}
	std::mt19937_64 rng(20260926);
	for (int a = 1; a + 2 < argc; a += 3) {
		const std::vector<uint8_t> original = readAll(argv[a]);
		const std::vector<uint8_t> packed = readAll(argv[a + 1]);
		const std::vector<uint8_t> dictionary = std::strcmp(argv[a + 2], "-") ? readAll(argv[a + 2]) : std::vector<uint8_t>();
		const std::string name = argv[a + 1];

		std::vector<uint8_t> out;
		check(inflateExact(packed.data(), packed.size(), out, original.size(), dictionary) && out == original,
		      name + ": differs from zlib's original");
		// The limit is enforced: one byte less than the original is refused.
		if (!original.empty()) {
			std::vector<uint8_t> small;
			check(!inflateExact(packed.data(), packed.size(), small, original.size() - 1, dictionary),
			      name + ": output beyond the limit accepted");
		}
		for (size_t cut = 0; cut < packed.size(); cut += 1 + packed.size() / 50) {
			std::vector<uint8_t> o;
			inflateExact(packed.data(), cut, o, original.size() + 1024, dictionary);
			check(o.size() <= original.size() + 1024, name + ": truncated input exceeded the limit");
		}
		for (int m = 0; m < 400 && !packed.empty(); ++m) {
			std::vector<uint8_t> damaged = packed;
			const int edits = 1 + (int)(rng() % 6);
			for (int k = 0; k < edits; ++k) damaged[rng() % damaged.size()] = (uint8_t)rng();
			std::vector<uint8_t> o;
			inflateExact(damaged.data(), damaged.size(), o, original.size() + 1024, dictionary);
			check(o.size() <= original.size() + 1024, name + ": damaged input exceeded the limit");
		}
	}
	std::printf("%d vector(s); %s: %llu check(s), %llu failure(s)\n", (argc - 1) / 3,
	            g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
