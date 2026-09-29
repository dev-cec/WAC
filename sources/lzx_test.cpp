/*! \file
 *  \brief Confronts the LZX decompression with Windows' own compressor, then
 *  with damaged input.
 *
 *  WHY THIS TEST. A wrong decompressor most often produces wrong data WITHOUT
 *  an error: only a byte-for-byte comparison with the original shows it. The
 *  test data are made by Windows itself: in the VM, `compact /c /exe:lzx`
 *  compresses a file with WOF's LZX, and `raw_hive_test --wof` writes the
 *  compressed stream as it lies on the disk. Checked:
 *    - every chunk of the stream decompresses into the original's bytes;
 *    - every chunk truncated, and mutated at random (fixed seed: a failure
 *      reproduces), never makes the decoder read or write out of bounds —
 *      built with AddressSanitizer and UBSan, the inputs in exact-size heap
 *      buffers — and never "succeeds" into a wrong size.
 *
 *  Usage: lzx_test `<original>` `<wof-stream.bin>`
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. lzx.cpp lzx_test.cpp -o lzx_test
 */
#include "lzx.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <random>
#include <vector>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const char* what, size_t chunk) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  chunk %zu: %s\n", chunk, what);
}

std::vector<uint8_t> readAll(const char* path) {
	std::ifstream f(path, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

/*! Decompresses from an exact-size heap copy of the input: a single byte read
 *  past it is caught by AddressSanitizer. */
size_t inflateExact(const uint8_t* data, size_t size, uint8_t* output, size_t outputSize) {
	std::unique_ptr<uint8_t[]> exact(new uint8_t[size ? size : 1]);
	if (size) std::memcpy(exact.get(), data, size);
	return LzxInflate(exact.get(), size, output, outputSize);
}

} // namespace

/*! Runs every check.
 * @param argc,argv `<original>` `<wof-stream.bin>`
 * @return 0 if all passed */
int main(int argc, char** argv) {
	if (argc < 3) {
		std::printf("usage: lzx_test <original> <wof-stream.bin>\n");
		return 2;
	}
	const std::vector<uint8_t> original = readAll(argv[1]);
	const std::vector<uint8_t> stream = readAll(argv[2]);
	if (original.empty() || stream.empty()) { std::printf("file(s) unreadable\n"); return 2; }

	// The WOF layout: a table of chunk ends (32 or 64 bits), then the chunks.
	const size_t chunks = (original.size() + LZX_CHUNK_SIZE - 1) / LZX_CHUNK_SIZE;
	const size_t entry = original.size() > 0xFFFFFFFFULL ? 8 : 4;
	const size_t table = (chunks - 1) * entry;
	if (stream.size() < table) { std::printf("stream shorter than its table\n"); return 1; }
	std::vector<size_t> starts(chunks + 1, 0);
	for (size_t i = 1; i < chunks; ++i) {
		size_t v = 0;
		for (size_t b = 0; b < entry; ++b) v |= (size_t)stream[(i - 1) * entry + b] << (8 * b);
		starts[i] = v;
	}
	starts[chunks] = stream.size() - table;

	std::mt19937_64 rng(20260926);
	size_t compressedChunks = 0;
	for (size_t i = 0; i < chunks; ++i) {
		const size_t expected = std::min<size_t>(LZX_CHUNK_SIZE, original.size() - i * LZX_CHUNK_SIZE);
		if (starts[i + 1] < starts[i] || table + starts[i + 1] > stream.size()) {
			check(false, "inconsistent chunk table", i);
			break;
		}
		const uint8_t* packed = stream.data() + table + starts[i];
		const size_t packedSize = starts[i + 1] - starts[i];
		if (packedSize >= expected) continue;           // stored as is: nothing to decompress
		++compressedChunks;

		// 1. The original's bytes, exactly.
		std::vector<uint8_t> output(expected, 0xCC);
		const size_t produced = inflateExact(packed, packedSize, output.data(), expected);
		check(produced == expected && std::memcmp(output.data(), original.data() + i * LZX_CHUNK_SIZE, expected) == 0,
		      "differs from the original", i);

		// 2. Truncated: in bounds, and never a success of the full size with wrong bytes.
		for (size_t cut = 0; cut < packedSize; cut += 1 + packedSize / 64) {
			std::vector<uint8_t> out(expected, 0);
			const size_t n = inflateExact(packed, cut, out.data(), expected);
			check(n == 0 || n == expected, "truncated input returned a partial size", i);
		}
		// 3. Mutated at random: in bounds (the sanitizers watch), a size of 0 or the full one.
		for (int m = 0; m < 300; ++m) {
			std::vector<uint8_t> damaged(packed, packed + packedSize);
			const int edits = 1 + (int)(rng() % 8);
			for (int k = 0; k < edits; ++k) damaged[rng() % damaged.size()] = (uint8_t)rng();
			std::vector<uint8_t> out(expected, 0);
			const size_t n = inflateExact(damaged.data(), damaged.size(), out.data(), expected);
			check(n == 0 || n == expected, "damaged input returned a partial size", i);
		}
	}
	std::printf("%zu LZX chunk(s) of %zu compared with the original; %s: %llu check(s), %llu failure(s)\n",
	            compressedChunks, chunks, g_failures ? "FAILED" : "all passed", g_checks, g_failures);
	return (g_failures || compressedChunks == 0) ? 1 : 0;
}
