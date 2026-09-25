/*! \file
 *  \brief DEFLATE decompression (see inflate.h).
 */
#include "inflate.h"
#include <cstring>

namespace {

const unsigned MAX_BITS = 15;
const unsigned LITERAL_SYMBOLS = 288;
const unsigned DISTANCE_SYMBOLS = 30;

//! Lengths 257..285: base and extra bits (RFC 1951, 3.2.5).
const uint16_t LENGTH_BASE[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                   35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
const uint8_t LENGTH_EXTRA[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                                   3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
//! Distances 0..29: base and extra bits.
const uint16_t DISTANCE_BASE[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                                     257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
                                     8193, 12289, 16385, 24577 };
const uint8_t DISTANCE_EXTRA[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                                     7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
//! Order of the code length code lengths (RFC 1951, 3.2.7).
const uint8_t CODE_LENGTH_ORDER[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

/*! The bit stream: bytes consumed least significant bit first. Reading past
 *  the end is an error, remembered: DEFLATE has no padding to rely on. */
class BitReader {
public:
	BitReader(const uint8_t* data, size_t size) : p_(data), end_(data + size) {}

	//! @param count 0 to 16 @return the next `count` bits, least significant first
	uint32_t read(unsigned count) {
		while (held_ < count) {
			if (p_ == end_) { overrun_ = true; return 0; }
			buffer_ |= (uint32_t)*p_++ << held_;
			held_ += 8;
		}
		const uint32_t value = buffer_ & ((1u << count) - 1);
		buffer_ >>= count;
		held_ -= count;
		return value;
	}
	//! Drops the bits left of the current byte (stored blocks start on a byte).
	void alignToByte() { buffer_ = 0; held_ = 0; }
	//! Takes raw bytes. @return false if the input is too short
	bool bytes(uint8_t* out, size_t count) {
		if ((size_t)(end_ - p_) < count) { overrun_ = true; return false; }
		if (count) std::memcpy(out, p_, count);      // an empty stored block: no buffer yet
		p_ += count;
		return true;
	}
	bool overrun() const { return overrun_; }

private:
	const uint8_t* p_;
	const uint8_t* end_;
	uint32_t buffer_ = 0;
	unsigned held_ = 0;
	bool overrun_ = false;
};

/*! A canonical Huffman code, decoded bit by bit (puff's method). */
class Huffman {
public:
	//! @return false if over-subscribed
	bool build(const uint8_t* lengths, unsigned symbols) {
		std::memset(count_, 0, sizeof(count_));
		for (unsigned s = 0; s < symbols; ++s) ++count_[lengths[s]];
		count_[0] = 0;
		int left = 1;
		for (unsigned length = 1; length <= MAX_BITS; ++length) {
			left = (left << 1) - count_[length];
			if (left < 0) return false;
		}
		uint16_t offset[MAX_BITS + 2] = {};
		for (unsigned length = 1; length <= MAX_BITS; ++length)
			offset[length + 1] = (uint16_t)(offset[length] + count_[length]);
		for (unsigned s = 0; s < symbols; ++s)
			if (lengths[s]) symbol_[offset[lengths[s]]++] = (uint16_t)s;
		return true;
	}
	//! @return the next symbol, or -1 if the bits match no code
	int decode(BitReader& bits) const {
		int code = 0, first = 0, index = 0;
		for (unsigned length = 1; length <= MAX_BITS; ++length) {
			// DEFLATE codes are sent most significant bit first, one bit at a time.
			code |= (int)bits.read(1);
			if (bits.overrun()) return -1;
			const int count = count_[length];
			if (code - count < first) return symbol_[index + (code - first)];
			index += count;
			first = (first + count) << 1;
			code <<= 1;
		}
		return -1;
	}
private:
	uint16_t count_[MAX_BITS + 1] = {};
	uint16_t symbol_[LITERAL_SYMBOLS] = {};
};

/*! Decodes one compressed block with its codes. Back-references reach into
 *  the dictionary (MSZIP) then the output. */
bool decodeBlock(BitReader& bits, const Huffman& literals, const Huffman& distances,
                 std::vector<uint8_t>& output, size_t base, size_t maxOutput,
                 const std::vector<uint8_t>& dictionary) {
	for (;;) {
		const int symbol = literals.decode(bits);
		if (symbol < 0) return false;
		if (symbol < 256) {
			if (output.size() - base >= maxOutput) return false;
			output.push_back((uint8_t)symbol);
			continue;
		}
		if (symbol == 256) return true;                    // end of block
		const unsigned lengthIndex = (unsigned)symbol - 257;
		if (lengthIndex >= 29) return false;
		const size_t length = LENGTH_BASE[lengthIndex] + bits.read(LENGTH_EXTRA[lengthIndex]);
		const int distanceSymbol = distances.decode(bits);
		if (distanceSymbol < 0 || distanceSymbol >= (int)DISTANCE_SYMBOLS) return false;
		const size_t distance = DISTANCE_BASE[distanceSymbol] + bits.read(DISTANCE_EXTRA[distanceSymbol]);
		if (bits.overrun()) return false;
		const size_t produced = output.size() - base;
		if (distance > produced + dictionary.size()) return false;   // before the start
		if (length > maxOutput - produced) return false;
		for (size_t k = 0; k < length; ++k) {
			const size_t at = output.size() - base;         // bytes produced so far
			const uint8_t byte = distance <= at ? output[output.size() - distance]
			                                    : dictionary[dictionary.size() - (distance - at)];
			output.push_back(byte);
		}
	}
}

} // namespace

bool Inflate(const uint8_t* compressed, size_t compressedSize, std::vector<uint8_t>& output,
             size_t maxOutput, const std::vector<uint8_t>& dictionary) {
	if (!compressed) return false;
	BitReader bits(compressed, compressedSize);
	const size_t base = output.size();
	for (bool last = false; !last;) {
		last = bits.read(1) != 0;
		const unsigned type = bits.read(2);
		if (bits.overrun()) return false;
		if (type == 0) {                                   // STORED
			bits.alignToByte();
			uint8_t header[4];
			if (!bits.bytes(header, 4)) return false;
			const unsigned length = header[0] | (header[1] << 8);
			const unsigned complement = header[2] | (header[3] << 8);
			if ((length ^ 0xFFFF) != complement) return false;
			if (length > maxOutput - (output.size() - base)) return false;
			const size_t at = output.size();
			output.resize(at + length);
			if (!bits.bytes(output.data() + at, length)) return false;
			continue;
		}
		Huffman literals, distances;
		uint8_t lengths[LITERAL_SYMBOLS + DISTANCE_SYMBOLS] = {};
		if (type == 1) {                                   // FIXED codes (RFC 1951, 3.2.6)
			for (unsigned s = 0; s < 144; ++s) lengths[s] = 8;
			for (unsigned s = 144; s < 256; ++s) lengths[s] = 9;
			for (unsigned s = 256; s < 280; ++s) lengths[s] = 7;
			for (unsigned s = 280; s < 288; ++s) lengths[s] = 8;
			uint8_t distanceLengths[DISTANCE_SYMBOLS];
			for (uint8_t& l : distanceLengths) l = 5;
			literals.build(lengths, LITERAL_SYMBOLS);
			distances.build(distanceLengths, DISTANCE_SYMBOLS);
		}
		else if (type == 2) {                              // DYNAMIC codes
			const unsigned literalCount = bits.read(5) + 257;
			const unsigned distanceCount = bits.read(5) + 1;
			const unsigned codeLengthCount = bits.read(4) + 4;
			if (literalCount > 286 || distanceCount > 30) return false;
			uint8_t codeLengthLengths[19] = {};
			for (unsigned k = 0; k < codeLengthCount; ++k) codeLengthLengths[CODE_LENGTH_ORDER[k]] = (uint8_t)bits.read(3);
			Huffman codeLengths;
			if (!codeLengths.build(codeLengthLengths, 19)) return false;
			for (unsigned k = 0; k < literalCount + distanceCount;) {
				const int symbol = codeLengths.decode(bits);
				if (symbol < 0) return false;
				if (symbol < 16) { lengths[k++] = (uint8_t)symbol; continue; }
				uint8_t value = 0;
				unsigned repeat;
				if (symbol == 16) {
					if (k == 0) return false;               // nothing to repeat
					value = lengths[k - 1];
					repeat = 3 + bits.read(2);
				}
				else if (symbol == 17) repeat = 3 + bits.read(3);
				else repeat = 11 + bits.read(7);
				if (k + repeat > literalCount + distanceCount) return false;
				while (repeat--) lengths[k++] = value;
			}
			if (lengths[256] == 0) return false;          // no end of block
			if (!literals.build(lengths, literalCount) || !distances.build(lengths + literalCount, distanceCount))
				return false;
		}
		else return false;
		if (bits.overrun()) return false;
		if (!decodeBlock(bits, literals, distances, output, base, maxOutput, dictionary)) return false;
	}
	return !bits.overrun();
}
