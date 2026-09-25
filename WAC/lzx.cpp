/*! \file
 *  \brief LZX decompression of WOF chunks (see lzx.h).
 */
#include "lzx.h"
#include <cstring>

namespace {

const unsigned MAIN_SYMBOLS = 256 + 8 * 30;   //!< literals, then 8 lengths x 30 offset slots (32 KiB window)
const unsigned LENGTH_SYMBOLS = 249;          //!< the length tree: lengths beyond 7 + 2
const unsigned PRETREE_SYMBOLS = 20;          //!< the tree that codes the code lengths
const unsigned ALIGNED_SYMBOLS = 8;           //!< the low three bits of an aligned offset
const unsigned MAX_CODE_LENGTH = 16;
const int32_t E8_FILE_SIZE = 12000000;        //!< the translation's fixed file size, in WIM and WOF

//! Offset slots: first formatted offset and number of extra bits of each.
const uint32_t SLOT_BASE[30] = {
	0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
	1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576 };
const uint8_t SLOT_EXTRA_BITS[30] = {
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
	9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

/*! The bit stream: 16-bit little-endian words, bits taken from the most
 *  significant. Beyond the end of the input it yields zeros, as the reference
 *  decoders do; a stream that relies on them decodes into a chunk whose size
 *  or content the caller checks. */
class BitReader {
public:
	BitReader(const uint8_t* data, size_t size) : p_(data), end_(data + size) {}

	//! @param count 0 to 16 @return the next `count` bits
	uint32_t read(unsigned count) {
		if (count == 0) return 0;
		ensure(count);
		const uint32_t value = buffer_ >> (32 - count);
		buffer_ <<= count;
		held_ -= count;
		return value;
	}

	/*! Aligns on the next 16-bit word, as an uncompressed block requires: the
	 *  bits left of the current word are dropped — and if none is left, the
	 *  whole next word is. */
	void align() {
		ensure(1);
		buffer_ = 0;
		held_ = 0;
	}

	//! Takes raw bytes after align(). @return false if the input is too short
	bool bytes(uint8_t* out, size_t count) {
		if ((size_t)(end_ - p_) < count) return false;
		if (out) std::memcpy(out, p_, count);
		p_ += count;
		return true;
	}

private:
	void ensure(unsigned count) {
		while (held_ < count) {
			uint32_t word = 0;
			if (end_ - p_ >= 2) { word = (uint32_t)p_[0] | ((uint32_t)p_[1] << 8); p_ += 2; }
			else p_ = end_;
			buffer_ |= word << (16 - held_);
			held_ += 16;
		}
	}
	const uint8_t* p_;
	const uint8_t* end_;
	uint32_t buffer_ = 0;   //!< bits held, most significant first
	unsigned held_ = 0;
};

/*! A canonical Huffman code, decoded bit by bit: short, and correct for
 *  incomplete codes, a symbol absent from the code being an error. */
class Huffman {
public:
	/*! Builds the code from the lengths of its symbols.
	 *  @return false if over-subscribed (more codes than bits can hold) */
	bool build(const uint8_t* lengths, unsigned symbols) {
		std::memset(count_, 0, sizeof(count_));
		for (unsigned s = 0; s < symbols; ++s) ++count_[lengths[s]];
		count_[0] = 0;
		int left = 1;
		for (unsigned length = 1; length <= MAX_CODE_LENGTH; ++length) {
			left = (left << 1) - count_[length];
			if (left < 0) return false;
		}
		uint16_t offset[MAX_CODE_LENGTH + 2] = {};
		for (unsigned length = 1; length <= MAX_CODE_LENGTH; ++length)
			offset[length + 1] = (uint16_t)(offset[length] + count_[length]);
		for (unsigned s = 0; s < symbols; ++s)
			if (lengths[s]) symbol_[offset[lengths[s]]++] = (uint16_t)s;
		return true;
	}

	//! @return the next symbol, or -1 if the bits match no code
	int decode(BitReader& bits) const {
		int code = 0, first = 0, index = 0;
		for (unsigned length = 1; length <= MAX_CODE_LENGTH; ++length) {
			code |= (int)bits.read(1);
			const int count = count_[length];
			if (code - count < first) return symbol_[index + (code - first)];
			index += count;
			first = (first + count) << 1;
			code <<= 1;
		}
		return -1;
	}

private:
	uint16_t count_[MAX_CODE_LENGTH + 1] = {};
	uint16_t symbol_[MAIN_SYMBOLS] = {};
};

/*! Reads code lengths [start, end) as differences with the previous ones,
 *  coded by a pretree read first (20 lengths of 4 bits). Codes 0 to 16: a
 *  difference, modulo 17; 17 and 18: a run of zeros (4 + 4 bits, 20 + 5
 *  bits); 19: a run of 4 + 1 bit of one same difference. A run is clamped at
 *  `end`: it cannot write past the table.
 *  @return false if the pretree is invalid or a code is not in it */
bool readLengths(BitReader& bits, uint8_t* lengths, unsigned start, unsigned end) {
	uint8_t pretreeLengths[PRETREE_SYMBOLS];
	for (uint8_t& l : pretreeLengths) l = (uint8_t)bits.read(4);
	Huffman pretree;
	if (!pretree.build(pretreeLengths, PRETREE_SYMBOLS)) return false;
	for (unsigned i = start; i < end;) {
		const int code = pretree.decode(bits);
		if (code < 0) return false;
		if (code <= 16) {
			lengths[i] = (uint8_t)((lengths[i] + 17 - code) % 17);
			++i;
			continue;
		}
		unsigned run;
		uint8_t value = 0;
		if (code == 17) run = 4 + bits.read(4);
		else if (code == 18) run = 20 + bits.read(5);
		else {
			run = 4 + bits.read(1);
			const int same = pretree.decode(bits);
			if (same < 0 || same > 16) return false;
			value = (uint8_t)((lengths[i] + 17 - same) % 17);
		}
		for (; run && i < end; --run) lengths[i++] = value;
	}
	return true;
}

/*! Undoes the x86 CALL translation: an E8 byte is followed by an absolute
 *  target, made relative again. Without this step, every CALL of a
 *  decompressed binary points elsewhere — valid bytes, wrong code. */
void undoE8Translation(uint8_t* data, size_t size) {
	if (size <= 10) return;
	for (size_t i = 0; i < size - 10;) {
		if (data[i] != 0xE8) { ++i; continue; }
		const int32_t position = (int32_t)i;
		int32_t target;
		std::memcpy(&target, data + i + 1, 4);                 // little-endian, as x86
		if (target >= 0) {
			if (target < E8_FILE_SIZE) target -= position;
			else { i += 5; continue; }
		}
		else if (target >= -position) target += E8_FILE_SIZE;
		else { i += 5; continue; }
		std::memcpy(data + i + 1, &target, 4);
		i += 5;
	}
}

} // namespace

size_t LzxInflate(const uint8_t* compressed, size_t compressedSize,
                  uint8_t* output, size_t outputSize) {
	if (!compressed || !output || outputSize == 0 || outputSize > LZX_CHUNK_SIZE) return 0;
	BitReader bits(compressed, compressedSize);
	uint8_t mainLengths[MAIN_SYMBOLS] = {};          // the previous block's, at first all 0
	uint8_t lengthLengths[LENGTH_SYMBOLS] = {};
	uint32_t recent[3] = { 1, 1, 1 };
	size_t position = 0;

	while (position < outputSize) {
		const unsigned type = bits.read(3);
		size_t blockSize = bits.read(1) ? LZX_CHUNK_SIZE : bits.read(16);
		if (blockSize == 0) return 0;
		// The last block of a short chunk may announce the default size.
		if (blockSize > outputSize - position) blockSize = outputSize - position;
		const size_t blockEnd = position + blockSize;

		if (type == 3) {                                  // UNCOMPRESSED
			bits.align();
			uint8_t header[12];
			if (!bits.bytes(header, sizeof(header))) return 0;
			for (unsigned k = 0; k < 3; ++k)
				recent[k] = (uint32_t)header[4 * k] | ((uint32_t)header[4 * k + 1] << 8)
				          | ((uint32_t)header[4 * k + 2] << 16) | ((uint32_t)header[4 * k + 3] << 24);
			if (!bits.bytes(output + position, blockSize)) return 0;
			position = blockEnd;
			if ((blockSize & 1) && !bits.bytes(nullptr, 1)) return 0;   // padding to 16 bits
			continue;
		}
		if (type != 1 && type != 2) return 0;

		Huffman aligned;
		if (type == 2) {                                  // ALIGNED: its own code for the low 3 bits
			uint8_t alignedLengths[ALIGNED_SYMBOLS];
			for (uint8_t& l : alignedLengths) l = (uint8_t)bits.read(3);
			if (!aligned.build(alignedLengths, ALIGNED_SYMBOLS)) return 0;
		}
		if (!readLengths(bits, mainLengths, 0, 256)
		    || !readLengths(bits, mainLengths, 256, MAIN_SYMBOLS)
		    || !readLengths(bits, lengthLengths, 0, LENGTH_SYMBOLS)) return 0;
		Huffman mainCode, lengthCode;
		if (!mainCode.build(mainLengths, MAIN_SYMBOLS) || !lengthCode.build(lengthLengths, LENGTH_SYMBOLS))
			return 0;

		while (position < blockEnd) {
			const int symbol = mainCode.decode(bits);
			if (symbol < 0) return 0;
			if (symbol < 256) { output[position++] = (uint8_t)symbol; continue; }

			const unsigned match = (unsigned)symbol - 256;
			const unsigned slot = match >> 3;
			size_t length = (match & 7) + 2;
			if ((match & 7) == 7) {
				const int extra = lengthCode.decode(bits);
				if (extra < 0) return 0;
				length += (size_t)extra;
			}
			uint32_t offset;
			if (slot < 3) {                               // one of the three recent offsets
				offset = recent[slot];
				recent[slot] = recent[0];
				recent[0] = offset;
			}
			else {
				const unsigned extraBits = SLOT_EXTRA_BITS[slot];
				uint32_t value;
				if (type == 2 && extraBits >= 3) {
					value = bits.read(extraBits - 3) << 3;
					const int low = aligned.decode(bits);
					if (low < 0) return 0;
					value += (uint32_t)low;
				}
				else value = bits.read(extraBits);
				offset = SLOT_BASE[slot] + value - 2;
				recent[2] = recent[1];
				recent[1] = recent[0];
				recent[0] = offset;
			}
			// Nothing before the chunk (its own window), nothing past the block.
			if (offset == 0 || offset > position || length > blockEnd - position) return 0;
			for (size_t k = 0; k < length; ++k, ++position) output[position] = output[position - offset];
		}
	}
	undoE8Translation(output, outputSize);
	return outputSize;
}
