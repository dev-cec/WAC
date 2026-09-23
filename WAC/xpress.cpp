#include "xpress.h"
#include <cstring>

/*  xpress.cpp — see xpress.h. The comments here do not restate the format: they
 *  mark the two places where an implementation goes wrong without an error.
 */

namespace {

const size_t TABLE_SIZE = 256;   //!< 512 code lengths on 4 bits
const int    SYMBOLS     = 512;
const int    MAX_LENGTH = 15;

/*! The format's bit stream: 16-bit little-endian words, bits consumed from
 *  most to least significant.
 *
 *  The byte cursor is SHARED with the reading of extended lengths: both move
 *  through the same stream, as the format intends.
 */
class TrainDeBits {
public:
	TrainDeBits(const uint8_t* d, size_t size, size_t depart)
		: d_(d), size_(size), byte_(depart) {}

	//! Ensures at least `n` bits are available, padding with zeros at the end of the stream.
	void fill(unsigned n) {
		while (bits_ < n) {
			if (size_ < 2 || byte_ > size_ - 2) {
				// End of stream: pad with zeros rather than reading outside.
				buffer_ <<= 16;
				bits_ += 16;
			}
			else {
				/*  The word is LITTLE-ENDIAN: its most significant byte is d_[byte_+1].
				    It goes into the buffer first, so that consuming from the top returns the
				    bits in the right order. */
				buffer_ = (buffer_ << 8) | d_[byte_ + 1];
				buffer_ = (buffer_ << 8) | d_[byte_];
				bits_ += 16;
				byte_ += 2;
			}
		}
	}

	//! Takes the `n` most significant bits of the buffer.
	uint32_t value(unsigned n) {
		if (n == 0) return 0;
		if (n > 32) return 0;
		fill(n);
		uint32_t v = buffer_;
		if (n < 32) v >>= (bits_ - n);
		bits_ -= n;
		if (bits_ == 0) buffer_ = 0;
		else            buffer_ &= 0xFFFFFFFFu >> (32 - bits_);
		return v;
	}

	//! Next byte of the stream, on the shared cursor.
	bool nextByte(uint8_t* v) {
		if (byte_ >= size_) return false;
		*v = d_[byte_++];
		return true;
	}
	bool word16(uint32_t* v) {
		if (size_ < 2 || byte_ > size_ - 2) return false;
		*v = (uint32_t)(d_[byte_] | (d_[byte_ + 1] << 8));
		byte_ += 2;
		return true;
	}
	bool word32(uint32_t* v) {
		if (size_ < 4 || byte_ > size_ - 4) return false;
		*v = (uint32_t)d_[byte_] | ((uint32_t)d_[byte_ + 1] << 8)
		   | ((uint32_t)d_[byte_ + 2] << 16) | ((uint32_t)d_[byte_ + 3] << 24);
		byte_ += 4;
		return true;
	}
	unsigned available() const { return bits_; }

private:
	const uint8_t* d_;
	size_t   size_;
	size_t   byte_;
	uint32_t buffer_ = 0;
	unsigned bits_ = 0;
};

/*! Canonical Huffman tree, built from the code lengths.
 *
 *  Codes are assigned by increasing length, then by increasing symbol number:
 *  that is the format's convention, and the only one that makes the stream
 *  decodable.
 */
class Huffman {
public:
	bool build(const uint8_t* lengths) {
		std::memset(nb_, 0, sizeof(nb_));
		int used = 0;
		for (int s = 0; s < SYMBOLS; ++s) {
			const uint8_t l = lengths[s];
			if (l > MAX_LENGTH) return false;
			if (l) { ++nb_[l]; ++used; }
		}
		if (used == 0) return false;

		int code = 0, offset = 0;
		for (int l = 1; l <= MAX_LENGTH; ++l) {
			first_[l] = code;
			start_[l] = offset;
			code = (code + nb_[l]) << 1;
			offset += nb_[l];
		}
		// Symbols sorted by (length, number).
		int cursor[MAX_LENGTH + 1];
		for (int l = 0; l <= MAX_LENGTH; ++l) cursor[l] = start_[l];
		for (int s = 0; s < SYMBOLS; ++s) {
			const uint8_t l = lengths[s];
			if (l) symbols_[cursor[l]++] = (uint16_t)s;
		}
		return true;
	}

	//! Decodes a symbol, or -1 if no code matches.
	int decoder(TrainDeBits& bits) const {
		int code = 0;
		for (int l = 1; l <= MAX_LENGTH; ++l) {
			code = (code << 1) | (int)bits.value(1);
			if (nb_[l] && (code - first_[l]) < nb_[l] && (code - first_[l]) >= 0)
				return symbols_[start_[l] + (code - first_[l])];
		}
		return -1;
	}

private:
	int      nb_[MAX_LENGTH + 1] = { 0 };
	int      first_[MAX_LENGTH + 1] = { 0 };
	int      start_[MAX_LENGTH + 1] = { 0 };
	uint16_t symbols_[SYMBOLS] = { 0 };
};

} // namespace

size_t XpressHuffmanInflate(const uint8_t* compressed, size_t compressedSize,
                             uint8_t* output, size_t outputSize) {
	if (!compressed || !output || outputSize == 0) return 0;
	// The table alone takes 256 bytes; below that there is no chunk.
	if (compressedSize <= TABLE_SIZE) return 0;

	uint8_t lengths[SYMBOLS];
	for (size_t i = 0; i < TABLE_SIZE; ++i) {
		lengths[2 * i]     = (uint8_t)(compressed[i] & 0x0F);
		lengths[2 * i + 1] = (uint8_t)(compressed[i] >> 4);
	}
	Huffman tree;
	if (!tree.build(lengths)) return 0;

	TrainDeBits bits(compressed, compressedSize, TABLE_SIZE);
	bits.fill(32);                       // priming, as the format requires

	size_t written = 0;
	while (written < outputSize) {
		const int symbol = tree.decoder(bits);
		if (symbol < 0) break;             // unknown code: inconsistent stream

		if (symbol < 256) output[written++] = (uint8_t)symbol;

		/*  TOP UP TO 16 BITS AFTER EVERY SYMBOL, literals included, and BEFORE
		    reading a back-reference. This is not an optimisation: the top-up
		    advances the byte cursor by two, and that cursor is the one extended
		    lengths are read from. Topping up only after back-references
		    desynchronises the chunk — measured: 16 chunks correct out of 137, the
		    others wrong without any error. */
		if (bits.available() < 16) bits.fill(16);

		if (symbol < 256) continue;

		const int rest = symbol - 256;
		uint32_t length = (uint32_t)(rest & 0x0F);
		const unsigned bitsDistance = (unsigned)(rest >> 4);

		// The distance is read BEFORE the extended length: the order is imposed.
		uint32_t distance = bits.value(bitsDistance);
		distance = (1u << bitsDistance) | distance;

		if (length == 15) {
			/*  EXTENDED LENGTH, read as BYTES on the bit stream's cursor. Three
			    levels: one byte, then a 16-bit word, then a 32-bit word. A separate
			    cursor would desynchronise the whole chunk. */
			uint8_t oct = 0;
			if (!bits.nextByte(&oct)) break;
			length = (uint32_t)oct + 15;
			if (length == 270) {
				uint32_t m = 0;
				if (!bits.word16(&m)) break;
				length = m;
				if (length == 0) {
					if (!bits.word32(&length)) break;
				}
			}
		}
		length += 3;

		if (distance > written) break;       // before the start: corrupt stream
		if (length > outputSize - written)
			length = (uint32_t)(outputSize - written);

		/*  Byte-by-byte copy: the ranges OVERLAP as soon as the distance is
		    smaller than the length, which is the normal case — it is how the format
		    encodes a repetition. */
		size_t source = written - distance;
		while (length-- > 0) output[written++] = output[source++];
	}
	return written;
}
