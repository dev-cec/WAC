#include "lznt1.h"
#include <cstring>

/*! \file
 *  \brief LZNT1 decompression, the NTFS compression.
 *
 *  See lznt1.h. Algorithm consistent with libyal's reference
 *  implementation (libfwnt); the comments do not restate the format, they mark
 *  its two traps: the variable split of back-references, and overlapping
 *  copies.
 */

namespace {

//! One compressed chunk: at most 4096 expanded bytes.
const size_t CHUNK_SIZE = 4096;

/*! Expands one compressed chunk.
 *  @param pos position in `compressed`, updated
 *  @return bytes written to `output`
 */
size_t decompressChunk(const uint8_t* compressed, size_t compressedSize, size_t& pos,
                       size_t chunkSize, uint8_t* output, size_t outputSize) {
	size_t written = 0;

	/*  VARIABLE SPLIT. As long as the chunk's output does not exceed the
	 *  threshold, the distance takes 4 bits and the length 12. Each time the
	 *  threshold is crossed, the distance gains a bit and the length loses one.
	 *  Fixing these values produces wrong data without any error. */
	unsigned offset = 12;          // position of the distance field
	uint16_t sizeMask = 0x0fff;  // length field
	size_t   threshold = 16;

	while (chunkSize > 0) {
		if (pos >= compressedSize) break;
		uint8_t flags = compressed[pos++];
		chunkSize -= 1;

		for (int bit = 0; bit < 8; ++bit) {
			if (flags & 0x01) {
				// Back-reference: 2 bytes, little-endian.
				if (pos + 1 >= compressedSize) return written;
				if (chunkSize < 2) return written;
				const uint16_t tuple = (uint16_t)(compressed[pos] | (compressed[pos + 1] << 8));
				pos += 2;
				chunkSize -= 2;

				const size_t distance = (size_t)(tuple >> offset) + 1;
				size_t length      = (size_t)(tuple & sizeMask) + 3;
				if (distance > written) return written;       // before the start: corrupt stream

				/*  BYTE-BY-BYTE COPY, not memcpy: the ranges OVERLAP as soon as the
				 *  distance is smaller than the length, and that is the normal case —
				 *  it is how the format encodes a repetition. memcpy would return
				 *  something else. */
				size_t source = written - distance;
				while (length-- > 0) {
					if (written >= outputSize) return written;
					output[written++] = output[source++];
				}
			}
			else {
				if (pos >= compressedSize || chunkSize == 0) return written;
				if (written >= outputSize) return written;
				output[written++] = compressed[pos++];
				chunkSize -= 1;
			}
			flags >>= 1;
			if (chunkSize == 0) break;

			// Re-evaluate the split after EACH item.
			while (written > threshold) {
				if (offset == 0) return written;          // inconsistent stream
				--offset;
				sizeMask >>= 1;
				threshold <<= 1;
			}
		}
	}
	return written;
}

} // namespace

size_t Lznt1Inflate(const uint8_t* compressed, size_t compressedSize,
                     uint8_t* output, size_t outputSize) {
	if (!compressed || !output || compressedSize < 2 || outputSize == 0) return 0;

	size_t pos = 0, written = 0;
	while (pos < compressedSize && written < outputSize) {
		if (pos + 1 >= compressedSize) break;
		const uint16_t header = (uint16_t)(compressed[pos] | (compressed[pos + 1] << 8));
		pos += 2;
		if (header == 0) break;                 // end of stream

		const size_t size = (size_t)(header & 0x0fff) + 1;

		if (header & 0x8000) {
			written += decompressChunk(compressed, compressedSize, pos, size,
			                          output + written, outputSize - written);
		}
		else {
			// Chunk stored as is: compression had gained nothing.
			const size_t n = (size < compressedSize - pos) ? size : (compressedSize - pos);
			const size_t m = (n < outputSize - written) ? n : (outputSize - written);
			std::memcpy(output + written, compressed + pos, m);
			pos    += n;
			written += m;
		}
		// A chunk yields at most 4096 bytes; beyond that, the stream is inconsistent.
		if (written > outputSize) return outputSize;
	}
	return written;
}
