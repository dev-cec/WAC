/*! \file
 *  \brief XPRESS HUFFMAN DECOMPRESSION (WOF / "Compact OS").
 *
 *  WHY THIS MODULE EXISTS. Windows 10 and 11 store their system binaries
 *  compressed by WOF. Seen through the API, such a file is perfectly ordinary:
 *  normal attributes, a single stream, full size — the system's filter rebuilds
 *  everything on the fly. Seen from the disk, it is something else, and
 *  listing the $MFT attributes shows it unambiguously:
 *
 *      0x80 (unnamed)          1,372,160 bytes   SPARSE    <- empty $DATA
 *      0x80 WofCompressedData    667,578 bytes             <- the real data
 *      0xC0 reparse point           0x80000017   algorithm 2
 *
 *  A raw read that ignores this returns a file of the right size, entirely
 *  zero. On a Windows 11 VM, the 121 event-provider binaries were in that case:
 *  no event message could be rebuilt without opening the files through the API
 *  — which this module avoids.
 *
 *  WOF HAS FOUR ALGORITHMS, named by the reparse point: XPRESS on 4, 8 or
 *  16 KiB chunks, and LZX on 32 KiB. The first three use THE SAME coding,
 *  XPRESS Huffman, handled here; only the chunk size differs. LZX is a distinct,
 *  far more complex format, handled by lzx.h.
 *
 *  THE CODING, and its two subtleties.
 *
 *  Each chunk starts with a 256-byte Huffman table: 512 code lengths on 4 bits,
 *  one per symbol. A bit stream follows, from which symbols are decoded; below
 *  256 it is a literal byte, above it is a back-reference whose high bits give
 *  the number of distance bits and whose low four give the length.
 *
 *    - THE BIT STREAM IS READ AS 16-BIT LITTLE-ENDIAN WORDS, but the bits are
 *      consumed from most to least significant within the word. Getting either
 *      wrong decodes a stream that looks like noise without ever raising an
 *      error.
 *    - EXTENDED LENGTHS ARE READ AS BYTES, on the SAME cursor as the bit
 *      stream. Both reads therefore interleave, and a separate cursor
 *      desynchronises the rest of the chunk.
 *
 *  The data come from the examined machine: every bound is checked, and an
 *  inconsistent stream returns what was produced so far rather than reading
 *  out of range.
 *
 *  Portable C++, no dependency: checked against Windows' own compressor (see
 *  xpress_test).
 */
#pragma once

#include <cstdint>
#include <cstddef>

/*! Expands one XPRESS Huffman compressed chunk.
*
*  @param compressed compressed data (one whole chunk, table included)
*  @param compressedSize size of that data
*  @param output destination buffer
*  @param outputSize expected size of the expanded chunk, bounding the writes
*  @return number of bytes written; 0 if the input is unusable.
*          A result below the expected size signals a truncated stream.
*/
size_t XpressHuffmanInflate(const uint8_t* compressed, size_t compressedSize,
                             uint8_t* output, size_t outputSize);
