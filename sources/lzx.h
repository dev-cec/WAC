/*! \file
 *  \brief LZX DECOMPRESSION (WOF / "Compact OS", algorithm 1).
 *
 *  WHY THIS MODULE EXISTS. WOF compresses a file in one of four ways: XPRESS
 *  on 4, 8 or 16 KiB chunks (xpress.h), or LZX on 32 KiB chunks. Windows uses
 *  XPRESS by default; LZX appears when someone asked for it (`compact
 *  /exe:lzx`, tools that "compact" a disk). Until this module, such a file was
 *  reported unreadable: no fingerprint, no copy — for executables, precisely
 *  the files --binary is there for.
 *
 *  THE FORMAT is the LZX of Microsoft's cabinets ([MS-PATCH], which documents
 *  it fully), in the variant WIM images and WOF share:
 *
 *    - every 32 KiB chunk is compressed on its own: the window is the chunk,
 *      the three recent offsets start at 1, and the code lengths at 0;
 *    - the bit stream is read as 16-bit little-endian words, bits consumed
 *      from the most significant;
 *    - a chunk is a sequence of blocks — VERBATIM, ALIGNED (offsets whose low
 *      three bits have their own Huffman code) or UNCOMPRESSED (raw bytes,
 *      after the stream is aligned on 16 bits and the three recent offsets
 *      given as is);
 *    - the Huffman code lengths are transmitted as differences with the
 *      previous block's, themselves coded by a "pretree";
 *    - once decompressed, a chunk undoes the x86 CALL translation: a byte E8
 *      is followed by an absolute target that must become relative again, with
 *      the fixed file size 12,000,000 of the WIM variant.
 *
 *  The data come from the examined machine: every read is bounded, a code
 *  length table that is over-subscribed, a match reaching before the start of
 *  the chunk or beyond the end of its block, is an error — never data made up.
 *
 *  Portable C++, no dependency: checked against Windows' own compressor
 *  (`compact /exe:lzx`, see lzx_test and the VM harness).
 */
#pragma once

#include <cstdint>
#include <cstddef>

/*! Size of a WOF LZX chunk, and of the LZX window it is compressed with. */
const size_t LZX_CHUNK_SIZE = 32768;

/*! Expands one LZX compressed chunk (WIM/WOF variant).
 *
 *  @param compressed compressed data (one whole chunk)
 *  @param compressedSize size of that data
 *  @param output destination buffer
 *  @param outputSize expected size of the expanded chunk (at most
 *         LZX_CHUNK_SIZE), bounding the writes
 *  @return outputSize on success; 0 if the stream is inconsistent or does not
 *          produce exactly outputSize bytes
 */
size_t LzxInflate(const uint8_t* compressed, size_t compressedSize,
                  uint8_t* output, size_t outputSize);
