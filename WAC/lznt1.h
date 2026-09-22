#pragma once

/*  lznt1.h — NTFS DECOMPRESSION (LZNT1).
 *
 *  WHY THIS MODULE EXISTS. Windows 11 turns NTFS compression on for
 *  `\Windows\System32\winevt\Logs`: the event logs are stored there compressed
 *  (measured: `System.evtx`, 1,118,208 bytes held in 589,824 on disk, 1.9 to
 *  1). A raw reader that ignores compression returns NOTHING for those files —
 *  on a Windows 11 VM, 400 of the 404 logs failed, which made offline event
 *  reading useless on the most common operating system.
 *
 *  It is not specific to logs: compression is a directory attribute that the
 *  user or a policy can set anywhere, so any artefact can be compressed.
 *
 *  THE FORMAT, on two levels.
 *
 *  1. THE COMPRESSION UNIT, on the NTFS side. The `$DATA` attribute declares a
 *     unit size (2^n clusters, 16 in practice). The file is cut into units of
 *     that size, each independent:
 *       - unit with ALL its clusters allocated: stored as is, compression
 *         having gained nothing;
 *       - entirely sparse unit: zeros;
 *       - partially allocated unit: the present clusters hold the compressed
 *         form, to be expanded up to the unit size.
 *     raw_hive handles this level, being the only one to know the runs.
 *
 *  2. THE LZNT1 STREAM, handled here. A compressed unit is a sequence of chunks
 *     of 4096 expanded bytes. Each chunk starts with a 2-byte header: bits 0-11
 *     the size of the following data minus one, bits 12-14 a signature, bit 15
 *     the "compressed" flag. A zero header ends the stream.
 *
 *     In a compressed chunk, a flag byte drives the next eight items: bit 0, a
 *     literal byte; bit 1, a 2-byte back-reference. THE SUBTLETY, and the only
 *     place where an implementation goes wrong: the split of those 16 bits
 *     between distance and length IS NOT FIXED — it depends on how much the
 *     chunk has already produced. The distance starts on 4 bits and gains one
 *     each time the output crosses a power of two, the length losing one
 *     accordingly. A fixed split gives a stream that decodes without error and
 *     produces wrong data.
 *
 *  The data come from the examined machine: every bound is checked, and a
 *  truncated output is reported as a partial result rather than by reading out
 *  of range.
 *
 *  Portable C++, no dependency: verifiable outside Windows (see lznt1_test).
 */

#include <cstdint>
#include <cstddef>

/*! Expands an LZNT1 stream.
*
*  @param compresse compressed data (one whole compression unit)
*  @param tailleCompressee size of that data
*  @param sortie destination buffer
*  @param tailleSortie buffer capacity
*  @return number of bytes written; 0 if the input is unusable.
*          A result below the capacity is not an error: a file's last unit is
*          usually partial.
*/
size_t Lznt1Detendre(const uint8_t* compresse, size_t tailleCompressee,
                     uint8_t* sortie, size_t tailleSortie);
