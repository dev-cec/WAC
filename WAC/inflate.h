/*! \file
 *  \brief DEFLATE DECOMPRESSION (RFC 1951), for the archives --update-trust
 *         downloads.
 *
 *  WHY THIS MODULE EXISTS. The trust material --update-trust fetches comes
 *  compressed: Microsoft's lists of trusted roots and of disallowed
 *  certificates are CAB archives whose blocks are MSZIP — DEFLATE behind a
 *  "CK" signature —, the list of vulnerable drivers a ZIP archive, DEFLATE
 *  too. Decoding them with WAC's own code, rather than a library of the
 *  workstation, keeps --update-trust the same on Windows and under wine.
 *
 *  The input comes from the network: every read is bounded, a code that is
 *  over-subscribed, a distance reaching before the start of the output, an
 *  output larger than announced, is an error — never data made up.
 *
 *  Portable C++, no dependency: checked against zlib (see inflate_test).
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

/*! Decompresses a raw DEFLATE stream (no zlib or gzip header).
 *
 *  @param compressed the stream
 *  @param compressedSize its size
 *  @param output receives the decompressed bytes, appended
 *  @param maxOutput limit of the output: beyond it, the stream is refused
 *  @param dictionary (MSZIP) the previous block's output, which back-
 *         references may reach into; empty for a stream of its own
 *  @return true if the stream is complete and consistent
 */
bool Inflate(const uint8_t* compressed, size_t compressedSize, std::vector<uint8_t>& output,
             size_t maxOutput, const std::vector<uint8_t>& dictionary = {});
