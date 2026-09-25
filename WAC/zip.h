/*! \file
 *  \brief ZIP EXTRACTION, for the list of vulnerable drivers --update-trust
 *         downloads.
 *
 *  WHY THIS MODULE EXISTS. Microsoft publishes its blocklist of vulnerable
 *  drivers as a ZIP archive (VulnerableDriverBlockList.zip). Only what the
 *  list needs is read: the central directory, then each file, stored or
 *  DEFLATE (inflate.h), its CRC-32 checked. ZIP64, encryption, and archives
 *  split over several parts are refused, not guessed at.
 *
 *  The archive comes from the network: every offset and size it announces is
 *  checked against its real size, the output is bounded, and a file whose
 *  content does not have the size and CRC-32 the directory announces is
 *  refused.
 *
 *  Portable C++: checked against Python's zipfile (see zip_test).
 */
#pragma once

#include "archive.h"

/*! Extracts every file of a ZIP archive (directories are skipped).
 *  @param archive the archive's bytes
 *  @param files receives its files, in the order of the central directory
 *  @param reason receives why the archive is refused
 *  @return false if it is malformed, or uses what is not read (see above) */
bool ZipExtract(const std::vector<uint8_t>& archive, std::vector<ArchiveFile>& files, std::string& reason);

/*! CRC-32 (ISO-HDLC, the one of ZIP and zlib).
 *  @param data,size the bytes
 *  @return their CRC */
uint32_t Crc32(const uint8_t* data, size_t size);
