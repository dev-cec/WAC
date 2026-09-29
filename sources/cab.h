/*! \file
 *  \brief CABINET (.cab) EXTRACTION, for the trust lists --update-trust
 *         downloads.
 *
 *  WHY THIS MODULE EXISTS. Microsoft publishes its list of trusted roots
 *  (authrootstl.cab) and its list of disallowed certificates
 *  (disallowedcertstl.cab) as cabinets holding one signed list each. The
 *  cabinet is only a container: what is trusted is the list's own signature,
 *  checked afterwards (authenticode.h). Uncompressed and MSZIP folders are
 *  read — MSZIP is DEFLATE (inflate.h) behind a "CK" signature, each block
 *  able to refer back into the previous one.
 *
 *  The cabinet comes from the network: every offset and size it announces is
 *  checked against its real size, and an output is bounded — a malformed
 *  cabinet is refused, never read out of bounds.
 *
 *  Portable C++: checked against cabextract (see cab_test).
 */
#pragma once

#include "archive.h"

/*! Extracts every file of a single-part cabinet.
 *  @param cabinet the cabinet's bytes
 *  @param files receives its files
 *  @param reason receives why the cabinet is refused
 *  @return false if it is malformed, split over several parts, or compressed
 *          otherwise than MSZIP */
bool CabExtract(const std::vector<uint8_t>& cabinet, std::vector<ArchiveFile>& files, std::string& reason);
