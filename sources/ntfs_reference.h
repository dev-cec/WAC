/*! \file
 *  \brief THE NTFS FILE REFERENCE: how the $MFT, its indexes, the USN journal,
 *         shell items and Prefetch files name a file on its volume.
 *
 *  8 bytes, little-endian: the low 48 bits are the record number in the $MFT,
 *  the high 16 bits the sequence number that every reuse of the record
 *  increments. A reference therefore designates ONE file, even renamed or
 *  moved, and tells it from a later file that reused its record.
 *
 *  WHY A HEADER OF ITS OWN. The split was written by hand in each decoder,
 *  seventeen times, and went wrong in one of them: the Prefetch decoding read
 *  the sequence on four bytes — two of them taken from the next entry — and
 *  lost the entry's high 16 bits. It has no dependency, so that the
 *  standalone readers (raw_hive, built alone for raw_hive_test) can share it.
 */
#pragma once

#include <cstdint>

/*! An NTFS file reference, split. */
struct NtfsReference {
	uint64_t entry = 0;     //!< record number in the $MFT (48 bits)
	uint16_t sequence = 0;  //!< sequence number of the record
};

/*! Splits an NTFS file reference into its record number and its sequence.
 *  @param reference the 8 bytes of the reference, read as a little-endian integer
 *  @return the record number and the sequence */
inline NtfsReference splitNtfsReference(uint64_t reference) {
	return { reference & 0x0000FFFFFFFFFFFFULL, (uint16_t)(reference >> 48) };
}
