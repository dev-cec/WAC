/*! \file
 *  \brief The NTFS boot sector, decoded: THE reading of a volume's geometry,
 *         shared by the raw reader (raw_hive) and ntfs_volumes.json.
 *
 *  WHY ONE READING. The raw reader read the sectors per cluster byte by byte,
 *  ntfs_volumes as a power of two above 0x80 (clusters of 128 KiB to 2 MiB,
 *  Windows 10 1709 and later): on such a volume the raw reader took a 2 MiB
 *  cluster for 124 928 bytes and read everything elsewhere (B-050, lot 1).
 *  Portable C++, built with raw_hive_test.
 */
#pragma once

#include <cstddef>
#include <cstdint>

/*! The boot sector of an NTFS volume, as far as it was read. */
struct NtfsBootSector {
	uint16_t bytesPerSector = 0;
	uint32_t bytesPerCluster = 0;
	uint64_t totalSectors = 0;
	uint64_t mftCluster = 0;         //!< first cluster of the $MFT
	uint64_t mftMirrorCluster = 0;   //!< first cluster of $MFTMirr
	uint32_t bytesPerRecord = 0;     //!< size of a $MFT record
	uint32_t bytesPerIndexBlock = 0; //!< size of a directory index block
	uint64_t serialNumber = 0;       //!< the 64-bit serial; Windows shows its low 32 bits
};

/*! Decodes an NTFS boot sector.
 *  @param data the first bytes of $Boot
 *  @param size their number
 *  @param boot receives the fields
 *  @return false if the sector is shorter than 512 bytes, lacks its signatures
 *          or declares an impossible geometry: nothing is then trusted */
bool parseNtfsBootSector(const uint8_t* data, size_t size, NtfsBootSector& boot);
