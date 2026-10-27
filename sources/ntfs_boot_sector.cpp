/*! \file
 *  \brief The NTFS boot sector, decoded (see ntfs_boot_sector.h).
 */
#include "ntfs_boot_sector.h"
#include "portable_conversions.h"
#include <cstring>

namespace {

// Layout of the NTFS boot sector (the Linux-NTFS project's documentation).
const size_t BOOT_OEM = 0x03;                 //!< "NTFS    "
const size_t BOOT_BYTES_PER_SECTOR = 0x0B;    //!< uint16
const size_t BOOT_SECTORS_PER_CLUSTER = 0x0D; //!< uint8; above 0x80, the cluster is 2^(256 - value) bytes
const size_t BOOT_TOTAL_SECTORS = 0x28;       //!< uint64
const size_t BOOT_MFT_CLUSTER = 0x30;         //!< uint64
const size_t BOOT_MFT_MIRROR_CLUSTER = 0x38;  //!< uint64
const size_t BOOT_CLUSTERS_PER_RECORD = 0x40; //!< int8; negative, the record is 2^-value bytes
const size_t BOOT_CLUSTERS_PER_INDEX = 0x44;  //!< int8; same rule
const size_t BOOT_SERIAL = 0x48;              //!< uint64
const size_t BOOT_SIGNATURE = 0x1FE;          //!< 0x55, 0xAA
const size_t BOOT_SECTOR_SIZE = 512;

/*! A size the boot sector gives in clusters, or as a power of two when negative.
 *  @return the size in bytes, 0 if impossible */
uint32_t clustersOrPower(uint8_t raw, uint32_t bytesPerCluster) {
	const int8_t value = (int8_t)raw;
	if (value < 0) return -value < 32 ? 1u << -value : 0;
	return (uint32_t)value * bytesPerCluster;
}

} // namespace

bool parseNtfsBootSector(const uint8_t* data, size_t size, NtfsBootSector& boot) {
	if (size < BOOT_SECTOR_SIZE || std::memcmp(data + BOOT_OEM, "NTFS    ", 8) != 0
	    || data[BOOT_SIGNATURE] != 0x55 || data[BOOT_SIGNATURE + 1] != 0xAA) return false;
	boot.bytesPerSector = readLittleEndian<uint16_t>(data + BOOT_BYTES_PER_SECTOR);
	const uint8_t sectorsPerCluster = data[BOOT_SECTORS_PER_CLUSTER];
	const uint32_t sectors = sectorsPerCluster <= 0x80 ? sectorsPerCluster
	                       : (256u - sectorsPerCluster < 32 ? 1u << (256u - sectorsPerCluster) : 0);
	boot.bytesPerCluster = boot.bytesPerSector * sectors;
	// Sectors of 256 to 4096 bytes, a power of two; a cluster of at least one sector.
	if (boot.bytesPerSector < 256 || boot.bytesPerSector > 4096
	    || (boot.bytesPerSector & (boot.bytesPerSector - 1)) || !boot.bytesPerCluster) return false;
	boot.totalSectors = readLittleEndian<uint64_t>(data + BOOT_TOTAL_SECTORS);
	boot.mftCluster = readLittleEndian<uint64_t>(data + BOOT_MFT_CLUSTER);
	boot.mftMirrorCluster = readLittleEndian<uint64_t>(data + BOOT_MFT_MIRROR_CLUSTER);
	boot.bytesPerRecord = clustersOrPower(data[BOOT_CLUSTERS_PER_RECORD], boot.bytesPerCluster);
	boot.bytesPerIndexBlock = clustersOrPower(data[BOOT_CLUSTERS_PER_INDEX], boot.bytesPerCluster);
	boot.serialNumber = readLittleEndian<uint64_t>(data + BOOT_SERIAL);
	return true;
}
