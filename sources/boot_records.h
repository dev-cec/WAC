/*! \file
 *  \brief THE BOOT RECORDS: what runs before Windows — each disk's first
 *         mebibyte, each partition's boot sectors, the EFI system
 *         partition's files (backlog B-052).
 *
 *  WHY. A bootkit runs before the system that could see it: it rewrites the
 *  master boot record or a volume's boot code (BIOS machines), hides its
 *  code in the sectors before the first partition, or replaces a boot
 *  loader of the EFI system partition (BlackLotus, CosmicStrand's chain)
 *  — ATT&CK T1542 "Pre-OS Boot". None of it is in a file the system shows:
 *  the EFI partition has no letter, the sectors no file. Read raw, they are
 *  kept as they were, for the analysis to confront with known boot code
 *  and with the signatures of the loaders.
 *
 *  WHAT IS COPIED, from each physical disk read raw (`\\.\PhysicalDriveN`,
 *  opened for reading; the disk holding the collection medium is left out):
 *    - its first mebibyte: the MBR (boot code, partition table, disk
 *      signature), the GPT header and entries, and the gap before the
 *      first partition, where a bootkit's code hides;
 *    - the first 16 sectors of each partition: its boot sector and, for
 *      NTFS, its initial program loader;
 *    - every present file of each EFI system partition (GPT type
 *      C12A7328-F81F-11D2-BA4B-00A0C93EC93B, or MBR type 0xEF), read
 *      through WAC's own FAT reader — the boot loaders, their
 *      configuration (BCD), their certificates' revocations.
 *  Logical partitions of an extended MBR partition are not followed: their
 *  tables lie past the first mebibyte, and Windows boots from a primary one.
 *
 *  The conversion (boot_records.json) reads the copies: the partition
 *  table decoded, in sectors as it is stored, the SHA-256 of the MBR's boot
 *  code and of each boot sector, each EFI file with its size and SHA-256.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

//! The bytes copied from the start of each disk.
const size_t BOOT_HEAD_BYTES = 1024 * 1024;

/*! One partition of a disk's table. */
struct BootPartition {
	unsigned index = 0;         //!< its entry in the table, from 1
	std::wstring type;          //!< GPT: its type GUID; MBR: its type byte, "0x07"
	std::wstring guid;          //!< GPT: its own GUID
	std::wstring name;          //!< GPT: its name ("EFI system partition", "Basic data partition")
	uint64_t firstSector = 0;   //!< its first sector, as the table counts it
	uint64_t sectors = 0;       //!< its length, in sectors
	bool active = false;        //!< MBR: the boot flag (0x80)
	bool efiSystem = false;     //!< the EFI system partition
};

/*! A disk's partition table, as its first mebibyte holds it. */
struct PartitionTable {
	std::wstring style;         //!< "MBR" or "GPT"; empty when neither
	/*! GPT: the bytes per sector its header was found at (512 or 4096); MBR:
	 *  0, the table does not say — the collection asks the disk */
	uint32_t sectorSize = 0;
	std::wstring diskId;        //!< MBR: the disk signature, "1A2B3C4D"; GPT: the disk GUID
	std::vector<BootPartition> partitions;
};

/*! Decodes a disk's partition table from its first bytes. A GPT is looked
 *  for after a protective MBR (type 0xEE), at 512 then 4096 bytes per
 *  sector; every entry is read within `length`, never past it.
 *  @param head the disk's first bytes
 *  @param length their number
 *  @return the table; style empty when the bytes hold neither */
PartitionTable parsePartitionTable(const uint8_t* head, size_t length);

/*! Copies the boot records of every physical disk into the exhibit store
 *  (collection phase).
 *  @return S_OK, S_FALSE if one could not be read, ERROR_EMPTY if no disk was opened */
HRESULT ExtractBootRecordsRaw();

/*! The boot records of the disks (boot_records.json). */
class BootRecords {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any disk
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases what was read
private:
	std::vector<Json> disks_;
};
