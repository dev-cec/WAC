/*! \file
 *  \brief Raw reader of FAT12, FAT16, FAT32 and exFAT volumes.
 *
 *  WHY. A suspect's USB key, a memory card, an EFI system partition are FAT
 *  or exFAT: files named by the artefacts may lie there, and what was deleted
 *  there is still in their directories. NTFS's reader does not apply; the
 *  file system's API would not show the deleted entries, and would update
 *  access dates.
 *
 *  THE FORMATS, from Microsoft's specifications (FAT: "Microsoft Extensible
 *  Firmware Initiative FAT32 File System Specification", 2000; exFAT: "exFAT
 *  File System Specification", 2019), checked on volumes Windows formatted
 *  in the test VM against dissect.fat (Fox-IT):
 *   - FAT: a boot sector (sizes, FAT count, root), one or two FATs (the
 *     chains of clusters, 12, 16 or 28 bits by entry), the root directory
 *     (a fixed region in FAT12/16, a chain in FAT32), 32-byte entries — the
 *     long name in entries of attribute 0x0F before its 8.3 entry. A deleted
 *     entry has 0xE5 as first byte: its long name survives, bound to its 8.3
 *     entry by a checksum, which also gives back the first letter lost;
 *   - exFAT: a boot sector, one FAT, an allocation bitmap, directories of
 *     entry sets (file 0x85, stream 0xC0, name 0xC1…): a deleted set only has
 *     the high "in use" bit of its types cleared — the whole name survives.
 *     Timestamps carry 10 ms and, when set, their UTC offset.
 *
 *  THE BYTES come from a VolumeSource: the volume itself during a
 *  collection, or the copy of what the collection read (its metadata — boot
 *  sector, FAT, directories —, never the files' content) during a
 *  conversion. Every read is bounded by the volume; every chain by the
 *  number of clusters, so that a looping FAT ends.
 */
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! Where a volume's bytes come from. */
class VolumeSource {
public:
	virtual ~VolumeSource() = default;
	/*! Reads bytes of the volume.
	 *  @return false if any of them is not available */
	virtual bool read(uint64_t offset, size_t size, std::vector<uint8_t>& out) = 0;
	virtual uint64_t size() const = 0;   //!< the volume's size, in bytes
};

/*! A volume in a file: an image, or the device itself opened by path. */
class FileVolumeSource : public VolumeSource {
public:
	/*! @param path an image, or "\\\\.\\E:"
	 *  @param size the volume's size (0: the file's) */
	explicit FileVolumeSource(const std::wstring& path, uint64_t size = 0);
	~FileVolumeSource() override;
	bool isOpen() const { return handle_ != INVALID_HANDLE_VALUE; }
	bool read(uint64_t offset, size_t size, std::vector<uint8_t>& out) override;
	uint64_t size() const override { return size_; }
	/*! The bytes read so far, by offset, adjacent reads merged: what a
	 *  collection copies of the volume — its metadata only. */
	const std::map<uint64_t, std::vector<uint8_t>>& ranges() const { return ranges_; }
private:
	HANDLE handle_ = INVALID_HANDLE_VALUE;
	uint64_t size_ = 0;
	std::map<uint64_t, std::vector<uint8_t>> ranges_;
};

/*! The metadata a collection copied from a volume: ranges of bytes, in a
 *  file of the exhibit store ("WACFATM1", the volume's size, the count, then
 *  offset, length and bytes of each range). */
class CopiedVolumeSource : public VolumeSource {
public:
	/*! Loads a copy.
	 *  @return false if it is not one, or a range exceeds the file */
	bool load(const std::wstring& path);
	bool read(uint64_t offset, size_t size, std::vector<uint8_t>& out) override;
	uint64_t size() const override { return size_; }
private:
	uint64_t size_ = 0;
	std::map<uint64_t, std::vector<uint8_t>> ranges_;
};

/*! The ranges a FileVolumeSource read, as a copy CopiedVolumeSource loads.
 *  @return the copy's bytes */
std::string volumeCopyBytes(const FileVolumeSource& source);

/*! An entry of a directory: a file or a folder, present or deleted. */
struct FatEntry {
	std::wstring path;              //!< from the volume's root, "\\DIR1\\sub file.bin"
	std::wstring shortName;         //!< FAT: the 8.3 name, as stored
	bool directory = false, deleted = false;
	bool nameIncomplete = false;    //!< deleted FAT entry: without its long name, the first letter is lost ('_'); or its long name lost its end
	uint32_t attributes = 0;
	uint64_t size = 0;
	uint32_t firstCluster = 0;
	bool contiguous = false;        //!< exFAT: no FAT chain, the clusters follow each other
	// Dates as stored: local time (FAT, exFAT without offset), or UTC.
	FILETIME created = { 0 }, modified = { 0 }, accessed = { 0 };
	bool createdUtc = false, modifiedUtc = false, accessedUtc = false;
	int createdOffset = 0, modifiedOffset = 0, accessedOffset = 0;   //!< exFAT: minutes east of UTC, when stored
};

/*! A FAT or exFAT volume. */
class FatVolume {
public:
	/*! Reads the boot sector.
	 *  @return false if it is neither FAT nor exFAT */
	bool open(VolumeSource& source);
	//! @return "FAT12", "FAT16", "FAT32" or "exFAT"
	const std::wstring& type() const { return type_; }
	//! @return the volume's label, when its root holds one
	const std::wstring& label() const { return label_; }
	/*! Every entry, present or deleted, from the root down; the folders of
	 *  deleted entries are visited when their first cluster still holds a
	 *  directory.
	 *  @return the entries, in the directories' order */
	std::vector<FatEntry> entries();

private:
	uint32_t next(uint32_t cluster);
	std::vector<uint8_t> chain(uint32_t first, uint64_t knownSize, bool contiguous);
	void fatDirectory(const std::vector<uint8_t>& data, const std::wstring& path, bool deletedParent, unsigned depth, std::vector<FatEntry>& out);
	void exfatDirectory(const std::vector<uint8_t>& data, const std::wstring& path, bool deletedParent, unsigned depth, std::vector<FatEntry>& out);
	void descend(const FatEntry& e, unsigned depth, std::vector<FatEntry>& out);

	VolumeSource* source_ = nullptr;
	std::wstring type_, label_;
	uint32_t clusterSize_ = 0, clusterCount_ = 0, rootCluster_ = 0;
	uint64_t rootOffset_ = 0, rootSize_ = 0, dataOffset_ = 0;
	std::vector<uint8_t> fat_;      //!< the first FAT, whole
	unsigned fatBits_ = 0;          //!< 12, 16, 32 (FAT32 and exFAT)
	size_t visited_ = 0;            //!< directories visited, against a hostile tree
};

/*! The checksum of an 8.3 name, which binds its long-name entries to it. */
uint8_t fatShortNameChecksum(const uint8_t name[11]);
