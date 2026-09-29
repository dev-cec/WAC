/*! \file
 *  \brief Cabinet extraction (see cab.h).
 */
#include "cab.h"
#include "inflate.h"
#include <cstring>

namespace {

const size_t MAX_FOLDER_OUTPUT = 256u << 20;   //!< beyond: refused, a trust list is a few hundred KiB
const size_t MSZIP_BLOCK = 32768;              //!< the largest uncompressed MSZIP block


/*! The data of one folder: its CFDATA blocks, decompressed in order.
 *  @return false if a block leaves the cabinet or does not decompress */
bool readFolder(const std::vector<uint8_t>& cab, size_t offset, unsigned blocks, unsigned compression,
                unsigned reservePerBlock, std::vector<uint8_t>& out, std::string& reason) {
	std::vector<uint8_t> previous;                   // MSZIP: the previous block, as dictionary
	for (unsigned b = 0; b < blocks; ++b) {
		if (offset + 8 + reservePerBlock > cab.size()) { reason = "data block outside the cabinet"; return false; }
		const size_t packed = archiveLe16(&cab[offset + 4]);
		const size_t unpacked = archiveLe16(&cab[offset + 6]);
		const size_t data = offset + 8 + reservePerBlock;
		if (data + packed > cab.size()) { reason = "data block outside the cabinet"; return false; }
		if (out.size() + unpacked > MAX_FOLDER_OUTPUT) { reason = "folder larger than allowed"; return false; }
		if (compression == 0) {
			if (packed != unpacked) { reason = "uncompressed block of inconsistent size"; return false; }
			out.insert(out.end(), cab.begin() + (long)data, cab.begin() + (long)(data + packed));
		}
		else {
			if (packed < 2 || cab[data] != 'C' || cab[data + 1] != 'K' || unpacked > MSZIP_BLOCK) {
				reason = "MSZIP block without its CK signature";
				return false;
			}
			std::vector<uint8_t> block;
			if (!Inflate(&cab[data + 2], packed - 2, block, unpacked, previous) || block.size() != unpacked) {
				reason = "MSZIP block that does not decompress";
				return false;
			}
			out.insert(out.end(), block.begin(), block.end());
			previous = std::move(block);
		}
		offset = data + packed;
	}
	return true;
}

} // namespace

bool CabExtract(const std::vector<uint8_t>& cab, std::vector<ArchiveFile>& files, std::string& reason) {
	files.clear();
	if (cab.size() < 36 || std::memcmp(cab.data(), "MSCF", 4) != 0) { reason = "not a cabinet"; return false; }
	const uint32_t filesOffset = archiveLe32(&cab[16]);
	const unsigned folderCount = archiveLe16(&cab[26]);
	const unsigned fileCount = archiveLe16(&cab[28]);
	const unsigned flags = archiveLe16(&cab[30]);
	if (flags & 0x0003) { reason = "cabinet split over several parts"; return false; }
	size_t cursor = 36;
	unsigned reservePerFolder = 0, reservePerBlock = 0;
	if (flags & 0x0004) {                                // RESERVE_PRESENT: the signature's room, among others
		if (cursor + 4 > cab.size()) { reason = "truncated header"; return false; }
		const unsigned headerReserve = archiveLe16(&cab[cursor]);
		reservePerFolder = cab[cursor + 2];
		reservePerBlock = cab[cursor + 3];
		cursor += 4 + headerReserve;
	}
	struct Folder { size_t offset; unsigned blocks, compression; };
	std::vector<Folder> folders;
	for (unsigned f = 0; f < folderCount; ++f) {
		if (cursor + 8 + reservePerFolder > cab.size()) { reason = "truncated folder table"; return false; }
		folders.push_back({ archiveLe32(&cab[cursor]), archiveLe16(&cab[cursor + 4]), (unsigned)(archiveLe16(&cab[cursor + 6]) & 0x000F) });
		cursor += 8 + reservePerFolder;
	}
	std::vector<std::vector<uint8_t>> folderData(folders.size());
	for (size_t f = 0; f < folders.size(); ++f) {
		if (folders[f].compression > 1) { reason = "compression other than MSZIP"; return false; }
		if (!readFolder(cab, folders[f].offset, folders[f].blocks, folders[f].compression, reservePerBlock,
		                folderData[f], reason)) return false;
	}
	cursor = filesOffset;
	for (unsigned k = 0; k < fileCount; ++k) {
		if (cursor + 16 > cab.size()) { reason = "truncated file table"; return false; }
		const uint32_t size = archiveLe32(&cab[cursor]);
		const uint32_t start = archiveLe32(&cab[cursor + 4]);
		const unsigned folder = archiveLe16(&cab[cursor + 8]);
		size_t end = cursor + 16;
		while (end < cab.size() && cab[end]) ++end;
		if (end >= cab.size()) { reason = "file name without its end"; return false; }
		if (folder >= folderData.size() || (uint64_t)start + size > folderData[folder].size()) {
			reason = "file outside its folder";
			return false;
		}
		ArchiveFile file;
		file.name.assign(reinterpret_cast<const char*>(&cab[cursor + 16]), end - cursor - 16);
		file.content.assign(folderData[folder].begin() + start, folderData[folder].begin() + start + size);
		files.push_back(std::move(file));
		cursor = end + 1;
	}
	return true;
}
