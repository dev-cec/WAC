/*! \file
 *  \brief ZIP extraction (see zip.h).
 */
#include "zip.h"
#include "inflate.h"
#include "portable_conversions.h"
#include <array>

namespace {

const uint32_t END_SIGNATURE = 0x06054B50;       //!< end of central directory record
const uint32_t ENTRY_SIGNATURE = 0x02014B50;     //!< central directory file header
const uint32_t LOCAL_SIGNATURE = 0x04034B50;     //!< local file header
const size_t END_SIZE = 22;                      //!< end record, comment excluded
const size_t ENTRY_SIZE = 46;                    //!< central header, name and extras excluded
const size_t LOCAL_SIZE = 30;                    //!< local header, name and extras excluded
const size_t COMMENT_MAX = 0xFFFF;               //!< the end record's comment, at most
const size_t MAX_TOTAL_OUTPUT = 256u << 20;      //!< beyond: refused, the blocklist is ~2 MiB
const uint16_t STORED = 0, DEFLATED = 8;
const uint16_t FLAG_ENCRYPTED = 0x0001;

/*! The end record: searched backwards, since a comment of any length up to
 *  64 KiB may follow it.
 *  @return its offset, or SIZE_MAX if absent */
size_t findEnd(const std::vector<uint8_t>& zip) {
	if (zip.size() < END_SIZE) return SIZE_MAX;
	const size_t lowest = zip.size() - END_SIZE > COMMENT_MAX ? zip.size() - END_SIZE - COMMENT_MAX : 0;
	for (size_t at = zip.size() - END_SIZE + 1; at-- > lowest;)
		if (readLittleEndian<uint32_t>(&zip[at]) == END_SIGNATURE && at + END_SIZE + readLittleEndian<uint16_t>(&zip[at + 20]) == zip.size())
			return at;
	return SIZE_MAX;
}

//! One file as the central directory describes it.
struct Entry {
	std::string name;
	uint16_t flags, method;
	uint32_t crc, packed, unpacked, localOffset;
};

/*! The data of one entry, located through its local header, decompressed,
 *  and checked against the directory's size and CRC.
 *  @return false with `reason` otherwise */
bool readEntry(const std::vector<uint8_t>& zip, const Entry& e, std::vector<uint8_t>& out, std::string& reason) {
	if ((size_t)e.localOffset + LOCAL_SIZE > zip.size() || readLittleEndian<uint32_t>(&zip[e.localOffset]) != LOCAL_SIGNATURE) {
		reason = e.name + ": local header missing";
		return false;
	}
	const size_t data = (size_t)e.localOffset + LOCAL_SIZE + readLittleEndian<uint16_t>(&zip[e.localOffset + 26])
	                  + readLittleEndian<uint16_t>(&zip[e.localOffset + 28]);
	if (data > zip.size() || e.packed > zip.size() - data) { reason = e.name + ": data outside the archive"; return false; }
	if (e.method == STORED) {
		if (e.packed != e.unpacked) { reason = e.name + ": stored with inconsistent sizes"; return false; }
		out.assign(zip.begin() + (long)data, zip.begin() + (long)(data + e.packed));
	}
	else if (e.method == DEFLATED) {
		out.clear();
		if (!Inflate(zip.data() + data, e.packed, out, e.unpacked) || out.size() != e.unpacked) {
			reason = e.name + ": does not decompress to its announced size";
			return false;
		}
	}
	else { reason = e.name + ": compression method " + std::to_string(e.method) + " not read"; return false; }
	if (Crc32(out.data(), out.size()) != e.crc) { reason = e.name + ": CRC-32 differs"; return false; }
	return true;
}

/*! The central directory's entries.
 *  @return false with `reason` if it leaves the archive or uses ZIP64 */
bool readDirectory(const std::vector<uint8_t>& zip, size_t end, std::vector<Entry>& entries, std::string& reason) {
	const uint16_t count = readLittleEndian<uint16_t>(&zip[end + 10]);
	const uint32_t size = readLittleEndian<uint32_t>(&zip[end + 12]);
	const uint32_t offset = readLittleEndian<uint32_t>(&zip[end + 16]);
	if (readLittleEndian<uint16_t>(&zip[end + 4]) != 0 || readLittleEndian<uint16_t>(&zip[end + 6]) != 0 || readLittleEndian<uint16_t>(&zip[end + 8]) != count) {
		reason = "archive split over several parts";
		return false;
	}
	if (count == 0xFFFF || size == 0xFFFFFFFF || offset == 0xFFFFFFFF) { reason = "ZIP64 not read"; return false; }
	if ((size_t)offset + size > end) { reason = "central directory outside the archive"; return false; }
	size_t at = offset;
	for (unsigned k = 0; k < count; ++k) {
		if (at + ENTRY_SIZE > (size_t)offset + size || readLittleEndian<uint32_t>(&zip[at]) != ENTRY_SIGNATURE) {
			reason = "central directory malformed";
			return false;
		}
		const size_t nameSize = readLittleEndian<uint16_t>(&zip[at + 28]);
		const size_t next = at + ENTRY_SIZE + nameSize + readLittleEndian<uint16_t>(&zip[at + 30]) + readLittleEndian<uint16_t>(&zip[at + 32]);
		if (next > (size_t)offset + size) { reason = "central directory malformed"; return false; }
		Entry e;
		e.flags = readLittleEndian<uint16_t>(&zip[at + 8]);
		e.method = readLittleEndian<uint16_t>(&zip[at + 10]);
		e.crc = readLittleEndian<uint32_t>(&zip[at + 16]);
		e.packed = readLittleEndian<uint32_t>(&zip[at + 20]);
		e.unpacked = readLittleEndian<uint32_t>(&zip[at + 24]);
		e.localOffset = readLittleEndian<uint32_t>(&zip[at + 42]);
		e.name.assign((const char*)&zip[at + ENTRY_SIZE], nameSize);
		if (e.packed == 0xFFFFFFFF || e.unpacked == 0xFFFFFFFF || e.localOffset == 0xFFFFFFFF) {
			reason = "ZIP64 not read";
			return false;
		}
		entries.push_back(std::move(e));
		at = next;
	}
	return true;
}

} // namespace

uint32_t Crc32(const uint8_t* data, size_t size) {
	static const std::array<uint32_t, 256> TABLE = [] {
		std::array<uint32_t, 256> t{};
		for (uint32_t n = 0; n < 256; ++n) {
			uint32_t c = n;
			for (int k = 0; k < 8; ++k) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
			t[n] = c;
		}
		return t;
	}();
	uint32_t crc = 0xFFFFFFFFu;
	for (size_t i = 0; i < size; ++i) crc = TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFFu;
}

bool ZipExtract(const std::vector<uint8_t>& archive, std::vector<ArchiveFile>& files, std::string& reason) {
	files.clear();
	const size_t end = findEnd(archive);
	if (end == SIZE_MAX) { reason = "not a ZIP archive: no end of central directory"; return false; }
	std::vector<Entry> entries;
	if (!readDirectory(archive, end, entries, reason)) return false;
	size_t total = 0;
	for (const Entry& e : entries) {
		if (!e.name.empty() && e.name.back() == '/') continue;          // a directory
		if (e.flags & FLAG_ENCRYPTED) { reason = e.name + ": encrypted"; return false; }
		if (e.unpacked > MAX_TOTAL_OUTPUT - total) { reason = "archive larger than allowed"; return false; }
		total += e.unpacked;
		ArchiveFile file;
		file.name = e.name;
		if (!readEntry(archive, e, file.content, reason)) return false;
		files.push_back(std::move(file));
	}
	return true;
}
