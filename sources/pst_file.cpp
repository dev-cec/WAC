/*! \file
 *  \brief PST and OST files, the NDB and LTP layers (see pst_file.h).
 */
#include "pst_file.h"
#include "conversions.h"
#include "inflate.h"
#include "tools.h"
#include <algorithm>
#include <cstring>
#include <filesystem>

namespace {

const int MAX_DEPTH = 16;                 //!< deeper than any real tree: a cycle, or a forged page
/* The depth alone did not bound the work: a page listing itself 20 times (169
   on 4 KiB pages) was walked 20^16 times. Every walk keeps the pages and
   internal blocks it entered: one met twice is a forged tree, refused. Leaf
   data blocks are left out, the block tree may share them. */
const size_t HEADER_SIZE = 564;           //!< the Unicode header, up to its last field read
const uint16_t VERSION_UNICODE = 23;      //!< PST of Outlook 2003 and later, 512-byte pages
const uint16_t VERSION_4K = 36;           //!< OST of Outlook 2013 and later, 4 KiB pages, compressed blocks
const uint8_t PAGE_BLOCK_TREE = 0x80, PAGE_NODE_TREE = 0x81;
const uint8_t HEAP_SIGNATURE = 0xEC;      //!< bSig of a heap on a node
const uint8_t CLIENT_PROPERTIES = 0xBC, CLIENT_TABLE = 0x7C, CLIENT_HEAP_TREE = 0xB5;
const uint64_t BID_INTERNAL = 0x2;        //!< a data tree or a subnode tree, never encrypted

/*! [MS-PST] §5.1, mpbbI: the "permutation" encryption's decoding table — the
 *  encrypted byte gives the plain one. Checked on the test corpus against
 *  pypff (backlog B-017). */
const uint8_t PERMUTATION[256] = {
	0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53,
	0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd,
	0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb,
	0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23,
	0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83,
	0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29,
	0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3,
	0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c,
	0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50,
	0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b,
	0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a,
	0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f,
	0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88,
	0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36,
	0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a,
	0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec
};

//! Adler-32 (RFC 1950): the checksum ending a zlib stream.
uint32_t adler32(const std::vector<uint8_t>& bytes) {
	uint32_t a = 1, b = 0;
	for (uint8_t x : bytes) { a = (a + x) % 65521; b = (b + a) % 65521; }
	return (b << 16) | a;
}

//! Rounds `size` up to a multiple of `alignment`.
size_t alignedTo(size_t size, size_t alignment) { return (size + alignment - 1) / alignment * alignment; }

/*! The size of a fixed-size property type, 0 for a variable one.
 *  @param type the property type */
size_t fixedSize(uint16_t type) {
	switch (type) {
	case 0x0002: return 2;                                         // PtypInteger16
	case 0x0003: case 0x0004: case 0x000A: return 4;               // Integer32, Floating32, ErrorCode
	case 0x000B: return 1;                                         // Boolean
	case 0x0005: case 0x0006: case 0x0007: case 0x0014: case 0x0040: return 8;   // Floating64, Currency, FloatingTime, Integer64, Time
	default: return 0;
	}
}

} // namespace

bool PstFile::readAt(uint64_t offset, size_t size, std::vector<uint8_t>& bytes) {
	if (offset > fileSize_ || size > fileSize_ - offset) return false;
	bytes.resize(size);
	file_.clear();
	file_.seekg((std::streamoff)offset);
	return (bool)file_.read(reinterpret_cast<char*>(bytes.data()), (std::streamsize)size);
}

bool PstFile::open(const std::wstring& path, std::wstring& why) {
	std::error_code ec;
	fileSize_ = std::filesystem::file_size(std::filesystem::path(path), ec);
	if (ec) { why = L"unreadable"; return false; }
	file_.open(std::filesystem::path(extendedPath(path)), std::ios::binary);
	std::vector<uint8_t> h;
	if (!file_ || !readAt(0, HEADER_SIZE, h)) { why = L"too short for a header"; return false; }
	if (memcmp(h.data(), "!BDN", 4) != 0) { why = L"no !BDN signature"; return false; }
	ost_ = h[8] == 'S' && h[9] == 'O';
	version_ = readLittleEndian<uint16_t>(h.data() + 10);
	if (version_ != VERSION_UNICODE && version_ != VERSION_4K) {
		why = L"version " + std::to_wstring(version_) + L" not decoded (ANSI or unknown)";
		return false;
	}
	encryption_ = h[513];
	if (encryption_ > 1) { why = L"\"cyclic\" encryption not decoded"; return false; }
	pageSize_ = version_ == VERSION_4K ? 4096 : 512;
	nodeTreeRoot_ = readLittleEndian<uint64_t>(h.data() + 224);
	blockTreeRoot_ = readLittleEndian<uint64_t>(h.data() + 240);
	return true;
}

/*! A B-tree page's layout: where its count, entry size and level lie, and its
 *  type in the trailer — at the end of 512 bytes, or of 4,096 (version 36). */
namespace {
struct PageLayout { size_t entries, count, entrySize, level, type; bool wideCount; };
PageLayout layoutOf(size_t pageSize) {
	return pageSize == 4096 ? PageLayout{ 4056, 4056, 4060, 4061, 4072, true }
	                        : PageLayout{ 488, 488, 490, 491, 496, false };
}
} // namespace

bool PstFile::findInTree(uint64_t pageOffset, uint64_t key, bool blockTree, std::vector<uint8_t>& entry, int depth) {
	std::vector<uint8_t> page;
	if (depth > MAX_DEPTH || !readAt(pageOffset, pageSize_, page)) return false;
	const PageLayout l = layoutOf(pageSize_);
	if (page[l.type] != (blockTree ? PAGE_BLOCK_TREE : PAGE_NODE_TREE)) return false;
	const size_t count = l.wideCount ? readLittleEndian<uint16_t>(page.data() + l.count) : page[l.count];
	const size_t size = page[l.entrySize], level = page[l.level];
	if (size < 24 || count * size > l.entries) return false;
	const uint64_t mask = blockTree ? ~1ULL : 0xFFFFFFFFULL;
	if (level > 0) {
		// The last child whose first key is not above the one looked for.
		uint64_t child = 0;
		bool found = false;
		for (size_t i = 0; i < count; ++i) {
			const uint8_t* e = page.data() + i * size;
			if ((readLittleEndian<uint64_t>(e) & mask) > (key & mask)) break;
			child = readLittleEndian<uint64_t>(e + 16);
			found = true;
		}
		return found && findInTree(child, key, blockTree, entry, depth + 1);
	}
	for (size_t i = 0; i < count; ++i) {
		const uint8_t* e = page.data() + i * size;
		if ((readLittleEndian<uint64_t>(e) & mask) == (key & mask)) {
			entry.assign(e, e + size);
			return true;
		}
	}
	return false;
}

bool PstFile::walkNodeTree(uint64_t pageOffset, std::vector<PstNode>& nodes, std::set<uint64_t>& visited, int depth) {
	std::vector<uint8_t> page;
	if (depth > MAX_DEPTH || !visited.insert(pageOffset).second || !readAt(pageOffset, pageSize_, page)) return false;
	const PageLayout l = layoutOf(pageSize_);
	if (page[l.type] != PAGE_NODE_TREE) return false;
	const size_t count = l.wideCount ? readLittleEndian<uint16_t>(page.data() + l.count) : page[l.count];
	const size_t size = page[l.entrySize], level = page[l.level];
	if (size < (level ? 24u : 32u) || count * size > l.entries) return false;
	bool whole = true;
	for (size_t i = 0; i < count; ++i) {
		const uint8_t* e = page.data() + i * size;
		if (level > 0) {
			whole = walkNodeTree(readLittleEndian<uint64_t>(e + 16), nodes, visited, depth + 1) && whole;
			continue;
		}
		PstNode n;
		n.nid = (uint32_t)readLittleEndian<uint64_t>(e);
		n.dataBid = readLittleEndian<uint64_t>(e + 8);
		n.subnodeBid = readLittleEndian<uint64_t>(e + 16);
		n.parent = readLittleEndian<uint32_t>(e + 24);
		nodes.push_back(n);
	}
	return whole;
}

bool PstFile::allNodes(std::vector<PstNode>& nodes) {
	std::set<uint64_t> visited;
	return walkNodeTree(nodeTreeRoot_, nodes, visited, 0);
}

bool PstFile::block(uint64_t bid, std::vector<uint8_t>& data) {
	std::vector<uint8_t> entry;
	if (!findInTree(blockTreeRoot_, bid, true, entry, 0)) return false;
	const uint64_t offset = readLittleEndian<uint64_t>(entry.data() + 8);
	const size_t size = readLittleEndian<uint16_t>(entry.data() + 16);
	const bool wide = version_ == VERSION_4K;
	const size_t trailer = wide ? 24 : 16;
	const size_t allocated = alignedTo(size + trailer, wide ? 512 : 64);
	std::vector<uint8_t> raw;
	if (!readAt(offset, allocated, raw)) return false;
	const uint8_t* t = raw.data() + allocated - trailer;
	// The trailer names its block: another one there is a block moved or a forged entry.
	if (readLittleEndian<uint16_t>(t) != size || (readLittleEndian<uint64_t>(t + 8) & ~1ULL) != (bid & ~1ULL)) return false;
	data.assign(raw.begin(), raw.begin() + size);
	if (bid & BID_INTERNAL) return true;
	if (encryption_ == 1) for (uint8_t& b : data) b = PERMUTATION[b];
	const size_t inflated = wide ? readLittleEndian<uint16_t>(t + 18) : size;
	if (inflated == 0 || inflated == size) return true;
	// A zlib stream: its header (0x78), DEFLATE, then the Adler-32 of the output, big-endian.
	if (size < 6 || data[0] != 0x78) return false;
	std::vector<uint8_t> out;
	if (!Inflate(data.data() + 2, size - 6, out, inflated) || out.size() != inflated) return false;
	const uint32_t expected = ((uint32_t)data[size - 4] << 24) | ((uint32_t)data[size - 3] << 16)
	                        | ((uint32_t)data[size - 2] << 8) | data[size - 1];
	if (adler32(out) != expected) return false;
	data.swap(out);
	return true;
}

bool PstFile::dataTree(uint64_t bid, std::vector<std::vector<uint8_t>>& blocks, std::set<uint64_t>& visited, int depth) {
	std::vector<uint8_t> d;
	if (depth > MAX_DEPTH || ((bid & BID_INTERNAL) && !visited.insert(bid).second) || !block(bid, d)) return false;
	if (!(bid & BID_INTERNAL)) { blocks.push_back(std::move(d)); return true; }
	// XBLOCK (level 1: data blocks) or XXBLOCK (level 2: XBLOCKs): type, level, count, total size, the identifiers.
	if (d.size() < 8 || d[0] != 0x01 || (d[1] != 1 && d[1] != 2)) return false;
	const size_t count = readLittleEndian<uint16_t>(d.data() + 2);
	if (!fits(d.size(), 8, count * 8)) return false;
	for (size_t i = 0; i < count; ++i) {
		const uint64_t child = readLittleEndian<uint64_t>(d.data() + 8 + 8 * i);
		if (d[1] == 1) {
			std::vector<uint8_t> leaf;
			if (!block(child, leaf)) return false;
			blocks.push_back(std::move(leaf));
		}
		else if (!dataTree(child, blocks, visited, depth + 1)) return false;
	}
	return true;
}

bool PstFile::dataBlocks(uint64_t bid, std::vector<std::vector<uint8_t>>& blocks) {
	blocks.clear();
	std::set<uint64_t> visited;
	// An XBLOCK may declare no child: no block is no data, never a front() to read.
	return bid != 0 && dataTree(bid, blocks, visited, 0) && !blocks.empty();
}

bool PstFile::subnodeTree(uint64_t bid, std::map<uint32_t, PstSubnode>& subnodes, std::set<uint64_t>& visited, int depth) {
	std::vector<uint8_t> d;
	if (depth > MAX_DEPTH || !visited.insert(bid).second || !block(bid, d)) return false;
	// SLBLOCK (level 0: the subnodes) or SIBLOCK (level 1: SLBLOCKs): type, level, count, padding.
	if (d.size() < 8 || d[0] != 0x02 || d[1] > 1) return false;
	const size_t count = readLittleEndian<uint16_t>(d.data() + 2);
	const size_t size = d[1] == 0 ? 24 : 16;
	if (!fits(d.size(), 8, count * size)) return false;
	bool whole = true;
	for (size_t i = 0; i < count; ++i) {
		const uint8_t* e = d.data() + 8 + i * size;
		if (d[1] == 1) { whole = subnodeTree(readLittleEndian<uint64_t>(e + 8), subnodes, visited, depth + 1) && whole; continue; }
		PstSubnode s;
		s.dataBid = readLittleEndian<uint64_t>(e + 8);
		s.subnodeBid = readLittleEndian<uint64_t>(e + 16);
		subnodes[(uint32_t)readLittleEndian<uint64_t>(e)] = s;
	}
	return whole;
}

bool PstFile::subnodes(uint64_t bid, std::map<uint32_t, PstSubnode>& subnodes) {
	subnodes.clear();
	std::set<uint64_t> visited;
	return bid == 0 || subnodeTree(bid, subnodes, visited, 0);
}

bool PstFile::heapItem(const std::vector<std::vector<uint8_t>>& heap, uint32_t hid, std::vector<uint8_t>& item) {
	// A heap identifier: type (5 bits, 0), index of the allocation (11 bits, from 1), index of the block (16 bits).
	const size_t index = (hid >> 5) & 0x7FF, blockIndex = hid >> 16;
	if ((hid & 0x1F) != 0 || index == 0 || blockIndex >= heap.size()) return false;
	const std::vector<uint8_t>& b = heap[blockIndex];
	if (b.size() < 2) return false;
	// The page map, at the offset each block starts with: allocations count, frees count, their offsets.
	const size_t map = readLittleEndian<uint16_t>(b.data());
	if (!fits(b.size(), map, 4)) return false;
	const size_t allocations = readLittleEndian<uint16_t>(b.data() + map);
	if (index > allocations || !fits(b.size(), map + 4, (allocations + 1) * 2)) return false;
	const size_t start = readLittleEndian<uint16_t>(b.data() + map + 4 + 2 * (index - 1));
	const size_t end = readLittleEndian<uint16_t>(b.data() + map + 4 + 2 * index);
	if (start > end || end > map) return false;
	item.assign(b.begin() + start, b.begin() + end);
	return true;
}

bool PstFile::hnidValue(const std::vector<std::vector<uint8_t>>& heap, const std::map<uint32_t, PstSubnode>& subnodes,
                        uint32_t hnid, std::vector<uint8_t>& value) {
	value.clear();
	if (hnid == 0) return true;
	if ((hnid & 0x1F) == 0) return heapItem(heap, hnid, value);
	// Not a heap item: the identifier of a subnode holding the value.
	const auto it = subnodes.find(hnid);
	std::vector<std::vector<uint8_t>> blocks;
	if (it == subnodes.end() || !dataBlocks(it->second.dataBid, blocks)) return false;
	for (const std::vector<uint8_t>& b : blocks) value.insert(value.end(), b.begin(), b.end());
	return true;
}

bool PstFile::heapTreeRecords(const std::vector<std::vector<uint8_t>>& heap, uint32_t hidHeader,
                              std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& records) {
	std::vector<uint8_t> header;
	if (!heapItem(heap, hidHeader, header) || header.size() < 8 || header[0] != CLIENT_HEAP_TREE) return false;
	const size_t keySize = header[1], dataSize = header[2], levels = header[3];
	const uint32_t root = readLittleEndian<uint32_t>(header.data() + 4);
	if (keySize == 0 || keySize > 16 || levels > MAX_DEPTH) return false;
	if (root == 0) return true;   // an empty tree
	// Each level an item of records: key, then a child's identifier (index levels) or the data (leaf).
	std::vector<std::pair<uint32_t, size_t>> pending = { { root, levels } };
	while (!pending.empty()) {
		const auto [hid, level] = pending.back();
		pending.pop_back();
		std::vector<uint8_t> item;
		if (!heapItem(heap, hid, item)) return false;
		const size_t size = keySize + (level ? 4 : dataSize);
		for (size_t at = 0; at + size <= item.size(); at += size) {
			if (level) pending.push_back({ readLittleEndian<uint32_t>(item.data() + at + keySize), level - 1 });
			else records.push_back({ std::vector<uint8_t>(item.begin() + at, item.begin() + at + keySize),
			                         std::vector<uint8_t>(item.begin() + at + keySize, item.begin() + at + size) });
		}
		if (records.size() > 1000000) return false;   // no object holds that many: a forged tree
	}
	return true;
}

bool PstFile::properties(uint64_t dataBid, uint64_t subnodeBid, PstProperties& properties) {
	properties.clear();
	std::vector<std::vector<uint8_t>> heap;
	std::map<uint32_t, PstSubnode> subs;
	if (!dataBlocks(dataBid, heap) || heap.front().size() < 8 || heap.front()[2] != HEAP_SIGNATURE
	    || heap.front()[3] != CLIENT_PROPERTIES || !subnodes(subnodeBid, subs)) return false;
	std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> records;
	if (!heapTreeRecords(heap, readLittleEndian<uint32_t>(heap.front().data() + 4), records)) return false;
	for (const auto& [key, data] : records) {
		if (key.size() != 2 || data.size() != 6) return false;
		PstValue v;
		v.type = readLittleEndian<uint16_t>(data.data());
		const uint32_t hnid = readLittleEndian<uint32_t>(data.data() + 2);
		const size_t fixed = fixedSize(v.type);
		if (fixed && fixed <= 4) v.bytes.assign(data.begin() + 2, data.begin() + 2 + fixed);   // inline
		else if (!hnidValue(heap, subs, hnid, v.bytes)) continue;   // a value that does not hold: left out
		if (fixed && v.bytes.size() != fixed) continue;
		properties[readLittleEndian<uint16_t>(key.data())] = std::move(v);
	}
	return true;
}

bool PstFile::tableRows(uint64_t dataBid, uint64_t subnodeBid, std::vector<PstProperties>& rows) {
	rows.clear();
	std::vector<std::vector<uint8_t>> heap;
	std::map<uint32_t, PstSubnode> subs;
	if (!dataBlocks(dataBid, heap) || heap.front().size() < 8 || heap.front()[2] != HEAP_SIGNATURE
	    || heap.front()[3] != CLIENT_TABLE || !subnodes(subnodeBid, subs)) return false;
	std::vector<uint8_t> info;
	if (!heapItem(heap, readLittleEndian<uint32_t>(heap.front().data() + 4), info) || info.size() < 22 || info[0] != CLIENT_TABLE)
		return false;
	// TCINFO: columns count, offsets of the 4-, 2-, 1-byte groups and of the row's end, row index, row matrix.
	const size_t columns = info[1];
	if (!fits(info.size(), 22, columns * 8)) return false;
	const size_t existence = readLittleEndian<uint16_t>(info.data() + 6), rowSize = readLittleEndian<uint16_t>(info.data() + 8);
	const uint32_t rowIndex = readLittleEndian<uint32_t>(info.data() + 10), matrix = readLittleEndian<uint32_t>(info.data() + 14);
	if (rowSize == 0 || existence + (columns + 7) / 8 > rowSize) return false;
	std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> index;
	if (!heapTreeRecords(heap, rowIndex, index)) return false;
	// The row matrix: one heap item, or a subnode whose blocks each hold whole rows.
	std::vector<std::vector<uint8_t>> matrixBlocks;
	if (matrix == 0) return true;
	if ((matrix & 0x1F) == 0) {
		std::vector<uint8_t> item;
		if (!heapItem(heap, matrix, item)) return false;
		matrixBlocks.push_back(std::move(item));
	}
	else {
		const auto it = subs.find(matrix);
		if (it == subs.end() || !dataBlocks(it->second.dataBid, matrixBlocks)) return false;
	}
	const size_t perBlock = matrixBlocks.front().size() / rowSize;
	for (const auto& [key, data] : index) {
		if (data.size() < 2 || perBlock == 0) return false;
		const size_t r = data.size() >= 4 ? readLittleEndian<uint32_t>(data.data()) : readLittleEndian<uint16_t>(data.data());
		const size_t blockIndex = r / perBlock, at = (r % perBlock) * rowSize;
		if (blockIndex >= matrixBlocks.size() || !fits(matrixBlocks[blockIndex].size(), at, rowSize)) continue;
		const uint8_t* row = matrixBlocks[blockIndex].data() + at;
		PstProperties properties;
		for (size_t c = 0; c < columns; ++c) {
			const uint8_t* desc = info.data() + 22 + c * 8;
			const uint32_t tag = readLittleEndian<uint32_t>(desc);
			const size_t offset = readLittleEndian<uint16_t>(desc + 4), size = desc[6], bit = desc[7];
			// The bit is the descriptor's, up to 255: bounded by the row, not by the column count.
			if (offset + size > rowSize || existence + bit / 8 >= rowSize || !(row[existence + bit / 8] & (0x80 >> (bit % 8)))) continue;
			PstValue v;
			v.type = (uint16_t)(tag & 0xFFFF);
			const size_t fixed = fixedSize(v.type);
			if (fixed) {
				if (size < fixed) continue;
				v.bytes.assign(row + offset, row + offset + fixed);
			}
			else if (size != 4 || !hnidValue(heap, subs, readLittleEndian<uint32_t>(row + offset), v.bytes)) continue;
			properties[(uint16_t)(tag >> 16)] = std::move(v);
		}
		rows.push_back(std::move(properties));
	}
	return true;
}

std::wstring pstValueText(const PstValue& v) {
	const std::vector<uint8_t>& b = v.bytes;
	switch (v.type) {
	case 0x001F: {   // PtypString, UTF-16
		std::wstring text;
		for (size_t i = 0; i + 1 < b.size(); i += 2) text += (wchar_t)readLittleEndian<uint16_t>(b.data() + i);
		while (!text.empty() && text.back() == L'\0') text.pop_back();
		return text;
	}
	case 0x001E: {   // PtypString8, in the message's code page: Western by default
		std::string text(b.begin(), b.end());
		while (!text.empty() && text.back() == '\0') text.pop_back();
		return decodeText(text, 1252);
	}
	case 0x0002: return b.size() == 2 ? std::to_wstring((int16_t)readLittleEndian<uint16_t>(b.data())) : L"";
	case 0x0003: return b.size() == 4 ? std::to_wstring((int32_t)readLittleEndian<uint32_t>(b.data())) : L"";
	case 0x0014: return b.size() == 8 ? std::to_wstring((long long)readLittleEndian<uint64_t>(b.data())) : L"";
	case 0x000B: return b.size() >= 1 ? (b[0] ? L"true" : L"false") : L"";
	case 0x0040: return b.size() == 8 ? timeToIso8601Utc(filetimeFromTicks(readLittleEndian<uint64_t>(b.data()))) : L"";
	case 0x0048: return b.size() == 16 ? guid_to_wstring(b.data()) : L"";
	case 0x0102: return toHexadecimal(b.data(), b.size());
	default: return L"";
	}
}

uint32_t pstInteger(const PstProperties& properties, uint16_t id) {
	const auto it = properties.find(id);
	if (it == properties.end()) return 0;
	const PstValue& v = it->second;
	if (v.type == 0x0003 && v.bytes.size() == 4) return readLittleEndian<uint32_t>(v.bytes.data());
	if (v.type == 0x0002 && v.bytes.size() == 2) return readLittleEndian<uint16_t>(v.bytes.data());
	return 0;
}
