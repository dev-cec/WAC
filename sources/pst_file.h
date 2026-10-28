/*! \file
 *  \brief Outlook's data files, PST and OST, read with WAC's own code: the
 *         node and block layer (NDB) and the lists and tables built on it (LTP),
 *         after [MS-PST].
 *
 *  WHY OUR OWN READER. A mailbox holds the messages and the attachments an
 *  intruder sent or received; no Windows API reads a PST without Outlook, and
 *  WAC takes no library it does not review. The format is Microsoft's open
 *  specification [MS-PST]; what it leaves out was measured on the test corpus
 *  (backlog B-017) and is said where it is used.
 *
 *  WHAT IS READ.
 *    - The header: "!BDN", the version — 23 for a Unicode PST (Outlook 2003
 *      and later), 36 for the OST of Outlook 2013 and later, with 4 KiB pages
 *      and compressed blocks —, the encryption, the roots of the two B-trees.
 *      The ANSI files (versions 14 and 15, Outlook 97 to 2002) are not decoded.
 *    - The node B-tree (NBT): a node per folder, message, attachment…, with
 *      its data, its subnodes and its parent; the block B-tree (BBT): where
 *      each block lies. Pages of 512 bytes (version 23) or 4,096 (36).
 *    - The blocks: their trailer, the "permutation" encryption undone; in
 *      version 36, a block whose stored size is not its inflated size is a
 *      zlib stream, inflated and its Adler-32 checked. The "cyclic"
 *      encryption has no sample to check it on: refused, and said.
 *    - The data trees (XBLOCK, XXBLOCK) and the subnode trees (SLBLOCK,
 *      SIBLOCK).
 *    - On top: the heap on a node (HN), the B-tree on a heap (BTH), the
 *      property context (PC: a message, a folder, an attachment) and the
 *      table context (TC: recipients, attachments).
 *
 *  HOSTILE INPUT. A PST is the suspect's file: every offset, count and size
 *  read in it is checked against the file and the block it lies in; a cycle
 *  in a tree is stopped by a depth limit. A part that does not hold is left
 *  out, and the rest still read.
 */
#pragma once

#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

/*! A node of the node B-tree. */
struct PstNode {
	uint32_t nid = 0;          //!< identifier: index << 5 | type
	uint64_t dataBid = 0;      //!< block (or data tree) of its data, 0 for none
	uint64_t subnodeBid = 0;   //!< block of its subnode tree, 0 for none
	uint32_t parent = 0;       //!< parent node: a message's folder, a folder's parent
};

//! The type of a node: its identifier's low five bits.
inline uint32_t pstNodeType(uint32_t nid) { return nid & 0x1F; }

const uint32_t PST_NODE_FOLDER = 0x02;       //!< a folder
const uint32_t PST_NODE_MESSAGE = 0x04;      //!< a message (or a contact, an appointment…)
const uint32_t PST_NODE_ATTACHMENT = 0x05;   //!< an attachment, in a message's subnodes
const uint32_t PST_NID_ROOT_FOLDER = 0x122;  //!< the root of the folders
const uint32_t PST_NID_ATTACHMENT_TABLE = 0x671;   //!< a message's attachment table, a subnode
const uint32_t PST_NID_RECIPIENT_TABLE = 0x692;    //!< a message's recipient table, a subnode

/*! A subnode: data of its own under a node (an attachment, a long value). */
struct PstSubnode {
	uint64_t dataBid = 0;      //!< its data
	uint64_t subnodeBid = 0;   //!< its own subnodes
};

/*! A property's value, as stored: its type and its bytes. */
struct PstValue {
	uint16_t type = 0;              //!< PtypInteger32 0x0003, PtypString 0x001F, PtypTime 0x0040…
	std::vector<uint8_t> bytes;     //!< the value; for a fixed type, its little-endian bytes
};

//! A property context: the properties of one object, by identifier.
using PstProperties = std::map<uint16_t, PstValue>;

/*! A PST or OST file, opened for reading. */
class PstFile {
public:
	/*! Opens a file and reads its header.
	 *  @param path the file (a working copy)
	 *  @param why receives, on failure, the reason in a few words
	 *  @return true if the file is a PST/OST of a version and encryption decoded */
	bool open(const std::wstring& path, std::wstring& why);

	//! @return the header's version: 23 (PST) or 36 (OST, 4 KiB pages)
	uint16_t version() const { return version_; }
	//! @return "PST" or "OST", from the header's client signature
	std::wstring kind() const { return ost_ ? L"OST" : L"PST"; }

	/*! Every node of the node B-tree.
	 *  @param nodes receives them, in the tree's order
	 *  @return false if the tree could not be walked entirely */
	bool allNodes(std::vector<PstNode>& nodes);

	/*! The data of a node or a subnode, block by block: a heap keeps its
	 *  structure per block, a binary value is their concatenation.
	 *  @param bid its data block or data tree
	 *  @param blocks receives the blocks' data, in order
	 *  @return false if a block is missing or does not hold */
	bool dataBlocks(uint64_t bid, std::vector<std::vector<uint8_t>>& blocks);

	/*! The subnodes under a node.
	 *  @param bid the node's subnode tree
	 *  @param subnodes receives them by identifier
	 *  @return false if the tree does not hold */
	bool subnodes(uint64_t bid, std::map<uint32_t, PstSubnode>& subnodes);

	/*! The properties of a property context (a message, a folder, an attachment).
	 *  @param dataBid its data
	 *  @param subnodeBid its subnodes, where its large values lie
	 *  @param properties receives them
	 *  @return false if it is not a property context */
	bool properties(uint64_t dataBid, uint64_t subnodeBid, PstProperties& properties);

	/*! The rows of a table context (recipients, attachments), each row as
	 *  properties, the columns the row does not hold left out.
	 *  @param dataBid its data
	 *  @param subnodeBid its subnodes, where its rows and large values may lie
	 *  @param rows receives the rows, in order
	 *  @return false if it is not a table context */
	bool tableRows(uint64_t dataBid, uint64_t subnodeBid, std::vector<PstProperties>& rows);

private:
	//! A leaf entry of the block B-tree: where a block lies.
	struct BlockEntry { uint64_t offset = 0; uint16_t size = 0; };

	bool readAt(uint64_t offset, size_t size, std::vector<uint8_t>& bytes);
	bool findInTree(uint64_t pageOffset, uint64_t key, bool blockTree, std::vector<uint8_t>& entry, int depth);
	bool walkNodeTree(uint64_t pageOffset, std::vector<PstNode>& nodes, std::set<uint64_t>& visited, int depth);
	bool block(uint64_t bid, std::vector<uint8_t>& data);
	bool dataTree(uint64_t bid, std::vector<std::vector<uint8_t>>& blocks, std::set<uint64_t>& visited, int depth);
	bool subnodeTree(uint64_t bid, std::map<uint32_t, PstSubnode>& subnodes, std::set<uint64_t>& visited, int depth);
	bool heapItem(const std::vector<std::vector<uint8_t>>& heap, uint32_t hid, std::vector<uint8_t>& item);
	bool hnidValue(const std::vector<std::vector<uint8_t>>& heap, const std::map<uint32_t, PstSubnode>& subnodes,
	               uint32_t hnid, std::vector<uint8_t>& value);
	bool heapTreeRecords(const std::vector<std::vector<uint8_t>>& heap, uint32_t hidHeader,
	                     std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& records);

	std::ifstream file_;
	uint64_t fileSize_ = 0;
	uint16_t version_ = 0;
	bool ost_ = false;
	uint8_t encryption_ = 0;        //!< 0 none, 1 permutation
	uint64_t nodeTreeRoot_ = 0;     //!< offset of the NBT's root page
	uint64_t blockTreeRoot_ = 0;    //!< offset of the BBT's root page
	size_t pageSize_ = 512;         //!< 512 (version 23) or 4,096 (36)
};

/*! A property's value as text: strings, numbers, times (ISO 8601 UTC),
 *  binaries (hexadecimal). Types WAC does not render come back empty.
 *  @param value the value
 *  @return its text */
std::wstring pstValueText(const PstValue& value);

/*! The 32-bit unsigned value of an integer property, 0 if absent or not an integer.
 *  @param properties the object's properties
 *  @param id the property's identifier
 *  @return the value */
uint32_t pstInteger(const PstProperties& properties, uint16_t id);
