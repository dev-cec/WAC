/*! \file
 *  \brief The messages of a PST or OST file (see pst_messages.h).
 */
#include "pst_messages.h"
#include "conversions.h"
#include <map>

namespace {

const uint16_t ATTACH_DATA = 0x3701, ATTACH_FILENAME = 0x3704, ATTACH_METHOD = 0x3705, ATTACH_LONG_FILENAME = 0x3707;
const uint16_t ATTACH_MIME = 0x370E, LTP_ROW_ID = 0x67F2;
const uint16_t EMAIL_ADDRESS = 0x3003, RECIPIENT_TYPE = 0x0C15;
const int MAX_FOLDER_DEPTH = 64;   //!< deeper than any real mailbox: a cycle of parents

/*! The folder path of a node, from the folders' display names.
 *  @param folders each folder's display name and parent
 *  @param nid the folder
 *  @return the names from the root folder down, joined by "/" */
std::wstring folderPath(const std::map<uint32_t, std::pair<std::wstring, uint32_t>>& folders, uint32_t nid) {
	std::wstring path;
	for (int depth = 0; depth < MAX_FOLDER_DEPTH && nid != PST_NID_ROOT_FOLDER; ++depth) {
		const auto it = folders.find(nid);
		if (it == folders.end()) break;
		path = it->second.first + (path.empty() ? L"" : L"/" + path);
		if (it->second.second == nid) break;
		nid = it->second.second;
	}
	return path;
}

/*! An attachment's properties into the attachment. An embedded object
 *  (PtypObject): the value names a subnode of the attachment and its size; the
 *  subnode's bytes are the attachment's data, as libpff gives them, and its
 *  properties those of the embedded message.
 *  @param file the file
 *  @param p the attachment's properties
 *  @param subnodeBid the attachment's own subnodes */
PstAttachment attachmentOf(PstFile& file, const PstProperties& p, uint64_t subnodeBid) {
	PstAttachment a;
	const auto text = [&](uint16_t id) { const auto it = p.find(id); return it == p.end() ? std::wstring() : pstValueText(it->second); };
	a.fileName = text(ATTACH_LONG_FILENAME);
	if (a.fileName.empty()) a.fileName = text(ATTACH_FILENAME);
	a.mimeType = text(ATTACH_MIME);
	a.method = pstInteger(p, ATTACH_METHOD);
	const auto data = p.find(ATTACH_DATA);
	if (data != p.end() && data->second.type == 0x0102) {
		a.data = data->second.bytes;
		a.dataRead = true;
	}
	else if (data != p.end() && data->second.type == 0x000D && data->second.bytes.size() >= 4) {
		std::map<uint32_t, PstSubnode> subs;
		std::vector<std::vector<uint8_t>> blocks;
		const auto sub = file.subnodes(subnodeBid, subs) ? subs.find(readLittleEndian<uint32_t>(data->second.bytes.data())) : subs.end();
		if (sub != subs.end() && file.dataBlocks(sub->second.dataBid, blocks)) {
			for (const std::vector<uint8_t>& b : blocks) a.data.insert(a.data.end(), b.begin(), b.end());
			a.dataRead = true;
			file.properties(sub->second.dataBid, sub->second.subnodeBid, a.embedded);
		}
	}
	return a;
}

} // namespace

std::wstring PstMessage::text(uint16_t id) const {
	const auto it = properties.find(id);
	return it == properties.end() ? std::wstring() : pstValueText(it->second);
}

std::wstring PstMessage::subject() const {
	std::wstring s = text(PST_SUBJECT);
	if (s.size() >= 2 && s[0] == 0x01) s.erase(0, 2);
	return s;
}

bool PstMessage::time(uint16_t id, FILETIME& utc) const {
	const auto it = properties.find(id);
	if (it == properties.end() || it->second.type != 0x0040 || it->second.bytes.size() != 8) return false;
	utc = filetimeFromTicks(readLittleEndian<uint64_t>(it->second.bytes.data()));
	return true;
}

bool forEachPstMessage(PstFile& file, const std::function<void(PstMessage&)>& onMessage, size_t& unreadable) {
	unreadable = 0;
	std::vector<PstNode> nodes;
	const bool whole = file.allNodes(nodes);
	std::map<uint32_t, std::pair<std::wstring, uint32_t>> folders;
	for (const PstNode& n : nodes) {
		if (pstNodeType(n.nid) != PST_NODE_FOLDER) continue;
		PstProperties p;
		std::wstring name;
		if (file.properties(n.dataBid, n.subnodeBid, p)) {
			const auto it = p.find(PST_DISPLAY_NAME);
			if (it != p.end()) name = pstValueText(it->second);
		}
		folders[n.nid] = { name, n.parent };
	}
	for (const PstNode& n : nodes) {
		if (pstNodeType(n.nid) != PST_NODE_MESSAGE || pstNodeType(n.parent) != PST_NODE_FOLDER) continue;
		PstMessage m;
		m.nid = n.nid;
		if (!file.properties(n.dataBid, n.subnodeBid, m.properties)) { ++unreadable; continue; }
		m.folder = folderPath(folders, n.parent);
		std::map<uint32_t, PstSubnode> subs;
		if (!file.subnodes(n.subnodeBid, subs)) m.readWhole = false;
		const auto recipients = subs.find(PST_NID_RECIPIENT_TABLE);
		std::vector<PstProperties> rows;
		if (recipients != subs.end()) {
			if (file.tableRows(recipients->second.dataBid, recipients->second.subnodeBid, rows)) {
				for (const PstProperties& r : rows) {
					PstRecipient rec;
					const auto name = r.find(PST_DISPLAY_NAME), address = r.find(EMAIL_ADDRESS);
					if (name != r.end()) rec.name = pstValueText(name->second);
					if (address != r.end()) rec.address = pstValueText(address->second);
					rec.type = pstInteger(r, RECIPIENT_TYPE);
					m.recipients.push_back(std::move(rec));
				}
			}
			else m.readWhole = false;
		}
		// The attachments: the table names each one's subnode (its row identifier).
		const auto table = subs.find(PST_NID_ATTACHMENT_TABLE);
		if (table != subs.end()) {
			if (file.tableRows(table->second.dataBid, table->second.subnodeBid, rows)) {
				for (const PstProperties& r : rows) {
					const auto sub = subs.find(pstInteger(r, LTP_ROW_ID));
					PstProperties p;
					if (sub == subs.end() || !file.properties(sub->second.dataBid, sub->second.subnodeBid, p)) {
						m.readWhole = false;
						continue;
					}
					m.attachments.push_back(attachmentOf(file, p, sub->second.subnodeBid));
				}
			}
			else m.readWhole = false;
		}
		onMessage(m);
	}
	return whole;
}
