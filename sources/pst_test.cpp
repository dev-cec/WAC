/*! \file
 *  \brief Confronts WAC's PST and OST reader with pypff (libpff), message by
 *  message, on the files pst_fixtures.sh downloads.
 *
 *  WHY THIS TEST. A message decoded wrong — a block decrypted with the wrong
 *  table, a heap item cut one byte off, a compressed block inflated short —
 *  still gives valid JSON. pypff, libpff's reader written independently of
 *  WAC, reads the same files: subject, sender, delivery and submission
 *  times, every attachment's name, size and SHA-256, and the plain body's
 *  SHA-256 must be the same for each message. The items pypff itself cannot
 *  read must not stop WAC.
 *
 *  Usage (runs under wine): pst_test.exe `<folder of pst_fixtures.sh>`
 */
#include "pst_messages.h"
#include "sha.h"
#include "tools.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 25) std::printf("  FAILED  %s\n", what.c_str());
}

//! @return the text as UTF-8, for the messages and the reference
std::string utf8(const std::wstring& text) { return encodeText(text, CP_UTF8); }

//! The SHA-256 of bytes, lower case as hashlib gives it.
std::string sha256Of(const uint8_t* bytes, size_t size) {
	Sha256Stream digest;
	digest.update(bytes, size);
	return utf8(toLower(digest.hexDigest()));
}

//! The reference's own cleaning of a text: no "|" nor line break.
std::string cleaned(std::string text) {
	for (char& c : text) if (c == '|' || c == '\n' || c == '\r') c = ' ';
	return text;
}

//! What WAC reads of a message, in the reference's form.
std::vector<std::string> fieldsOf(const PstMessage& m) {
	std::string attachments;
	for (const PstAttachment& a : m.attachments) {
		if (!attachments.empty()) attachments += ";";
		attachments += cleaned(utf8(a.fileName)) + ":" + std::to_string(a.data.size()) + ":" + sha256Of(a.data.data(), a.data.size());
	}
	FILETIME t{};
	const std::string delivery = m.time(PST_DELIVERY_TIME, t) ? std::to_string(ticksFromFiletime(t)) : "0";
	const std::string submit = m.time(PST_CLIENT_SUBMIT_TIME, t) ? std::to_string(ticksFromFiletime(t)) : "0";
	const std::string body = utf8(m.text(PST_BODY));
	return { cleaned(utf8(m.subject())), cleaned(utf8(m.text(PST_SENDER_NAME))), delivery, submit, attachments,
	         body.empty() ? "" : sha256Of(reinterpret_cast<const uint8_t*>(body.data()), body.size()) };
}


/*! A PST forged here, page by page: the three defects a hostile mailbox
 *  reached. A node-tree page whose children are all itself (walked 20^16
 *  times before), an XBLOCK declaring no child (an empty list then read by
 *  front()), and a table whose column names an existence bit past its row
 *  bitmap (read in the next row). Each case is answered, not crashed on.
 *  @param folder where the file is written */
void forgedFile(const std::wstring& folder) {
	std::vector<uint8_t> f(2240, 0);
	auto put16 = [&](size_t at, uint16_t v) { writeLittleEndian<uint16_t>(f.data() + at, v); };
	auto put32 = [&](size_t at, uint32_t v) { writeLittleEndian<uint32_t>(f.data() + at, v); };
	auto put64 = [&](size_t at, uint64_t v) { writeLittleEndian<uint64_t>(f.data() + at, v); };
	std::memcpy(f.data(), "!BDN", 4);
	f[8] = 'S'; f[9] = 'M';
	put16(10, 23);                       // Unicode PST, 512-byte pages, no encryption (byte 513)
	put64(224, 1024);                    // node tree root
	put64(240, 1536);                    // block tree root
	// Node tree: an index page (level 1) of 20 entries, each child the page itself.
	for (size_t i = 0; i < 20; ++i) { put64(1024 + i * 24, i + 1); put64(1024 + i * 24 + 16, 1024); }
	f[1024 + 488] = 20; f[1024 + 490] = 24; f[1024 + 491] = 1; f[1024 + 496] = 0x81;
	// Block tree, a leaf: the heap (bid 4, 84 bytes at 2048), the empty XBLOCK (bid 6, 8 bytes at 2176).
	put64(1536, 4); put64(1536 + 8, 2048); put16(1536 + 16, 84);
	put64(1560, 6); put64(1560 + 8, 2176); put16(1560 + 16, 8);
	f[1536 + 488] = 2; f[1536 + 490] = 24; f[1536 + 491] = 0; f[1536 + 496] = 0x80;
	// The heap of a table: header, TCINFO, BTH header, its one record, a matrix of two rows; the page map.
	const size_t h = 2048;
	put16(h, 70); f[h + 2] = 0xEC; f[h + 3] = 0x7C; put32(h + 4, 0x20);
	f[h + 8] = 0x7C; f[h + 9] = 1;                         // TCINFO: one column
	put16(h + 8 + 6, 4); put16(h + 8 + 8, 8);              // existence bitmap at 4, rows of 8 bytes
	put32(h + 8 + 10, 0x40); put32(h + 8 + 14, 0x80);      // row index, row matrix
	put32(h + 8 + 22, 0x30010003);                         // PT_LONG 0x3001: at 0, 4 bytes, bit 40
	put16(h + 8 + 26, 0); f[h + 8 + 28] = 4; f[h + 8 + 29] = 40;
	f[h + 38] = 0xB5; f[h + 39] = 4; f[h + 40] = 4; f[h + 41] = 0; put32(h + 42, 0x60);
	put32(h + 46, 1); put32(h + 50, 0);                    // row id 1 -> row 0
	put32(h + 54, 0x11223344);                             // row 0: its value, no existence bit set
	for (size_t i = 62; i < 70; ++i) f[h + i] = 0xFF;      // row 1: every bit set
	put16(h + 70, 4); put16(h + 72, 0);
	const uint16_t starts[] = { 8, 38, 46, 54, 70 };
	for (size_t i = 0; i < 5; ++i) put16(h + 74 + 2 * i, starts[i]);
	put16(h + 128 - 16, 84); put64(h + 128 - 8, 4);         // its trailer: size, bid
	// The XBLOCK: type 1, level 1, no child; its trailer.
	f[2176] = 0x01; f[2177] = 0x01;
	put16(2176 + 64 - 16, 8); put64(2176 + 64 - 8, 6);
	const std::wstring path = folder + L"\\forged.pst";
	std::ofstream(std::filesystem::path(path), std::ios::binary).write(reinterpret_cast<const char*>(f.data()), (std::streamsize)f.size());

	{   // the file closed before it is removed
		PstFile file;
		std::wstring why;
		check(file.open(path, why), "forged: opened");
		std::vector<PstNode> nodes;
		check(!file.allNodes(nodes), "forged: a node-tree page that is its own child refused, not walked 20^16 times");
		PstProperties properties;
		std::vector<PstProperties> rows;
		check(!file.properties(6, 0, properties) && !file.tableRows(6, 0, rows), "forged: an XBLOCK without child gives no data, nothing read past it");
		check(file.tableRows(4, 0, rows) && rows.size() == 1 && rows[0].find(0x3001) == rows[0].end(),
		      "forged: an existence bit past the row's bitmap not read in the next row");
	}
	std::error_code ec;
	std::filesystem::remove(std::filesystem::path(path), ec);
}
} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) { std::printf("usage: pst_test <folder of pst_fixtures.sh>\n"); return 2; }
	const std::wstring folder = argv[1];
	std::ifstream in(std::filesystem::path(folder + L"\\pst-reference.txt"), std::ios::binary);
	if (!in) { std::printf("no pst-reference.txt in the folder\n"); return 2; }
	forgedFile(folder);
	std::map<std::string, std::vector<std::vector<std::string>>> reference;   // file -> its lines
	std::map<std::string, size_t> pyUnreadable;
	for (std::string line; std::getline(in, line);) {
		std::vector<std::string> f;
		std::stringstream s(line);
		for (std::string part; std::getline(s, part, '|');) f.push_back(part);
		if (!line.empty() && line.back() == '|') f.push_back("");
		if (f.size() >= 3 && f[1] == "-") { ++pyUnreadable[f[0]]; continue; }
		if (f.size() == 8) reference[f[0]].push_back(f);
	}
	const char* names[] = { "dist-list.pst", "passworded.pst", "example-2013.ost", "zl_south-s_000.pst" };
	const char* fields[] = { "subject", "sender", "delivery", "submit", "attachments", "body" };
	for (const char* name : names) {
		PstFile file;
		std::wstring why;
		const bool opened = file.open(folder + L"\\" + decodeText(name, CP_UTF8), why);
		check(opened, std::string(name) + ": not opened: " + utf8(why));
		if (!opened) continue;
		std::map<uint32_t, std::vector<std::string>> byNid;   // what WAC read of each message
		size_t unreadable = 0;
		check(forEachPstMessage(file, [&](PstMessage& m) { byNid[m.nid] = fieldsOf(m); }, unreadable),
		      std::string(name) + ": node tree not walked whole");
		size_t same = 0;
		for (const std::vector<std::string>& ref : reference[name]) {
			const auto it = byNid.find((uint32_t)std::stoul(ref[1]));
			check(it != byNid.end(), std::string(name) + ": message " + ref[1] + " (" + ref[2] + ") not read");
			if (it == byNid.end()) continue;
			const std::vector<std::string>& mine = it->second;
			bool all = true;
			for (size_t k = 0; k < 6; ++k) {
				const bool ok = mine[k] == ref[2 + k];
				all = all && ok;
				check(ok, std::string(name) + " " + ref[1] + " " + fields[k] + ": WAC \"" + mine[k].substr(0, 120)
				          + "\", pypff \"" + ref[2 + k].substr(0, 120) + "\"");
			}
			if (all) ++same;
		}
		std::printf("%s: %zu message(s) read, %zu identical to pypff's %zu; %zu unreadable for WAC, %zu for pypff\n",
		            name, byNid.size(), same, reference[name].size(), unreadable, pyUnreadable[name]);
	}
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
