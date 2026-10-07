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

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc != 2) { std::printf("usage: pst_test <folder of pst_fixtures.sh>\n"); return 2; }
	const std::wstring folder = argv[1];
	std::ifstream in(std::filesystem::path(folder + L"\\pst-reference.txt"), std::ios::binary);
	if (!in) { std::printf("no pst-reference.txt in the folder\n"); return 2; }
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
