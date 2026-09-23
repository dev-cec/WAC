/*! \file
 *  \brief Exercises the chain that produces an event's plain-text message.
 *
 *  WHY THIS TEST. The chain has FIVE links — registry, PE resources,
 *  WEVT_TEMPLATE, MESSAGETABLE, substitution — and each of them fails in
 *  silence: the field disappears, the collection stays valid, and nothing says
 *  which link broke. Two defects were caught this way while writing that code:
 *    - a provider's descriptors are EIGHT bytes long, not four. Read four by
 *      four, the blocks are never found: 0 events described on a provider that
 *      describes 202.
 *    - an event descriptor is 48 bytes long, not 44. With a step of 44, only
 *      one record in twelve is coherent, and no error is raised.
 *      The step is therefore DEDUCED from the block's declared size.
 *
 *  Usage: wevt_test <file.dll> <file.dll.mui> <guid> [id[:version] ...]
 *    Both files are those of a real provider: the metadata are in the binary,
 *    the texts in its localised satellite.
 *
 *  Excluded from WAC's build by the "_test.cpp" pattern.
 *  Native build: g++ -std=c++17 -I. pe_resource.cpp wevt.cpp wevt_test.cpp -o wevt_test
 */
#include "pe_resource.h"
#include "wevt.h"
#include <iostream>
#include <string>
#include <vector>

namespace {

//! Returns a wide string as UTF-8, for a terminal.
std::string utf8(const std::wstring& w) {
	std::string r;
	for (wchar_t c : w) {
		const unsigned long u = (unsigned long)c;
		if (u < 0x80) r += (char)u;
		else if (u < 0x800) { r += (char)(0xC0 | (u >> 6)); r += (char)(0x80 | (u & 0x3F)); }
		else { r += (char)(0xE0 | (u >> 12)); r += (char)(0x80 | ((u >> 6) & 0x3F));
		       r += (char)(0x80 | (u & 0x3F)); }
	}
	return r;
}

std::wstring large(const std::string& s) { return std::wstring(s.begin(), s.end()); }

} // namespace

int main(int argc, char** argv) {
	if (argc < 4) {
		std::cout << "usage: wevt_test <dll> <mui> <guid> [id[:version] ...]\n";
		return 2;
	}
	PeResource dll, mui;
	if (!dll.open(large(argv[1]))) {
		std::cout << "  ECHEC  binaire : " << utf8(dll.error()) << "\n";
		return 1;
	}
	if (!mui.open(large(argv[2]))) {
		std::cout << "  ECHEC  satellite : " << utf8(mui.error()) << "\n";
		return 1;
	}

	int failures = 0;

	const std::vector<uint8_t> wevtResource = dll.namedResource(L"WEVT_TEMPLATE");
	const std::vector<uint8_t> messageResource  = mui.resource(PE_RT_MESSAGETABLE);
	std::cout << (wevtResource.empty() ? "  ECHEC  " : "  ok     ")
	          << "WEVT_TEMPLATE lue (" << wevtResource.size() << " octets)\n";
	std::cout << (messageResource.empty() ? "  ECHEC  " : "  ok     ")
	          << "MESSAGETABLE lue (" << messageResource.size() << " octets)\n";
	if (wevtResource.empty() || messageResource.empty()) return 1;

	WevtMetadata meta;
	const size_t nEvents = meta.analyse(wevtResource, large(argv[3]));
	TableMessages table;
	const size_t nbMessages = table.analyse(messageResource);
	std::cout << (nEvents ? "  ok     " : "  ECHEC  ")
	          << nEvents << " evenement(s) decrit(s)\n";
	std::cout << (nbMessages ? "  ok     " : "  ECHEC  ")
	          << nbMessages << " message(s)\n";
	if (!nEvents || !nbMessages) return 1;

	// Every requested id must come back with a non-empty text.
	for (int i = 4; i < argc; ++i) {
		const std::string a = argv[i];
		const size_t sep = a.find(':');
		const uint16_t id = (uint16_t)strtoul(a.substr(0, sep).c_str(), nullptr, 10);
		const uint8_t ver = (uint8_t)(sep == std::string::npos ? 0
		                              : strtoul(a.substr(sep + 1).c_str(), nullptr, 10));
		const uint32_t idMessage = meta.messageId(id, ver);
		const std::wstring messageTemplate = idMessage ? table.text(idMessage) : std::wstring();
		const bool ok = !messageTemplate.empty();
		if (!ok) ++failures;
		std::cout << (ok ? "  ok     " : "  ECHEC  ") << "evenement " << id
		          << " v" << (int)ver << " -> message " << idMessage << "\n";
		if (ok) {
			const std::vector<std::wstring> values = { L"<1>", L"<2>", L"<3>", L"<4>" };
			std::cout << "         modele  : " << utf8(messageTemplate.substr(0, 150)) << "\n";
			std::cout << "         formate : "
			          << utf8(formatMessage(messageTemplate, values).substr(0, 150)) << "\n";
		}
	}

	/*  Substitution is checked on its own, on built cases: a mark
	    sans donnee doit RESTER visible, l'effacer ferait croire a une phrase
	    complete. */
	struct Case { const wchar_t* messageTemplate; const wchar_t* expected; };
	const std::vector<Case> case_ = {
		{ L"a %1 b",            L"a <1> b" },
		{ L"%1 %2 %3",          L"<1> <2> <3>" },
		{ L"%9 manquant",       L"%9 manquant" },     // no data: the mark is kept
		{ L"100%% sur",         L"100% sur" },
		{ L"ligne%nsuivante",   L"ligne\nsuivante" },
		{ L"tab%tici",          L"tab\tici" },
		{ L"%1!s! formate",     L"<1> formate" },     // display instruction removed
		{ L"fin.%n%0",          L"fin." },            // %0 ends the message, with no trailing break
		{ L"a%0 ignore",        L"a" },
		{ L"x%by%.%!",          L"x y.!" },
	};
	const std::vector<std::wstring> v = { L"<1>", L"<2>", L"<3>" };
	for (const Case& c : case_) {
		const std::wstring r = formatMessage(c.messageTemplate, v);
		const bool ok = (r == c.expected);
		if (!ok) ++failures;
		std::cout << (ok ? "  ok     " : "  ECHEC  ") << "substitution « "
		          << utf8(c.messageTemplate) << " »";
		if (!ok) std::cout << " -> « " << utf8(r) << " » au lieu de « "
		                   << utf8(c.expected) << " »";
		std::cout << "\n";
	}

	std::cout << (failures ? "ECHECS : " : "tous conformes (echecs : ") << failures
	          << (failures ? "\n" : ")\n");
	return failures ? 1 : 0;
}
