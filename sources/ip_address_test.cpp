/*! \file
 *  \brief Confronts the text of IP addresses with Python's ipaddress.
 *
 *  WHY THIS TEST. Two texts for one address make one connection look like
 *  two, and the output stays valid. The reference is Python's ipaddress,
 *  independent: it writes, one per line, "hex bytes|text" for random
 *  addresses weighted towards the cases that go wrong — runs of zeros of
 *  every length and place, ties between runs, a single zero group, IPv4-
 *  mapped, loopback, all zeros — and each must be formatted the same. One
 *  convention differs and is aligned in the reference: an IPv4-mapped
 *  address is written "::ffff:a.b.c.d" (RFC 5952 section 5, as Windows and
 *  netstat write it), where Python 3.12's str gives hexadecimal groups.
 *
 *  Usage: ip_address_test `<reference>`
 *  Native build (Linux): g++ -std=c++17 -g -fsanitize=address,undefined -I. ip_address.cpp ip_address_test.cpp -o ip_address_test
 */
#include "ip_address.h"
#include <cstdio>
#include <fstream>

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

std::string narrow(const std::wstring& w) { return std::string(w.begin(), w.end()); }

} // namespace

int main(int argc, char** argv) {
	if (argc != 2) { std::printf("usage: ip_address_test <reference>\n"); return 2; }
	std::ifstream reference(argv[1]);
	for (std::string line; std::getline(reference, line);) {
		const size_t bar = line.find('|');
		if (bar == std::string::npos) continue;
		const std::string hex = line.substr(0, bar), expected = line.substr(bar + 1);
		uint8_t bytes[16];
		const size_t size = hex.size() / 2;
		for (size_t k = 0; k < size && k < 16; ++k) bytes[k] = (uint8_t)std::stoi(hex.substr(2 * k, 2), nullptr, 16);
		const std::string mine = narrow(size == 4 ? Ipv4Text(bytes) : Ipv6Text(bytes));
		check(mine == expected, hex + ": \"" + mine + "\", Python \"" + expected + "\"");
	}
	const uint8_t mac[6] = { 0x52, 0x54, 0x00, 0x0a, 0xbc, 0xff };
	check(narrow(HardwareAddressText(mac, 6)) == "52-54-00-0A-BC-FF", "hardware address");
	check(HardwareAddressText(mac, 0).empty(), "empty hardware address");
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
