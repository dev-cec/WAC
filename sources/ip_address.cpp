/*! \file
 *  \brief IP addresses as text (see ip_address.h).
 */
#include "ip_address.h"

std::wstring Ipv4Text(const uint8_t address[4]) {
	return std::to_wstring(address[0]) + L"." + std::to_wstring(address[1]) + L"."
	     + std::to_wstring(address[2]) + L"." + std::to_wstring(address[3]);
}

std::wstring Ipv6Text(const uint8_t address[16]) {
	uint16_t groups[8];
	for (int k = 0; k < 8; ++k) groups[k] = (uint16_t)((address[2 * k] << 8) | address[2 * k + 1]);
	// IPv4-mapped (::ffff:a.b.c.d): its IPv4 part as IPv4, RFC 5952 section 5.
	bool mapped = groups[5] == 0xFFFF;
	for (int k = 0; k < 5; ++k) mapped = mapped && groups[k] == 0;
	if (mapped) return L"::ffff:" + Ipv4Text(address + 12);
	// The longest run of zero groups, two at least; the first one if tied.
	int bestStart = -1, bestLength = 0;
	for (int k = 0; k < 8;) {
		if (groups[k] != 0) { ++k; continue; }
		int end = k;
		while (end < 8 && groups[end] == 0) ++end;
		if (end - k > bestLength && end - k >= 2) { bestStart = k; bestLength = end - k; }
		k = end;
	}
	static const wchar_t HEX[] = L"0123456789abcdef";
	std::wstring text;
	for (int k = 0; k < 8; ++k) {
		if (k == bestStart) {
			text += L"::";
			k += bestLength - 1;
			continue;
		}
		if (!text.empty() && text.back() != L':') text += L':';
		std::wstring group;
		for (int shift = 12; shift >= 0; shift -= 4) {
			const wchar_t digit = HEX[(groups[k] >> shift) & 0xF];
			if (!group.empty() || digit != L'0' || shift == 0) group += digit;   // leading zeros dropped
		}
		text += group;
	}
	return text;
}

std::wstring HardwareAddressText(const uint8_t* bytes, size_t size) {
	static const wchar_t HEX[] = L"0123456789ABCDEF";
	std::wstring text;
	for (size_t k = 0; k < size; ++k) {
		if (k) text += L'-';
		text += HEX[bytes[k] >> 4];
		text += HEX[bytes[k] & 0xF];
	}
	return text;
}
