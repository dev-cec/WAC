/*! \file
 *  \brief The general conversions of bytes, in one place and self-contained.
 *
 *  WHY A HEADER OF ITS OWN. These conversions were scattered: `toHexadecimal`
 *  in sha.h, which any module wanting to print bytes had to include, and one
 *  little-endian reader per module. They gather here (backlog B-030),
 *  header-only and depending on nothing of WAC, so that tools.h and the
 *  harnesses that link without tools.cpp (raw_hive_test: sha.cpp) share the
 *  same code.
 */
#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdio>
#include <charconv>
#include <cstring>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>
#include "portable_conversions.h"

/*! THE NTFS FILE REFERENCE: how the $MFT, its indexes, the USN journal, shell
 *  items and Prefetch files name a file on its volume. 8 bytes, little-endian:
 *  the low 48 bits are the record number in the $MFT, the high 16 bits the
 *  sequence number that every reuse of the record increments. The split was
 *  written by hand seventeen times, and went wrong in the Prefetch decoding
 *  (sequence read on four bytes, the entry's high 16 bits lost). */
struct NtfsReference {
	uint64_t entry = 0;     //!< record number in the $MFT (48 bits)
	uint16_t sequence = 0;  //!< sequence number of the record
};

/*! Splits an NTFS file reference into its record number and its sequence.
 *  @param reference the 8 bytes of the reference, read as a little-endian integer
 *  @return the record number and the sequence */
inline NtfsReference splitNtfsReference(uint64_t reference) {
	return { reference & 0x0000FFFFFFFFFFFFULL, (uint16_t)(reference >> 48) };
}

/*! Seconds from 1601-01-01, the FILETIME's origin, to 1970-01-01, Unix's —
 *  the one constant every conversion between the two starts from. */
const uint64_t SECONDS_1601_TO_1970 = 11644473600ULL;

/*! A FILETIME from its 64-bit value — 100-ns intervals since 1601 — the form
 *  the raw readers, ESE, SRUM and the event logs give dates in. The only
 *  place where the two halves are put together (B-030).
 *  @param ticks the 64-bit value
 *  @return the FILETIME */
inline FILETIME filetimeFromTicks(uint64_t ticks) {
	return FILETIME{ (DWORD)(ticks & 0xFFFFFFFFULL), (DWORD)(ticks >> 32) };
}

/*! The reverse: a FILETIME's 64-bit value.
 *  @param filetime the FILETIME
 *  @return its 100-ns intervals since 1601 */
inline uint64_t ticksFromFiletime(const FILETIME& filetime) {
	return ((uint64_t)filetime.dwHighDateTime << 32) | filetime.dwLowDateTime;
}

/*! Converts a GUID to a wstring. The output is of the form
* "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", upper case — as StringFromCLSID
* (ole32) wrote it, which this replaces: a formatting has no reason to go
* through a library.
* @param guid the GUID to convert
* @return the wstring that results from the conversion
*/
inline std::wstring guid_to_wstring(GUID guid) {
	wchar_t text[39];
	swprintf(text, 39, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
	         (unsigned long)guid.Data1, guid.Data2, guid.Data3,
	         guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
	         guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	return text;
}

/*! The same, from the 16 bytes as Windows lays a GUID out in memory (the
 *  first three fields little-endian), wherever a format stores one: BITS,
 *  Defender, WEVT_TEMPLATE, ESE columns.
 *  @param bytes its 16 bytes; the caller has checked they are there
 *  @return "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" */
inline std::wstring guid_to_wstring(const uint8_t* bytes) {
	GUID guid;
	memcpy(&guid, bytes, sizeof guid);
	return guid_to_wstring(guid);
}

/*! A GUID's text in the form the registry writes it — lower case, in braces —
 *  whatever the form it came in: the one form two GUIDs are compared in.
 *  @param guid its text, with or without braces, in any case
 *  @return "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" */
inline std::wstring normalizeGuid(const std::wstring& guid) {
	std::wstring text;
	for (wchar_t c : guid) text += (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
	if (!text.empty() && text.front() != L'{') text = L"{" + text + L"}";
	return text;
}

//! The case of the letters of a hexadecimal number.
enum class HexLetters { Lower, Upper };

/*! Writes an integer in lower-case hexadecimal, on the WIDTH OF ITS TYPE.
*
* A template rather than one `long long` signature: every value used to be
* widened to 64 bits first, so a negative 32-bit value — an HRESULT such as
* 0x80070005 — came out as "ffffffff80070005". The value is now read as the
* unsigned type of the same width. A `char` is written as a number, never as
* a character.
* @param value the integer
* @param minDigits minimum number of digits, left-padded with zeros (2 by
*        default; 1 for no padding, e.g. the stream names of a jump list)
* @param letters lower case (the default) or upper case
* @param prefixed "0x" before the digits
* @return the digits, "0x" first if prefixed */
template <typename T>
std::wstring to_hex(T value, int minDigits = 2, HexLetters letters = HexLetters::Lower, bool prefixed = false) {
	static_assert(std::is_integral_v<T>, "to_hex: integer types only");
	unsigned long long bits = static_cast<std::make_unsigned_t<T>>(value);
	const wchar_t* digits = letters == HexLetters::Upper ? L"0123456789ABCDEF" : L"0123456789abcdef";
	std::wstring text;
	do { text.insert(text.begin(), digits[bits & 0xF]); bits >>= 4; } while (bits);
	if ((int)text.size() < minDigits) text.insert(0, (size_t)minDigits - text.size(), L'0');
	return prefixed ? L"0x" + text : text;
}

/*! A real in text with `digits` significant digits (printf's %g): 9 give a
 *  float back exactly, 17 a double. ESE and CIM columns.
 *  @param value the real
 *  @param digits the significant digits
 *  @return its text */
inline std::wstring realText(double value, int digits) {
	wchar_t text[40];
	swprintf(text, 40, L"%.*g", digits, value);
	return text;
}

/*! A real as Windows renders it in an event: the shortest text that reads
 *  back to the same value, per its own width — a float gives "0.0020121",
 *  zero gives "0". A fixed 6 decimals ("0.002012") lost digits (B-015,
 *  against Windows' XML).
 *  @tparam Real float or double: the width decides the digits
 *  @param value the real
 *  @return its text, empty if it cannot be written */
template <typename Real>
std::wstring shortestRealText(Real value) {
	char text[64];
	const std::to_chars_result r = std::to_chars(text, text + sizeof text, value);
	return r.ec == std::errc() ? std::wstring(text, r.ptr) : L"";
}

