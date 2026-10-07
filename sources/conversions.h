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

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>

/*! Bytes in uppercase hexadecimal, the project's convention for digests
 *  (see Md5Stream).
 *  @param bytes the bytes
 *  @param length their number
 *  @return two digits per byte */
inline std::wstring toHexadecimal(const uint8_t* bytes, size_t length) {
	static const wchar_t DIGITS[] = L"0123456789ABCDEF";
	std::wstring text;
	text.reserve(length * 2);
	for (size_t i = 0; i < length; ++i) {
		text.push_back(DIGITS[bytes[i] >> 4]);
		text.push_back(DIGITS[bytes[i] & 0x0F]);
	}
	return text;
}

/*! An unsigned integer stored little-endian, as every on-disk Windows format
 *  holds them, read without alignment requirement. The ONE reader for new
 *  code; the per-module copies (rd32 in mft.cpp, fat_volume.cpp,
 *  ese_database.cpp…) are to come back to it (backlog B-030).
 *  @tparam T uint16_t, uint32_t or uint64_t
 *  @param p its first byte; the caller has checked that sizeof(T) bytes are there
 *  @return the value */
template <class T>
T readLittleEndian(const uint8_t* p) {
	static_assert(std::is_unsigned<T>::value, "an unsigned integer");
	T value = 0;
	for (size_t i = 0; i < sizeof(T); ++i) value |= (T)((T)p[i] << (8 * i));
	return value;
}

/*! UTF-8 bytes as UTF-16 text, without the system's API: a module that must
 *  stay verifiable outside Windows (wevt.cpp) cannot call MultiByteToWideChar.
 *  A malformed sequence (bad continuation, overlong form, surrogate, beyond
 *  U+10FFFF, cut at the end) gives U+FFFD and the reading goes on at the
 *  next byte, as MultiByteToWideChar does.
 *  @param bytes the bytes
 *  @param length their number
 *  @return the text, characters beyond U+FFFF as surrogate pairs */
inline std::wstring utf8ToWide(const uint8_t* bytes, size_t length) {
	std::wstring text;
	text.reserve(length);
	for (size_t i = 0; i < length;) {
		const uint8_t lead = bytes[i];
		const size_t size = lead < 0x80 ? 1 : (lead >> 5) == 0x6 ? 2 : (lead >> 4) == 0xE ? 3 : (lead >> 3) == 0x1E ? 4 : 0;
		uint32_t code = size == 1 ? lead : size == 2 ? (lead & 0x1Fu) : size == 3 ? (lead & 0x0Fu) : (lead & 0x07u);
		bool valid = size != 0 && i + size <= length;
		for (size_t k = 1; valid && k < size; ++k) {
			if ((bytes[i + k] & 0xC0) != 0x80) valid = false;
			else code = (code << 6) | (bytes[i + k] & 0x3Fu);
		}
		static const uint32_t SMALLEST[] = { 0, 0, 0x80, 0x800, 0x10000 };
		if (valid && (code < SMALLEST[size] || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF))) valid = false;
		if (!valid) { text += (wchar_t)0xFFFD; ++i; continue; }
		if (code > 0xFFFF) {
			code -= 0x10000;
			text += (wchar_t)(0xD800 + (code >> 10));
			text += (wchar_t)(0xDC00 + (code & 0x3FF));
		} else text += (wchar_t)code;
		i += size;
	}
	return text;
}

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
