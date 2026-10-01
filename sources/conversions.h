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
