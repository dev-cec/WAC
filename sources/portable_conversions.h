/*! \file
 *  \brief The conversions that need no system: little-endian integers, read
 *         and written — the byte order of every on-disk Windows format —,
 *         bytes as hexadecimal text, UTF-8 as UTF-16, base64.
 *
 *  Without windows.h, so that the modules built and checked outside Windows
 *  (sha.cpp, authenticode.cpp, the archive readers) use the same functions as
 *  the rest; conversions.h includes it.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

/*! True if `length` bytes starting at `offset` lie inside a structure of `size`
 *  bytes. Written so that no addition can wrap around — the form every bound
 *  check on data read from a file takes.
 *  @param size size of the structure (or buffer)
 *  @param offset position of the field
 *  @param length size of the field
 *  @return true if the field is entirely inside */
inline bool fits(size_t size, size_t offset, size_t length) {
	return offset <= size && length <= size - offset;
}

/*! An unsigned integer stored little-endian, as every on-disk Windows format
 *  holds them, read without alignment requirement. The ONE reader for new
 *  code and the old alike: the thirteen per-module copies (rd16, rd32, rd64,
 *  two of them copied word for word between pe_resource.cpp and wevt.cpp)
 *  came back to it (backlog B-030), then the ones named otherwise: lu16 and
 *  lu32 of authenticode.cpp, read8 to read64 of evtx.cpp, archiveLe16 and
 *  archiveLe32 of the archive readers (B-044).
 *  @tparam T uint8_t, uint16_t, uint32_t or uint64_t
 *  @param p its first byte; the caller has checked that sizeof(T) bytes are there
 *  @return the value */
template <class T>
T readLittleEndian(const uint8_t* p) {
	static_assert(std::is_unsigned<T>::value, "an unsigned integer");
	T value = 0;
	for (size_t i = 0; i < sizeof(T); ++i) value |= (T)((T)p[i] << (8 * i));
	return value;
}

/*! The same, bounded by the buffer: for the readers that walk a structure by
 *  offsets read in the data itself (PE resources, WEVT_TEMPLATE, EVTX).
 *  @tparam T uint8_t, uint16_t, uint32_t or uint64_t
 *  @param bytes the buffer
 *  @param size its size
 *  @param offset position of the value
 *  @return the value, or 0 if it does not lie entirely inside the buffer */
template <class T>
T readLittleEndian(const uint8_t* bytes, size_t size, size_t offset) {
	if (offset > size || sizeof(T) > size - offset) return 0;
	return readLittleEndian<T>(bytes + offset);
}

//! @copydoc readLittleEndian(const uint8_t*, size_t, size_t)
template <class T>
T readLittleEndian(const std::vector<uint8_t>& bytes, size_t offset) {
	return readLittleEndian<T>(bytes.data(), bytes.size(), offset);
}

/*! An unsigned integer written little-endian, the reverse of readLittleEndian.
 *  @tparam T uint16_t, uint32_t or uint64_t
 *  @param p its first byte; the caller has checked that sizeof(T) bytes are there
 *  @param value the value */
template <class T>
void writeLittleEndian(uint8_t* p, T value) {
	static_assert(std::is_unsigned<T>::value, "an unsigned integer");
	for (size_t i = 0; i < sizeof(T); ++i) p[i] = (uint8_t)(value >> (8 * i));
}

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

//! The value of a base64 character (standard alphabet), -1 for any other.
inline int base64Value(char32_t c) {
	if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
	if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
	if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

/*! Base64 (the standard alphabet) to bytes; padding and characters outside
 *  the alphabet are skipped. Authenticode's certificates and signature
 *  blocks, MIME parts and encoded words.
 *  @param text the encoded text
 *  @return the bytes */
inline std::vector<uint8_t> DecodeBase64(const std::string& text) {
	std::vector<uint8_t> bytes;
	uint32_t acc = 0; int bits = 0;
	for (char c : text) {
		const int b = base64Value((char32_t)(unsigned char)c);
		if (b < 0) continue;                               // "=" padding, spaces
		acc = (acc << 6) | (uint32_t)b; bits += 6;
		if (bits >= 8) { bits -= 8; bytes.push_back((uint8_t)(acc >> bits)); }
	}
	return bytes;
}

/*! Bytes to Base64 (the standard alphabet, padded), for the PEM files
 *  --update-trust writes.
 *  @param bytes,size the bytes
 *  @param lineLength characters per line, a line feed after each; 0: one line
 *  @return the encoded text */
inline std::string EncodeBase64(const uint8_t* bytes, size_t size, size_t lineLength = 0) {
	static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string text;
	auto put = [&](char c) {
		text += c;
		if (lineLength && (text.size() + 1) % (lineLength + 1) == 0) text += '\n';
	};
	for (size_t i = 0; i < size; i += 3) {
		const uint32_t group = (uint32_t)bytes[i] << 16 | (i + 1 < size ? (uint32_t)bytes[i + 1] << 8 : 0)
		                     | (i + 2 < size ? bytes[i + 2] : 0);
		put(ALPHABET[group >> 18 & 63]);
		put(ALPHABET[group >> 12 & 63]);
		put(i + 1 < size ? ALPHABET[group >> 6 & 63] : '=');
		put(i + 2 < size ? ALPHABET[group & 63] : '=');
	}
	if (lineLength && !text.empty() && text.back() != '\n') text += '\n';
	return text;
}
