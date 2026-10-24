/*! \file
 *  \brief Carving: where a PE, a ZIP or a PDF ends (see carving.h).
 */
#include "carving.h"
#include <algorithm>
#include <cstring>

namespace {

uint16_t u16(const uint8_t* p) { return (uint16_t)(p[0] | p[1] << 8); }
uint32_t u32(const uint8_t* p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

// The PE layout (Microsoft's PE format specification).
const size_t PE_OFFSET = 0x3C;             //!< e_lfanew in the DOS header
const size_t COFF_SIZE = 20;               //!< the file header after "PE\0\0"
const size_t SECTION_SIZE = 40;            //!< one entry of the section table
const uint16_t PE32 = 0x10B, PE32_PLUS = 0x20B;
const uint16_t MAX_SECTIONS = 96;          //!< the loader's own bound
const uint32_t SECURITY_DIRECTORY = 4;     //!< the Authenticode signature: a file offset and a size
const uint64_t PE_MAX = 4ull << 30;        //!< larger, a forged header

//! Machines of the PE a Windows runs: x86, x64, ARM64, ARM Thumb-2, IA-64.
bool knownMachine(uint16_t machine) {
	return machine == 0x14C || machine == 0x8664 || machine == 0xAA64 || machine == 0x1C4 || machine == 0x200;
}

const size_t COFF_SYMBOL = 18;             //!< one entry of the COFF symbol table

/*! A PE's exact size, from its headers: the end of the last section's raw
 *  data, of its signature, or of its COFF symbol and string tables. 0 when
 *  the headers do not hold (or do not fit in `length`).
 *  @param symbols receives where the COFF symbol table ends, 0 without one:
 *         the string table's length (4 bytes) follows it, and the size then
 *         needs the bytes up to there */
uint64_t peSize(const uint8_t* d, size_t length, uint64_t& symbols) {
	symbols = 0;
	if (length < PE_OFFSET + 4) return 0;
	const uint32_t pe = u32(d + PE_OFFSET);
	if (pe < 0x40 || (uint64_t)pe + 4 + COFF_SIZE > length || std::memcmp(d + pe, "PE\0\0", 4) != 0) return 0;
	const uint8_t* coff = d + pe + 4;
	const uint16_t sections = u16(coff + 2), optionalSize = u16(coff + 16);
	if (!knownMachine(u16(coff)) || sections == 0 || sections > MAX_SECTIONS || optionalSize < 0x60) return 0;
	const uint64_t optional = (uint64_t)pe + 4 + COFF_SIZE;
	const uint64_t table = optional + optionalSize;
	if (table + (uint64_t)sections * SECTION_SIZE > length) return 0;
	const uint8_t* o = d + optional;
	const uint16_t magic = u16(o);
	if (magic != PE32 && magic != PE32_PLUS) return 0;
	const uint32_t fileAlignment = u32(o + 36), headers = u32(o + 60);
	if (fileAlignment < 512 || fileAlignment > 65536 || (fileAlignment & (fileAlignment - 1)) || headers < table) return 0;
	uint64_t end = headers;
	for (uint16_t k = 0; k < sections; ++k) {
		const uint8_t* s = d + table + (uint64_t)k * SECTION_SIZE;
		const uint32_t raw = u32(s + 16), at = u32(s + 20);
		if (raw == 0) continue;
		if (at % fileAlignment || at < headers) return 0;
		end = std::max<uint64_t>(end, (uint64_t)at + raw);
	}
	// The data directories: after 96 bytes of PE32 fields, 112 of PE32+.
	const uint32_t directories = magic == PE32 ? 96 : 112;
	if (optionalSize >= directories + (SECURITY_DIRECTORY + 1) * 8 && u32(o + directories - 4) > SECURITY_DIRECTORY) {
		const uint8_t* security = o + directories + SECURITY_DIRECTORY * 8;
		const uint32_t at = u32(security), size = u32(security + 4);
		if (at && size) {
			if (at < end) return 0;                   // the signature follows the sections
			end = (uint64_t)at + size;
		}
	}
	// The COFF symbol table, then its string table, whose first 4 bytes are its length.
	const uint32_t table32 = u32(coff + 8), count = u32(coff + 12);
	if (table32 && count) {
		if (table32 < end || (uint64_t)count * COFF_SYMBOL > PE_MAX) return 0;
		symbols = (uint64_t)table32 + (uint64_t)count * COFF_SYMBOL;
		if (symbols + 4 > length) return end <= PE_MAX ? end : 0;
		const uint32_t strings = u32(d + symbols);
		if (strings < 4) return 0;
		end = symbols + strings;
	}
	return end <= PE_MAX ? end : 0;
}

/*! A ZIP's exact size: the end of the first end-of-central-directory record
 *  whose central directory lies right before it, from its signature. */
uint64_t zipEnd(const uint8_t* d, size_t length) {
	const size_t EOCD = 22;
	for (size_t p = 30; p + EOCD <= length; ++p) {
		if (d[p] != 'P' || std::memcmp(d + p, "PK\5\6", 4) != 0) continue;
		const uint8_t* e = d + p;
		const uint32_t cdSize = u32(e + 12), cdOffset = u32(e + 16);
		if (u16(e + 4) || u16(e + 6) || u16(e + 8) != u16(e + 10)) continue;   // one disk, its entries
		if (cdOffset == 0xFFFFFFFF || cdSize == 0xFFFFFFFF) return 0;          // ZIP64: not carved
		if ((uint64_t)cdOffset + cdSize != p || cdSize < 46 || std::memcmp(d + cdOffset, "PK\1\2", 4) != 0) continue;
		const uint64_t end = p + EOCD + u16(e + 20);
		return end <= length ? end : 0;
	}
	return 0;
}

/*! A PDF's exact size: the first "%%EOF" whose "startxref" points back at a
 *  cross-reference table ("xref") or stream ("<n> <g> obj"). */
uint64_t pdfEnd(const uint8_t* d, size_t length) {
	const char* XREF = "startxref";
	for (size_t p = 8; p + 5 <= length; ++p) {
		if (d[p] != '%' || std::memcmp(d + p, "%%EOF", 5) != 0) continue;
		// "startxref", its offset, then %%EOF: within the few bytes before.
		const size_t from = p > 64 ? p - 64 : 0;
		size_t s = std::string::npos;
		for (size_t q = from; q + 9 <= p; ++q) if (std::memcmp(d + q, XREF, 9) == 0) s = q;
		if (s == std::string::npos) continue;
		size_t q = s + 9;
		while (q < p && (d[q] == ' ' || d[q] == '\r' || d[q] == '\n')) ++q;
		uint64_t offset = 0;
		size_t digits = 0;
		for (; q < p && d[q] >= '0' && d[q] <= '9' && digits < 12; ++q, ++digits) offset = offset * 10 + (d[q] - '0');
		if (!digits || offset >= s) continue;
		const uint8_t* x = d + offset;
		bool table = s - offset >= 4 && std::memcmp(x, "xref", 4) == 0;
		if (!table) {                                    // "<number> <number> obj"
			size_t k = 0;
			const size_t room = s - offset;
			while (k < room && x[k] >= '0' && x[k] <= '9') ++k;
			if (k && k < room && x[k] == ' ') {
				size_t g = ++k;
				while (k < room && x[k] >= '0' && x[k] <= '9') ++k;
				table = k > g && k + 4 <= room && std::memcmp(x + k, " obj", 4) == 0;
			}
		}
		if (!table) continue;
		uint64_t end = p + 5;
		if (end < length && d[end] == '\r') ++end;
		if (end < length && d[end] == '\n') ++end;
		return end;
	}
	return 0;
}

} // namespace

const wchar_t* carvedFormatName(CarvedFormat format) {
	switch (format) {
	case CarvedFormat::Pe: return L"PE";
	case CarvedFormat::Zip: return L"ZIP";
	case CarvedFormat::Pdf: return L"PDF";
	case CarvedFormat::None: break;
	}
	return L"";
}

const wchar_t* carvedFormatExtension(CarvedFormat format) {
	switch (format) {
	case CarvedFormat::Pe: return L".exe";
	case CarvedFormat::Zip: return L".zip";
	case CarvedFormat::Pdf: return L".pdf";
	case CarvedFormat::None: break;
	}
	return L"";
}

CarvedStart carvedStart(const uint8_t* head, size_t length) {
	CarvedStart start;
	if (!head || length < 8) return start;
	if (head[0] == 'M' && head[1] == 'Z') {
		uint64_t symbols = 0;
		const uint64_t size = peSize(head, length, symbols);
		if (!size) return start;
		start.format = CarvedFormat::Pe;
		if (symbols && symbols + 4 > length) start.needed = symbols + 4;   // its string table: further on
		else start.size = size;
	}
	else if (std::memcmp(head, "PK\3\4", 4) == 0) start.format = CarvedFormat::Zip;
	else if (std::memcmp(head, "%PDF-", 5) == 0) start.format = CarvedFormat::Pdf;
	return start;
}

uint64_t carvedEnd(CarvedFormat format, const uint8_t* data, size_t length) {
	if (!data) return 0;
	if (format == CarvedFormat::Zip) return zipEnd(data, length);
	if (format == CarvedFormat::Pdf) return pdfEnd(data, length);
	if (format == CarvedFormat::Pe) {
		uint64_t symbols = 0;
		const uint64_t size = peSize(data, length, symbols);
		return symbols && symbols + 4 > length ? 0 : size;
	}
	return 0;
}
