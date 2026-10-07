/*! \file
 *  \brief Checks the decoding of the shell items of an archive's content
 *         (ARCHIVE_FILE_CONTENT), and that it never reads outside the item.
 *
 *  WHY THIS TEST. The item's bytes at 0x08 and 0x10 are the archive entry's
 *  sizes; they were read as dates, so that a file inside a ZIP came out with
 *  a date made of its sizes and the date text in place of its name (B-029).
 *  A folder, which has no sizes, decoded right and hid the defect.
 *
 *  Inputs:
 *    - a folder's item as Explorer wrote it on the test VM (Windows 11), read
 *      from its BagMRU: the reference, with the values the VM's witness gave;
 *    - a file's item, the same layout with its sizes, method and CRC-32
 *      (libfwsi, "Compressed folder shell item", Windows 10);
 *    - the same without a date ("N/A"), and the Windows XP layout (libfwsi;
 *      Zimmerman's Lnk library, ShellBagZipContents, which SBECmd uses);
 *    - a folder of a 7z and of a tar.gz, as the test VM's Explorer wrote them
 *      (Windows 11 reads them through libarchive: another layout, a FILETIME
 *      in UTC);
 *    - every truncation of each, its declared size following, against a
 *      PAGE_NOACCESS page (guard_page.h): one byte read outside it stops the
 *      test.
 *
 *  Usage (runs under wine): shell_items_test.exe
 */
#include <cstdio>
#include <string>
#include <vector>
#include "conversions.h"
#include "guard_page.h"
#include "idList.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references (empty here)

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::wstring& what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::fwprintf(stderr, L"  FAILED  %ls\n", what.c_str());
}

/*! The text of a member of the item's JSON, empty if it is absent.
 *  @param item the decoded item's JSON
 *  @param key the member */
std::wstring member(const Json& item, const std::wstring& key) {
	const Json* value = item.find(key);
	return value == nullptr ? L"" : value->text();
}

//! The bytes of a hexadecimal text.
std::vector<BYTE> fromHex(const char* hex) {
	std::vector<BYTE> bytes;
	for (const char* p = hex; p[0] && p[1]; p += 2)
		bytes.push_back((BYTE)std::stoi(std::string(p, 2), nullptr, 16));
	return bytes;
}

/*! Writes a UTF-16 text and its terminator into an item.
 *  @param item the item
 *  @param offset where the text starts
 *  @param text the text */
void putWide(std::vector<BYTE>& item, size_t offset, const std::wstring& text) {
	for (size_t i = 0; i <= text.size(); ++i)
		writeLittleEndian<uint16_t>(item.data() + offset + 2 * i, i < text.size() ? (uint16_t)text[i] : 0);
}

/*! An item in the layout of Windows 10 and later.
 *  @param date the date text, or "N/A"
 *  @param name the entry's name
 *  @param uncompressed,compressed its sizes
 *  @param method its ZIP compression method
 *  @param crc its CRC-32 */
std::vector<BYTE> currentItem(const std::wstring& date, const std::wstring& name,
                              uint64_t uncompressed, uint64_t compressed, uint16_t method, uint32_t crc) {
	std::vector<BYTE> item(0x5C + (name.size() + 1) * 2 + 2 + 4, 0);
	writeLittleEndian<uint16_t>(item.data(), (uint16_t)item.size());
	writeLittleEndian<uint64_t>(item.data() + 0x08, uncompressed);
	writeLittleEndian<uint64_t>(item.data() + 0x10, compressed);
	writeLittleEndian<uint16_t>(item.data() + 0x18, method);
	writeLittleEndian<uint32_t>(item.data() + 0x1C, crc);
	writeLittleEndian<uint32_t>(item.data() + 0x20, 0x00010010);   // as on the VM
	putWide(item, 0x24, date);
	writeLittleEndian<uint32_t>(item.data() + 0x54, (uint32_t)name.size());
	putWide(item, 0x5C, name);
	return item;
}

//! An item in the Windows XP layout: date at 0x18, sizes of the strings at 0x3C.
std::vector<BYTE> xpItem(const std::wstring& date, const std::wstring& name) {
	std::vector<BYTE> item(0x44 + (name.size() + 1) * 2 + 2, 0);
	writeLittleEndian<uint16_t>(item.data(), (uint16_t)item.size());
	item[2] = 0x08;
	item[0x14] = 0x10;
	putWide(item, 0x18, date);
	writeLittleEndian<uint32_t>(item.data() + 0x3C, (uint32_t)name.size());
	putWide(item, 0x44, name);
	return item;
}

/*! Decodes an item as the content of an archive.
 *  @param item its bytes, its declared size included
 *  @param side where the guard page lies
 *  @return its JSON */
Json decode(const std::vector<BYTE>& item, GuardSide side) {
	GuardedCopy copy(item, side);
	if (copy.data() == nullptr) return Json::obj();
	std::unique_ptr<IShellItem> shellItem = makeShellItem(copy.data(), 0, true);
	return shellItem ? shellItem->toJson() : Json::obj();
}

/*! Checks the decoding of an item.
 *  @param label what the item is
 *  @param item its bytes
 *  @param expected the expected members, a pair (key, text) each; an empty
 *         text means the member must be absent */
void expect(const std::wstring& label, const std::vector<BYTE>& item,
            const std::vector<std::pair<std::wstring, std::wstring>>& expected) {
	const Json json = decode(item, GuardSide::After);
	for (const auto& [key, text] : expected)
		check(member(json, key) == text, label + L": " + key + L" \"" + member(json, key) + L"\", \"" + text + L"\" expected");
}

/*! Every truncation of an item, its declared size following, on both sides
 *  of the guard page: none may read outside the item.
 *  @param item the full item */
void truncations(const std::vector<BYTE>& item) {
	for (size_t n = 4; n < item.size(); ++n) {
		std::vector<BYTE> cut(item.begin(), item.begin() + n);
		writeLittleEndian<uint16_t>(cut.data(), (uint16_t)n);
		for (GuardSide side : { GuardSide::After, GuardSide::Before }) decode(cut, side);
		++g_checks;
	}
}

} // namespace

/*! Runs the checks.
 * @return 0 if every one passed */
int wmain() {
	// The VM's witness: folder "winterdir" of wac-archive.zip, entry dated
	// 10 January 2022 13:00 (vmtest/guest/place-file-artefacts.ps1, section 16).
	const std::vector<BYTE> folder = fromHex(
		"760000002700000000000000000000000000000000000000000000000000000010000100"
		"300031002F00310030002F00320030003200320020002000310033003A00300030003A00"
		"3000300000000000000000000900000000000000770069006E0074006500720064006900"
		"720000000000000000000000");
	expect(L"VM folder", folder, { { L"Name", L"winterdir" }, { L"ModifiedAsWritten", L"2022-01-10T13:00:00" },
	                               { L"UncompressedSize", L"" }, { L"Crc32", L"" } });

	// Folder "sevendir", dated 2023-03-05 09:15:30 in Paris, of a 7z then of a
	// tar.gz made by Windows' tar.exe (place-file-artefacts.ps1, section 16).
	const std::vector<BYTE> sevenZip = fromHex(
		"38000000100000000000000000000000003D3FA63A4FD901010000000800000073006500"
		"760065006E0064006900720000000000000000000000");
	const std::vector<BYTE> tarball = fromHex(
		"38000000100000000000000000000000003D3FA63A4FD901000000000800000073006500"
		"760065006E0064006900720000000000000000000000");
	for (const std::vector<BYTE>& item : { sevenZip, tarball })
		expect(L"libarchive folder", item, { { L"Name", L"sevendir" }, { L"ModifiedUtc", L"2023-03-05T08:15:30.0000000Z" },
		                                     { L"ModifiedAsWritten", L"" }, { L"TimeZone", L"" } });

	// A file: its sizes at 0x08 and 0x10, which were taken for dates.
	const std::vector<BYTE> file = currentItem(L"06/15/2021  18:24:28", L"inner.txt", 0x2710, 0x0110, 8, 0x8BADF00D);
	expect(L"file", file, { { L"Name", L"inner.txt" }, { L"ModifiedAsWritten", L"2021-06-15T18:24:28" },
	                        { L"UncompressedSize", L"10000" }, { L"CompressedSize", L"272" },
	                        { L"CompressionMethod", L"Deflate" }, { L"Crc32", L"8badf00d" } });

	const std::vector<BYTE> undated = currentItem(L"N/A", L"nodate.bin", 5, 5, 0, 0x12345678);
	expect(L"N/A date", undated, { { L"Name", L"nodate.bin" }, { L"ModifiedAsWritten", L"" },
	                               { L"CompressionMethod", L"Stored" } });

	const std::vector<BYTE> xp = xpItem(L"11/26/04  21:00", L"report.doc");
	expect(L"XP layout", xp, { { L"Name", L"report.doc" }, { L"ModifiedAsWritten", L"2004-11-26T21:00" },
	                           { L"UncompressedSize", L"" } });

	// No date text where either layout puts it: nothing read but the type.
	std::vector<BYTE> unknown = file;
	putWide(unknown, 0x24, L"garbage");
	expect(L"unknown layout", unknown, { { L"Name", L"" }, { L"ModifiedAsWritten", L"" } });

	// A name size beyond the item: the name is not read.
	std::vector<BYTE> lying = file;
	writeLittleEndian<uint32_t>(lying.data() + 0x54, 0x7FFFFFFF);
	expect(L"name size beyond the item", lying, { { L"Name", L"" } });

	for (const std::vector<BYTE>& item : { folder, sevenZip, tarball, file, undated, xp, lying }) truncations(item);

	std::wprintf(L"%ls: %llu check(s), %llu failure(s)\n", g_failures ? L"FAILED" : L"all passed", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
