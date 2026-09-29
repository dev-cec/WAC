/*! \file
 *  \brief Reading of registry hive files (regf), with offreg's contract — see
 *         offline_registry.h.
 *
 *  Format (libregf's documentation, "Windows NT Registry File format"):
 *  - a 4096-byte base block: "regf", the root key's cell offset at 0x24, the
 *    size of the hive bins at 0x28;
 *  - hive bins from offset 4096; every cell offset is relative to that point.
 *    A cell starts with its size on 4 bytes, NEGATIVE when it is in use;
 *  - "nk" key cells, "vk" value cells, subkey lists "lf"/"lh" (offset + hash),
 *    "li" (offsets) and "ri" (a list of those lists), "sk" security cells,
 *    "db" cells for values larger than 16,344 bytes (hive version 1.4+).
 *  Names flagged "compressed" hold one byte per character (Latin-1).
 */
#include "offline_registry.h"
#include "tools.h"
#include <algorithm>
#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace {

const size_t BASE_BLOCK = 4096;              //!< size of the base block; cell offsets start after it
const unsigned short KEY_COMP_NAME = 0x0020; //!< nk flag: name stored one byte per character
const unsigned short VALUE_COMP_NAME = 0x0001; //!< vk flag: same, for a value
const DWORD DATA_IN_OFFSET = 0x80000000;     //!< vk size flag: data (<= 4 bytes) held in the offset field
const size_t DB_SEGMENT = 16344;             //!< largest segment of a "db" big-data value

/*! A hive: a mapped file, or a buffer the caller owns (openHiveBuffer). */
struct Hive {
	HANDLE file = INVALID_HANDLE_VALUE;   //!< the hive file
	HANDLE mapping = nullptr;             //!< its read-only mapping
	const BYTE* base = nullptr;           //!< first byte of the file
	size_t size = 0;                      //!< real size of the file: the bound of every read
	unsigned minorVersion = 0;            //!< regf minor version (big data from 4 on)
	unsigned rootCell = 0;                //!< offset of the root key's cell
	bool mapped = false;                  //!< true if `base` is a view of `mapping` to unmap

	~Hive() {
		if (mapped) UnmapViewOfFile(base);
		if (mapping) CloseHandle(mapping);
		if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
	}
};

/*! What an ORHKEY designates: a key cell of a hive. */
struct Key {
	std::shared_ptr<Hive> hive;   //!< keeps the mapping alive while a key uses it
	unsigned cell = 0;            //!< offset of the key's "nk" cell
	/*! Cells from the root down to this key, itself excluded. A forged hive can
	    make a subkey point back at one of its ancestors: every recursive walk
	    of the registry — the shellbags', for one — would then never end. A
	    subkey found on this chain is refused (ERROR_BADDB). */
	std::vector<unsigned> ancestors;
	bool hiveRoot = false;        //!< true for the handle OROpenHive returned
};

/*! The live handles. An ORHKEY is only ever dereferenced after being found
 *  here: a stale or forged handle gives ERROR_INVALID_HANDLE, not a crash. */
std::mutex g_mutex;
std::unordered_map<const Key*, std::unique_ptr<Key>> g_keys;

ORHKEY registerKey(std::unique_ptr<Key> key) {
	std::lock_guard<std::mutex> lock(g_mutex);
	Key* raw = key.get();
	g_keys.emplace(raw, std::move(key));
	return reinterpret_cast<ORHKEY>(raw);
}

/*! @return the key an ORHKEY designates, or nullptr if it is not live. */
const Key* findKey(ORHKEY handle) {
	std::lock_guard<std::mutex> lock(g_mutex);
	const auto it = g_keys.find(reinterpret_cast<const Key*>(handle));
	return it == g_keys.end() ? nullptr : it->second.get();
}

/*! Bounded reads in a hive. */
struct Reader {
	const Hive& h;

	template <typename T>
	bool read(size_t at, T& out) const {
		if (!fits(h.size, at, sizeof(T))) return false;
		std::memcpy(&out, h.base + at, sizeof(T));
		return true;
	}

	/*! Content of the cell at `offset` (after its size field).
	 *  @param data receives its first byte
	 *  @param length receives its usable length
	 *  @return false if the cell lies outside the file or its size is absurd */
	bool cell(unsigned offset, const BYTE*& data, size_t& length) const {
		const size_t at = BASE_BLOCK + (size_t)offset;
		int32_t size = 0;
		if (!read(at, size)) return false;
		// In use: negative. A free cell is still read (offreg does not check
		// either), its size taken as is.
		const size_t total = size < 0 ? (size_t)(-(int64_t)size) : (size_t)size;
		if (total < 4 || !fits(h.size, at, total)) return false;
		data = h.base + at + 4;
		length = total - 4;
		return true;
	}

	/*! A cell that must start with the 2-character signature `sig`. */
	bool signedCell(unsigned offset, const char* sig, const BYTE*& data, size_t& length) const {
		return cell(offset, data, length) && length >= 2 && data[0] == sig[0] && data[1] == sig[1];
	}
};

template <typename T>
T field(const BYTE* data, size_t at) {   // caller has checked the bounds
	T v;
	std::memcpy(&v, data + at, sizeof(T));
	return v;
}

/*! A name stored in a cell: one byte per character if `compressed`, UTF-16
 *  otherwise. */
std::wstring cellName(const BYTE* p, size_t bytes, bool compressed) {
	std::wstring name;
	if (compressed) {
		name.reserve(bytes);
		for (size_t i = 0; i < bytes; ++i) name.push_back((wchar_t)p[i]);
	}
	else {
		name.resize(bytes / 2);
		if (!name.empty()) std::memcpy(&name[0], p, name.size() * 2);
	}
	return name;
}

/*! The fields of an "nk" cell that WAC's calls need. */
struct KeyCell {
	FILETIME lastWrite = { 0, 0 };
	unsigned subkeyCount = 0, subkeyList = 0;
	unsigned valueCount = 0, valueList = 0;
	unsigned security = 0, classCell = 0;
	unsigned short classLength = 0;   // in bytes
	// The maxima the key records for its SUBKEYS — what offreg returns, even
	// when stale (a subkey since deleted). Those of the values are measured.
	DWORD maxSubkeyName = 0, maxSubkeyClass = 0;
	std::wstring name;
};

bool readKeyCell(const Reader& r, unsigned offset, KeyCell& k) {
	const BYTE* d; size_t n;
	if (!r.signedCell(offset, "nk", d, n) || n < 0x4C) return false;
	const unsigned short flags = field<unsigned short>(d, 2);
	std::memcpy(&k.lastWrite, d + 4, 8);
	k.subkeyCount = field<uint32_t>(d, 0x14);
	k.subkeyList = field<uint32_t>(d, 0x1C);
	k.valueCount = field<uint32_t>(d, 0x24);
	k.valueList = field<uint32_t>(d, 0x28);
	k.security = field<uint32_t>(d, 0x2C);
	k.classCell = field<uint32_t>(d, 0x30);
	// Stored in bytes; the high half of the first one carries flags.
	k.maxSubkeyName = (field<uint32_t>(d, 0x34) & 0xFFFF) / 2;
	k.maxSubkeyClass = field<uint32_t>(d, 0x38) / 2;
	const unsigned short nameLength = field<unsigned short>(d, 0x48);
	k.classLength = field<unsigned short>(d, 0x4A);
	if (!fits(n, 0x4C, nameLength)) return false;
	k.name = cellName(d + 0x4C, nameLength, (flags & KEY_COMP_NAME) != 0);
	return true;
}

/*! The class of a key: UTF-16, in its own cell. */
std::wstring keyClass(const Reader& r, const KeyCell& k) {
	if (k.classLength == 0 || k.classCell == 0xFFFFFFFF) return std::wstring();
	const BYTE* d; size_t n;
	if (!r.cell(k.classCell, d, n) || n < k.classLength) return std::wstring();
	return cellName(d, k.classLength, false);
}

/*! Offsets of the subkeys, in the hive's order, through "lf", "lh", "li" and
 *  "ri" lists. An "ri" holds leaf lists only: a nested "ri" is refused, which
 *  also rules out a list pointing back at itself.
 *  @return false if a list is damaged */
bool subkeyCells(const Reader& r, unsigned list, std::vector<unsigned>& out, bool insideRi = false) {
	const BYTE* d; size_t n;
	if (!r.cell(list, d, n) || n < 4) return false;
	const unsigned count = field<unsigned short>(d, 2);
	if ((d[0] == 'l' && (d[1] == 'f' || d[1] == 'h'))) {
		if (!fits(n, 4, (size_t)count * 8)) return false;
		for (unsigned i = 0; i < count; ++i) out.push_back(field<uint32_t>(d, 4 + (size_t)i * 8));
		return true;
	}
	if (d[0] == 'l' && d[1] == 'i') {
		if (!fits(n, 4, (size_t)count * 4)) return false;
		for (unsigned i = 0; i < count; ++i) out.push_back(field<uint32_t>(d, 4 + (size_t)i * 4));
		return true;
	}
	if (d[0] == 'r' && d[1] == 'i' && !insideRi) {
		if (!fits(n, 4, (size_t)count * 4)) return false;
		for (unsigned i = 0; i < count; ++i)
			if (!subkeyCells(r, field<uint32_t>(d, 4 + (size_t)i * 4), out, true)) return false;
		return true;
	}
	return false;
}

/*! Subkeys of a key: none if it has no list. */
bool subkeysOf(const Reader& r, const KeyCell& k, std::vector<unsigned>& out) {
	out.clear();
	if (k.subkeyCount == 0 || k.subkeyList == 0xFFFFFFFF) return true;
	return subkeyCells(r, k.subkeyList, out);
}

/*! Offsets of the value cells of a key. */
bool valuesOf(const Reader& r, const KeyCell& k, std::vector<unsigned>& out) {
	out.clear();
	if (k.valueCount == 0 || k.valueList == 0xFFFFFFFF) return true;
	const BYTE* d; size_t n;
	if (!r.cell(k.valueList, d, n) || !fits(n, 0, (size_t)k.valueCount * 4)) return false;
	for (unsigned i = 0; i < k.valueCount; ++i) out.push_back(field<uint32_t>(d, (size_t)i * 4));
	return true;
}

/*! A "vk" cell. */
struct ValueCell {
	std::wstring name;
	DWORD type = 0;
	DWORD dataSize = 0;       // real size, flag removed
	bool inOffset = false;    // data held in the offset field
	unsigned dataOffset = 0;
};

bool readValueCell(const Reader& r, unsigned offset, ValueCell& v) {
	const BYTE* d; size_t n;
	if (!r.signedCell(offset, "vk", d, n) || n < 0x14) return false;
	const unsigned short nameLength = field<unsigned short>(d, 2);
	const DWORD size = field<uint32_t>(d, 4);
	v.dataOffset = field<uint32_t>(d, 8);
	v.type = field<uint32_t>(d, 0xC);
	const unsigned short flags = field<unsigned short>(d, 0x10);
	if (!fits(n, 0x14, nameLength)) return false;
	v.name = cellName(d + 0x14, nameLength, (flags & VALUE_COMP_NAME) != 0);
	v.inOffset = (size & DATA_IN_OFFSET) != 0;
	v.dataSize = size & ~DATA_IN_OFFSET;
	if (v.inOffset && v.dataSize > 4) return false;
	return true;
}

/*! The data of a value: in the offset field, in one cell, or in the segments
 *  of a "db" cell. */
bool valueData(const Reader& r, const ValueCell& v, std::vector<BYTE>& out) {
	out.clear();
	if (v.dataSize == 0) return true;
	if (v.inOffset) {
		const BYTE* p = reinterpret_cast<const BYTE*>(&v.dataOffset);
		out.assign(p, p + v.dataSize);
		return true;
	}
	const BYTE* d; size_t n;
	if (!r.cell(v.dataOffset, d, n)) return false;
	if (v.dataSize > DB_SEGMENT && r.h.minorVersion >= 4 && n >= 8 && d[0] == 'd' && d[1] == 'b') {
		const unsigned segments = field<unsigned short>(d, 2);
		const BYTE* list; size_t listLength;
		if (!r.cell(field<uint32_t>(d, 4), list, listLength) || !fits(listLength, 0, (size_t)segments * 4))
			return false;
		out.reserve(v.dataSize);
		for (unsigned i = 0; i < segments && out.size() < v.dataSize; ++i) {
			const BYTE* s; size_t sl;
			if (!r.cell(field<uint32_t>(list, (size_t)i * 4), s, sl)) return false;
			const size_t take = std::min<size_t>({ sl, DB_SEGMENT, v.dataSize - out.size() });
			out.insert(out.end(), s, s + take);
		}
		return out.size() == v.dataSize;
	}
	if (n < v.dataSize) return false;
	out.assign(d, d + v.dataSize);
	return true;
}

bool sameName(const std::wstring& a, const wchar_t* b, size_t bLength) {
	return CompareStringOrdinal(a.c_str(), (int)a.size(), b, (int)bLength, TRUE) == CSTR_EQUAL;
}

/*! Copies a name into a caller's buffer, as offreg does: `cch` holds the
 *  buffer size with its terminator on input; the length without it on success,
 *  the size needed WITH it on ERROR_MORE_DATA (checked against Microsoft's
 *  DLL). */
DWORD copyName(const std::wstring& name, PWSTR buffer, PDWORD cch) {
	if (!cch) return buffer ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;
	if (!buffer || *cch <= name.size()) {
		*cch = (DWORD)name.size() + 1;
		return buffer ? ERROR_MORE_DATA : ERROR_SUCCESS;
	}
	std::memcpy(buffer, name.c_str(), (name.size() + 1) * sizeof(wchar_t));
	*cch = (DWORD)name.size();
	return ERROR_SUCCESS;
}

/*! Copies data into a caller's buffer. A null buffer asks for the size only —
 *  but offreg's OREnumValue still reports ERROR_MORE_DATA when the size given
 *  is too small, where ORGetValue reports success: `probeSucceeds` says which
 *  (both checked against Microsoft's DLL). */
DWORD copyData(const std::vector<BYTE>& data, PBYTE buffer, PDWORD cb, bool probeSucceeds) {
	if (!cb) return buffer ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;
	const DWORD needed = (DWORD)data.size();
	if (!buffer && probeSucceeds) { *cb = needed; return ERROR_SUCCESS; }
	if (*cb < needed) { *cb = needed; return ERROR_MORE_DATA; }
	if (!buffer) { *cb = needed; return ERROR_SUCCESS; }
	if (needed) std::memcpy(buffer, data.data(), needed);
	*cb = needed;
	return ERROR_SUCCESS;
}

/*! Finds a direct subkey by name, case-insensitive. */
DWORD findSubkey(const Reader& r, unsigned parent, const wchar_t* name, size_t length, unsigned& found) {
	KeyCell k;
	if (!readKeyCell(r, parent, k)) return ERROR_BADDB;
	std::vector<unsigned> children;
	if (!subkeysOf(r, k, children)) return ERROR_BADDB;
	for (unsigned child : children) {
		KeyCell c;
		if (!readKeyCell(r, child, c)) return ERROR_BADDB;
		if (sameName(c.name, name, length)) { found = child; return ERROR_SUCCESS; }
	}
	return ERROR_FILE_NOT_FOUND;
}

/*! Walks a relative path from a key cell.
 *  @param chain in: the cells from the root down to `from`, `from` excluded;
 *         out: extended down to the key found, that key excluded
 *  @return ERROR_BADDB if a step leads back to a cell already on the chain */
DWORD walkPath(const Reader& r, unsigned from, PCWSTR path, unsigned& found, std::vector<unsigned>& chain) {
	found = from;
	if (!path) return ERROR_SUCCESS;
	const wchar_t* p = path;
	while (*p) {
		const wchar_t* end = p;
		while (*end && *end != L'\\') ++end;
		if (end > p) {
			unsigned next = 0;
			const DWORD e = findSubkey(r, found, p, (size_t)(end - p), next);
			if (e != ERROR_SUCCESS) return e;
			chain.push_back(found);
			for (unsigned c : chain) if (c == next) return ERROR_BADDB;   // a cycle
			found = next;
		}
		p = *end ? end + 1 : end;
	}
	return ERROR_SUCCESS;
}

/*! Finds a value by name; empty name = the default value. */
DWORD findValue(const Reader& r, unsigned keyCell, PCWSTR name, ValueCell& found) {
	KeyCell k;
	if (!readKeyCell(r, keyCell, k)) return ERROR_BADDB;
	std::vector<unsigned> values;
	if (!valuesOf(r, k, values)) return ERROR_BADDB;
	const size_t length = name ? wcslen(name) : 0;
	for (unsigned offset : values) {
		ValueCell v;
		if (!readValueCell(r, offset, v)) return ERROR_BADDB;
		if (length == 0 ? v.name.empty() : sameName(v.name, name, length)) { found = v; return ERROR_SUCCESS; }
	}
	return ERROR_FILE_NOT_FOUND;
}

} // namespace

namespace {

/*! Checks the base block of a hive in memory and registers its root key: what
 *  OROpenHive and openHiveBuffer share. */
DWORD openHive(std::shared_ptr<Hive> hive, PORHKEY phkResult) {
	if (hive->size < BASE_BLOCK + 32 || std::memcmp(hive->base, "regf", 4) != 0) return ERROR_BADDB;
	Reader r{ *hive };
	/* A hive whose last write was not completed is refused: sequence numbers
	   that differ, or a base block whose checksum is wrong, mean the file lags
	   behind its transaction logs. Read as is, it would give stale keys without
	   any error — WAC replays the logs first (hive_recover.h). Recent versions
	   of Microsoft's DLL read such a hive as is: the one intended difference.
	   The checksum is the XOR of the first 127 double words, 0 and -1 being
	   replaced by 1 and -2. */
	uint32_t primary = 0, secondary = 0, fileType = 0, checksum = 0, minor = 0, root = 0;
	if (!r.read(0x04, primary) || !r.read(0x08, secondary) || !r.read(0x1C, fileType)
	    || !r.read(0x1FC, checksum) || !r.read(0x18, minor) || !r.read(0x24, root)) return ERROR_BADDB;
	uint32_t computed = 0;
	for (size_t i = 0; i < 127; ++i) {
		uint32_t w = 0;
		r.read(i * 4, w);
		computed ^= w;
	}
	if (computed == 0) computed = 1;
	else if (computed == 0xFFFFFFFF) computed = 0xFFFFFFFE;
	if (fileType != 0 || primary != secondary || checksum != computed) return ERROR_BADDB;
	hive->minorVersion = minor;
	hive->rootCell = root;
	KeyCell k;
	if (!readKeyCell(r, root, k)) return ERROR_BADDB;

	auto key = std::make_unique<Key>();
	key->hive = hive;
	key->cell = root;
	key->hiveRoot = true;
	*phkResult = registerKey(std::move(key));
	return ERROR_SUCCESS;
}

} // namespace

DWORD OROpenHive(PCWSTR lpHivePath, PORHKEY phkResult) {
	if (!lpHivePath || !phkResult) return ERROR_INVALID_PARAMETER;
	*phkResult = nullptr;
	auto hive = std::make_shared<Hive>();
	hive->file = CreateFileW(lpHivePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
	                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hive->file == INVALID_HANDLE_VALUE) return GetLastError();
	LARGE_INTEGER size;
	if (!GetFileSizeEx(hive->file, &size)) return GetLastError();
	if ((unsigned long long)size.QuadPart < BASE_BLOCK + 32) return ERROR_BADDB;
	hive->size = (size_t)size.QuadPart;
	hive->mapping = CreateFileMappingW(hive->file, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hive->mapping) return GetLastError();
	hive->base = static_cast<const BYTE*>(MapViewOfFile(hive->mapping, FILE_MAP_READ, 0, 0, 0));
	if (!hive->base) return GetLastError();
	hive->mapped = true;
	return openHive(hive, phkResult);
}

DWORD openHiveBuffer(const BYTE* data, size_t size, PORHKEY phkResult) {
	if (!data || !phkResult) return ERROR_INVALID_PARAMETER;
	*phkResult = nullptr;
	auto hive = std::make_shared<Hive>();
	hive->base = data;
	hive->size = size;
	return openHive(hive, phkResult);
}

DWORD ORCloseHive(ORHKEY Handle) {
	std::lock_guard<std::mutex> lock(g_mutex);
	const auto it = g_keys.find(reinterpret_cast<const Key*>(Handle));
	if (it == g_keys.end() || !it->second->hiveRoot) return ERROR_INVALID_HANDLE;
	g_keys.erase(it);   // the mapping goes when its last key does
	return ERROR_SUCCESS;
}

DWORD OROpenKey(ORHKEY Handle, PCWSTR lpSubKey, PORHKEY phkResult) {
	if (!phkResult) return ERROR_INVALID_PARAMETER;
	*phkResult = nullptr;
	const Key* parent = findKey(Handle);
	if (!parent) return ERROR_INVALID_HANDLE;
	Reader r{ *parent->hive };
	unsigned cell = 0;
	std::vector<unsigned> chain = parent->ancestors;
	const DWORD e = walkPath(r, parent->cell, lpSubKey, cell, chain);
	if (e != ERROR_SUCCESS) return e;
	auto key = std::make_unique<Key>();
	key->hive = parent->hive;
	key->cell = cell;
	key->ancestors = std::move(chain);
	*phkResult = registerKey(std::move(key));
	return ERROR_SUCCESS;
}

DWORD ORCloseKey(ORHKEY Handle) {
	std::lock_guard<std::mutex> lock(g_mutex);
	const auto it = g_keys.find(reinterpret_cast<const Key*>(Handle));
	if (it == g_keys.end() || it->second->hiveRoot) return ERROR_INVALID_HANDLE;
	g_keys.erase(it);
	return ERROR_SUCCESS;
}

DWORD OREnumKey(ORHKEY Handle, DWORD dwIndex, PWSTR lpName, PDWORD lpcName,
                PWSTR lpClass, PDWORD lpcClass, PFILETIME lpftLastWriteTime) {
	const Key* key = findKey(Handle);
	if (!key) return ERROR_INVALID_HANDLE;
	if (!lpName || !lpcName) return ERROR_INVALID_PARAMETER;
	Reader r{ *key->hive };
	KeyCell k;
	std::vector<unsigned> children;
	if (!readKeyCell(r, key->cell, k) || !subkeysOf(r, k, children)) return ERROR_BADDB;
	if (dwIndex >= children.size()) return ERROR_NO_MORE_ITEMS;
	KeyCell c;
	if (!readKeyCell(r, children[dwIndex], c)) return ERROR_BADDB;
	const DWORD e = copyName(c.name, lpName, lpcName);
	if (e != ERROR_SUCCESS) return e;
	if (lpcClass) {
		const DWORD ec = copyName(keyClass(r, c), lpClass, lpcClass);
		if (ec != ERROR_SUCCESS) return ec;
	}
	if (lpftLastWriteTime) *lpftLastWriteTime = c.lastWrite;
	return ERROR_SUCCESS;
}

DWORD OREnumValue(ORHKEY Handle, DWORD dwIndex, PWSTR lpValueName,
                  PDWORD lpcValueName, PDWORD lpType, PBYTE lpData, PDWORD lpcbData) {
	const Key* key = findKey(Handle);
	if (!key) return ERROR_INVALID_HANDLE;
	if (!lpValueName || !lpcValueName) return ERROR_INVALID_PARAMETER;
	Reader r{ *key->hive };
	KeyCell k;
	std::vector<unsigned> values;
	if (!readKeyCell(r, key->cell, k) || !valuesOf(r, k, values)) return ERROR_BADDB;
	if (dwIndex >= values.size()) return ERROR_NO_MORE_ITEMS;
	ValueCell v;
	if (!readValueCell(r, values[dwIndex], v)) return ERROR_BADDB;
	const DWORD e = copyName(v.name, lpValueName, lpcValueName);
	if (e != ERROR_SUCCESS) return e;
	if (lpType) *lpType = v.type;
	if (lpcbData) {
		std::vector<BYTE> data;
		if (!valueData(r, v, data)) return ERROR_BADDB;
		return copyData(data, lpData, lpcbData, false);
	}
	return ERROR_SUCCESS;
}

DWORD ORGetValue(ORHKEY Handle, PCWSTR lpSubKey, PCWSTR lpValue,
                 PDWORD pdwType, PVOID pvData, PDWORD pcbData) {
	const Key* key = findKey(Handle);
	if (!key) return ERROR_INVALID_HANDLE;
	Reader r{ *key->hive };
	unsigned cell = 0;
	std::vector<unsigned> chain = key->ancestors;
	DWORD e = walkPath(r, key->cell, lpSubKey, cell, chain);
	if (e != ERROR_SUCCESS) return e;
	ValueCell v;
	e = findValue(r, cell, lpValue, v);
	if (e != ERROR_SUCCESS) return e;
	if (pdwType) *pdwType = v.type;
	if (!pcbData) return pvData ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;
	std::vector<BYTE> data;
	if (!valueData(r, v, data)) return ERROR_BADDB;
	return copyData(data, static_cast<PBYTE>(pvData), pcbData, true);
}

DWORD ORQueryInfoKey(ORHKEY Handle, PWSTR lpClass, PDWORD lpcClass,
                     PDWORD lpcSubKeys, PDWORD lpcMaxSubKeyLen,
                     PDWORD lpcMaxClassLen, PDWORD lpcValues,
                     PDWORD lpcMaxValueNameLen, PDWORD lpcMaxValueLen,
                     PDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime) {
	const Key* key = findKey(Handle);
	if (!key) return ERROR_INVALID_HANDLE;
	Reader r{ *key->hive };
	KeyCell k;
	if (!readKeyCell(r, key->cell, k)) return ERROR_BADDB;

	/* As offreg does, checked against Microsoft's DLL on whole hives: the
	   counts come from the lists; the SUBKEY maxima are those the key records
	   (possibly stale), the VALUE maxima are measured on the values. */
	if (lpcSubKeys) {
		std::vector<unsigned> children;
		if (!subkeysOf(r, k, children)) return ERROR_BADDB;
		*lpcSubKeys = (DWORD)children.size();
	}
	if (lpcMaxSubKeyLen) *lpcMaxSubKeyLen = k.maxSubkeyName;
	if (lpcMaxClassLen) *lpcMaxClassLen = k.maxSubkeyClass;
	if (lpcValues || lpcMaxValueNameLen || lpcMaxValueLen) {
		std::vector<unsigned> values;
		if (!valuesOf(r, k, values)) return ERROR_BADDB;
		DWORD maxName = 0, maxData = 0;
		for (unsigned offset : values) {
			ValueCell v;
			if (!readValueCell(r, offset, v)) return ERROR_BADDB;
			maxName = std::max<DWORD>(maxName, (DWORD)v.name.size());
			maxData = std::max<DWORD>(maxData, v.dataSize);
		}
		if (lpcValues) *lpcValues = (DWORD)values.size();
		if (lpcMaxValueNameLen) *lpcMaxValueNameLen = maxName;
		if (lpcMaxValueLen) *lpcMaxValueLen = maxData;
	}
	if (lpcbSecurityDescriptor) {
		*lpcbSecurityDescriptor = 0;
		const BYTE* d; size_t n;
		if (k.security != 0xFFFFFFFF && r.signedCell(k.security, "sk", d, n) && n >= 0x14)
			*lpcbSecurityDescriptor = field<uint32_t>(d, 0x10);
	}
	if (lpftLastWriteTime) *lpftLastWriteTime = k.lastWrite;
	if (lpcClass) return copyName(keyClass(r, k), lpClass, lpcClass);
	return ERROR_SUCCESS;
}
