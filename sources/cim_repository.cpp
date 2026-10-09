/*! \file
 *  \brief Offline reader of the WMI repository (see cim_repository.h).
 */
#include "conversions.h"
#include "cim_repository.h"
#include "sha.h"
#include "whole_file.h"
#include <algorithm>
#include <cstring>
#include <cwctype>
#include <filesystem>

namespace {

const size_t PAGE = 0x2000;
const uint32_t MAPPING_START = 0xABCD, MAPPING_END = 0xDCBA, INDEX_PAGE_ACTIVE = 0xACCC;
const size_t MAPPING_ENTRY = 24;              //!< six 32-bit fields per logical page (Vista and later)
const unsigned DEPTH_MAX = 64;                //!< B-tree, namespaces, inheritance: far beyond any real depth
const size_t RECORD_MAX = 64 * 1024 * 1024;   //!< a class or an instance is a few kilobytes
const size_t INSTANCE_HASH = 0x80;            //!< an instance starts with its class's hash, 64 UTF-16 characters
const char SYSTEM_NAMESPACE[] = "__SystemClass";

//! Size of a value in a value table: 4 bytes (a heap offset) for an array, a string, a reference, a date.
size_t valueSize(uint8_t type, bool array) {
	if (array) return 4;
	switch (type) {
	case 0x10: case 0x11: return 1;            // sint8, uint8
	case 0x02: case 0x0B: case 0x12: return 2; // sint16, boolean, uint16
	case 0x05: case 0x14: case 0x15: return 8; // real64, sint64, uint64
	default: return 4;                         // sint32, uint32, real32, string, date, reference, object
	}
}

/*! A string of a heap: a flag byte — 0 one byte per character, 1 UTF-16 —
 *  then the text, zero-terminated, never read past the heap. */
bool heapString(const std::vector<uint8_t>& heap, size_t ref, std::wstring& out) {
	if (ref >= heap.size()) return false;
	out.clear();
	if (heap[ref] == 0) {
		for (size_t i = ref + 1; i < heap.size() && heap[i]; ++i) out.push_back((wchar_t)heap[i]);
		return true;
	}
	out = readWideZ(heap.data(), heap.size(), ref + 1);
	return true;
}

//! Skips a qualifier list: its size, counted from its own start.
bool skipQualifiers(const std::vector<uint8_t>& b, size_t& o) {
	if (!fits(b.size(), o, 4)) return false;
	const size_t size = readLittleEndian<uint32_t>(b.data() + o);
	if (size < 4 || !fits(b.size(), o, size)) return false;
	o += size;
	return true;
}

/*! One value of a table, decoded: a number, a boolean, a string or a
 *  reference from the heap, an array from the heap. A type WAC does not
 *  decode (an embedded object) comes back as false. */
bool decodeValue(const std::vector<uint8_t>& heap, uint8_t type, bool array, const uint8_t* raw, Json& out) {
	if (array) {
		const size_t ref = readLittleEndian<uint32_t>(raw);
		if (!fits(heap.size(), ref, 4)) return false;
		const size_t count = readLittleEndian<uint32_t>(heap.data() + ref), size = valueSize(type, false);
		if (count > (heap.size() - ref - 4) / size) return false;
		out = Json::arr();
		for (size_t i = 0; i < count; ++i) {
			Json item = Json::null();
			if (!decodeValue(heap, type, false, heap.data() + ref + 4 + i * size, item)) return false;
			out.push(std::move(item));
		}
		return true;
	}
	switch (type) {
	case 0x08: case 0x65: case 0x66: {         // string, date (DMTF text), reference (object path)
		std::wstring text;
		if (!heapString(heap, readLittleEndian<uint32_t>(raw), text)) return false;
		out = Json::str(text);
		return true;
	}
	case 0x0B: out = Json::boolean(readLittleEndian<uint16_t>(raw) != 0); return true;
	case 0x10: out = Json::num((int)(int8_t)raw[0]); return true;
	case 0x11: out = Json::num((unsigned)raw[0]); return true;
	case 0x02: out = Json::num((int)(int16_t)readLittleEndian<uint16_t>(raw)); return true;
	case 0x12: out = Json::num((unsigned)readLittleEndian<uint16_t>(raw)); return true;
	case 0x03: out = Json::num((int32_t)readLittleEndian<uint32_t>(raw)); return true;
	case 0x13: out = Json::num(readLittleEndian<uint32_t>(raw)); return true;
	case 0x14: out = Json::num((long long)readLittleEndian<uint64_t>(raw)); return true;
	case 0x15: out = Json::num((unsigned long long)readLittleEndian<uint64_t>(raw)); return true;
	// Reals, as text: every digit needed to give the same value back (JSON numbers here are integers).
	case 0x04: { float f; memcpy(&f, raw, 4); out = Json::str(realText(f, 9)); return true; }
	case 0x05: { double d; memcpy(&d, raw, 8); out = Json::str(realText(d, 17)); return true; }
	default: return false;
	}
}

//! Two state bits of a property, at its index.
unsigned stateBits(const uint8_t* states, uint16_t index) {
	return (states[index / 4] >> (2 * (index % 4))) & 3;
}

//! The properties of a chain up to `level`, a later definition replacing an earlier one at the same index.
std::map<uint16_t, const CimProperty*> layoutUpTo(const std::vector<const CimClass*>& chain, size_t level) {
	std::map<uint16_t, const CimProperty*> props;
	for (size_t i = 0; i <= level && i < chain.size(); ++i)
		for (const CimProperty& p : chain[i]->properties) props[p.index] = &p;
	return props;
}

//! Size of a value table: up to the end of its last value.
size_t tableSize(const std::map<uint16_t, const CimProperty*>& props) {
	size_t size = 0;
	for (const auto& [index, p] : props) size = std::max<size_t>(size, (size_t)p->offset + valueSize(p->type, p->array));
	return size;
}

/*! A property's default value: from the class up, the first definition that
 *  holds it itself. Each definition's defaults cover ITS layout — its
 *  properties and its ancestors'. States: bit 0 set, no default; bit 1 set,
 *  inherited from above. */
bool defaultValue(const std::vector<const CimClass*>& chain, const CimProperty& p, Json& out) {
	for (size_t level = chain.size(); level-- > 0;) {
		const auto own = layoutUpTo(chain, level);
		if (!own.count(p.index)) return false;
		const std::vector<uint8_t>& defaults = chain[level]->defaults;
		const size_t states = (2 * own.size() + 7) / 8;
		if (p.index / 4 >= defaults.size()) return false;
		const unsigned state = stateBits(defaults.data(), p.index);
		if (state & 1) return false;
		if (state & 2) continue;
		const size_t at = states + p.offset;
		if (!fits(defaults.size(), at, valueSize(p.type, p.array))) return false;
		return decodeValue(chain[level]->heap, p.type, p.array, defaults.data() + at, out);
	}
	return false;
}

//! "NS_<hash>" of a namespace.
std::string namespacePart(const std::wstring& space) {
	return "NS_" + cimNameHash(space);
}

} // namespace

std::string cimNameHash(const std::wstring& name) {
	std::vector<uint8_t> bytes;
	for (wchar_t c : name) {
		const wchar_t upper = (wchar_t)std::towupper(c);
		bytes.push_back((uint8_t)upper);
		bytes.push_back((uint8_t)(upper >> 8));
	}
	uint8_t digest[32];
	sha256Bytes(bytes.data(), bytes.size(), digest);
	std::string hex;
	for (wchar_t c : toHexadecimal(digest, sizeof digest)) hex.push_back((char)c);
	return hex;
}

// ------------------------------------------------------------ records

bool parseCimClass(const std::vector<uint8_t>& b, CimClass& c) {
	const size_t size = b.size();
	size_t o = 0;
	if (!fits(size, o, 4)) return false;
	const size_t superChars = readLittleEndian<uint32_t>(b.data());
	o += 4;
	if (superChars > size / 2 || !fits(size, o, superChars * 2)) return false;
	c.superName.assign(reinterpret_cast<const wchar_t*>(b.data() + o), superChars);   // wchar_t is 2 bytes on Windows
	o += superChars * 2;
	// Timestamp (8), length of what follows (4), a byte, class name's heap offset (4), defaults' length (4).
	if (!fits(size, o, 8 + 4 + 1 + 4 + 4 + 4)) return false;
	o += 13;
	const size_t nameRef = readLittleEndian<uint32_t>(b.data() + o), defaultsLength = readLittleEndian<uint32_t>(b.data() + o + 4);
	o += 8;
	// The superclass's name again, in one byte per character, with its length: 4 when there is none.
	const size_t superAscii = readLittleEndian<uint32_t>(b.data() + o);
	if (superAscii < 4 || !fits(size, o, superAscii)) return false;
	o += superAscii;
	if (!skipQualifiers(b, o) || !fits(size, o, 4)) return false;
	const size_t count = readLittleEndian<uint32_t>(b.data() + o);
	o += 4;
	if (count > (size - o) / 8) return false;
	const size_t references = o;
	o += count * 8;
	if (!fits(size, o, defaultsLength)) return false;
	c.defaults.assign(b.begin() + o, b.begin() + o + defaultsLength);
	o += defaultsLength;
	if (!fits(size, o, 4)) return false;
	const size_t heapSize = readLittleEndian<uint32_t>(b.data() + o) & 0x7FFFFFFF;
	o += 4;
	if (!fits(size, o, heapSize)) return false;
	c.heap.assign(b.begin() + o, b.begin() + o + heapSize);
	if (!heapString(c.heap, nameRef, c.name)) return false;
	for (size_t i = 0; i < count; ++i) {
		const uint32_t nameOffset = readLittleEndian<uint32_t>(b.data() + references + 8 * i), structure = readLittleEndian<uint32_t>(b.data() + references + 8 * i + 4);
		CimProperty p;
		// A name with its high bit set is one of WMI's built-in names, by number.
		if (nameOffset & 0x80000000) p.name = L"BuiltinProperty" + std::to_wstring(nameOffset & 0x7FFFFFFF);
		else if (!heapString(c.heap, nameOffset, p.name)) return false;
		// type (1), array flag (1), two bytes, index (2), offset (4), level (4)
		if (!fits(c.heap.size(), structure, 14)) return false;
		p.type = c.heap[structure];
		p.array = (c.heap[structure + 1] & 0x20) != 0;
		p.index = readLittleEndian<uint16_t>(c.heap.data() + structure + 4);
		p.offset = readLittleEndian<uint32_t>(c.heap.data() + structure + 6);
		c.properties.push_back(std::move(p));
	}
	return true;
}

bool parseCimInstance(const std::vector<uint8_t>& b, const std::vector<const CimClass*>& chain, CimValues& out) {
	if (chain.empty()) return false;
	const auto props = layoutUpTo(chain, chain.size() - 1);
	const size_t size = b.size();
	// Class hash, two FILETIMEs, record length (4), class name's heap offset (4), a byte.
	size_t o = INSTANCE_HASH + 16 + 9;
	const size_t states = o, stateBytes = (2 * props.size() + 7) / 8;
	if (!fits(size, o, stateBytes)) return false;
	o += stateBytes;
	const size_t table = o, tableBytes = tableSize(props);
	if (!fits(size, o, tableBytes)) return false;
	o += tableBytes;
	if (!skipQualifiers(b, o) || !fits(size, o, 1)) return false;
	// Dynamic property qualifiers: 1 when there are none, the only form met; another is refused.
	if (b[o] != 1) return false;
	++o;
	if (!fits(size, o, 4)) return false;
	const size_t heapSize = readLittleEndian<uint32_t>(b.data() + o) & 0x7FFFFFFF;
	o += 4;
	if (!fits(size, o, heapSize)) return false;
	const std::vector<uint8_t> heap(b.begin() + o, b.begin() + o + heapSize);
	for (const auto& [index, p] : props) {
		if (index / 4 >= stateBytes) return false;
		const unsigned state = stateBits(b.data() + states, index);
		if (state & 1) continue;                               // not set
		Json value = Json::null();
		const bool read = (state & 2) ? defaultValue(chain, *p, value)
		                              : decodeValue(heap, p->type, p->array, b.data() + table + p->offset, value);
		if (!read) {
			// Not decoded (an embedded object): said, not left out as if unset.
			Json undecoded = Json::obj();
			undecoded.add(L"CimType", Json::str(L"0x" + to_hex(p->type)));
			undecoded.add(L"Undecoded", Json::boolean(true));
			out.emplace_back(p->name, std::move(undecoded));
			continue;
		}
		out.emplace_back(p->name, std::move(value));
	}
	return true;
}

bool parseCimMappings(const std::vector<uint8_t>& file, CimMapping& data, CimMapping& index) {
	size_t o = 0;
	for (CimMapping* m : { &data, &index }) {
		// Signature, version, two identifiers, physical page count, entry count.
		if (!fits(file.size(), o, 24) || readLittleEndian<uint32_t>(file.data() + o) != MAPPING_START) return false;
		const size_t count = readLittleEndian<uint32_t>(file.data() + o + 20);
		o += 24;
		if (count > (file.size() - o) / MAPPING_ENTRY) return false;
		m->physical.resize(count);
		for (size_t i = 0; i < count; ++i) m->physical[i] = readLittleEndian<uint32_t>(file.data() + o + i * MAPPING_ENTRY) & CimMapping::UNMAPPED;
		// For the index, entry 0's "used space" field holds the root's logical page.
		if (count) m->indexRoot = readLittleEndian<uint32_t>(file.data() + o + 12);
		o += count * MAPPING_ENTRY;
		if (!fits(file.size(), o, 4)) return false;
		const size_t free = readLittleEndian<uint32_t>(file.data() + o);
		o += 4;
		if (free > (file.size() - o) / 4) return false;
		o += free * 4;
		if (!fits(file.size(), o, 4) || readLittleEndian<uint32_t>(file.data() + o) != MAPPING_END) return false;
		o += 4;
	}
	return true;
}

// ------------------------------------------------------------ repository

HRESULT CimRepository::open(const std::wstring& index, const std::wstring& objects, const std::vector<std::wstring>& mappings) {
	// The current mapping: the highest version among those that read whole.
	uint32_t best = 0;
	bool found = false;
	for (const std::wstring& path : mappings) {
		std::vector<uint8_t> file;
		CimMapping data, idx;
		if (!readWholeFile(std::filesystem::path(path), RECORD_MAX, file) || file.size() < 8 || !parseCimMappings(file, data, idx)) continue;
		const uint32_t version = readLittleEndian<uint32_t>(file.data() + 4);
		if (found && version <= best) continue;
		best = version;
		found = true;
		data_ = std::move(data);
		index_ = std::move(idx);
	}
	if (!found) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	std::error_code ec;
	indexSize_ = std::filesystem::file_size(index, ec);
	if (ec) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	objectsSize_ = std::filesystem::file_size(objects, ec);
	if (ec) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	indexFile_.open(std::filesystem::path(extendedPath(index)), std::ios::binary);
	objectsFile_.open(std::filesystem::path(extendedPath(objects)), std::ios::binary);
	if (!indexFile_ || !objectsFile_) return HRESULT_FROM_WIN32(ERROR_OPEN_FAILED);
	std::vector<bool> visited(index_.physical.size(), false);
	collectKeys(index_.indexRoot, 0, visited);
	std::sort(keys_.begin(), keys_.end());
	return keys_.empty() ? HRESULT_FROM_WIN32(ERROR_INVALID_DATA) : ERROR_SUCCESS;
}

bool CimRepository::readPage(std::ifstream& file, uint64_t size, const CimMapping& mapping, uint32_t logical,
                             std::vector<uint8_t>& page) {
	if (logical >= mapping.physical.size() || mapping.physical[logical] == CimMapping::UNMAPPED) return false;
	const uint64_t at = (uint64_t)mapping.physical[logical] * PAGE;
	if (at > size || size - at < PAGE) return false;
	page.resize(PAGE);
	file.clear();
	file.seekg((std::streamoff)at);
	file.read(reinterpret_cast<char*>(page.data()), PAGE);
	return file.gcount() == (std::streamsize)PAGE;
}

/*! Walks the B-tree in order, each page once: header (signature, logical id,
 *  a zero, root, key count), a table per key, children, the key strings'
 *  definitions — a count of parts, then each part's number — and the parts'
 *  offsets in the text that ends the page. */
void CimRepository::collectKeys(uint32_t logical, unsigned depth, std::vector<bool>& visited) {
	if (depth > DEPTH_MAX || logical >= visited.size() || visited[logical]) return;
	visited[logical] = true;
	std::vector<uint8_t> page;
	if (!readPage(indexFile_, indexSize_, index_, logical, page) || readLittleEndian<uint32_t>(page.data()) != INDEX_PAGE_ACTIVE) return;
	const size_t count = readLittleEndian<uint32_t>(page.data() + 16);
	// 20 bytes of header, then 10 bytes per key and 4 for the last child, before the counts.
	if (count > (PAGE - 30) / 10) return;
	size_t o = 20 + 4 * count;
	const size_t children = o;
	o += 4 * (count + 1);
	const size_t keyTable = o;
	o += 2 * count;
	if (!fits(PAGE, o, 2)) return;
	const size_t definitions = readLittleEndian<uint16_t>(page.data() + o);
	const size_t definitionTable = o + 2;
	o += 2 + 2 * definitions;
	if (!fits(PAGE, o, 2)) return;
	const size_t parts = readLittleEndian<uint16_t>(page.data() + o);
	const size_t partTable = o + 2;
	o += 2 + 2 * ((size_t)parts + 1);
	if (o > PAGE) return;
	const size_t text = o;
	auto part = [&](size_t n, std::string& out) {
		if (n > parts) return false;
		const size_t at = text + readLittleEndian<uint16_t>(page.data() + partTable + 2 * n);
		if (at >= PAGE) return false;
		const uint8_t* end = static_cast<const uint8_t*>(memchr(page.data() + at, 0, PAGE - at));
		if (!end) return false;
		out.assign(reinterpret_cast<const char*>(page.data() + at), end - (page.data() + at));
		return true;
	};
	auto child = [&](size_t i) {
		const uint32_t c = readLittleEndian<uint32_t>(page.data() + children + 4 * i);
		if (c != 0 && c != 0xFFFFFFFF) collectKeys(c, depth + 1, visited);
	};
	for (size_t i = 0; i < count; ++i) {
		child(i);
		const size_t definition = readLittleEndian<uint16_t>(page.data() + keyTable + 2 * i);
		if (definition >= definitions) continue;
		const size_t partCount = readLittleEndian<uint16_t>(page.data() + definitionTable + 2 * definition);
		if (definition + partCount >= definitions) continue;
		std::string key, piece;
		bool whole = true;
		for (size_t j = 0; j < partCount && whole; ++j) {
			whole = part(readLittleEndian<uint16_t>(page.data() + definitionTable + 2 * (definition + 1 + j)), piece);
			key += (j ? "/" : "") + piece;
		}
		if (whole) keys_.push_back(std::move(key));
	}
	child(count);
}

std::vector<std::string> CimRepository::keys(const std::string& prefix) const {
	std::vector<std::string> out;
	for (auto it = std::lower_bound(keys_.begin(), keys_.end(), prefix);
	     it != keys_.end() && it->compare(0, prefix.size(), prefix) == 0; ++it)
		out.push_back(*it);
	return out;
}

/*! A record, by its key's last part ".<page>.<id>.<size>": found in its
 *  page's table, continued on the following logical pages when larger. */
bool CimRepository::object(const std::string& key, std::vector<uint8_t>& out) {
	const size_t dot = key.find('.', key.rfind('/') == std::string::npos ? 0 : key.rfind('/'));
	if (dot == std::string::npos) return false;
	unsigned long page = 0, id = 0;
	unsigned long long size = 0;
	if (sscanf(key.c_str() + dot, ".%lu.%lu.%llu", &page, &id, &size) != 3 || size == 0 || size > RECORD_MAX) return false;
	std::vector<uint8_t> buffer;
	if (!readPage(objectsFile_, objectsSize_, data_, (uint32_t)page, buffer)) return false;
	for (size_t o = 0; fits(PAGE, o, 16); o += 16) {
		const uint32_t record = readLittleEndian<uint32_t>(buffer.data() + o), offset = readLittleEndian<uint32_t>(buffer.data() + o + 4), length = readLittleEndian<uint32_t>(buffer.data() + o + 8);
		if (record == 0 && offset == 0 && length == 0) return false;
		if (record != id) continue;
		if (offset >= PAGE || length < size) return false;
		out.assign(buffer.begin() + offset, buffer.begin() + offset + std::min<size_t>((size_t)size, PAGE - offset));
		for (uint32_t next = (uint32_t)page + 1; out.size() < size; ++next) {
			if (!readPage(objectsFile_, objectsSize_, data_, next, buffer)) return false;
			out.insert(out.end(), buffer.begin(), buffer.begin() + std::min<size_t>(PAGE, (size_t)size - out.size()));
		}
		return true;
	}
	return false;
}

std::vector<std::wstring> CimRepository::namespaces() {
	std::vector<std::wstring> out;
	const std::vector<const CimClass*> chain = classChain(L"root", cimNameHash(L"__namespace"));
	std::vector<std::pair<std::wstring, unsigned>> pending = { { L"root", 0 } };
	while (!pending.empty() && out.size() < 100000) {
		const auto [space, depth] = pending.back();
		pending.pop_back();
		out.push_back(space);
		if (depth >= DEPTH_MAX || chain.empty()) continue;
		for (const CimValues& values : instances(space, cimNameHash(L"__namespace"), chain))
			for (const auto& [name, value] : values)
				if (name == L"Name" && !value.text().empty()) pending.push_back({ space + L"\\" + value.text(), depth + 1 });
	}
	return out;
}

std::vector<std::string> CimRepository::classHashesWithInstances(const std::wstring& space) {
	std::vector<std::string> out;
	const std::string prefix = namespacePart(space) + "/CI_";
	for (const std::string& key : keys(prefix)) {
		const size_t end = key.find('/', prefix.size());
		if (end == std::string::npos || key.compare(end, 4, "/IL_") != 0) continue;
		std::string hash = key.substr(prefix.size(), end - prefix.size());
		if (out.empty() || out.back() != hash) out.push_back(std::move(hash));
	}
	return out;
}

const CimClass* CimRepository::definition(const std::wstring& space, const std::string& classHash) {
	for (const std::string& ns : { namespacePart(space), "NS_" + cimNameHash(std::wstring(SYSTEM_NAMESPACE, SYSTEM_NAMESPACE + strlen(SYSTEM_NAMESPACE))) }) {
		const std::string id = ns + "/CD_" + classHash;
		const auto cached = classes_.find(id);
		if (cached != classes_.end()) return cached->second.get();
		const std::vector<std::string> found = keys(id + ".");
		if (found.empty()) continue;
		std::vector<uint8_t> record;
		auto c = std::make_unique<CimClass>();
		if (!object(found.front(), record) || !parseCimClass(record, *c)) return nullptr;
		return (classes_[id] = std::move(c)).get();
	}
	return nullptr;
}

std::vector<const CimClass*> CimRepository::classChain(const std::wstring& space, const std::string& classHash) {
	std::vector<const CimClass*> chain;
	const CimClass* c = definition(space, classHash);
	while (c && chain.size() < DEPTH_MAX) {
		chain.push_back(c);
		if (c->superName.empty()) {
			std::reverse(chain.begin(), chain.end());
			return chain;
		}
		c = definition(space, cimNameHash(c->superName));
	}
	return {};
}

std::vector<CimValues> CimRepository::instances(const std::wstring& space, const std::string& classHash,
                                                const std::vector<const CimClass*>& chain) {
	std::vector<CimValues> out;
	for (const std::string& key : keys(namespacePart(space) + "/CI_" + classHash + "/IL_")) {
		std::vector<uint8_t> record;
		CimValues values;
		if (object(key, record) && parseCimInstance(record, chain, values)) out.push_back(std::move(values));
		else log(2, L"🔥WMI instance not read: " + decodeText(key, CP_UTF8));
	}
	return out;
}
